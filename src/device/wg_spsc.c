/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Lock-free SPSC bounded ring buffer — implementation.
 */

#include "wg_spsc.h"

#include "platform/wg_platform.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/eventfd.h>
#include <time.h>
#endif
#endif

#ifdef __linux__
/* How long a consumer spins for an item before it blocks on the eventfd
 * (Linux). A time, not a count of spin-loop hints, for the same reason
 * as WG_SEQ_SPIN_NS: PAUSE costs about 140 cycles on Skylake and later
 * x86 and ARM's yield a few nanoseconds, so the old 512 hints ("about
 * 2 µs") were about 20 µs on x86 and under 1 µs on arm64. Eight crypto
 * workers per device each spun that long after every batch, which is
 * where much of x86's CPU at moderate rates went. */
#ifndef WG_SPSC_SPIN_NS
#if defined(__aarch64__)
#define WG_SPSC_SPIN_NS \
    1000 /* Graviton: 2 µs cost +3.5 pts at 200 B UDP, 1 µs matched main */
#else
#define WG_SPSC_SPIN_NS \
    2000 /* c6i: -3 pts at TCP 1G, -17 at 200 B UDP, throughput unchanged */
#endif
#endif
/* The clock is read once per this many spins (about 0.6 µs of PAUSE). */
#define WG_SPSC_SPIN_CHECK_EVERY 16

static inline uint64_t spsc_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

/* Spin-loop control for wg_spsc_pop: bounded by time on Linux, by
 * q->spin_limit hints elsewhere. spin_limit == 0 means no spin. */
static inline uint64_t spsc_spin_start(const wg_spsc_t *q)
{
#ifdef __linux__
    return q->spin_limit > 0 ? spsc_now_ns() : 0;
#else
    (void)q;
    return 0;
#endif
}

static inline bool spsc_spin_continue(const wg_spsc_t *q, int spin, uint64_t start)
{
#ifdef __linux__
    if (q->spin_limit <= 0)
        return false;
    if (spin % WG_SPSC_SPIN_CHECK_EVERY != WG_SPSC_SPIN_CHECK_EVERY - 1)
        return true;
    return spsc_now_ns() - start < WG_SPSC_SPIN_NS;
#else
    (void)start;
    return spin < q->spin_limit;
#endif
}

/* ──────────────────────────────────────── */

wg_error_t wg_spsc_init(wg_spsc_t *q, size_t capacity)
{
    /* capacity must be a power of 2 */
    if (capacity == 0 || (capacity & (capacity - 1)) != 0)
        return WG_ERR_INVALID_ARGUMENT;

    memset(q, 0, sizeof(*q));

    q->items = calloc(capacity, sizeof(void *));
    if (!q->items)
        return WG_ERR_NO_MEMORY;

    q->mask = capacity - 1;
#if defined(__APPLE__) && defined(__aarch64__)
    q->spin_limit = 16384; /* ARM64 yield ≈ 1ns, so 16384 yields ≈ 16µs.
                            * Covers typical inter-packet arrival (~15µs at
                            * 67K pkt/sec).  macOS pipe(2) doesn't coalesce
                            * writes like Linux eventfd, so avoiding the pipe
                            * block entirely is critical for throughput.
                            * Pure userspace spinning — no kernel involvement. */
#elif defined(_WIN32) && defined(_M_ARM64)
    q->spin_limit = 16384; /* Windows ARM64: yield ≈ 1ns, same as macOS ARM64.
                            * WaitForSingleObject has high latency (~15µs+),
                            * so spinning longer avoids kernel transition. */
#elif defined(__APPLE__)
    q->spin_limit = 4096; /* x86_64 macOS: PAUSE ≈ 4ns, 4096 ≈ 16µs. */
#elif defined(__linux__)
    q->spin_limit = 1; /* Linux: spin on, bounded by WG_SPSC_SPIN_NS. */
#else
    q->spin_limit = 512; /* Windows x64 and others: 512 PAUSEs. */
#endif
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
    atomic_store(&q->closed, false);
    atomic_store(&q->consumer_waiting, false);

#ifdef _WIN32
    q->wake_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!q->wake_event) {
        free(q->items);
        q->items = NULL;
        return WG_ERR_NO_MEMORY;
    }
#elif defined(__linux__)
    q->wake_fd = eventfd(0, EFD_CLOEXEC);
    if (q->wake_fd < 0) {
        free(q->items);
        q->items = NULL;
        return WG_ERR_NO_MEMORY;
    }
#else
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            free(q->items);
            q->items = NULL;
            return WG_ERR_NO_MEMORY;
        }
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        q->wake_fd = pipefd[0];       /* read end */
        q->wake_write_fd = pipefd[1]; /* write end */
    }
#endif

    return WG_OK;
}

void wg_spsc_destroy(wg_spsc_t *q)
{
    if (!q)
        return;
#ifdef _WIN32
    if (q->wake_event)
        CloseHandle(q->wake_event);
    q->wake_event = NULL;
#else
    if (q->wake_fd >= 0)
        close(q->wake_fd);
#ifndef __linux__
    if (q->wake_write_fd >= 0)
        close(q->wake_write_fd);
    q->wake_write_fd = -1;
#endif
    q->wake_fd = -1;
#endif
    free(q->items);
    q->items = NULL;
}

/* ──────────────────────────────────────── */

static inline void wake_consumer(wg_spsc_t *q)
{
    /* Dekker pattern: producer stores tail (release), then loads
     * consumer_waiting.  Consumer stores consumer_waiting, then loads tail.
     * On ARM64 (and other weakly-ordered architectures), release+acquire to
     * different addresses can reorder — both sides can miss each other's
     * store.  A seq_cst fence between store and load on the producer side
     * prevents this.  On x86 (TSO) this compiles to MFENCE but the hot path
     * rarely takes this branch (consumer_waiting is usually false). */
    atomic_thread_fence(memory_order_seq_cst);
    /* Only the producer that flips consumer_waiting from true to false
     * signals, so a sleeping consumer costs one write(2) however many
     * items land before it runs. The plain load keeps the common case
     * (consumer awake) free of a read-modify-write. A consumer that
     * rechecks, finds an item and skips the read leaves one count in the
     * eventfd; its next block returns at once and the loop rechecks. */
    if (atomic_load_explicit(&q->consumer_waiting, memory_order_acquire) &&
        atomic_exchange_explicit(&q->consumer_waiting, false, memory_order_acq_rel)) {
#ifdef _WIN32
        SetEvent(q->wake_event);
#else
#ifdef __APPLE__
        /* Bump the word first: a consumer that already passed its
         * recheck waits for this exact change. */
        atomic_fetch_add_explicit(&q->wake_word, 1, memory_order_release);
#if WG_HAVE_OS_SYNC
        if (WG_OS_SYNC_AVAILABLE()) {
            os_sync_wake_by_address_any(&q->wake_word, sizeof(q->wake_word),
                                        OS_SYNC_WAKE_BY_ADDRESS_NONE);
            return;
        }
#endif
#endif
        uint64_t one = 1;
#ifdef __linux__
        (void)write(q->wake_fd, &one, sizeof(one));
#else
        (void)write(q->wake_write_fd, &one, sizeof(one));
#endif
#endif
    }
}

wg_error_t wg_spsc_try_push(wg_spsc_t *q, void *item)
{
    if (atomic_load_explicit(&q->closed, memory_order_relaxed))
        return WG_ERR_DEVICE_CLOSED;

    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&q->head, memory_order_acquire);

    if (tail - head > q->mask) /* full: capacity = mask + 1 */
        return WG_ERR_QUEUE_FULL;

    q->items[tail & q->mask] = item;
    atomic_store_explicit(&q->tail, tail + 1, memory_order_release);

    wake_consumer(q);
    return WG_OK;
}

int wg_spsc_try_push_batch(wg_spsc_t *q, void **items, int count)
{
    if (count <= 0)
        return 0;
    if (atomic_load_explicit(&q->closed, memory_order_relaxed))
        return 0;

    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    size_t avail = (q->mask + 1) - (tail - head);

    int n = count < (int)avail ? count : (int)avail;
    for (int i = 0; i < n; i++) {
        q->items[(tail + i) & q->mask] = items[i];
    }

    if (n > 0) {
        atomic_store_explicit(&q->tail, tail + n, memory_order_release);
        wake_consumer(q);
    }

    return n;
}

/* ──────────────────────────────────────── */

wg_error_t wg_spsc_pop(wg_spsc_t *q, void **out)
{
    for (;;) {
        size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);

        if (head < tail) {
            *out = q->items[head & q->mask];
            atomic_store_explicit(&q->head, head + 1, memory_order_release);
            return WG_OK;
        }

        if (atomic_load_explicit(&q->closed, memory_order_acquire)) {
            *out = NULL;
            return WG_ERR_DEVICE_CLOSED;
        }

        /* Spin-wait briefly before blocking on eventfd.
         * With container pattern, the SPSC has fewer entries (1 per TUN read
         * batch) so the consumer often empties it between producer pushes.
         * Spinning avoids the ~5-50µs eventfd kernel wake-up latency.
         * On single-core, spin_limit=0 to avoid wasting the only CPU. */
        uint64_t spin_start = spsc_spin_start(q);
        for (int spin = 0; spsc_spin_continue(q, spin, spin_start); spin++) {
            tail = atomic_load_explicit(&q->tail, memory_order_acquire);
            if (head < tail) {
                *out = q->items[head & q->mask];
                atomic_store_explicit(&q->head, head + 1, memory_order_release);
                return WG_OK;
            }
            if (atomic_load_explicit(&q->closed, memory_order_acquire)) {
                *out = NULL;
                return WG_ERR_DEVICE_CLOSED;
            }
#if defined(_MSC_VER)
            YieldProcessor();
#elif defined(__x86_64__) || defined(__i386__)
            __builtin_ia32_pause();
#elif defined(__aarch64__)
            __asm__ volatile("yield");
#endif
        }

#ifndef __linux__
        /* macOS/non-Linux: brief sched_yield before pipe block.
         *
         * The tight spin above (16384 yields on ARM64 ≈ 16µs) handles
         * most inter-packet gaps.  This yield phase is a safety net for
         * occasional longer gaps, avoiding the expensive pipe block.
         * Keep iterations low (4) to avoid E-core migration on Apple
         * Silicon, which causes devastating latency spikes. */
        for (int yld = 0; yld < 4; yld++) {
            sched_yield();
            tail = atomic_load_explicit(&q->tail, memory_order_acquire);
            if (head < tail) {
                *out = q->items[head & q->mask];
                atomic_store_explicit(&q->head, head + 1, memory_order_release);
                return WG_OK;
            }
            if (atomic_load_explicit(&q->closed, memory_order_acquire)) {
                *out = NULL;
                return WG_ERR_DEVICE_CLOSED;
            }
        }
#endif

        /* Slow path: mark ourselves waiting, re-check, then block */
#if WG_HAVE_OS_SYNC
        uint32_t wake_seen = atomic_load_explicit(&q->wake_word, memory_order_relaxed);
#endif
        atomic_store_explicit(&q->consumer_waiting, true, memory_order_release);

        /* Dekker pattern: consumer stores consumer_waiting, then loads tail.
         * seq_cst fence ensures our store is visible before our load. */
        atomic_thread_fence(memory_order_seq_cst);

        /* Re-check after setting flag (avoid missed wakeup) */
        tail = atomic_load_explicit(&q->tail, memory_order_acquire);
        if (head < tail) {
            atomic_store_explicit(&q->consumer_waiting, false, memory_order_relaxed);
            *out = q->items[head & q->mask];
            atomic_store_explicit(&q->head, head + 1, memory_order_release);
            return WG_OK;
        }

        if (atomic_load_explicit(&q->closed, memory_order_acquire)) {
            atomic_store_explicit(&q->consumer_waiting, false, memory_order_relaxed);
            *out = NULL;
            return WG_ERR_DEVICE_CLOSED;
        }

        /* Block on event (Windows), eventfd (Linux), os_sync_wait_on_address
         * (macOS 14.4+, the futex; #64) or a pipe (older macOS). */
#ifdef _WIN32
        WaitForSingleObject(q->wake_event, INFINITE);
#else
#if WG_HAVE_OS_SYNC
        if (WG_OS_SYNC_AVAILABLE()) {
            /* The wake bumps wake_word; if it already did, this returns
             * at once. 1 ms timeout as a safety net, like the futex path. */
            os_sync_wait_on_address_with_timeout(
                &q->wake_word, wake_seen, sizeof(q->wake_word),
                OS_SYNC_WAIT_ON_ADDRESS_NONE, OS_CLOCK_MACH_ABSOLUTE_TIME, 1000000);
        } else
#endif
        {
            uint64_t dummy;
            (void)read(q->wake_fd, &dummy, sizeof(dummy));
        }
#endif

        atomic_store_explicit(&q->consumer_waiting, false, memory_order_relaxed);
    }
}

wg_error_t wg_spsc_try_pop(wg_spsc_t *q, void **out)
{
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);

    if (head >= tail) {
        *out = NULL;
        if (atomic_load_explicit(&q->closed, memory_order_relaxed))
            return WG_ERR_DEVICE_CLOSED;
        return WG_ERR_QUEUE_EMPTY;
    }

    *out = q->items[head & q->mask];
    atomic_store_explicit(&q->head, head + 1, memory_order_release);
    return WG_OK;
}

int wg_spsc_pop_batch(wg_spsc_t *q, void **out, int max)
{
    if (max <= 0)
        return 0;

    /* Block for first item */
    void *first;
    wg_error_t err = wg_spsc_pop(q, &first);
    if (err != WG_OK)
        return -1;

    out[0] = first;
    int popped = 1;

    /* Greedily drain up to max */
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    size_t avail = tail - head;
    int grab = (max - 1) < (int)avail ? (max - 1) : (int)avail;

    for (int i = 0; i < grab; i++) {
        out[popped++] = q->items[(head + i) & q->mask];
    }

    if (grab > 0)
        atomic_store_explicit(&q->head, head + grab, memory_order_release);

    return popped;
}

/* ──────────────────────────────────────── */

void wg_spsc_close(wg_spsc_t *q)
{
    atomic_store_explicit(&q->closed, true, memory_order_release);
    /* Wake consumer if blocked */
#ifdef _WIN32
    SetEvent(q->wake_event);
#else
#ifdef __APPLE__
    atomic_fetch_add_explicit(&q->wake_word, 1, memory_order_release);
#if WG_HAVE_OS_SYNC
    if (WG_OS_SYNC_AVAILABLE())
        os_sync_wake_by_address_all(&q->wake_word, sizeof(q->wake_word),
                                    OS_SYNC_WAKE_BY_ADDRESS_NONE);
#endif
#endif
    uint64_t one = 1;
#ifdef __linux__
    (void)write(q->wake_fd, &one, sizeof(one));
#else
    (void)write(q->wake_write_fd, &one, sizeof(one));
#endif
#endif
}

void wg_spsc_flush(wg_spsc_t *q, void (*free_fn)(void *))
{
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);

    while (head < tail) {
        void *item = q->items[head & q->mask];
        if (free_fn && item)
            free_fn(item);
        head++;
    }

    atomic_store_explicit(&q->head, tail, memory_order_relaxed);

    /* Drain any pending wake signal (non-blocking). */
#ifdef _WIN32
    if (q->wake_event)
        ResetEvent(q->wake_event);
#else
    if (q->wake_fd >= 0) {
        uint64_t dummy;
        int flags = fcntl(q->wake_fd, F_GETFL);
        fcntl(q->wake_fd, F_SETFL, flags | O_NONBLOCK);
        (void)read(q->wake_fd, &dummy, sizeof(dummy));
        fcntl(q->wake_fd, F_SETFL, flags);
    }
#endif
}

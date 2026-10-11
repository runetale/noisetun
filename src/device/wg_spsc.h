/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Lock-free Single-Producer / Single-Consumer (SPSC) bounded ring buffer.
 *
 * Designed for per-peer outbound/inbound queues where exactly one thread
 * pushes and one thread pops.  Uses atomic load/store with acquire/release
 * ordering — no mutex, no futex on the hot path.
 *
 * Blocking pop uses Linux eventfd (or a pipe on macOS/Windows); the
 * producer only writes to it when the consumer has set `consumer_waiting`.
 */

#ifndef WG_SPSC_H
#define WG_SPSC_H

#include "wg_error.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    /* Producer cache-line */
    _Alignas(64) _Atomic size_t tail; /* next write index (only producer writes) */

    /* Consumer cache-line */
    _Alignas(64) _Atomic size_t head; /* next read index (only consumer writes) */

    /* Shared (read-only after init) */
    void **items;
    size_t mask; /* capacity - 1;  capacity MUST be power of 2 */

    /* Signalling */
    _Atomic bool closed;
    _Atomic bool consumer_waiting; /* set by consumer before blocking */
    _Atomic uint32_t wake_word;    /* macOS 14.4+: bumped by the producer before
                                    * os_sync_wake_by_address; the consumer waits
                                    * for it to change (pipe on older macOS) */
#ifdef _WIN32
    void *wake_event; /* Win32 manual-reset Event */
#else
    int wake_fd; /* read end: eventfd (Linux) or pipe[0] (others) */
#ifndef __linux__
    int wake_write_fd; /* write end of pipe (non-Linux only) */
#endif
#endif
    int spin_limit; /* spin iterations before blocking (0 = no spin);
                     * on Linux only on/off, the bound is WG_SPSC_SPIN_NS */
} wg_spsc_t;

/*
 * Init with the given capacity (must be power of 2).
 * Creates an eventfd (Linux) or pipe (macOS/Windows) for blocking pop.
 */
wg_error_t wg_spsc_init(wg_spsc_t *q, size_t capacity);

/*
 * Destroy: free ring buffer, close wake fd.
 */
void wg_spsc_destroy(wg_spsc_t *q);

/*
 * Non-blocking push.  Returns WG_OK, WG_ERR_QUEUE_FULL, or WG_ERR_DEVICE_CLOSED.
 */
wg_error_t wg_spsc_try_push(wg_spsc_t *q, void *item);

/*
 * Non-blocking batch push.  Returns count of items pushed (0..count).
 */
int wg_spsc_try_push_batch(wg_spsc_t *q, void **items, int count);

/*
 * Blocking pop — waits until an item is available or the queue is closed.
 */
wg_error_t wg_spsc_pop(wg_spsc_t *q, void **out);

/*
 * Non-blocking pop.
 */
wg_error_t wg_spsc_try_pop(wg_spsc_t *q, void **out);

/*
 * Blocking batch pop — blocks for at least one, then greedily drains up to max.
 * Returns count popped, or -1 if closed+empty.
 */
int wg_spsc_pop_batch(wg_spsc_t *q, void **out, int max);

/*
 * Close the queue.  Wakes any blocked consumer.
 */
void wg_spsc_close(wg_spsc_t *q);

/*
 * Flush: pop and discard all items, calling free_fn on each if non-NULL.
 * NOT thread-safe — call only when no producer/consumer is active.
 */
void wg_spsc_flush(wg_spsc_t *q, void (*free_fn)(void *));

/*
 * Return current item count (approximate — no lock).
 */
static inline size_t wg_spsc_count(const wg_spsc_t *q)
{
    size_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
    return t - h;
}

/*
 * Return whether closed.
 */
static inline bool wg_spsc_is_closed(const wg_spsc_t *q)
{
    return atomic_load_explicit(&q->closed, memory_order_acquire);
}

#endif /* WG_SPSC_H */

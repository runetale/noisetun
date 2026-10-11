/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * DEV-7 (partial): TUN read worker — reads IP packets from the TUN device,
 * looks up the destination peer via AllowedIPs, and stages outbound elements
 * for encryption.
 *
 * DEV-9: Encryption worker — pulls outbound elements from the device
 * encryption queue and encrypts them in-place using ChaCha20-Poly1305.
 *
 * DEV-12: Sequential sender — per-peer thread that waits for encryption
 * completion and sends packets via bind in order.
 *
 * Reference: wireguard-go/device/send.go
 */

#include "wg_workers.h"
#include "wg_seq_wake.h"

#include "../crypto/wg_crypto.h"
#include "../peer/wg_allowedips.h"
#include "../session/wg_session.h"
#include "../timers/wg_timers.h"
#include "../transport/wg_transport.h"

#include "../device/wg_pools.h"
#include "../device/wg_spsc.h"

#include "platform/wg_platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif


/* CPU-friendly spin hint. */
#if defined(_MSC_VER)
#include <intrin.h>
#if defined(_M_ARM64)
#define WG_CPU_RELAX() __yield()
#elif defined(_M_X64) || defined(_M_IX86)
#define WG_CPU_RELAX() _mm_pause()
#else
#define WG_CPU_RELAX() ((void)0)
#endif
#elif defined(__x86_64__) || defined(__i386__)
#define WG_CPU_RELAX() __builtin_ia32_pause()
#elif defined(__aarch64__)
#define WG_CPU_RELAX() __asm__ volatile("yield")
#else
#define WG_CPU_RELAX() ((void)0)
#endif

/* Adaptive spin + futex helpers for sequential SEND thread wake-up.
 * Send crypto workers call seq_wake_send_signal() after encryption.
 * Sequential sender calls seq_wake_send_wait() when no work is found.
 * Separated from recv to eliminate false wakeups (#35). */
static inline void seq_wake_send_signal(wg_device_t *dev)
{
    wg_seq_wake_signal(&dev->seq_wake_send, &dev->seq_wake_send_waiting);
}

#if defined(__linux__)
static inline void seq_wake_send_wait(wg_device_t *dev, int spin_iters)
{
    /* exchange, not store: a second worker's signal landing between a
     * load and a store would be overwritten. Work that is already waiting
     * needs no clock read. */
    (void)spin_iters; /* Linux spins for WG_SEQ_SPIN_NS instead */
    if (atomic_load_explicit(&dev->seq_wake_send, memory_order_relaxed) &&
        atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
        return;
    uint64_t start = wg_seq_spin_now_ns();
    for (;;) {
        for (int i = 0; i < WG_SEQ_SPIN_CHECK_EVERY; i++) {
            if (atomic_load_explicit(&dev->seq_wake_send, memory_order_relaxed) &&
                atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
                return;
            WG_CPU_RELAX();
        }
        if (wg_seq_spin_now_ns() - start >= WG_SEQ_SPIN_NS)
            break;
    }

    /* Announce the wait, then look once more: a signal that lands after
     * the spin either shows up in the exchange or sees the flag and makes
     * the FUTEX_WAKE. If it lands between the exchange and FUTEX_WAIT,
     * the word is no longer 0 and FUTEX_WAIT returns at once. */
    atomic_store_explicit(&dev->seq_wake_send_waiting, 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if (!atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acquire)) {
        struct timespec timeout = {.tv_sec = WG_SEQ_FUTEX_TIMEOUT_NS / 1000000000L,
                                   .tv_nsec = WG_SEQ_FUTEX_TIMEOUT_NS % 1000000000L};
        syscall(SYS_futex, &dev->seq_wake_send, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                &timeout, NULL, 0);
        /* Consume the signal that woke us, so the next idle wait does not
         * return on its first spin. An exchange, not a relaxed store: if it
         * reads 1, acquire makes the signalling worker's element state
         * visible to the scan that follows; if the worker signals after
         * it, the word stays 1. Either way no signal is lost. */
        (void)atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel);
    }
    atomic_store_explicit(&dev->seq_wake_send_waiting, 0, memory_order_relaxed);
}
#elif defined(_WIN32)
static inline void seq_wake_send_wait(wg_device_t *dev, int spin_iters)
{
    for (int i = 0; i < spin_iters; i++) {
        if (atomic_load_explicit(&dev->seq_wake_send, memory_order_relaxed) &&
            atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
            return;
        WG_CPU_RELAX();
    }

    /* Consume a signal that arrived after the spin instead of
     * overwriting it with 0; otherwise wait (the compare value 0 makes a
     * later signal return WaitOnAddress at once). */
    if (atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
        return;
    ULONG zero = 0;
    WaitOnAddress((volatile VOID *)&dev->seq_wake_send, &zero, sizeof(ULONG), 1);
}
#elif defined(__APPLE__)
/* macOS: the Linux shape (spin WG_SEQ_SPIN_NS, announce, sleep) with
 * os_sync_wait_on_address (macOS 14.4) in place of FUTEX_WAIT. Before
 * this the thread polled with sched_yield(): a syscall per turn, a
 * million a second per sequential thread, and most of their CPU on
 * Apple silicon (performance-analysis.md #64). Older macOS keeps the
 * poll. */
static inline void seq_wake_send_wait(wg_device_t *dev, int spin_iters)
{
    (void)spin_iters;
    if (atomic_load_explicit(&dev->seq_wake_send, memory_order_relaxed) &&
        atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
        return;
    uint64_t start = wg_seq_spin_now_ns();
    for (;;) {
        for (int i = 0; i < WG_SEQ_SPIN_CHECK_EVERY; i++) {
            if (atomic_load_explicit(&dev->seq_wake_send, memory_order_relaxed) &&
                atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel))
                return;
            WG_CPU_RELAX();
        }
        if (wg_seq_spin_now_ns() - start >= WG_SEQ_SPIN_NS)
            break;
    }
#if WG_HAVE_OS_SYNC
    if (WG_OS_SYNC_AVAILABLE()) {
        atomic_store_explicit(&dev->seq_wake_send_waiting, 1, memory_order_relaxed);
        atomic_thread_fence(memory_order_seq_cst);
        if (!atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acquire)) {
            os_sync_wait_on_address_with_timeout(
                &dev->seq_wake_send, 0, sizeof(dev->seq_wake_send),
                OS_SYNC_WAIT_ON_ADDRESS_NONE, OS_CLOCK_MACH_ABSOLUTE_TIME,
                (uint64_t)WG_SEQ_FUTEX_TIMEOUT_NS);
            (void)atomic_exchange_explicit(&dev->seq_wake_send, 0, memory_order_acq_rel);
        }
        atomic_store_explicit(&dev->seq_wake_send_waiting, 0, memory_order_relaxed);
        return;
    }
#endif
    sched_yield();
}
#else
static inline void seq_wake_send_wait(wg_device_t *dev, int spin_iters)
{
    (void)spin_iters;
    sched_yield();
}
#endif

/* Forward declarations. */
static void encrypt_elem(wg_outbound_elem_t *elem, wg_device_t *dev);
static void keep_key_fresh_sending(struct wg_peer *peer);

/* ────────────────────────────────────────
 * Outbound element allocation (pool-backed)
 *
 * When a pool is available, elems are recycled to avoid
 * per-packet calloc/free overhead.
 * ──────────────────────────────────────── */

wg_outbound_elem_t *wg_outbound_elem_new(void)
{
    wg_outbound_elem_t *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->pool = NULL;
    atomic_store_explicit(&e->refs, 1, memory_order_relaxed);
    return e;
}

void wg_outbound_elem_free(void *elem)
{
    wg_outbound_elem_t *e = elem;
    if (!e)
        return;
#if WG_SEQ_INLINE
    if (!wg_elem_drop_ref(&e->refs))
        return; /* a crypto SPSC still points at it */
#endif

    /* If this elem came from a pool, return it there.
     * The pool's reset callback handles keypair release and field cleanup. */
    if (e->pool) {
        wg_wait_pool_put(e->pool, e);
        return;
    }

    /* Non-pooled path: full cleanup. */
    if (e->keypair)
        wg_noise_keypair_put(e->keypair);
    free(e);
}

/* ────────────────────────────────────────
 * Helper: determine IP version and extract dst address
 * ──────────────────────────────────────── */

static struct wg_peer *lookup_peer_for_packet(wg_device_t *dev, const uint8_t *packet,
                                              size_t len)
{
    if (len < 1)
        return NULL;

    uint8_t version = (packet[0] >> 4) & 0x0F;

    if (version == 4 && len >= 20) {
        /* IPv4: dst address at offset 16, 4 bytes */
        return wg_allowedips_lookup(&dev->allowedips, packet + 16, AF_INET);
    } else if (version == 6 && len >= 40) {
        /* IPv6: dst address at offset 24, 16 bytes */
        return wg_allowedips_lookup(&dev->allowedips, packet + 24, AF_INET6);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Helper: send a packet via bind to a peer's endpoint
 * ──────────────────────────────────────── */

wg_error_t wg_peer_send_buffer(struct wg_peer *peer, uint8_t *buf, size_t len)
{
    wg_device_t *dev = peer->device;

    pthread_rwlock_rdlock(&dev->net.lock);
    if (!dev->net.bind.send) {
        pthread_rwlock_unlock(&dev->net.lock);
        return WG_ERR_BIND;
    }

    wg_endpoint_t ep;
    if (!wg_peer_get_endpoint(peer, &ep)) {
        pthread_rwlock_unlock(&dev->net.lock);
        return WG_ERR_BIND;
    }

    uint8_t *bufs[1] = {buf};
    int sizes[1] = {(int)len};
    int ret = dev->net.bind.send(dev->net.bind.ctx, bufs, sizes, 1, &ep);
    pthread_rwlock_unlock(&dev->net.lock);

    if (ret <= 0)
        return WG_ERR_SEND;

    atomic_fetch_add(&peer->tx_bytes, (uint64_t)len);
    return WG_OK;
}

/* ────────────────────────────────────────
 * Helper: dual-enqueue outbound elem to prev_queue (ordering) + SPSC (crypto).
 *
 * Same pattern as enqueue_inbound: element goes to both per-peer
 * prev_queue (ordering for sequential sender) and SPSC (parallel
 * crypto dispatch).
 * ──────────────────────────────────────── */
static void enqueue_outbound(wg_device_t *dev, struct wg_peer *peer,
                             wg_outbound_elem_t *elem)
{
    /* Always dual-enqueue: prev_queue (ordering) + SPSC (crypto dispatch).
     * Enables pipelining: crypto worker + sequential sender on separate threads.
     * One reference per queue; the enqueue publishes it. */
#if WG_SEQ_INLINE
    atomic_store_explicit(&elem->refs, 2, memory_order_relaxed);
#endif
    if (!wg_prev_queue_enqueue(&peer->queue.tx_order, elem)) {
#if WG_SEQ_INLINE
        atomic_store_explicit(&elem->refs, 1, memory_order_relaxed);
#endif
        atomic_fetch_add(&dev->stats.outbound_drops, 1);
        wg_outbound_elem_free(elem);
        return;
    }

    uint64_t idx = atomic_fetch_add_explicit(&dev->rtc.send_rr, 1, memory_order_relaxed);
    int w = (int)(idx % (uint64_t)dev->rtc.num_send);

    /* Backpressure on SPSC push: emulate wireguard-go's blocking channel.
     * Phase 1: 32 PAUSE iterations (~2µs) — fast path for transient fullness.
     * Phase 2: sched_yield + retry 64 times — let crypto workers drain.
     * Only drop after exhausting both phases (~ms-scale wait). */
    bool pushed = false;
    for (int retry = 0; retry < 32; retry++) {
        if (wg_spsc_try_push(&dev->rtc.send[w].queue, elem) == WG_OK) {
            pushed = true;
            break;
        }
        WG_CPU_RELAX();
    }
    for (int retry = 0; !pushed && retry < 64; retry++) {
        sched_yield();
        if (wg_spsc_try_push(&dev->rtc.send[w].queue, elem) == WG_OK) {
            pushed = true;
            break;
        }
    }
    /* The sequential sender may have claimed it meanwhile; then it is
     * encrypted and sent after all, and nothing is dropped. Either way
     * the SPSC's reference goes. */
    if (!pushed) {
#if WG_SEQ_INLINE
        if (wg_elem_kill(&elem->state))
            atomic_fetch_add(&dev->stats.outbound_drops, 1);
        wg_outbound_elem_free(elem);
#else
        atomic_store_explicit(&elem->state, WG_ELEM_DEAD, memory_order_release);
        atomic_fetch_add(&dev->stats.outbound_drops, 1);
#endif
    }
}

/* ────────────────────────────────────────
 * Helper: encrypt an elem here and hand it to the sequential sender.
 *
 * For every producer but the TUN reader: the crypto SPSC queues have a
 * single producer, and a second thread pushing at the same time loses
 * an element, which then stalls the peer's tx_order for good (#143).
 * These are staged packets and keepalives, at most WG_QUEUE_STAGED_SIZE
 * per peer after a handshake, so encrypting them on the calling thread
 * costs little. Order still comes from tx_order.
 * ──────────────────────────────────────── */
static bool enqueue_outbound_encrypted(wg_device_t *dev, struct wg_peer *peer,
                                       wg_outbound_elem_t *elem)
{
    encrypt_elem(elem, dev);
    int st = (elem->packet_len > 0) ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
    /* Relaxed: the enqueue below publishes the elem with release. */
    atomic_store_explicit(&elem->state, st, memory_order_relaxed);
    if (!wg_prev_queue_enqueue(&peer->queue.tx_order, elem)) {
        atomic_fetch_add(&dev->stats.outbound_drops, 1);
        wg_outbound_elem_free(elem);
        return false;
    }
    return true;
}

/* ────────────────────────────────────────
 * Helper: encrypt + send a single elem inline (single-core path).
 * ──────────────────────────────────────── */
static void send_elem_inline(wg_device_t *dev, struct wg_peer *peer,
                             wg_outbound_elem_t *elem)
{
    encrypt_elem(elem, dev);
    if (elem->packet_len > 0) {
        wg_timers_any_authenticated_packet_traversal(peer);
        wg_timers_any_authenticated_packet_sent(peer);

        pthread_rwlock_rdlock(&dev->net.lock);
        if (dev->net.bind.send) {
            wg_endpoint_t ep;
            if (wg_peer_get_endpoint(peer, &ep)) {
                uint8_t *b[1] = {elem->buffer};
                int s[1] = {(int)elem->packet_len};
                dev->net.bind.send(dev->net.bind.ctx, b, s, 1, &ep);
            }
        }
        pthread_rwlock_unlock(&dev->net.lock);

        atomic_fetch_add(&peer->tx_bytes, (uint64_t)elem->packet_len);
        atomic_fetch_add(&dev->stats.send_batches, 1);
        atomic_fetch_add(&dev->stats.send_packets, 1);

        if (elem->packet_len > WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)
            wg_timers_data_sent(peer);
    }
    atomic_fetch_add(&dev->stats.staged_pushed, 1);
    wg_outbound_elem_free(elem);
    keep_key_fresh_sending(peer);
}

/* ────────────────────────────────────────
 * Inline path: send one TUN batch with one bind.send (#65).
 *
 * With inline_crypto the TUN reader encrypts on the spot. It used to
 * send each packet on its own, which on Windows was a kernel transition
 * per packet although Wintun hands over 16 packets per read, and on
 * macOS a sendmsg_x per packet. Packets for one peer are collected and
 * sent together; the timers and counters run once per batch, as the
 * sequential sender does.
 * ──────────────────────────────────────── */
#define WG_INLINE_BATCH 128

static void flush_inline_batch(wg_device_t *dev, struct wg_peer *peer,
                               wg_outbound_elem_t **elems, uint8_t **bufs, int *sizes,
                               int n)
{
    if (n == 0)
        return;

    wg_timers_any_authenticated_packet_traversal(peer);
    wg_timers_any_authenticated_packet_sent(peer);

    wg_endpoint_t ep;
    if (wg_peer_get_endpoint(peer, &ep)) {
        pthread_rwlock_rdlock(&dev->net.lock);
        if (dev->net.bind.send)
            dev->net.bind.send(dev->net.bind.ctx, bufs, sizes, n, &ep);
        pthread_rwlock_unlock(&dev->net.lock);
    }

    uint64_t total = 0;
    bool any_data = false;
    for (int i = 0; i < n; i++) {
        total += (uint64_t)sizes[i];
        if (sizes[i] > WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)
            any_data = true;
    }
    atomic_fetch_add(&peer->tx_bytes, total);
    atomic_fetch_add(&dev->stats.send_batches, 1);
    atomic_fetch_add(&dev->stats.send_packets, (uint64_t)n);
    atomic_fetch_add(&dev->stats.staged_pushed, (uint64_t)n);
    if (any_data)
        wg_timers_data_sent(peer);

    for (int i = 0; i < n; i++)
        wg_outbound_elem_free(elems[i]);
    keep_key_fresh_sending(peer);
}

/* ────────────────────────────────────────
 * DEV-7: TUN Read Worker
 *
 * Reads packets from TUN → looks up peer → stages for encryption.
 * Single thread per device.
 *
 * Two-Level Queue pattern: each elem is enqueued in BOTH
 * per-peer prev_queue (ordering) and device MPMC (crypto dispatch).
 * ──────────────────────────────────────── */

void *wg_worker_tun_read(void *arg)
{
    wg_device_t *dev = arg;

    if (!dev->tun.tun.read || !dev->tun.tun.ctx)
        return NULL;

    /* Determine batch size from TUN device. */
    int batch_size = 1;
    if (dev->tun.tun.batch_size && dev->tun.tun.ctx)
        batch_size = dev->tun.tun.batch_size(dev->tun.tun.ctx);
    if (batch_size < 1)
        batch_size = 1;
    if (batch_size > 128)
        batch_size = 128;

    wg_outbound_elem_t **elems = calloc((size_t)batch_size, sizeof(*elems));
    uint8_t **bufs = calloc((size_t)batch_size, sizeof(*bufs));
    int *sizes = calloc((size_t)batch_size, sizeof(*sizes));
    if (!elems || !bufs || !sizes) {
        free(elems);
        free(bufs);
        free(sizes);
        return NULL;
    }

    const int offset = WG_MESSAGE_TRANSPORT_HEADER;

    /* Inline path: the batch being collected for one bind.send. */
    wg_outbound_elem_t *ib_elems[WG_INLINE_BATCH];
    uint8_t *ib_bufs[WG_INLINE_BATCH];
    int ib_sizes[WG_INLINE_BATCH];
    int ib_n = 0;
    struct wg_peer *ib_peer = NULL;

    /* Pre-allocate all elements ONCE.
     * Elements are kept persistent across iterations — only replaced
     * when consumed (pushed to staged queue).  This eliminates
     * ~250 pool mutex operations per read cycle in the common non-GSO
     * case (128 get + 127 put → ~1 get for the consumed element). */
    for (int i = 0; i < batch_size; i++) {
        if (dev->pool.outbound) {
            elems[i] = wg_wait_pool_get(dev->pool.outbound);
            if (elems[i])
                elems[i]->pool = dev->pool.outbound;
        } else {
            elems[i] = wg_outbound_elem_new();
        }
        if (!elems[i]) {
            batch_size = i;
            break;
        }
        bufs[i] = elems[i]->buffer;
    }

    if (batch_size == 0)
        goto out;

    while (!wg_device_is_closed(dev) && wg_device_is_up(dev)) {
        /* Reset sizes for next read. */
        for (int i = 0; i < batch_size; i++)
            sizes[i] = WG_MAX_MESSAGE_SIZE;

        /* Read up to batch_size packets from TUN (GSO-split happens inside). */
        int n = dev->tun.tun.read(dev->tun.tun.ctx, bufs, sizes, batch_size, offset);
        if (n > 0) {
            /* Accumulate bytes locally, single atomic add. */
            uint64_t total_bytes = 0;
            for (int i = 0; i < n; i++)
                total_bytes += (uint64_t)sizes[i];
            atomic_fetch_add_explicit(&dev->stats.tun_read_calls, 1,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&dev->stats.tun_read_packets, (uint64_t)n,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&dev->stats.tun_read_bytes, total_bytes,
                                      memory_order_relaxed);
            if (n > 1) {
                atomic_fetch_add_explicit(&dev->stats.tun_read_gso, 1,
                                          memory_order_relaxed);
                atomic_fetch_add_explicit(&dev->stats.tun_read_gso_segs, (uint64_t)n,
                                          memory_order_relaxed);
            }
        }
        if (n <= 0) {
            if (n < 0 && !wg_device_is_closed(dev))
                continue;
            break;
        }

        /* Two-Level Queue: each elem enqueued to both per-peer
         * prev_queue (ordering) and device MPMC (crypto dispatch).
         * No containers — individual elements tracked by atomic state. */

        /* Peers looked up in this batch stay in use until the exit below. */
        wg_peer_reader_enter(dev, &dev->tun_peer_gen);

        struct wg_peer *cur_peer = NULL;
        wg_noise_keypair_t *kp = NULL;

        /* Destination IP cache: all GSO segments share the same dst,
         * so we skip the AllowedIPs trie lookup for ~97% of packets. */
        uint8_t cached_dst[16];
        int cached_dst_len = 0;
        struct wg_peer *cached_dst_peer = NULL;

        for (int i = 0; i < n; i++) {
            size_t pkt_len = (size_t)sizes[i];
            if (pkt_len == 0 || pkt_len > WG_MAX_SEGMENT_SIZE)
                continue;

            uint8_t *pkt = bufs[i] + offset;

            /* Fast path: check dst IP cache. */
            struct wg_peer *peer;
            uint8_t version = (pkt[0] >> 4) & 0x0F;
            if (version == 4 && pkt_len >= 20) {
                if (cached_dst_len == 4 && memcmp(pkt + 16, cached_dst, 4) == 0) {
                    peer = cached_dst_peer;
                } else {
                    peer = lookup_peer_for_packet(dev, pkt, pkt_len);
                    if (peer) {
                        memcpy(cached_dst, pkt + 16, 4);
                        cached_dst_len = 4;
                        cached_dst_peer = peer;
                    }
                }
            } else if (version == 6 && pkt_len >= 40) {
                if (cached_dst_len == 16 && memcmp(pkt + 24, cached_dst, 16) == 0) {
                    peer = cached_dst_peer;
                } else {
                    peer = lookup_peer_for_packet(dev, pkt, pkt_len);
                    if (peer) {
                        memcpy(cached_dst, pkt + 24, 16);
                        cached_dst_len = 16;
                        cached_dst_peer = peer;
                    }
                }
            } else {
                peer = lookup_peer_for_packet(dev, pkt, pkt_len);
            }
            if (!peer || !atomic_load(&peer->is_running))
                continue;

            /* On peer change, release old keypair and look up new one. */
            if (peer != cur_peer) {
                if (kp)
                    wg_noise_keypair_put(kp);
                kp = wg_noise_keypairs_get_current(&peer->keypairs);
                if (kp &&
                    (atomic_load_explicit(&kp->sending_counter, memory_order_relaxed) >=
                         WG_REJECT_AFTER_MESSAGES ||
                     wg_keypair_is_expired(kp))) {
                    wg_noise_keypair_put(kp);
                    kp = NULL;
                }
                cur_peer = peer;
            }

            elems[i]->packet_len = pkt_len;
            elems[i]->peer = peer;

            if (kp) {
                /* Fast path: assign nonce, enqueue for encryption. */
                wg_outbound_elem_t *elem = elems[i];
                elem->nonce = atomic_fetch_add(&kp->sending_counter, 1);
                if (elem->nonce >= WG_REJECT_AFTER_MESSAGES) {
                    atomic_store(&kp->sending_counter, WG_REJECT_AFTER_MESSAGES);
                    wg_noise_keypair_put(kp);
                    kp = NULL;
                    goto slow_path_i;
                }
                elem->keypair = wg_noise_keypair_get(kp);
                atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED,
                                      memory_order_relaxed);

                if (dev->inline_crypto) {
                    encrypt_elem(elem, dev);
                    if (elem->packet_len == 0) {
                        wg_outbound_elem_free(elem);
                    } else {
                        if (ib_n > 0 && (peer != ib_peer || ib_n == WG_INLINE_BATCH)) {
                            flush_inline_batch(dev, ib_peer, ib_elems, ib_bufs, ib_sizes,
                                               ib_n);
                            ib_n = 0;
                        }
                        ib_peer = peer;
                        ib_elems[ib_n] = elem;
                        ib_bufs[ib_n] = elem->buffer;
                        ib_sizes[ib_n] = (int)elem->packet_len;
                        ib_n++;
                    }
                } else {
                    enqueue_outbound(dev, peer, elem);
                }
                elems[i] = NULL;
            } else {
            slow_path_i:;
                /* Slow path: push elem to staged, initiate handshake. */
                wg_outbound_elem_t *elem = elems[i];
                atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED,
                                      memory_order_relaxed);
                wg_error_t serr = wg_queue_try_push(peer->queue.staged, elem);
                if (serr != WG_OK)
                    wg_outbound_elem_free(elem);
                elems[i] = NULL;
                wg_send_staged_packets(peer);
            }
        }

        if (ib_n > 0) {
            flush_inline_batch(dev, ib_peer, ib_elems, ib_bufs, ib_sizes, ib_n);
            ib_n = 0;
        }

        if (kp)
            wg_noise_keypair_put(kp);

        /* Before replenishing, which may wait for the pool. */
        wg_peer_reader_exit(&dev->tun_peer_gen);

        /* Replace only consumed elements — the critical optimization.
         * Non-GSO (93% of reads): typically 1 element consumed, 1 pool_get.
         * GSO (~7% of reads): ~46 consumed, 46 pool_get.
         * Old code: 128 pool_get + ~127 pool_put = ~255 mutex ops EVERY read. */
        for (int i = 0; i < batch_size; i++) {
            if (elems[i] == NULL) {
                if (dev->pool.outbound) {
                    elems[i] = wg_wait_pool_get(dev->pool.outbound);
                    if (elems[i])
                        elems[i]->pool = dev->pool.outbound;
                } else {
                    elems[i] = wg_outbound_elem_new();
                }
                if (!elems[i]) {
                    /* Alloc failure — compact and shrink batch. */
                    int j = 0;
                    for (int k = 0; k < batch_size; k++) {
                        if (elems[k]) {
                            elems[j] = elems[k];
                            bufs[j] = elems[j]->buffer;
                            j++;
                        }
                    }
                    batch_size = j;
                    break;
                }
                bufs[i] = elems[i]->buffer;
            } else {
                /* Reset reused element for next iteration. */
                elems[i]->peer = NULL;
                elems[i]->packet_len = 0;
            }
        }

        if (batch_size == 0)
            break;
    }

    /* Free all remaining persistent elements. */
    for (int i = 0; i < batch_size; i++) {
        if (elems[i])
            wg_outbound_elem_free(elems[i]);
    }

out:

    free(elems);
    free(bufs);
    free(sizes);
    return NULL;
}

/* ────────────────────────────────────────
 * DEV-7: TUN Write helper
 * ──────────────────────────────────────── */

wg_error_t wg_worker_tun_write(wg_device_t *dev, uint8_t **bufs, int *sizes, int count,
                               int offset)
{
    if (!dev->tun.tun.write || !dev->tun.tun.ctx)
        return WG_ERR_TUN;

    int n = dev->tun.tun.write(dev->tun.tun.ctx, bufs, sizes, count, offset);
    if (n <= 0)
        return WG_ERR_TUN;

    /* Track actual TUN write syscalls (= packets after GRO coalescing). */
    atomic_fetch_add(&dev->stats.tun_write_calls, (uint64_t)n);

    return WG_OK;
}

/* ────────────────────────────────────────
 * DEV-12: SendStagedPackets
 *
 * Drain the staged queue: look up current keypair,
 * assign nonces, push to both encryption + outbound queues.
 * If no valid keypair, initiate handshake instead.
 *
 * Reference: wireguard-go/device/send.go SendStagedPackets
 * ──────────────────────────────────────── */

void wg_send_staged_packets(struct wg_peer *peer)
{
    wg_device_t *dev = peer->device;

top:
    if (wg_queue_count(peer->queue.staged) == 0 || !wg_device_is_up(dev))
        return;

    /* Get current keypair. */
    wg_noise_keypair_t *kp = wg_noise_keypairs_get_current(&peer->keypairs);
    if (!kp ||
        atomic_load_explicit(&kp->sending_counter, memory_order_relaxed) >=
            WG_REJECT_AFTER_MESSAGES ||
        wg_keypair_is_expired(kp)) {
        if (kp)
            wg_noise_keypair_put(kp);
        wg_send_handshake_initiation(peer, false);
        return;
    }

    /* Pop individual elements from staged, assign nonces, encrypt, and
     * queue them for the sequential sender. The lock keeps callers
     * (handshake worker, recv workers, TUN reader) from interleaving one
     * peer's staged packets. This is cold path only. */
    pthread_mutex_lock(&peer->queue.staged_send_lock);
    bool queued = false;
    void *raw = NULL;
    while (wg_queue_try_pop(peer->queue.staged, &raw) == WG_OK) {
        wg_outbound_elem_t *elem = raw;
        elem->peer = peer;
        elem->nonce = atomic_fetch_add(&kp->sending_counter, 1);

        if (elem->nonce >= WG_REJECT_AFTER_MESSAGES) {
            atomic_store(&kp->sending_counter, WG_REJECT_AFTER_MESSAGES);
            wg_error_t restage = wg_queue_try_push(peer->queue.staged, elem);
            if (restage != WG_OK)
                wg_outbound_elem_free(elem);
            pthread_mutex_unlock(&peer->queue.staged_send_lock);
            wg_noise_keypair_put(kp);
            if (queued)
                seq_wake_send_signal(dev);
            goto top;
        }

        elem->keypair = wg_noise_keypair_get(kp);
        atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

        if (dev->inline_crypto) {
            send_elem_inline(dev, peer, elem);
        } else if (enqueue_outbound_encrypted(dev, peer, elem)) {
            queued = true;
        }
    }
    pthread_mutex_unlock(&peer->queue.staged_send_lock);

    wg_noise_keypair_put(kp);

    /* Wake the sequential sender once, as a crypto worker does. */
    if (queued)
        seq_wake_send_signal(dev);
}

/* ────────────────────────────────────────
 * DEV-12: Flush staged packets
 * ──────────────────────────────────────── */

void wg_peer_flush_staged_packets(struct wg_peer *peer)
{
    if (peer->queue.staged)
        wg_queue_flush(peer->queue.staged, wg_outbound_elem_free);
}

/* ────────────────────────────────────────
 * keepKeyFreshSending
 *
 * Check if we should initiate a rekey based on counter or time.
 *
 * Reference: wireguard-go/device/send.go keepKeyFreshSending
 * ──────────────────────────────────────── */

static void keep_key_fresh_sending(struct wg_peer *peer)
{
    wg_noise_keypair_t *kp = wg_noise_keypairs_get_current(&peer->keypairs);
    if (!kp)
        return;

    uint64_t nonce = atomic_load_explicit(&kp->sending_counter, memory_order_relaxed);
    bool need_rekey = (nonce > WG_REKEY_AFTER_MESSAGES) ||
                      (kp->i_am_initiator &&
                       (wg_mono_ns() - kp->birthdate_ns > WG_REKEY_AFTER_TIME_NS));

    wg_noise_keypair_put(kp);

    if (need_rekey)
        wg_send_handshake_initiation(peer, false);
}

/* ────────────────────────────────────────
 * Core encryption logic for a single element.
 * Used by both the worker thread and inline-crypto path.
 * ──────────────────────────────────────── */
static void encrypt_elem(wg_outbound_elem_t *elem, wg_device_t *dev)
{
    if (!elem->keypair) {
        elem->packet_len = 0;
        return;
    }
    wg_message_transport_t *hdr = (wg_message_transport_t *)elem->buffer;
    hdr->header.type = wg_htole32(WG_MESSAGE_TRANSPORT);
    hdr->receiver_index = wg_htole32(elem->keypair->remote_index);
    hdr->counter = wg_htole64(elem->nonce);

    uint8_t *plaintext = elem->buffer + WG_MESSAGE_TRANSPORT_HEADER;
    size_t padded_len = elem->packet_len;
    size_t pad = (16 - (padded_len % 16)) % 16;
    if (WG_MESSAGE_TRANSPORT_HEADER + padded_len + pad + WG_AEAD_TAG_SIZE >
        WG_MAX_MESSAGE_SIZE) {
        elem->packet_len = 0;
        return;
    }
    if (pad > 0) {
        memset(plaintext + padded_len, 0, pad);
        padded_len += pad;
    }
    size_t ct_len = 0;
    wg_error_t enc_err = wg_aead_encrypt(plaintext, &ct_len, plaintext, padded_len, NULL,
                                         0, elem->nonce, elem->keypair->sending_key);
    atomic_fetch_add(&dev->stats.encrypt_count, 1);
    if (enc_err == WG_OK) {
        elem->packet_len = WG_MESSAGE_TRANSPORT_HEADER + ct_len;
    } else {
        elem->packet_len = 0;
    }
}

/* ────────────────────────────────────────
 * RTC Send Worker (crypto + ordered drain)
 *
 * Pops outbound elements from its SPSC queue, encrypts them,
 * sets atomic state, then tries to drain the peer's prev_queue
 * for ordered sending via bind.  Uses trylock so only one worker
 * drains a given peer at a time.
 *
 * N workers per device (typically ncpu/2).
 * ──────────────────────────────────────── */

#define WG_RTC_SEND_BATCH 128

/* Drain the peer's tx_order prev_queue: send all elements whose
 * state is CRYPTED, skip DEAD.  Stops at first UNCRYPTED.
 *
 * Hot path optimizations (#35):
 * - bind send under net.lock for reading once per batch, not per packet (#129)
 * - keep_key_fresh: once per batch, by the caller after the drain lock
 * - batch pool put: single CAS instead of per-elem CAS
 * - stats returned via out params for local accumulation */
static int drain_tx_order(wg_device_t *dev, struct wg_peer *peer, uint64_t *out_packets,
                          uint64_t *out_bytes)
{
    uint8_t *batch_bufs[WG_RTC_SEND_BATCH];
    int batch_sizes[WG_RTC_SEND_BATCH];
    wg_outbound_elem_t *batch_elems[WG_RTC_SEND_BATCH];
    int batch_count = 0;
    bool any_data_sent = false;

    for (;;) {
        wg_outbound_elem_t *elem =
            (wg_outbound_elem_t *)wg_prev_queue_peek(&peer->queue.tx_order);
        if (!elem)
            break;

        int st = atomic_load_explicit(&elem->state, memory_order_acquire);
        if (!wg_elem_done(st))
            break;

        wg_prev_queue_drop_peeked(&peer->queue.tx_order);

        if (st == WG_ELEM_DEAD || elem->packet_len == 0) {
            wg_outbound_elem_free(elem);
            continue;
        }

        batch_bufs[batch_count] = elem->buffer;
        batch_sizes[batch_count] = (int)elem->packet_len;
        batch_elems[batch_count] = elem;
        if (elem->packet_len > WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)
            any_data_sent = true;
        batch_count++;

        if (batch_count >= WG_RTC_SEND_BATCH)
            break;
    }

    if (batch_count == 0)
        return 0;

    wg_timers_any_authenticated_packet_traversal(peer);
    wg_timers_any_authenticated_packet_sent(peer);

    /* Send under net.lock for reading, like every other sender, so a
     * bind update or device close (net.lock for writing) never closes the
     * socket under this sendmmsg (#129). Once per batch, not per packet. */
    wg_endpoint_t ep;
    if (wg_peer_get_endpoint(peer, &ep)) {
        pthread_rwlock_rdlock(&dev->net.lock);
        if (dev->net.bind.send)
            dev->net.bind.send(dev->net.bind.ctx, batch_bufs, batch_sizes, batch_count,
                               &ep);
        pthread_rwlock_unlock(&dev->net.lock);
    }

    uint64_t total_tx = 0;
    for (int j = 0; j < batch_count; j++)
        total_tx += (uint64_t)batch_sizes[j];
    atomic_fetch_add(&peer->tx_bytes, total_tx);

    if (any_data_sent)
        wg_timers_data_sent(peer);

    for (int i = 0; i < batch_count; i++)
        wg_outbound_elem_free(batch_elems[i]);

    /* Return stats for local accumulation. */
    *out_packets += (uint64_t)batch_count;
    *out_bytes += total_tx;
    return batch_count;
}

void *wg_worker_rtc_send(void *arg)
{
    wg_rtc_send_worker_t *w = arg;
    wg_device_t *dev = w->dev;

    /* Crypto-only: encrypt + set atomic state.
     * The sequential sender thread handles ordered UDP send.
     * This enables pipelining: crypto processes next batch while
     * sequential thread does I/O. */
    for (;;) {
        void *raw_batch[WG_RTC_SEND_BATCH];
        int n = wg_spsc_pop_batch(&w->queue, raw_batch, WG_RTC_SEND_BATCH);
        if (n <= 0)
            break;

        for (int i = 0; i < n; i++) {
            wg_outbound_elem_t *elem = raw_batch[i];
#if WG_SEQ_INLINE
            if (wg_elem_claim(&elem->state)) {
                encrypt_elem(elem, dev);
                int new_state = (elem->packet_len > 0) ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
                atomic_store_explicit(&elem->state, new_state, memory_order_release);
            }
            /* else the sequential sender took it. Either way this queue
             * is done with it. */
            wg_outbound_elem_free(elem);
#else
            encrypt_elem(elem, dev);
            int new_state = (elem->packet_len > 0) ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
            atomic_store_explicit(&elem->state, new_state, memory_order_release);
#endif
        }
        /* Wake sequential sender — crypto batch is ready. */
        seq_wake_send_signal(dev);
    }

    return NULL;
}

/* Encrypt up to WG_SEQ_INLINE_MAX of the peer's queued elements on this
 * thread. Called with tx_drain_lock held, when the drain found nothing
 * ready: the sequential sender would otherwise spin and then sleep while
 * the crypto workers are asleep or still getting to these elements
 * (performance-analysis.md #62 found x86 bound by these hand-offs).
 *
 * Walks tx_order from the peeked element with wg_prev_queue_walk_next(),
 * which only this consumer may do; producers append at the far end.
 * Stops at the first finished element, since then there is something to
 * send. Returns how many it encrypted. */
#if WG_SEQ_INLINE
static int seq_encrypt_inline(wg_device_t *dev, struct wg_peer *peer, uint64_t *head)
{
    wg_prev_queue_t *q = &peer->queue.tx_order;
    wg_outbound_elem_t *first = wg_prev_queue_peek(q);
    int n = 0;

    for (wg_outbound_elem_t *elem = first; elem && n < WG_SEQ_INLINE_MAX;
         elem = wg_prev_queue_walk_next(q, elem)) {
        int st = atomic_load_explicit(&elem->state, memory_order_acquire);
        if (wg_elem_done(st))
            break;
        if (st == WG_ELEM_UNCRYPTED && wg_elem_claim(&elem->state)) {
            encrypt_elem(elem, dev);
            int new_state = (elem->packet_len > 0) ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
            atomic_store_explicit(&elem->state, new_state, memory_order_release);
            n++;
            if (elem == first)
                (*head)++;
        }
        /* INFLIGHT: a worker is on it; look past it. */
    }
    return n;
}
#endif

/* ────────────────────────────────────────
 * Sequential Sender
 *
 * Single device-global thread that drains all peers' tx_order
 * prev_queues in order.  Processes elements whose crypto is
 * complete (state == CRYPTED/DEAD), stops at UNCRYPTED (not ready).
 *
 * This thread handles: UDP send (sendmmsg batching), timers, elem free.
 * Pipelining with crypto workers gives ~40% throughput improvement.
 * ──────────────────────────────────────── */
void *wg_worker_sequential_send(void *arg)
{
    wg_device_t *dev = arg;

    /* Local peer cache, refreshed when the peer list's generation changes. */
    struct wg_peer *peer_cache[256];
    int num_peers = 0;
    uint64_t cached_gen = UINT64_MAX; /* forces the first refresh */

    /* Local stats — flushed every 256 iterations to reduce atomics. */
    uint64_t local_batches = 0, local_packets = 0, local_bytes = 0;
    uint64_t local_inline = 0, local_inline_head = 0, local_waits = 0;
    int stats_flush_counter = 0;

    while (wg_device_is_up(dev)) {
        /* Refresh the peer cache when peers were added or removed, so a new
         * peer is served at once and a removed one is dropped before it is
         * freed. Publish the generation first, then copy the list under
         * peers.lock: see wg_device_wait_peer_readers(). */
        uint64_t gen = atomic_load_explicit(&dev->peers.generation, memory_order_acquire);
        if (gen != cached_gen) {
            atomic_store_explicit(&dev->seq_send_peer_gen, gen + 1, memory_order_seq_cst);
            cached_gen = gen;
            pthread_rwlock_rdlock(&dev->peers.lock);
            num_peers = 0;
            for (size_t i = 0; i < dev->peers.capacity && num_peers < 256; i++) {
                if (dev->peers.entries[i].occupied)
                    peer_cache[num_peers++] = dev->peers.entries[i].peer;
            }
            pthread_rwlock_unlock(&dev->peers.lock);
        }

        bool did_work = false;
        for (int p = 0; p < num_peers; p++) {
            struct wg_peer *peer = peer_cache[p];
            if (pthread_mutex_trylock(&peer->queue.tx_drain_lock) != 0)
                continue;
            int n = 0;
            wg_outbound_elem_t *elem =
                (wg_outbound_elem_t *)wg_prev_queue_peek(&peer->queue.tx_order);
            if (elem) {
                int st = atomic_load_explicit(&elem->state, memory_order_acquire);
                if (wg_elem_done(st)) {
                    n = drain_tx_order(dev, peer, &local_packets, &local_bytes);
                    if (n > 0) {
                        local_batches++;
                        did_work = true;
                    }
                }
            }
            pthread_mutex_unlock(&peer->queue.tx_drain_lock);

            /* keep_key_fresh: once per batch, not per element — all
             * elements use the same keypair. After the drain lock: a
             * rekey takes the identity lock, and peer removal takes the
             * drain lock while other threads hold that. */
            if (n > 0)
                keep_key_fresh_sending(peer);
        }

        /* Flush local stats periodically. */
        if (++stats_flush_counter >= 256) {
            if (local_batches > 0) {
                atomic_fetch_add(&dev->stats.send_batches, local_batches);
                atomic_fetch_add(&dev->stats.send_packets, local_packets);
                atomic_fetch_add(&dev->stats.staged_pushed, local_packets);
                local_batches = 0;
                local_packets = 0;
                local_bytes = 0;
            }
            if (local_inline > 0) {
                atomic_fetch_add(&dev->stats.seq_inline_encrypt, local_inline);
                atomic_fetch_add(&dev->stats.seq_inline_encrypt_head, local_inline_head);
                local_inline = 0;
                local_inline_head = 0;
            }
            if (local_waits > 0) {
                atomic_fetch_add(&dev->stats.seq_send_waits, local_waits);
                local_waits = 0;
            }
            stats_flush_counter = 0;
        }

        if (!did_work) {
            /* Nothing to send: encrypt waiting elements here rather than
             * spin for a worker. Whatever this pass encrypts, the next
             * pass sends. Only when it finds nothing either does the
             * thread wait. */
            int claimed = 0;
#if WG_SEQ_INLINE
            for (int p = 0; p < num_peers; p++) {
                struct wg_peer *peer = peer_cache[p];
                if (pthread_mutex_trylock(&peer->queue.tx_drain_lock) != 0)
                    continue;
                claimed += seq_encrypt_inline(dev, peer, &local_inline_head);
                pthread_mutex_unlock(&peer->queue.tx_drain_lock);
            }
            local_inline += (uint64_t)claimed;
#endif
            if (claimed == 0) {
                local_waits++;
                seq_wake_send_wait(dev, 1024);
            }
        }
    }

    /* Flush remaining stats. */
    if (local_batches > 0) {
        atomic_fetch_add(&dev->stats.send_batches, local_batches);
        atomic_fetch_add(&dev->stats.send_packets, local_packets);
        atomic_fetch_add(&dev->stats.staged_pushed, local_packets);
    }
    if (local_inline > 0) {
        atomic_fetch_add(&dev->stats.seq_inline_encrypt, local_inline);
        atomic_fetch_add(&dev->stats.seq_inline_encrypt_head, local_inline_head);
    }
    if (local_waits > 0)
        atomic_fetch_add(&dev->stats.seq_send_waits, local_waits);

    /* Final drain. */
    uint64_t dummy_p = 0, dummy_b = 0;
    for (int p = 0; p < num_peers; p++) {
        drain_tx_order(dev, peer_cache[p], &dummy_p, &dummy_b);
    }

    /* This thread holds no peer pointers any more. */
    atomic_store_explicit(&dev->seq_send_peer_gen, 0, memory_order_seq_cst);

    return NULL;
}

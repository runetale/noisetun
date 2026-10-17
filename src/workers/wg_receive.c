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
 * DEV-8: UDP receive worker — calls bind.recv(), classifies by message
 * type, dispatches to handshake or decryption queues.
 *
 * DEV-10: Decryption worker — pulls inbound elements from the device
 * decryption queue and decrypts them in-place using ChaCha20-Poly1305.
 *
 * DEV-12: Sequential receiver — per-peer thread that waits for decryption
 * completion, validates, and writes to TUN.
 *
 * Reference: wireguard-go/device/receive.go
 */

#include "wg_workers.h"
#include "wg_seq_wake.h"

#include "../crypto/wg_crypto.h"
#include "../peer/wg_allowedips.h"
#include "../replay/wg_replay.h"
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

/* Adaptive spin + futex helpers for sequential RECV thread wake-up.
 * Recv crypto workers call seq_wake_recv_signal() after decryption.
 * Sequential receiver calls seq_wake_recv_wait() when no work is found.
 * Separated from send to eliminate false wakeups (#35). */
static inline void seq_wake_recv_signal(wg_device_t *dev)
{
    wg_seq_wake_signal(&dev->seq_wake_recv, &dev->seq_wake_recv_waiting);
}

#if defined(__linux__)
static inline void seq_wake_recv_wait(wg_device_t *dev, int spin_iters)
{
    /* exchange, not store: a second worker's signal landing between a
     * load and a store would be overwritten. Work that is already waiting
     * needs no clock read. */
    (void)spin_iters; /* Linux spins for WG_SEQ_SPIN_NS instead */
    if (atomic_load_explicit(&dev->seq_wake_recv, memory_order_relaxed) &&
        atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
        return;
    uint64_t start = wg_seq_spin_now_ns();
    for (;;) {
        for (int i = 0; i < WG_SEQ_SPIN_CHECK_EVERY; i++) {
            if (atomic_load_explicit(&dev->seq_wake_recv, memory_order_relaxed) &&
                atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
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
    atomic_store_explicit(&dev->seq_wake_recv_waiting, 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if (!atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acquire)) {
        struct timespec timeout = {.tv_sec = WG_SEQ_FUTEX_TIMEOUT_NS / 1000000000L,
                                   .tv_nsec = WG_SEQ_FUTEX_TIMEOUT_NS % 1000000000L};
        syscall(SYS_futex, &dev->seq_wake_recv, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                &timeout, NULL, 0);
        /* Consume the signal that woke us, so the next idle wait does not
         * return on its first spin. An exchange, not a relaxed store: if it
         * reads 1, acquire makes the signalling worker's element state
         * visible to the scan that follows; if the worker signals after
         * it, the word stays 1. Either way no signal is lost. */
        (void)atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel);
    }
    atomic_store_explicit(&dev->seq_wake_recv_waiting, 0, memory_order_relaxed);
}
#elif defined(_WIN32)
static inline void seq_wake_recv_wait(wg_device_t *dev, int spin_iters)
{
    for (int i = 0; i < spin_iters; i++) {
        if (atomic_load_explicit(&dev->seq_wake_recv, memory_order_relaxed) &&
            atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
            return;
        WG_CPU_RELAX();
    }

    /* Consume a signal that arrived after the spin instead of
     * overwriting it with 0; otherwise wait (the compare value 0 makes a
     * later signal return WaitOnAddress at once). */
    if (atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
        return;
    ULONG zero = 0;
    WaitOnAddress((volatile VOID *)&dev->seq_wake_recv, &zero, sizeof(ULONG), 1);
}
#elif defined(__APPLE__)
/* macOS: the Linux shape (spin WG_SEQ_SPIN_NS, announce, sleep) with
 * os_sync_wait_on_address (macOS 14.4) in place of FUTEX_WAIT. Before
 * this the thread polled with sched_yield(): a syscall per turn, a
 * million a second per sequential thread, and most of their CPU on
 * Apple silicon (performance-analysis.md #64). Older macOS keeps the
 * poll. */
static inline void seq_wake_recv_wait(wg_device_t *dev, int spin_iters)
{
    (void)spin_iters;
    if (atomic_load_explicit(&dev->seq_wake_recv, memory_order_relaxed) &&
        atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
        return;
    uint64_t start = wg_seq_spin_now_ns();
    for (;;) {
        for (int i = 0; i < WG_SEQ_SPIN_CHECK_EVERY; i++) {
            if (atomic_load_explicit(&dev->seq_wake_recv, memory_order_relaxed) &&
                atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel))
                return;
            WG_CPU_RELAX();
        }
        if (wg_seq_spin_now_ns() - start >= WG_SEQ_SPIN_NS)
            break;
    }
#if WG_HAVE_OS_SYNC
    if (WG_OS_SYNC_AVAILABLE()) {
        atomic_store_explicit(&dev->seq_wake_recv_waiting, 1, memory_order_relaxed);
        atomic_thread_fence(memory_order_seq_cst);
        if (!atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acquire)) {
            os_sync_wait_on_address_with_timeout(
                &dev->seq_wake_recv, 0, sizeof(dev->seq_wake_recv),
                OS_SYNC_WAIT_ON_ADDRESS_NONE, OS_CLOCK_MACH_ABSOLUTE_TIME,
                (uint64_t)WG_SEQ_FUTEX_TIMEOUT_NS);
            (void)atomic_exchange_explicit(&dev->seq_wake_recv, 0, memory_order_acq_rel);
        }
        atomic_store_explicit(&dev->seq_wake_recv_waiting, 0, memory_order_relaxed);
        return;
    }
#endif
    sched_yield();
}
#else
static inline void seq_wake_recv_wait(wg_device_t *dev, int spin_iters)
{
    (void)spin_iters;
    sched_yield();
}
#endif

/* Forward declarations. */
static void decrypt_elem(wg_inbound_elem_t *elem);
static void keep_key_fresh_receiving(struct wg_peer *peer);

/* ────────────────────────────────────────
 * Inbound element allocation (pool-backed)
 * ──────────────────────────────────────── */

wg_inbound_elem_t *wg_inbound_elem_new(void)
{
    wg_inbound_elem_t *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->ok = false;
    e->pool = NULL;
    atomic_store_explicit(&e->refs, 1, memory_order_relaxed);
    return e;
}

void wg_inbound_elem_free(void *elem)
{
    wg_inbound_elem_t *e = elem;
    if (!e)
        return;
#if WG_SEQ_INLINE
    if (!wg_elem_drop_ref(&e->refs))
        return; /* a crypto SPSC still points at it */
#endif

    /* If this elem came from a pool, return it there. */
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
 * Core decryption logic for a single element.
 * Used by both the worker thread and inline-crypto path.
 * ──────────────────────────────────────── */
static void decrypt_elem(wg_inbound_elem_t *elem)
{
    if (!elem->keypair ||
        elem->packet_len < WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE) {
        elem->plaintext_len = 0;
        elem->ok = false;
        return;
    }
    const wg_message_transport_t *hdr = (const wg_message_transport_t *)elem->buffer;
    elem->counter = wg_le64toh(hdr->counter);

    uint8_t *ciphertext = elem->buffer + WG_MESSAGE_TRANSPORT_HEADER;
    size_t ct_len = elem->packet_len - WG_MESSAGE_TRANSPORT_HEADER;
    size_t pt_len = 0;
    wg_error_t dec_err = wg_aead_decrypt(ciphertext, &pt_len, ciphertext, ct_len, NULL, 0,
                                         elem->counter, elem->keypair->receiving_key);

    if (dec_err != WG_OK) {
        elem->plaintext_len = 0;
        elem->ok = false;
    } else if (!wg_replay_counter_validate(&elem->keypair->receiving_counter,
                                           elem->counter, WG_REJECT_AFTER_MESSAGES)) {
        elem->plaintext_len = 0;
        elem->ok = false;
    } else {
        elem->plaintext_len = pt_len;
        elem->ok = true;
    }
}

/* (Decryption worker removed — replaced by RTC recv worker below.) */

/* ────────────────────────────────────────
 * Helper: length of the IP packet in decrypted plaintext
 *
 * WireGuard pads plaintext to a multiple of 16 bytes before encrypting it,
 * so the decrypted buffer can run past the end of the IP packet. Only the
 * packet itself may reach the TUN. Returns 0 unless the plaintext starts
 * with an IPv4 or IPv6 header that fits and states a length that fits too.
 *
 * Reference: wireguard-go/device/receive.go RoutineSequentialReceiver
 * ──────────────────────────────────────── */

static size_t ip_packet_len(const uint8_t *packet, size_t len)
{
    if (len < 1)
        return 0;

    uint8_t version = (packet[0] >> 4) & 0x0F;

    if (version == 4) {
        if (len < 20)
            return 0;
        /* IPv4: total length at offset 2, header included */
        size_t total = ((size_t)packet[2] << 8) | packet[3];
        if (total < 20 || total > len)
            return 0;
        return total;
    }
    if (version == 6) {
        if (len < 40)
            return 0;
        /* IPv6: payload length at offset 4, 40-byte header excluded */
        size_t total = 40 + (((size_t)packet[4] << 8) | packet[5]);
        if (total > len)
            return 0;
        return total;
    }
    return 0;
}

/* ────────────────────────────────────────
 * Helper: look up peer by source IP in decrypted packet
 * (for source address validation on receive)
 * ──────────────────────────────────────── */

static struct wg_peer *lookup_peer_for_src_packet(wg_device_t *dev, const uint8_t *packet,
                                                  size_t len)
{
    if (len < 1)
        return NULL;

    uint8_t version = (packet[0] >> 4) & 0x0F;

    if (version == 4 && len >= 20) {
        /* IPv4: src address at offset 12, 4 bytes */
        return wg_allowedips_lookup(&dev->allowedips, packet + 12, AF_INET);
    } else if (version == 6 && len >= 40) {
        /* IPv6: src address at offset 8, 16 bytes */
        return wg_allowedips_lookup(&dev->allowedips, packet + 8, AF_INET6);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * keepKeyFreshReceiving
 *
 * If we're receiving with a keypair that's close to expiry
 * and we're the initiator, trigger a rekey.
 *
 * Reference: wireguard-go/device/receive.go keepKeyFreshReceiving
 * ──────────────────────────────────────── */

static void keep_key_fresh_receiving(struct wg_peer *peer)
{
    if (atomic_load(&peer->timers.sent_last_minute_handshake))
        return;

    wg_noise_keypair_t *kp = wg_noise_keypairs_get_current(&peer->keypairs);
    if (!kp)
        return;

    bool need_rekey =
        kp->i_am_initiator && kp->has_keys &&
        (wg_mono_ns() - kp->birthdate_ns >
         WG_REJECT_AFTER_TIME_NS - (uint64_t)WG_KEEPALIVE_TIMEOUT * 1000000000ULL -
             (uint64_t)WG_REKEY_TIMEOUT * 1000000000ULL);

    wg_noise_keypair_put(kp);

    if (need_rekey) {
        atomic_store(&peer->timers.sent_last_minute_handshake, true);
        wg_send_handshake_initiation(peer, false);
    }
}

/* ────────────────────────────────────────
 * RTC Recv Worker (crypto + ordered drain)
 *
 * Pops inbound elements from its SPSC queue, decrypts them,
 * sets atomic state, then tries to drain the peer's prev_queue
 * for ordered TUN write.  Uses trylock so only one worker drains
 * a given peer at a time — guaranteeing single-consumer semantics.
 *
 * N workers per device (typically ncpu/2).
 * ──────────────────────────────────────── */

#define WG_RTC_RECV_BATCH 128

/* Drain the peer's rx_order prev_queue: process all elements whose
 * state is CRYPTED or DEAD.  Stops at the first UNCRYPTED element.
 * Called with rx_drain_lock held.
 *
 * Hot path optimizations (#35):
 * - stats returned via out params for local accumulation
 * - batch pool put: single CAS for all elements */
static int drain_rx_order(wg_device_t *dev, struct wg_peer *peer, uint64_t *out_packets,
                          uint64_t *out_bytes, bool *out_rotated)
{
    const int offset = WG_MESSAGE_TRANSPORT_HEADER;
    uint8_t *bufs[WG_RTC_RECV_BATCH];
    int sizes[WG_RTC_RECV_BATCH];
    wg_inbound_elem_t *batch_elems[WG_RTC_RECV_BATCH];
    int batch_count = 0;
    bool data_received = false;
    wg_inbound_elem_t *tail_elem = NULL;

    for (;;) {
        wg_inbound_elem_t *elem =
            (wg_inbound_elem_t *)wg_prev_queue_peek(&peer->queue.rx_order);
        if (!elem)
            break;

        int st = atomic_load_explicit(&elem->state, memory_order_acquire);
        if (!wg_elem_done(st))
            break;

        wg_prev_queue_drop_peeked(&peer->queue.rx_order);

        if (st == WG_ELEM_DEAD || !elem->ok) {
            wg_inbound_elem_free(elem);
            continue;
        }

        /* Keypair rotation check. The caller sends the staged packets
         * once the drain lock is released. */
        if (wg_noise_received_with_keypair(&peer->keypairs, elem->keypair,
                                           &dev->index_table)) {
            wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);
            wg_timers_handshake_complete(peer);
            *out_rotated = true;
        }

        uint8_t *plaintext = elem->buffer + offset;
        size_t pt_len = elem->plaintext_len;
        atomic_fetch_add(&peer->rx_bytes, (uint64_t)pt_len + WG_MESSAGE_TRANSPORT_HEADER +
                                              WG_AEAD_TAG_SIZE);

        if (pt_len == 0) {
            wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);
            wg_timers_any_authenticated_packet_traversal(peer);
            wg_timers_any_authenticated_packet_received(peer);
            wg_inbound_elem_free(elem);
            continue;
        }

        /* Source IP validation, on the IP packet without WireGuard's padding. */
        size_t ip_len = ip_packet_len(plaintext, pt_len);
        struct wg_peer *allowed_peer =
            ip_len ? lookup_peer_for_src_packet(dev, plaintext, ip_len) : NULL;

        if (allowed_peer == peer) {
            batch_elems[batch_count] = elem;
            bufs[batch_count] = elem->buffer;
            sizes[batch_count] = offset + (int)ip_len;
            batch_count++;
            data_received = true;
            tail_elem = elem;
        } else {
            wg_inbound_elem_free(elem);
        }

        if (batch_count >= WG_RTC_RECV_BATCH)
            break;
    }

    if (batch_count > 0) {
        uint64_t batch_bytes = 0;
        for (int b = 0; b < batch_count; b++)
            batch_bytes += (uint64_t)sizes[b];
        *out_packets += (uint64_t)batch_count;
        *out_bytes += batch_bytes;
        wg_worker_tun_write(dev, bufs, sizes, batch_count, offset);
    }

    if (tail_elem) {
        wg_peer_set_endpoint_from_packet(tail_elem->peer, &tail_elem->endpoint);
        wg_timers_any_authenticated_packet_traversal(tail_elem->peer);
        wg_timers_any_authenticated_packet_received(tail_elem->peer);
    }
    if (data_received && tail_elem)
        wg_timers_data_received(tail_elem->peer);

    for (int i = 0; i < batch_count; i++)
        wg_inbound_elem_free(batch_elems[i]);

    return batch_count;
}

void *wg_worker_rtc_recv(void *arg)
{
    wg_rtc_recv_worker_t *w = arg;
    wg_device_t *dev = w->dev;

    /* Crypto-only: decrypt + set atomic state.
     * The sequential receiver thread handles ordered TUN write.
     * Note: inline drain was tested (#33) but hurt batching (-1%,
     * GRO 13.2x→11.3x) — pipelining must be preserved. */
    uint64_t local_decrypt_count = 0;
    uint64_t local_decrypt_ok = 0;

    for (;;) {
        void *raw_batch[WG_RTC_RECV_BATCH];
        int n = wg_spsc_pop_batch(&w->queue, raw_batch, WG_RTC_RECV_BATCH);
        if (n <= 0)
            break;

        for (int i = 0; i < n; i++) {
            wg_inbound_elem_t *elem = raw_batch[i];
#if WG_SEQ_INLINE
            if (wg_elem_claim(&elem->state)) {
                decrypt_elem(elem);
                local_decrypt_count++;
                if (elem->ok)
                    local_decrypt_ok++;
                int new_state = elem->ok ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
                atomic_store_explicit(&elem->state, new_state, memory_order_release);
            }
            /* else the sequential receiver took it. This queue is done
             * with it either way. */
            wg_inbound_elem_free(elem);
#else
            decrypt_elem(elem);
            local_decrypt_count++;
            if (elem->ok)
                local_decrypt_ok++;
            int new_state = elem->ok ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
            atomic_store_explicit(&elem->state, new_state, memory_order_release);
#endif
        }
        /* Wake sequential receiver — crypto batch is ready. */
        seq_wake_recv_signal(dev);

#if WG_SEQ_INLINE
        /* Per batch, not at thread exit, so a SIGUSR1 dump mid-run
         * counts the workers' share (#63 compared it with the
         * sequential receiver's). Two relaxed adds per batch. */
        atomic_fetch_add_explicit(&dev->stats.decrypt_count, local_decrypt_count,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&dev->stats.decrypt_ok, local_decrypt_ok,
                                  memory_order_relaxed);
        local_decrypt_count = 0;
        local_decrypt_ok = 0;
#endif
    }

    /* Flush accumulated stats once at thread exit. */
    atomic_fetch_add_explicit(&dev->stats.decrypt_count, local_decrypt_count,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&dev->stats.decrypt_ok, local_decrypt_ok,
                              memory_order_relaxed);


    return NULL;
}

/* The receive side of seq_encrypt_inline() in wg_send.c: decrypt up to
 * WG_SEQ_INLINE_MAX queued elements on this thread. Called with
 * rx_drain_lock held when the drain found nothing ready. */
#if WG_SEQ_INLINE
static int seq_decrypt_inline(struct wg_peer *peer, uint64_t *ok, uint64_t *head)
{
    wg_prev_queue_t *q = &peer->queue.rx_order;
    wg_inbound_elem_t *first = wg_prev_queue_peek(q);
    int n = 0;

    for (wg_inbound_elem_t *elem = first; elem && n < WG_SEQ_INLINE_MAX;
         elem = wg_prev_queue_walk_next(q, elem)) {
        int st = atomic_load_explicit(&elem->state, memory_order_acquire);
        if (wg_elem_done(st))
            break;
        if (st == WG_ELEM_UNCRYPTED && wg_elem_claim(&elem->state)) {
            decrypt_elem(elem);
            if (elem->ok)
                (*ok)++;
            int new_state = elem->ok ? WG_ELEM_CRYPTED : WG_ELEM_DEAD;
            atomic_store_explicit(&elem->state, new_state, memory_order_release);
            n++;
            if (elem == first)
                (*head)++;
        }
    }
    return n;
}
#endif

/* ────────────────────────────────────────
 * Sequential Receiver
 *
 * Single device-global thread that drains all peers' rx_order
 * prev_queues in order.  Processes elements whose crypto is
 * complete (state == CRYPTED/DEAD), stops at UNCRYPTED (not ready).
 *
 * Uses adaptive spin + futex wait (seq_wake) when no work is found.
 * ──────────────────────────────────────── */
void *wg_worker_sequential_recv(void *arg)
{
    wg_device_t *dev = arg;

    /* Local peer cache, refreshed when the peer list's generation changes,
     * so peers.lock is not taken every iteration. */
    struct wg_peer *peer_cache[256];
    int num_peers = 0;
    uint64_t cached_gen = UINT64_MAX; /* forces the first refresh */

    /* Local stats — flushed every 256 iterations to reduce atomics. */
    uint64_t local_batches = 0, local_packets = 0, local_bytes = 0;
    uint64_t local_inline = 0, local_inline_head = 0, local_waits = 0;
    uint64_t local_decrypt_ok = 0; /* the inline decrypts, counted as the workers do */
    int stats_flush_counter = 0;

    while (wg_device_is_up(dev)) {
        /* Refresh the peer cache when peers were added or removed, so a new
         * peer is served at once and a removed one is dropped before it is
         * freed. Publish the generation first, then copy the list under
         * peers.lock: see wg_device_wait_peer_readers(). */
        uint64_t gen = atomic_load_explicit(&dev->peers.generation, memory_order_acquire);
        if (gen != cached_gen) {
            atomic_store_explicit(&dev->seq_recv_peer_gen, gen + 1, memory_order_seq_cst);
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
            if (pthread_mutex_trylock(&peer->queue.rx_drain_lock) != 0)
                continue;
            int n = 0;
            bool rotated = false;
            wg_inbound_elem_t *elem =
                (wg_inbound_elem_t *)wg_prev_queue_peek(&peer->queue.rx_order);
            if (elem) {
                int st = atomic_load_explicit(&elem->state, memory_order_acquire);
                if (wg_elem_done(st)) {
                    /* Brief spin to let crypto worker complete more elements.
                     * Increases GRO coalescing by producing larger batches. */
                    for (int wait = 0; wait < 32; wait++)
                        WG_CPU_RELAX();
                    n = drain_rx_order(dev, peer, &local_packets, &local_bytes, &rotated);
                    if (n > 0) {
                        local_batches++;
                        did_work = true;
                    }
                }
            }
            pthread_mutex_unlock(&peer->queue.rx_drain_lock);

            /* After the drain lock, as on the send side: both may start a
             * handshake, which takes the identity lock. */
            if (rotated)
                wg_send_staged_packets(peer);
            if (n > 0)
                keep_key_fresh_receiving(peer);
        }

        /* Flush local stats periodically. */
        if (++stats_flush_counter >= 256) {
            if (local_batches > 0) {
                atomic_fetch_add(&dev->stats.recv_batches, local_batches);
                atomic_fetch_add(&dev->stats.recv_packets, local_packets);
                atomic_fetch_add(&dev->stats.recv_bytes, local_bytes);
                local_batches = 0;
                local_packets = 0;
                local_bytes = 0;
            }
            if (local_inline > 0) {
                atomic_fetch_add(&dev->stats.seq_inline_decrypt, local_inline);
                atomic_fetch_add(&dev->stats.seq_inline_decrypt_head, local_inline_head);
                atomic_fetch_add(&dev->stats.decrypt_count, local_inline);
                atomic_fetch_add(&dev->stats.decrypt_ok, local_decrypt_ok);
                local_inline = 0;
                local_inline_head = 0;
                local_decrypt_ok = 0;
            }
            if (local_waits > 0) {
                atomic_fetch_add(&dev->stats.seq_recv_waits, local_waits);
                local_waits = 0;
            }
            stats_flush_counter = 0;
        }

        if (!did_work) {
            /* As in the sequential sender: decrypt here before waiting. */
            int claimed = 0;
#if WG_SEQ_INLINE
            for (int p = 0; p < num_peers; p++) {
                struct wg_peer *peer = peer_cache[p];
                if (pthread_mutex_trylock(&peer->queue.rx_drain_lock) != 0)
                    continue;
                claimed +=
                    seq_decrypt_inline(peer, &local_decrypt_ok, &local_inline_head);
                pthread_mutex_unlock(&peer->queue.rx_drain_lock);
            }
            local_inline += (uint64_t)claimed;
#endif
            if (claimed == 0) {
                local_waits++;
                seq_wake_recv_wait(dev, 1024);
            }
        }
    }

    /* Flush remaining stats. */
    if (local_batches > 0) {
        atomic_fetch_add(&dev->stats.recv_batches, local_batches);
        atomic_fetch_add(&dev->stats.recv_packets, local_packets);
        atomic_fetch_add(&dev->stats.recv_bytes, local_bytes);
    }
    if (local_inline > 0) {
        atomic_fetch_add(&dev->stats.seq_inline_decrypt, local_inline);
        atomic_fetch_add(&dev->stats.seq_inline_decrypt_head, local_inline_head);
        atomic_fetch_add(&dev->stats.decrypt_count, local_inline);
        atomic_fetch_add(&dev->stats.decrypt_ok, local_decrypt_ok);
    }
    if (local_waits > 0)
        atomic_fetch_add(&dev->stats.seq_recv_waits, local_waits);

    /* Final drain: after crypto workers joined and remaining SPSC
     * elements marked DEAD, drain any leftover prev_queue entries. */
    uint64_t dummy_p = 0, dummy_b = 0;
    for (int p = 0; p < num_peers; p++) {
        bool rotated = false;
        drain_rx_order(dev, peer_cache[p], &dummy_p, &dummy_b, &rotated);
    }

    /* This thread holds no peer pointers any more. */
    atomic_store_explicit(&dev->seq_recv_peer_gen, 0, memory_order_seq_cst);

    return NULL;
}

/* ────────────────────────────────────────
 * DEV-8: UDP Receive Worker
 *
 * Calls bind.recv() in a loop, classifies packets by message
 * type (first 4 bytes LE), and dispatches to the appropriate
 * device queue.
 *
 * Reference: wireguard-go/device/receive.go RoutineReceiveIncoming
 * ──────────────────────────────────────── */

/* ────────────────────────────────────────
 * Process a single received UDP packet: classify by message type
 * and dispatch to the appropriate queue.
 * ──────────────────────────────────────── */

static void process_incoming_packet(wg_device_t *dev, uint8_t *buf, size_t pkt_len,
                                    const wg_endpoint_t *ep)
{
    if (pkt_len < 4)
        return; /* too small: need at least message type */

    uint32_t msg_type = wg_message_type(buf, pkt_len);

    /* ── Handshake messages (type 1/2/3) ── */

    if (msg_type == WG_MESSAGE_INITIATION || msg_type == WG_MESSAGE_RESPONSE ||
        msg_type == WG_MESSAGE_COOKIE_REPLY) {

        /* Validate exact message size. */
        if (msg_type == WG_MESSAGE_INITIATION && pkt_len != WG_MESSAGE_INITIATION_SIZE)
            return;
        if (msg_type == WG_MESSAGE_RESPONSE && pkt_len != WG_MESSAGE_RESPONSE_SIZE)
            return;
        if (msg_type == WG_MESSAGE_COOKIE_REPLY &&
            pkt_len != WG_MESSAGE_COOKIE_REPLY_SIZE)
            return;

        wg_handshake_elem_t *elem = wg_handshake_elem_new();
        if (!elem)
            return;

        memcpy(elem->buffer, buf, pkt_len);
        elem->msg_type = msg_type;
        elem->packet_len = pkt_len;
        elem->endpoint = *ep;

        /* Non-blocking push; drop on full (DoS protection). */
        wg_error_t err = wg_queue_try_push(dev->queue.handshake, elem);
        if (err != WG_OK)
            wg_handshake_elem_free(elem);

        return;
    }

    /* Transport messages (type 4) are handled in wg_worker_udp_recv()
     * via Two-Level Queue dispatch. Unknown types are dropped. */
}

/* ────────────────────────────────────────
 * Helper: enqueue inbound elem to prev_queue + SPSC for crypto dispatch.
 *
 * Dual-enqueue: prev_queue for ordering, SPSC for parallel crypto.
 * On SPSC push failure, mark DEAD so sequential receiver skips it.
 * ──────────────────────────────────────── */
static void enqueue_inbound(wg_device_t *dev, struct wg_peer *peer,
                            wg_inbound_elem_t *elem)
{
    atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);
#if WG_SEQ_INLINE
    atomic_store_explicit(&elem->refs, 2, memory_order_relaxed); /* order queue + SPSC */
#endif

    if (!wg_prev_queue_enqueue(&peer->queue.rx_order, elem)) {
#if WG_SEQ_INLINE
        atomic_store_explicit(&elem->refs, 1, memory_order_relaxed);
#endif
        atomic_fetch_add(&dev->stats.inbound_drops, 1);
        wg_inbound_elem_free(elem);
        return;
    }

    uint64_t idx = atomic_fetch_add_explicit(&dev->rtc.recv_rr, 1, memory_order_relaxed);
    int w = (int)(idx % (uint64_t)dev->rtc.num_recv);

    /* Backpressure on SPSC push: emulate wireguard-go's blocking channel.
     * Phase 1: 32 PAUSE iterations (~2µs) — fast path for transient fullness.
     * Phase 2: sched_yield + retry 64 times — let crypto workers drain.
     * Only drop after exhausting both phases (~ms-scale wait). */
    bool pushed = false;
    for (int retry = 0; retry < 32; retry++) {
        if (wg_spsc_try_push(&dev->rtc.recv[w].queue, elem) == WG_OK) {
            pushed = true;
            break;
        }
        WG_CPU_RELAX();
    }
    for (int retry = 0; !pushed && retry < 64; retry++) {
        sched_yield();
        if (wg_spsc_try_push(&dev->rtc.recv[w].queue, elem) == WG_OK) {
            pushed = true;
            break;
        }
    }
    if (!pushed) {
#if WG_SEQ_INLINE
        if (wg_elem_kill(&elem->state))
            atomic_fetch_add(&dev->stats.inbound_drops, 1);
        wg_inbound_elem_free(elem); /* the SPSC's reference */
#else
        atomic_store_explicit(&elem->state, WG_ELEM_DEAD, memory_order_release);
        atomic_fetch_add(&dev->stats.inbound_drops, 1);
#endif
    }
}

/* ────────────────────────────────────────
 * Helper: keypair getter for the index table
 *
 * wg_index_table_lookup_keypair takes a void * getter so the index table
 * does not depend on noise types. Calling wg_noise_keypair_get through a
 * pointer cast to that type is undefined behaviour, which UBSan's
 * -fsanitize=function traps on, so adapt the signature here instead.
 * ──────────────────────────────────────── */
static void *keypair_get_ref(void *kp)
{
    return wg_noise_keypair_get(kp);
}

/* ────────────────────────────────────────
 * Helper: decrypt + validate + send a single elem inline (single-core).
 * ──────────────────────────────────────── */
static void recv_elem_inline(wg_device_t *dev, struct wg_peer *peer,
                             wg_inbound_elem_t *elem)
{
    const int offset = WG_MESSAGE_TRANSPORT_HEADER;
    decrypt_elem(elem);

    if (elem->ok) {
        if (wg_noise_received_with_keypair(&peer->keypairs, elem->keypair,
                                           &dev->index_table)) {
            wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);
            wg_timers_handshake_complete(peer);
            wg_send_staged_packets(peer);
        }
        uint8_t *plaintext = elem->buffer + offset;
        size_t pt_len = elem->plaintext_len;
        atomic_fetch_add(&peer->rx_bytes, (uint64_t)pt_len + WG_MESSAGE_TRANSPORT_HEADER +
                                              WG_AEAD_TAG_SIZE);
        if (pt_len > 0) {
            size_t ip_len = ip_packet_len(plaintext, pt_len);
            struct wg_peer *allowed =
                ip_len ? lookup_peer_for_src_packet(dev, plaintext, ip_len) : NULL;
            if (allowed == peer) {
                uint8_t *b[1] = {elem->buffer};
                int s[1] = {offset + (int)ip_len};
                atomic_fetch_add(&dev->stats.recv_batches, 1);
                atomic_fetch_add(&dev->stats.recv_packets, 1);
                atomic_fetch_add(&dev->stats.recv_bytes, (uint64_t)s[0]);
                wg_worker_tun_write(dev, b, s, 1, offset);
                wg_timers_data_received(peer);
            }
        }
        wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);
        keep_key_fresh_receiving(peer);
        wg_timers_any_authenticated_packet_traversal(peer);
        wg_timers_any_authenticated_packet_received(peer);
    }
    wg_inbound_elem_free(elem);
}

/* ────────────────────────────────────────
 * DEV-8: UDP Receive Worker
 *
 * Calls bind.recv() in a loop, classifies packets by message
 * type (first 4 bytes LE), and dispatches to the appropriate
 * device queue.
 *
 * On Linux, receives up to batch_size packets per syscall via
 * recvmmsg for reduced syscall overhead.
 *
 * Reference: wireguard-go/device/receive.go RoutineReceiveIncoming
 * ──────────────────────────────────────── */

#define WG_UDP_RECV_BATCH_MAX 128

void *wg_worker_udp_recv(void *arg)
{
    wg_device_t *dev = arg;

    /* Determine batch size from bind. */
    pthread_rwlock_rdlock(&dev->net.lock);
    int batch_size = 1;
    if (dev->net.bind.batch_size)
        batch_size = dev->net.bind.batch_size(dev->net.bind.ctx);
    pthread_rwlock_unlock(&dev->net.lock);

    if (batch_size < 1)
        batch_size = 1;
    if (batch_size > WG_UDP_RECV_BATCH_MAX)
        batch_size = WG_UDP_RECV_BATCH_MAX;
    batch_size = wg_wait_pool_batch_limit(dev->pool.inbound, batch_size);

    /* Pre-allocate inbound elements — recvmmsg writes directly into
     * element buffers, avoiding a memcpy per packet. */
    wg_inbound_elem_t **elems = calloc((size_t)batch_size, sizeof(*elems));
    uint8_t **batch_bufs = calloc((size_t)batch_size, sizeof(*batch_bufs));
    int *batch_sizes = calloc((size_t)batch_size, sizeof(*batch_sizes));
    wg_endpoint_t *batch_eps = calloc((size_t)batch_size, sizeof(*batch_eps));

    if (!elems || !batch_bufs || !batch_sizes || !batch_eps) {
        free(elems);
        free(batch_bufs);
        free(batch_sizes);
        free(batch_eps);
        return NULL;
    }


    for (int i = 0; i < batch_size; i++) {
        if (dev->pool.inbound) {
            elems[i] = wg_wait_pool_get(dev->pool.inbound);
            if (elems[i])
                elems[i]->pool = dev->pool.inbound;
        } else {
            elems[i] = wg_inbound_elem_new();
        }
        if (!elems[i]) {
            batch_size = i;
            break;
        }
        batch_bufs[i] = elems[i]->buffer;
    }

    if (batch_size == 0)
        goto out;

    /* Snapshot bind ops once; re-snapshot only after recv returns -1
     * (which means bind was closed/changed). Eliminates rwlock on hot path. */
    pthread_rwlock_rdlock(&dev->net.lock);
    wg_bind_ops_t bind = dev->net.bind;
    pthread_rwlock_unlock(&dev->net.lock);

    for (;;) {
        if (!bind.recv)
            break;

        for (int i = 0; i < batch_size; i++)
            batch_sizes[i] = (int)WG_MAX_MESSAGE_SIZE;
        memset(batch_eps, 0, (size_t)batch_size * sizeof(wg_endpoint_t));

        int n = bind.recv(bind.ctx, batch_bufs, batch_sizes, batch_size, batch_eps);
        if (n <= 0)
            break;

        atomic_fetch_add(&dev->stats.udp_recv_calls, 1);
        atomic_fetch_add(&dev->stats.udp_recv_packets, (uint64_t)n);

        /* Peers looked up in this batch stay in use until the exit below. */
        wg_peer_reader_enter(dev, &dev->udp_peer_gen);

        for (int i = 0; i < n; i++) {
            size_t pkt_len = (size_t)batch_sizes[i];
            if (pkt_len < 4)
                continue;

            uint32_t msg_type = wg_message_type(batch_bufs[i], pkt_len);

            if (msg_type == WG_MESSAGE_TRANSPORT) {
                if (pkt_len < WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)
                    continue;

                uint32_t receiver_index;
                memcpy(&receiver_index, elems[i]->buffer + 4, sizeof(receiver_index));
                receiver_index = wg_le32toh(receiver_index);

                /* Lookup keypair via index table — atomically acquires
                 * a reference under the table's read lock to prevent
                 * use-after-free during concurrent peer removal. */
                wg_index_entry_t entry;
                if (!wg_index_table_lookup_keypair(&dev->index_table, receiver_index,
                                                   &entry, keypair_get_ref))
                    continue;

                wg_noise_keypair_t *kp = entry.data;
                struct wg_peer *peer = entry.peer;
                if (!peer || !atomic_load(&peer->is_running)) {
                    wg_noise_keypair_put(kp);
                    continue;
                }
                if (wg_keypair_is_expired(kp)) {
                    wg_noise_keypair_put(kp);
                    continue;
                }

                elems[i]->packet_len = pkt_len;
                elems[i]->keypair = kp;
                elems[i]->peer = peer;
                elems[i]->endpoint = batch_eps[i];
                atomic_store_explicit(&elems[i]->state, WG_ELEM_UNCRYPTED,
                                      memory_order_relaxed);

                if (dev->inline_crypto) {
                    recv_elem_inline(dev, peer, elems[i]);
                } else {
                    enqueue_inbound(dev, peer, elems[i]);
                }
                elems[i] = NULL;
            } else if (msg_type == WG_MESSAGE_INITIATION ||
                       msg_type == WG_MESSAGE_RESPONSE ||
                       msg_type == WG_MESSAGE_COOKIE_REPLY) {
                process_incoming_packet(dev, batch_bufs[i], pkt_len, &batch_eps[i]);
            }
        }

        /* Before replenishing, which may wait for the pool. */
        wg_peer_reader_exit(&dev->udp_peer_gen);

        /* Replace consumed elements from pool. */
        for (int i = 0; i < batch_size; i++) {
            if (elems[i] == NULL) {
                if (dev->pool.inbound) {
                    elems[i] = wg_wait_pool_get(dev->pool.inbound);
                    if (elems[i])
                        elems[i]->pool = dev->pool.inbound;
                } else {
                    elems[i] = wg_inbound_elem_new();
                }
                if (!elems[i]) {
                    int j = 0;
                    for (int k = 0; k < batch_size; k++) {
                        if (elems[k]) {
                            elems[j] = elems[k];
                            batch_bufs[j] = elems[j]->buffer;
                            j++;
                        }
                    }
                    batch_size = j;
                    break;
                }
                batch_bufs[i] = elems[i]->buffer;
            } else {
                /* Reset reused element. */
                elems[i]->peer = NULL;
                elems[i]->packet_len = 0;
                elems[i]->ok = false;
            }
        }

        if (batch_size == 0)
            break;
    }

    for (int i = 0; i < batch_size; i++) {
        if (elems[i])
            wg_inbound_elem_free(elems[i]);
    }

out:

    free(elems);
    free(batch_bufs);
    free(batch_sizes);
    free(batch_eps);
    return NULL;
}

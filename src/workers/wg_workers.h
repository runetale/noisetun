/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Worker thread infrastructure: packet element types, worker lifecycle.
 *
 * Data flow (Two-Level Queue + Atomic State):
 *   TUN read → elem(UNCRYPTED) → prev_queue(peer) + MPMC(device)
 *            → EncryptionWorker → state=CRYPTED → SequentialSender → UDP
 *
 *   UDP recv → elem(UNCRYPTED) → prev_queue(peer) + MPMC(device)
 *            → DecryptionWorker → state=CRYPTED → SequentialReceiver → TUN
 *
 * Each element carries an atomic state that transitions:
 *   UNCRYPTED → CRYPTED (success) or DEAD (failure)
 *
 * The same element is enqueued in BOTH the per-peer prev_queue (ordering)
 * and the device MPMC queue (parallel crypto dispatch). The sequential
 * sender/receiver peeks the per-peer queue and checks atomic state.
 */

#ifndef WG_WORKERS_H
#define WG_WORKERS_H

#include "../device/wg_device.h"
#include "../device/wg_prev_queue.h"
#include "../device/wg_queue.h"
#include "../noise/wg_noise.h"
#include "../peer/wg_peer.h"
#include "wg_constants.h"
#include "wg_error.h"
#include "wg_types.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Buffer size: MTU + transport overhead
 * ──────────────────────────────────────── */
#define WG_MAX_MESSAGE_SIZE \
    (WG_MAX_SEGMENT_SIZE + WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)

/* ────────────────────────────────────────
 * Per-element atomic state
 *
 * Set to UNCRYPTED by producer (TUN reader / UDP recv),
 * changed to CRYPTED or DEAD by crypto worker.
 * Checked by sequential sender/receiver via peek.
 * ──────────────────────────────────────── */
enum wg_elem_state {
    WG_ELEM_UNCRYPTED = 0,
    WG_ELEM_CRYPTED = 1,
    WG_ELEM_DEAD = 2,
    WG_ELEM_INFLIGHT = 3, /* a thread is doing the crypto right now */
};

/* How many elements the sequential thread encrypts or decrypts itself
 * in one pass over a peer before it goes back to sending; 0 removes the
 * pass. Measured only on Linux (performance-analysis.md #63): x86 gained
 * 6% of throughput; Graviton gained under 1% and spent 3-5 points more
 * CPU on small UDP at low rates, where the sequential thread takes the
 * element before the worker it woke gets to it. Off on Linux aarch64
 * for that reason, and off everywhere unmeasured (macOS, Windows). */
#ifndef WG_SEQ_INLINE_MAX
#if defined(__linux__) && defined(__x86_64__)
#define WG_SEQ_INLINE_MAX 16
#else
#define WG_SEQ_INLINE_MAX 0
#endif
#endif

/* Crypto is finished: the sequential thread may consume the element. */
static inline bool wg_elem_done(int st)
{
    return st == WG_ELEM_CRYPTED || st == WG_ELEM_DEAD;
}

/* Take an element for crypto. Two threads may want the same element: the
 * crypto worker whose SPSC holds it, and the sequential thread, which
 * encrypts or decrypts elements itself instead of waiting for a worker
 * when it has nothing to send (performance-analysis.md #63). Whoever
 * wins the UNCRYPTED → INFLIGHT exchange does the work; the other skips
 * the element. Producers that must mark an element DEAD before any
 * crypto use the same exchange, so a claimed element is never
 * overwritten. */
static inline bool wg_elem_claim(_Atomic int *state)
{
    int expected = WG_ELEM_UNCRYPTED;
    return atomic_compare_exchange_strong_explicit(
        state, &expected, WG_ELEM_INFLIGHT, memory_order_acq_rel, memory_order_relaxed);
}

/* With the pass compiled out, nothing but the crypto worker ever
 * touches an UNCRYPTED element, so the claim, the reference count and
 * the worker's free are compiled out too and the hot path is main's. */
#if WG_SEQ_INLINE_MAX > 0
#define WG_SEQ_INLINE 1
#else
#define WG_SEQ_INLINE 0
#endif

/* An element on the hot path sits in two queues at once: the peer's
 * order queue, which the sequential thread consumes, and a crypto
 * worker's SPSC. Since the sequential thread may finish and send it
 * before the worker even pops it, the element must not go back to the
 * pool while the SPSC still points at it, or the worker would claim a
 * recycled element (TSan found this). `refs` counts the holders; the
 * one that drops the last reference frees. Elements that never enter a
 * SPSC (staged packets, keepalives) keep refs at 1. */
static inline bool wg_elem_drop_ref(_Atomic int *refs)
{
    return atomic_fetch_sub_explicit(refs, 1, memory_order_acq_rel) == 1;
}

static inline bool wg_elem_kill(_Atomic int *state)
{
    int expected = WG_ELEM_UNCRYPTED;
    return atomic_compare_exchange_strong_explicit(
        state, &expected, WG_ELEM_DEAD, memory_order_acq_rel, memory_order_relaxed);
}


/* ────────────────────────────────────────
 * Outbound element (TUN → encrypt → UDP)
 *
 * wg_prev_link_t MUST be the first field for prev_queue intrusive list.
 * ──────────────────────────────────────── */
typedef struct wg_wait_pool wg_wait_pool_t; /* forward decl for pool backptr */

typedef struct {
    wg_prev_link_t link; /* MUST be first — prev_queue intrusive link */
    _Atomic int state;   /* wg_elem_state: UNCRYPTED → CRYPTED / DEAD */
    _Atomic int refs;    /* holders: the order queue, plus a crypto SPSC */

    uint8_t buffer[WG_MAX_MESSAGE_SIZE];
    size_t packet_len; /* plaintext length (before encryption) */
    uint64_t nonce;    /* assigned counter / nonce */
    wg_noise_keypair_t *keypair;
    struct wg_peer *peer;

    /* Pool back-pointer: if non-NULL, elem is returned to pool on free. */
    wg_wait_pool_t *pool;
    void *_pool_next; /* intrusive link for lock-free Treiber stack */
} wg_outbound_elem_t;

/* ────────────────────────────────────────
 * Inbound element (UDP → decrypt → TUN)
 *
 * wg_prev_link_t MUST be the first field for prev_queue intrusive list.
 * ──────────────────────────────────────── */
typedef struct {
    wg_prev_link_t link; /* MUST be first — prev_queue intrusive link */
    _Atomic int state;   /* wg_elem_state: UNCRYPTED → CRYPTED / DEAD */
    _Atomic int refs;    /* holders: the order queue, plus a crypto SPSC */

    uint8_t buffer[WG_MAX_MESSAGE_SIZE];
    size_t packet_len;    /* raw message length (header + ciphertext) */
    size_t plaintext_len; /* after decryption (0 if failed) */
    uint64_t counter;     /* nonce from transport header */
    wg_noise_keypair_t *keypair;
    struct wg_peer *peer;
    wg_endpoint_t endpoint; /* source endpoint */

    bool ok; /* true if decryption succeeded */

    /* Pool back-pointer: if non-NULL, elem is returned to pool on free. */
    wg_wait_pool_t *pool;
    void *_pool_next; /* intrusive link for lock-free Treiber stack */
} wg_inbound_elem_t;

/* ────────────────────────────────────────
 * Handshake queue element (DEV-11)
 *
 * Carries a raw handshake message (initiation, response, or cookie reply)
 * from the UDP receive path into the handshake worker.
 * ──────────────────────────────────────── */
typedef struct {
    uint32_t msg_type; /* WG_MESSAGE_INITIATION / RESPONSE / COOKIE_REPLY */
    uint8_t buffer[WG_MAX_MESSAGE_SIZE];
    size_t packet_len;
    wg_endpoint_t endpoint; /* source endpoint of the packet */
} wg_handshake_elem_t;

/* ────────────────────────────────────────
 * Handshake element lifecycle
 * ──────────────────────────────────────── */

wg_handshake_elem_t *wg_handshake_elem_new(void);
void wg_handshake_elem_free(void *elem); /* void* for queue flush */

/* ────────────────────────────────────────
 * Outbound element lifecycle
 * ──────────────────────────────────────── */

wg_outbound_elem_t *wg_outbound_elem_new(void);
void wg_outbound_elem_free(void *elem); /* void* for queue flush */

/* ────────────────────────────────────────
 * Inbound element lifecycle
 * ──────────────────────────────────────── */

wg_inbound_elem_t *wg_inbound_elem_new(void);
void wg_inbound_elem_free(void *elem);

/* ────────────────────────────────────────
 * Shared helper: send buffer to peer's endpoint via bind
 * ──────────────────────────────────────── */

wg_error_t wg_peer_send_buffer(struct wg_peer *peer, uint8_t *buf, size_t len);

/* ────────────────────────────────────────
 * DEV-7: TUN Read/Write Workers
 * ──────────────────────────────────────── */

/*
 * TUN reader thread: reads packets from TUN device, looks up peer
 * via AllowedIPs, stages them for encryption.
 * One thread per device.
 */
void *wg_worker_tun_read(void *arg); /* arg = wg_device_t* */

/*
 * TUN writer: called by sequential receiver to batch-write
 * decrypted packets to the TUN device.
 * Not a standalone thread — called from sequential receiver context.
 */
wg_error_t wg_worker_tun_write(wg_device_t *dev, uint8_t **bufs, int *sizes, int count,
                               int offset);

/* ────────────────────────────────────────
 * RTC (Run-to-Completion) Workers
 *
 * Replace MPMC encryption/decryption workers + sequential sender/receiver.
 * Each worker owns a SPSC queue, does crypto inline, and sends/writes directly.
 * ──────────────────────────────────────── */

/*
 * RTC send crypto worker: pops outbound elements from its SPSC queue,
 * encrypts inline, sets atomic state. N per device.
 */
void *wg_worker_rtc_send(void *arg); /* arg = wg_rtc_send_worker_t* */

/*
 * Sequential sender: peeks per-peer prev_queue, spin-waits for
 * crypto completion (atomic state), sends via bind in order.
 * 1 per device.
 */
void *wg_worker_sequential_send(void *arg); /* arg = wg_device_t* */

/*
 * RTC recv crypto worker: pops inbound elements from its SPSC queue,
 * decrypts inline, sets atomic state. N per device.
 */
void *wg_worker_rtc_recv(void *arg); /* arg = wg_rtc_recv_worker_t* */

/*
 * Sequential receiver: peeks per-peer prev_queue, spin-waits for
 * crypto completion (atomic state), validates, writes to TUN in order.
 * 1 per device.
 */
void *wg_worker_sequential_recv(void *arg); /* arg = wg_device_t* */

/* ────────────────────────────────────────
 * DEV-8: UDP Receive Worker
 * ──────────────────────────────────────── */

/*
 * UDP receive worker thread: calls bind.recv() in a loop,
 * classifies packets by message type, dispatches to handshake
 * or decryption queues. One thread per device.
 */
void *wg_worker_udp_recv(void *arg); /* arg = wg_device_t* */

/* ────────────────────────────────────────
 * DEV-11: Handshake Worker
 * ──────────────────────────────────────── */

/*
 * Handshake worker thread: processes handshake messages from
 * device.queue.handshake (initiation, response, cookie reply).
 * Single thread per device.
 */
void *wg_worker_handshake(void *arg); /* arg = wg_device_t* */

/*
 * Create and send a handshake initiation message.
 * Rate-limited: skips if last sent < REKEY_TIMEOUT ago.
 * Called from TUN reader (no keypair), timers, and keepKeyFresh.
 */
wg_error_t wg_send_handshake_initiation(struct wg_peer *peer, bool is_retry);

/*
 * Create and send a handshake response, then derive session keys.
 * Called from handshake worker after consuming an initiation.
 */
wg_error_t wg_send_handshake_response(struct wg_peer *peer);

/*
 * Send a cookie reply to a handshake message that failed MAC2
 * validation under load.
 */
wg_error_t wg_send_handshake_cookie(wg_device_t *dev, wg_handshake_elem_t *elem);

/*
 * Queue an empty (keepalive) packet for the peer.
 * Called from timers and handshake completion.
 */
void wg_send_keepalive(struct wg_peer *peer);

/*
 * Drain the staged queue: assign nonces, push to encryption + outbound.
 * If no valid keypair, initiate handshake instead.
 */
void wg_send_staged_packets(struct wg_peer *peer);

/*
 * Flush all staged packets (discard). Called during peer stop.
 */
void wg_peer_flush_staged_packets(struct wg_peer *peer);

#if defined(__linux__) || defined(__APPLE__)
#include <time.h>

/* How long a sequential thread spins for work before it sleeps in
 * FUTEX_WAIT (Linux) or os_sync_wait_on_address (macOS). A time, not a count of spin-loop
 * hints: PAUSE costs about 140 cycles on Skylake and later x86 while ARM's yield costs a
 * few nanoseconds, so 1024 hints meant roughly 40-50 µs on x86 and a µs or two on arm64.
 * On EC2 c6i, 3, 5 and 10 µs all beat the old spin and 3 µs used the least CPU
 * (performance-analysis.md #52); those runs checked the clock every 64 spins, so 3 and 5
 * µs may both have spun about 5 µs, and the default is to be confirmed. */
#ifndef WG_SEQ_SPIN_NS
#define WG_SEQ_SPIN_NS 3000
#endif

/* How long FUTEX_WAIT sleeps at most. Only a safety net: the waiting
 * flag guarantees that a signaller makes the FUTEX_WAKE, so the timeout
 * never decides when work is seen. At 50 µs an idle sequential thread
 * woke up to twenty thousand times a second, which was most of the CPU a
 * lightly loaded tunnel used (performance-analysis #53). */
#ifndef WG_SEQ_FUTEX_TIMEOUT_NS
#define WG_SEQ_FUTEX_TIMEOUT_NS 1000000L /* 1 ms */
#endif

/* The clock is read once per this many spins. 16 PAUSEs are about
 * 0.6 µs on x86, so the spin ends within that of WG_SEQ_SPIN_NS; a
 * vDSO clock_gettime costs about 20 ns. (64 made a 3 µs spin run about
 * 5 µs on x86.) */
#define WG_SEQ_SPIN_CHECK_EVERY 16

static inline uint64_t wg_seq_spin_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

#endif /* WG_WORKERS_H */

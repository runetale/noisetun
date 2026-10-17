/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Timer state machine for per-peer WireGuard timers.
 *
 * Five timers per peer:
 *   retransmit_handshake  — 5s timeout, retransmit initiation
 *   send_keepalive        — 10s idle, send empty keepalive
 *   new_handshake         — no response -> retry handshake
 *   zero_key_material     — REJECT_AFTER_TIME * 3, clear all keys
 *   persistent_keepalive  — user-configured interval
 *
 * Timer callbacks operate on the peer state and may trigger
 * handshake initiations, keepalive sends, or key material zeroing.
 *
 * Implementation uses per-timer threads with condition variables
 * for sleeping, modification, and cancellation, or, with
 * WG_TIMERS_SHARED_THREAD, one thread for every timer in the process.
 *
 * Reference: wireguard-go/device/timers.go
 */

#ifndef WG_TIMERS_H
#define WG_TIMERS_H

#include "wg_constants.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stdint.h>

/* Forward declaration */
struct wg_peer;

/* ────────────────────────────────────────
 * Timer
 * ──────────────────────────────────────── */

/* Timer expiration callback. */
typedef void (*wg_timer_fn)(struct wg_peer *peer);

typedef struct wg_timer {
    struct wg_peer *peer;
    wg_timer_fn callback;

    /* Timing state */
    uint64_t deadline_ns; /* absolute monotonic deadline (0 = not set) */
    bool is_pending;      /* timer is armed */

#if WG_TIMERS_SHARED_THREAD
    /* The shared thread's lock guards the fields above. */
    struct wg_timer *next; /* every live timer, for the shared thread to scan */
#else
    uint64_t wait_deadline_ns; /* what the thread sleeps until: UINT64_MAX
                                  untimed, 0 not sleeping */
    bool should_stop;          /* signal the thread to exit */

    /* Synchronisation */
    pthread_mutex_t lock;
    pthread_cond_t cond;      /* signalled on mod/del/stop */
    int cond_clock;           /* clock cond's timed waits count on: CLOCK_MONOTONIC
                                 unless pthread_condattr_setclock refused it */
    pthread_mutex_t run_lock; /* held while callback runs (for DelSync) */

    /* Timer thread */
    pthread_t thread;
    bool thread_started;
#endif
} wg_timer_t;

/* ────────────────────────────────────────
 * Timer lifecycle
 * ──────────────────────────────────────── */

/*
 * Create and start a new timer for a peer.
 * The timer is initially stopped (not pending).
 * Returns NULL on failure.
 */
wg_timer_t *wg_timer_new(struct wg_peer *peer, wg_timer_fn callback);

/*
 * Modify (arm/reset) a timer with a relative duration in nanoseconds.
 * If the timer is already pending, it is rearmed with the new deadline.
 */
void wg_timer_mod(wg_timer_t *timer, uint64_t duration_ns);

/*
 * Delete (disarm) a timer. If the timer fires concurrently,
 * the callback may still run. Use wg_timer_del_sync to wait.
 */
void wg_timer_del(wg_timer_t *timer);

/*
 * Delete and wait for any running callback to complete.
 * Safe to call from any thread except the timer's own callback.
 */
void wg_timer_del_sync(wg_timer_t *timer);

/*
 * Check if the timer is currently pending (armed).
 */
bool wg_timer_is_pending(wg_timer_t *timer);

/*
 * Destroy a timer: stop thread, free resources.
 * Must not be called from the timer's callback.
 */
void wg_timer_destroy(wg_timer_t *timer);

/* ────────────────────────────────────────
 * Per-peer timer management
 * ──────────────────────────────────────── */

/*
 * Initialise all 5 timers for a peer.
 * Called from wg_peer_new().
 * Returns false if any timer allocation fails.
 */
bool wg_timers_init(struct wg_peer *peer);

/*
 * Start timers (reset counters, enable firing).
 * Called from wg_peer_start().
 */
void wg_timers_start(struct wg_peer *peer);

/*
 * Stop all timers synchronously.
 * Called from wg_peer_stop().
 */
void wg_timers_stop(struct wg_peer *peer);

/*
 * Destroy all timers.
 * Called from wg_peer_destroy().
 */
void wg_timers_destroy(struct wg_peer *peer);

/* ────────────────────────────────────────
 * Timer event callbacks
 *
 * Called by the send/receive workers and handshake handlers
 * to trigger appropriate timer actions.
 * ──────────────────────────────────────── */

/* After an authenticated data packet is sent. */
void wg_timers_data_sent(struct wg_peer *peer);

/* After an authenticated data packet is received. */
void wg_timers_data_received(struct wg_peer *peer);

/* After any authenticated packet is sent (data, keepalive, handshake). */
void wg_timers_any_authenticated_packet_sent(struct wg_peer *peer);

/* After any authenticated packet is received. */
void wg_timers_any_authenticated_packet_received(struct wg_peer *peer);

/* After a handshake initiation is sent. */
void wg_timers_handshake_initiated(struct wg_peer *peer);

/* After a handshake response is received and processed. */
void wg_timers_handshake_complete(struct wg_peer *peer);

/* After session keys are derived (ephemeral key created). */
void wg_timers_session_derived(struct wg_peer *peer);

/* Before/after any authenticated packet traversal (for persistent keepalive). */
void wg_timers_any_authenticated_packet_traversal(struct wg_peer *peer);

#endif /* WG_TIMERS_H */

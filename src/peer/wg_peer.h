/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Peer state machine.
 *
 * Each peer holds:
 *   - Noise handshake state + keypair set
 *   - Cookie generator (for mac1/mac2)
 *   - Endpoint (network address)
 *   - Timer state (retransmit, keepalive, rekey, etc.)
 *   - Traffic counters (atomic)
 *   - Queues for staged/outbound/inbound packets
 *
 * Reference: wireguard-go/device/peer.go
 */

#ifndef WG_PEER_H
#define WG_PEER_H

#include "../cookie/wg_cookie.h"
#include "../device/wg_prev_queue.h"
#include "../device/wg_queue.h"
#include "../noise/wg_noise.h"
#include "wg_allowedips.h"
#include "wg_indextable.h"
#include "wg_constants.h"
#include "wg_error.h"
#include "wg_types.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Forward declarations */
struct wg_device;
struct wg_timer;

/* ────────────────────────────────────────
 * Peer endpoint
 * ──────────────────────────────────────── */
typedef struct {
    wg_endpoint_t val;
    bool has_value;
    bool clear_src_on_tx;
    bool disable_roaming;
    pthread_mutex_t lock;
} wg_peer_endpoint_t;

/* ────────────────────────────────────────
 * Peer timer state
 * ──────────────────────────────────────── */
typedef struct {
    struct wg_timer *retransmit_handshake;
    struct wg_timer *send_keepalive;
    struct wg_timer *new_handshake;
    struct wg_timer *zero_key_material;
    struct wg_timer *persistent_keepalive;

    _Atomic uint32_t handshake_attempts;
    _Atomic bool need_another_keepalive;
    _Atomic bool sent_last_minute_handshake;
} wg_peer_timers_t;

/* ────────────────────────────────────────
 * Peer structure
 * ──────────────────────────────────────── */
struct wg_peer {
    _Atomic bool is_running;

    /* Set once, when the peer is being removed. No new handshake index
     * is added for it after that (checked under handshake.lock), so the
     * index table cannot lead to it again. */
    _Atomic bool is_dead;

    /* Noise protocol state */
    wg_noise_keypairs_t keypairs;
    wg_noise_handshake_t handshake;

    /* Back-pointer to owning device */
    struct wg_device *device;

    /* Traffic counters */
    _Atomic uint64_t tx_bytes;
    _Atomic uint64_t rx_bytes;
    _Atomic int64_t last_handshake_ns; /* nanoseconds since epoch */

    /* Endpoint */
    wg_peer_endpoint_t endpoint;

    /* Timer state */
    wg_peer_timers_t timers;

    /* Persistent keepalive interval (seconds, 0 = disabled) */
    _Atomic uint32_t persistent_keepalive_interval;

    /* Cookie generator for this peer */
    wg_cookie_generator_t cookie_generator;

    /* Per-peer queues
     *
     * staged: TUN packets waiting for keypair (MPMC, small)
     * staged_send_lock: protects wg_send_staged_packets SPSC push (cold path)
     * tx_order / rx_order: prev_queues for ordered delivery with parallel crypto
     */
    struct {
        wg_queue_t *staged;               /* TUN packets waiting for keypair */
        pthread_mutex_t staged_send_lock; /* protects SPSC push in staged path */
        wg_prev_queue_t tx_order;         /* send: ordered delivery (parallel encrypt) */
        wg_prev_queue_t rx_order;         /* recv: ordered delivery (parallel decrypt) */
        pthread_mutex_t tx_drain_lock;    /* trylock: only 1 thread drains tx_order */
        pthread_mutex_t rx_drain_lock;    /* trylock: only 1 thread drains rx_order */
    } queue;

    /* State lock: protects concurrent Start/Stop */
    pthread_mutex_t state_lock;
};

/* Make the public opaque handle match the internal struct */
typedef struct wg_peer wg_peer_t;

/* ────────────────────────────────────────
 * Peer lifecycle
 * ──────────────────────────────────────── */

/*
 * Create a new peer associated with a device.
 *
 * Performs:
 *   - Maximum peer count check
 *   - Duplicate public key check
 *   - Handshake initialisation with static-static DH precomputation
 *     (zero until the device has a private key)
 *   - Cookie generator initialisation
 *   - Endpoint reset
 *
 * On success, *out_peer is set and the peer is added to the device.
 *
 * device       — owning device
 * public_key   — peer's static public key
 * preshared_key— optional PSK (may be NULL for no PSK)
 */
wg_error_t wg_peer_new(struct wg_device *device, const uint8_t public_key[WG_KEY_LEN],
                       const uint8_t *preshared_key, wg_peer_t **out_peer);

/*
 * Start the peer: enable timers, prepare queues.
 * Idempotent — does nothing if already running.
 */
void wg_peer_start(wg_peer_t *peer);

/*
 * Stop the peer: disable timers, flush queues, zero keys.
 * Idempotent — does nothing if not running.
 */
void wg_peer_stop(wg_peer_t *peer);

/*
 * Zero all keys and flush all queued packets.
 * Called during stop and removal.
 */
void wg_peer_zero_and_flush(wg_peer_t *peer);

/*
 * Expire current keypairs: force rekey on next packet.
 * Clears handshake state and invalidates current/next keypairs.
 */
void wg_peer_expire_current_keypairs(wg_peer_t *peer);

/*
 * Destroy and free the peer.
 * The peer must already be stopped and removed from device data structures.
 */
void wg_peer_destroy(wg_peer_t *peer);

/* ────────────────────────────────────────
 * Endpoint management
 * ──────────────────────────────────────── */

/*
 * Set endpoint from a received packet (roaming).
 * Respects disable_roaming flag.
 */
void wg_peer_set_endpoint_from_packet(wg_peer_t *peer, const wg_endpoint_t *ep);

/*
 * Get a snapshot of the peer's current endpoint.
 * Returns false if no endpoint is set.
 */
bool wg_peer_get_endpoint(wg_peer_t *peer, wg_endpoint_t *out);

#endif /* WG_PEER_H */

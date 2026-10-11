/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Device structure and lifecycle.
 *
 * State machine: DOWN <-> UP -> CLOSED
 *   - DOWN: device created, not processing packets
 *   - UP:   bind open, peers started, processing packets
 *   - CLOSED: terminal state, all resources released
 *
 * ────────────────────────────────────────────────────────────
 * Lock Acquisition Order (must be maintained to prevent deadlock)
 * ────────────────────────────────────────────────────────────
 *
 *   Level 0: static_identity.lock    (pthread_rwlock_t)  device key pair
 *   Level 1: dev->state_lock         (pthread_mutex_t)   device state machine
 *   Level 2: peers.lock              (pthread_rwlock_t)   peer hash map
 *   Level 3: peer->keypairs.lock     (pthread_mutex_t)   keypair rotation
 *            peer->handshake.lock    (pthread_rwlock_t)   handshake state
 *   Level 4: index_table.lock        (pthread_rwlock_t)   sender index table
 *   Level 5: peer->endpoint.lock     (pthread_mutex_t)   peer endpoint
 *            receiving_counter.lock  (pthread_mutex_t)   anti-replay window
 *
 * Leaf locks (never held while acquiring another lock):
 *   net.lock, receiving_counter.lock, peer->endpoint.lock
 *
 * Timers: a timer callback runs holding the timer's run_lock and may take
 * static_identity (to start a handshake), and wg_timers_stop() waits for
 * run_lock. So never stop a peer (wg_peer_stop) while holding
 * static_identity or peers.lock; state_lock is fine (#132).
 *
 * Rules:
 *   - Never acquire a lock at level N while holding a lock at level > N.
 *   - Same-level locks must not be held simultaneously
 *     (exception: iterating all peers under peers.lock may take per-peer locks).
 *   - Prefer copy-and-release: read under lock, release, then do work.
 *
 * Critical nested-lock paths:
 *   set_private_key:  static_identity(W) → peers(W) → handshake(R),
 *                     release handshake(R), then handshake(W) per peer
 *                     then outside: handshake(W) → index_table(W) → keypairs(M)
 *   expire_keypairs:  handshake(W) → index_table(W), then keypairs(M)
 *   create_initiation: static_identity(R) release, then handshake(W)
 *   consume_response:  index_table(R), then handshake(W)
 *
 * Reference: wireguard-go/device/device.go
 */

#ifndef WG_DEVICE_INTERNAL_H
#define WG_DEVICE_INTERNAL_H

#include "../cookie/wg_cookie.h"
#include "../noise/wg_noise.h"
#include "../peer/wg_allowedips.h"
#include "../peer/wg_indextable.h"
#include "../ratelimiter/wg_ratelimiter.h"
#include "wg_pools.h"
#include "wg_queue.h"
#include "wg_spsc.h"
#include "wg_stats.h"
#include "wg_constants.h"
#include "wg_error.h"
#include "wg_types.h"
#include "wireguard.h"

#include "platform/wg_platform.h"
#ifdef __linux__
#include <sched.h>
#endif
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declaration */
struct wg_peer;
struct wg_device;

/* ────────────────────────────────────────
 * RTC (Run-to-Completion) worker types
 *
 * Each worker owns a SPSC queue and runs encrypt+send or decrypt+write
 * inline, eliminating MPMC condvar / eventfd synchronisation overhead.
 * ──────────────────────────────────────── */
typedef struct {
    wg_spsc_t queue;
    pthread_t thread;
    struct wg_device *dev;
    int id;
    bool started;
} wg_rtc_send_worker_t;

typedef struct {
    wg_spsc_t queue;
    pthread_t thread;
    struct wg_device *dev;
    int id;
    bool started;
} wg_rtc_recv_worker_t;

/* ────────────────────────────────────────
 * Device state
 * ──────────────────────────────────────── */
typedef enum {
    WG_DEVICE_STATE_DOWN = 0,
    WG_DEVICE_STATE_UP = 1,
    WG_DEVICE_STATE_CLOSED = 2,
} wg_device_state_t;

/* ────────────────────────────────────────
 * Peer map: public_key -> peer
 *
 * Simple hash table (open addressing) keyed by public key.
 * ──────────────────────────────────────── */

#define WG_PEER_MAP_INITIAL_CAPACITY 64

typedef struct {
    uint8_t public_key[WG_KEY_LEN];
    struct wg_peer *peer;
    bool occupied;
} wg_peer_map_entry_t;

typedef struct {
    wg_peer_map_entry_t *entries;
    size_t capacity;
    size_t count;
    pthread_rwlock_t lock;
    /* Bumped (under lock, for writing) whenever a peer is added or
     * removed. The sequential threads cache the peer list and refresh it
     * when this changes; see wg_device_wait_peer_readers(). They read it
     * every loop, so it gets a cache line of its own, away from the lock
     * that other threads take for reading. */
    _Alignas(64) _Atomic uint64_t generation;
} wg_peer_map_t;

/* ────────────────────────────────────────
 * Device structure
 * ──────────────────────────────────────── */
struct wg_device {
    /* State machine */
    _Atomic uint32_t state;     /* wg_device_state_t */
    pthread_mutex_t state_lock; /* protects state transitions */

    /* Static identity (device's own key pair) */
    wg_noise_static_identity_t static_identity;

    /* Peers: key map + allowed IPs */
    wg_peer_map_t peers;
    wg_allowedips_t allowedips;

    /* Index table: sender_index -> peer/handshake/keypair */
    wg_index_table_t index_table;

    /* Cookie checker (receiver side, validates mac1/mac2) */
    wg_cookie_checker_t cookie_checker;

    /* Rate limiter */
    struct {
        _Atomic int64_t under_load_until_ns;
        wg_ratelimiter_t limiter;
    } rate;

    /* Network / bind */
    struct {
        pthread_rwlock_t lock;
        wg_bind_ops_t bind; /* copy of caller-provided bind ops */
        uint16_t port;
        uint32_t fwmark;
        bool broken_roaming; /* wg_device_disable_roaming() */
    } net;

    /* TUN device */
    struct {
        wg_tun_ops_t tun; /* copy of caller-provided tun ops */
        _Atomic int32_t mtu;
    } tun;

    /* Device queues */
    struct {
        wg_queue_t *handshake;
        wg_queue_t *encryption; /* legacy MPMC — kept for inline_crypto fallback */
        wg_queue_t *decryption; /* legacy MPMC — kept for inline_crypto fallback */
    } queue;

    /* RTC (Run-to-Completion) workers: SPSC fan-out + inline crypto.
     * Replaces MPMC encryption/decryption workers + sequential sender/receiver. */
    struct {
        wg_rtc_send_worker_t *send; /* array[num_send] */
        wg_rtc_recv_worker_t *recv; /* array[num_recv] */
        int num_send;
        int num_recv;
        _Atomic uint64_t send_rr; /* round-robin counter for send SPSC */
        _Atomic uint64_t recv_rr; /* round-robin counter for recv SPSC */
    } rtc;

    /* Element pools: reuse outbound/inbound elems to avoid per-packet
     * calloc overhead. */
    struct {
        wg_wait_pool_t *outbound;
        wg_wait_pool_t *inbound;
    } pool;

    /* Logger */
    wg_logger_t logger;

    /* Device-level worker threads */
    struct {
        pthread_t tun_reader;
        pthread_t handshake;
        pthread_t udp_recv;
        pthread_t sequential_send;
        pthread_t sequential_recv;
        bool tun_reader_started;
        bool handshake_started;
        bool udp_recv_started;
        bool sequential_send_started;
        bool sequential_recv_started;
    } workers;

    /* CPU topology (detected at device up) */
    int ncpu;             /* online vCPU count */
    int phys_cores;       /* physical core count (ncpu / threads_per_core) */
    int threads_per_core; /* 1 = no HT, 2 = HT */
    bool inline_crypto;   /* true: encrypt/decrypt inline (no worker threads) */
#ifdef __linux__
    cpu_set_t send_mask; /* affinity mask for send path threads */
    cpu_set_t recv_mask; /* affinity mask for recv path threads */
#endif

    /* Sequential thread wake-up (adaptive spin + futex).
     * Separated into send/recv to eliminate false wakeups:
     * send crypto workers signal seq_wake_send only,
     * recv crypto workers signal seq_wake_recv only.
     * The *_waiting flag shares the line with its word: the sequential
     * thread sets it before FUTEX_WAIT, and signallers only make the
     * FUTEX_WAKE syscall when it is set (Linux). */
    _Alignas(64) _Atomic uint32_t seq_wake_send;
    _Atomic uint32_t seq_wake_send_waiting;
    _Alignas(64) _Atomic uint32_t seq_wake_recv;
    _Atomic uint32_t seq_wake_recv_waiting;

    /* Peer-list generation each sequential thread has cached, plus one,
     * or 0 while it caches none (not running; a zeroed device reads so).
     * A thread publishes the generation it is about to cache before it
     * takes peers.lock to copy the list, so a peer removed under that lock
     * is never freed while a thread may still hold it
     * (wg_device_wait_peer_readers()). */
    _Alignas(64) _Atomic uint64_t seq_send_peer_gen;
    _Alignas(64) _Atomic uint64_t seq_recv_peer_gen;

    /* The same for the threads that take peers from the peer map,
     * AllowedIPs or the index table and use them after dropping the
     * table's lock: the handshake worker (per message), the TUN reader
     * and the UDP receiver (per batch). They hold no peer between
     * sections, so they read 0 while they wait for work; see
     * wg_peer_reader_enter(). */
    _Alignas(64) _Atomic uint64_t hs_peer_gen;
    _Alignas(64) _Atomic uint64_t tun_peer_gen;
    _Alignas(64) _Atomic uint64_t udp_peer_gen;

    /* Pipeline performance counters */
    wg_stats_t stats;
};

typedef struct wg_device wg_device_t;

/* ────────────────────────────────────────
 * Device state helpers
 * ──────────────────────────────────────── */
static inline wg_device_state_t wg_device_get_state(wg_device_t *dev)
{
    return (wg_device_state_t)atomic_load(&dev->state);
}

static inline bool wg_device_is_closed(wg_device_t *dev)
{
    return wg_device_get_state(dev) == WG_DEVICE_STATE_CLOSED;
}

static inline bool wg_device_is_up(wg_device_t *dev)
{
    return wg_device_get_state(dev) == WG_DEVICE_STATE_UP;
}

/* ────────────────────────────────────────
 * Device lifecycle (implements public API from wireguard.h)
 * ──────────────────────────────────────── */

/*
 * Create a new device in DOWN state.
 * Initialises all subsystems (peers, index table, rate limiter, queues, etc.)
 * Does NOT start processing — call wg_device_up() for that.
 */
wg_error_t wg_device_new(wg_device_t **out, const wg_tun_ops_t *tun,
                         const wg_bind_ops_t *bind, const wg_logger_t *logger);

/*
 * Bring the device up: open bind, start all peers.
 */
wg_error_t wg_device_up(wg_device_t *dev);

/*
 * Re-bind: close old sockets, join recv thread, open new sockets,
 * start new recv thread. Caller must hold dev->state_lock and, after it,
 * dev->net.lock for WRITE.
 * Note: temporarily releases and re-acquires net.lock internally; the
 * state_lock keeps the device from going down and up in that window.
 */
wg_error_t wg_device_bind_update(wg_device_t *dev);

/*
 * Wait until no thread can still hold a peer pointer it found before
 * generation `gen`: the sequential threads' peer caches and the peer
 * reader sections below. Call after removing peers (and releasing every
 * lock), before freeing them.
 */
void wg_device_wait_peer_readers(wg_device_t *dev, uint64_t gen);

/*
 * Peer reader section. A thread that looks a peer up and keeps using it
 * after the lookup's lock is released brackets that use with these, on
 * its own slot (dev->hs_peer_gen etc.). A remover unlinks the peer
 * everywhere, bumps peers.generation, and wg_device_wait_peer_readers()
 * then waits for every slot that entered before the bump.
 *
 * The fence orders the slot store before the lookups, and pairs with the
 * fence in wg_device_wait_peer_readers() before it loads the slots:
 * either the remover sees the slot, or this thread's lookups see the
 * unlink. Reading a generation at or past the remover's bump (acquire)
 * also makes the unlink visible. One full fence per section (a batch or
 * a handshake message), and a store to a line only this thread writes.
 */
static inline void wg_peer_reader_enter(wg_device_t *dev, _Atomic uint64_t *slot)
{
    uint64_t gen = atomic_load_explicit(&dev->peers.generation, memory_order_acquire);
    atomic_store_explicit(slot, gen + 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void wg_peer_reader_exit(_Atomic uint64_t *slot)
{
    atomic_store_explicit(slot, 0, memory_order_release);
}

/*
 * Bring the device down: close bind, stop all peers.
 * Can be brought back up with wg_device_up().
 */
wg_error_t wg_device_down(wg_device_t *dev);

/*
 * Close the device permanently. Terminal state.
 * Stops all peers, closes bind/tun, frees queues and rate limiter.
 */
void wg_device_close(wg_device_t *dev);

/* ────────────────────────────────────────
 * Identity
 * ──────────────────────────────────────── */

/*
 * Set the device private key. Recomputes static-static DH for all peers.
 * Removes any peer whose public key matches the new device public key.
 */
wg_error_t wg_device_set_private_key(wg_device_t *dev, const wg_key_t *private_key);

/* ────────────────────────────────────────
 * Rate / load detection
 * ──────────────────────────────────────── */

/* Under-load grace period: 1 second */
#define WG_UNDER_LOAD_AFTER_TIME_NS 1000000000LL

/*
 * Returns true if the device is currently under load
 * (handshake queue >= 1/8 full, or was recently).
 */
bool wg_device_is_under_load(wg_device_t *dev);

/* ────────────────────────────────────────
 * Peer management
 * ──────────────────────────────────────── */

/*
 * Look up a peer by public key. Returns NULL if not found.
 * Thread-safe (acquires peers read lock).
 */
struct wg_peer *wg_device_lookup_peer(wg_device_t *dev,
                                      const uint8_t public_key[WG_KEY_LEN]);

/*
 * Remove a single peer by public key.
 * Stops the peer, removes from allowed IPs and peer map.
 * Signature matches public API in wireguard.h.
 */
wg_error_t wg_device_remove_peer(wg_device_t *dev, const wg_key_t *public_key);

/*
 * Remove all peers from the device.
 */
void wg_device_remove_all_peers(wg_device_t *dev);

/* ────────────────────────────────────────
 * Peer map operations
 * ──────────────────────────────────────── */
wg_error_t wg_peer_map_init(wg_peer_map_t *map);
void wg_peer_map_destroy(wg_peer_map_t *map);

/* Insert a peer. Returns WG_ERR_MAX_PEERS on duplicate key. */
wg_error_t wg_peer_map_insert(wg_peer_map_t *map, const uint8_t public_key[WG_KEY_LEN],
                              struct wg_peer *peer);

/* Lookup by public key. Returns NULL if not found. */
struct wg_peer *wg_peer_map_lookup(wg_peer_map_t *map,
                                   const uint8_t public_key[WG_KEY_LEN]);

/* Remove by public key. Returns the removed peer, or NULL. */
struct wg_peer *wg_peer_map_remove(wg_peer_map_t *map,
                                   const uint8_t public_key[WG_KEY_LEN]);

/* Return the number of peers. */
size_t wg_peer_map_count(wg_peer_map_t *map);

#endif /* WG_DEVICE_INTERNAL_H */

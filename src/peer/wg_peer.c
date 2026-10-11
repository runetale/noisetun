/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Peer state machine.
 *
 * Reference: wireguard-go/device/peer.go
 */

#include "wg_peer.h"

#include "../device/wg_device.h"
#include "../device/wg_queue.h"
#include "../noise/wg_noise.h"
#include "../timers/wg_timers.h"
#include "../workers/wg_workers.h"
#include "wg_indextable.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Peer map (public_key -> peer hash table)
 * ──────────────────────────────────────── */

static uint32_t peer_map_hash(const uint8_t key[WG_KEY_LEN])
{
    /* FNV-1a over the 32-byte key */
    uint32_t h = 0x811c9dc5;
    for (int i = 0; i < WG_KEY_LEN; i++) {
        h ^= key[i];
        h *= 0x01000193;
    }
    return h;
}

wg_error_t wg_peer_map_init(wg_peer_map_t *map)
{
    map->entries = calloc(WG_PEER_MAP_INITIAL_CAPACITY, sizeof(*map->entries));
    if (!map->entries)
        return WG_ERR_NO_MEMORY;
    map->capacity = WG_PEER_MAP_INITIAL_CAPACITY;
    map->count = 0;
    pthread_rwlock_init(&map->lock, NULL);
    return WG_OK;
}

void wg_peer_map_destroy(wg_peer_map_t *map)
{
    if (!map)
        return;
    free(map->entries);
    map->entries = NULL;
    map->capacity = 0;
    map->count = 0;
    pthread_rwlock_destroy(&map->lock);
}

static wg_error_t peer_map_resize(wg_peer_map_t *map)
{
    size_t new_cap = map->capacity * 2;
    wg_peer_map_entry_t *new_entries = calloc(new_cap, sizeof(*new_entries));
    if (!new_entries)
        return WG_ERR_NO_MEMORY;

    /* Re-insert all existing entries */
    for (size_t i = 0; i < map->capacity; i++) {
        if (!map->entries[i].occupied)
            continue;
        uint32_t h = peer_map_hash(map->entries[i].public_key);
        size_t idx = h & (new_cap - 1);
        while (new_entries[idx].occupied)
            idx = (idx + 1) & (new_cap - 1);
        new_entries[idx] = map->entries[i];
    }

    free(map->entries);
    map->entries = new_entries;
    map->capacity = new_cap;
    return WG_OK;
}

wg_error_t wg_peer_map_insert(wg_peer_map_t *map, const uint8_t public_key[WG_KEY_LEN],
                              struct wg_peer *peer)
{
    /* Resize if load factor > 3/4 */
    if (map->count * 4 >= map->capacity * 3) {
        wg_error_t err = peer_map_resize(map);
        if (err != WG_OK)
            return err;
    }

    uint32_t h = peer_map_hash(public_key);
    size_t idx = h & (map->capacity - 1);

    while (map->entries[idx].occupied) {
        if (memcmp(map->entries[idx].public_key, public_key, WG_KEY_LEN) == 0)
            return WG_ERR_DUPLICATE_PEER;
        idx = (idx + 1) & (map->capacity - 1);
    }

    memcpy(map->entries[idx].public_key, public_key, WG_KEY_LEN);
    map->entries[idx].peer = peer;
    map->entries[idx].occupied = true;
    map->count++;
    atomic_fetch_add_explicit(&map->generation, 1, memory_order_release);

    return WG_OK;
}

struct wg_peer *wg_peer_map_lookup(wg_peer_map_t *map,
                                   const uint8_t public_key[WG_KEY_LEN])
{
    uint32_t h = peer_map_hash(public_key);
    size_t idx = h & (map->capacity - 1);

    while (map->entries[idx].occupied) {
        if (memcmp(map->entries[idx].public_key, public_key, WG_KEY_LEN) == 0)
            return map->entries[idx].peer;
        idx = (idx + 1) & (map->capacity - 1);
    }

    return NULL;
}

struct wg_peer *wg_peer_map_remove(wg_peer_map_t *map,
                                   const uint8_t public_key[WG_KEY_LEN])
{
    uint32_t h = peer_map_hash(public_key);
    size_t idx = h & (map->capacity - 1);

    while (map->entries[idx].occupied) {
        if (memcmp(map->entries[idx].public_key, public_key, WG_KEY_LEN) == 0) {
            struct wg_peer *peer = map->entries[idx].peer;
            map->entries[idx].occupied = false;
            map->entries[idx].peer = NULL;
            map->count--;
            atomic_fetch_add_explicit(&map->generation, 1, memory_order_release);

            /* Backward-shift deletion to maintain linear probing invariant */
            size_t j = (idx + 1) & (map->capacity - 1);
            while (map->entries[j].occupied) {
                uint32_t jh = peer_map_hash(map->entries[j].public_key);
                size_t natural = jh & (map->capacity - 1);

                /* Check if j is displaced past idx */
                bool displaced;
                if (idx <= j)
                    displaced = (natural <= idx || natural > j);
                else
                    displaced = (natural <= idx && natural > j);

                if (displaced) {
                    map->entries[idx] = map->entries[j];
                    map->entries[j].occupied = false;
                    map->entries[j].peer = NULL;
                    idx = j;
                }
                j = (j + 1) & (map->capacity - 1);
            }

            return peer;
        }
        idx = (idx + 1) & (map->capacity - 1);
    }

    return NULL;
}

size_t wg_peer_map_count(wg_peer_map_t *map)
{
    return map->count;
}

/* ────────────────────────────────────────
 * Peer lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_peer_new(struct wg_device *device, const uint8_t public_key[WG_KEY_LEN],
                       const uint8_t *preshared_key, wg_peer_t **out_peer)
{
    if (wg_device_is_closed(device))
        return WG_ERR_DEVICE_CLOSED;

    /* Lock static identity for reading. A device without a private key
     * yet may still get peers, as in wireguard-go (`wg set wg0 peer ...`
     * before `private-key`): their static-static DH stays zero until
     * wg_device_set_private_key recomputes it for every peer, and no
     * handshake starts without an identity. */
    pthread_rwlock_rdlock(&device->static_identity.lock);

    /* Lock peer map */
    pthread_rwlock_wrlock(&device->peers.lock);

    /* Check peer limit */
    if (device->peers.count >= WG_MAX_PEERS_PER_DEVICE) {
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        return WG_ERR_MAX_PEERS;
    }

    /* Check for duplicate */
    if (wg_peer_map_lookup(&device->peers, public_key)) {
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        return WG_ERR_DUPLICATE_PEER;
    }

    /* Allocate peer */
    wg_peer_t *peer = calloc(1, sizeof(*peer));
    if (!peer) {
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        return WG_ERR_NO_MEMORY;
    }

    atomic_store(&peer->is_running, false);
    peer->device = device;

    /* Initialise traffic counters */
    atomic_store(&peer->tx_bytes, 0);
    atomic_store(&peer->rx_bytes, 0);
    atomic_store(&peer->last_handshake_ns, 0);

    /* Initialise keypairs */
    wg_noise_keypairs_init(&peer->keypairs);

    /* Initialise handshake with static-static DH precomputation */
    wg_noise_handshake_init(&peer->handshake, &device->static_identity, public_key,
                            preshared_key);
    wg_noise_precompute_static_static(&peer->handshake);

    /* Initialise cookie generator */
    wg_cookie_generator_init(&peer->cookie_generator, public_key);

    /* Initialise endpoint */
    memset(&peer->endpoint, 0, sizeof(peer->endpoint));
    pthread_mutex_init(&peer->endpoint.lock, NULL);

    /* Initialise timer state */
    memset(&peer->timers, 0, sizeof(peer->timers));
    atomic_store(&peer->timers.handshake_attempts, 0);
    atomic_store(&peer->timers.need_another_keepalive, false);
    atomic_store(&peer->timers.sent_last_minute_handshake, false);
    atomic_store(&peer->persistent_keepalive_interval, 0);

    /* Per-peer queues (Two-Level Queue pattern) */
    peer->queue.staged = calloc(1, sizeof(wg_queue_t));
    if (!peer->queue.staged) {
        pthread_mutex_destroy(&peer->endpoint.lock);
        free(peer);
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        return WG_ERR_NO_MEMORY;
    }
    wg_queue_init(peer->queue.staged, WG_QUEUE_STAGED_SIZE);
    pthread_mutex_init(&peer->queue.staged_send_lock, NULL);
    wg_prev_queue_init(&peer->queue.tx_order, WG_PREV_QUEUE_MAX_PACKETS);
    wg_prev_queue_init(&peer->queue.rx_order, WG_PREV_QUEUE_MAX_PACKETS);
    pthread_mutex_init(&peer->queue.tx_drain_lock, NULL);
    pthread_mutex_init(&peer->queue.rx_drain_lock, NULL);

    /* State lock */
    pthread_mutex_init(&peer->state_lock, NULL);

    /* Initialise per-peer timers (each timer spawns its own thread) */
    if (!wg_timers_init(peer)) {
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        wg_peer_destroy(peer);
        return WG_ERR_NO_MEMORY;
    }

    /* Add to device peer map */
    wg_error_t err = wg_peer_map_insert(&device->peers, public_key, peer);
    if (err != WG_OK) {
        pthread_rwlock_unlock(&device->peers.lock);
        pthread_rwlock_unlock(&device->static_identity.lock);
        wg_peer_destroy(peer);
        return err;
    }

    pthread_rwlock_unlock(&device->peers.lock);
    pthread_rwlock_unlock(&device->static_identity.lock);

    *out_peer = peer;
    return WG_OK;
}

void wg_peer_start(wg_peer_t *peer)
{
    if (wg_device_is_closed(peer->device))
        return;

    pthread_mutex_lock(&peer->state_lock);

    if (atomic_load(&peer->is_running)) {
        pthread_mutex_unlock(&peer->state_lock);
        return;
    }

    /* Start timers. */
    wg_timers_start(peer);

    atomic_store(&peer->is_running, true);

    pthread_mutex_unlock(&peer->state_lock);
}

/* Drain prev_queues (ordering queues for parallel crypto).
 *
 * Acquire drain locks to serialize with sequential workers — prevents
 * use-after-free when removing a peer while the device is still UP.
 * (Issue #94: sequential workers cache peer pointers and may be
 * mid-drain when wg_peer_stop() is called from retire_peers().)
 *
 * Spin-wait for each element to reach CRYPTED/DEAD state before freeing.
 * When called from down_locked(), all workers are already joined so
 * elements are already in terminal state (no spinning occurs).
 * When called from retire_peers() or wg_peer_destroy() (device UP),
 * crypto workers may still be processing elements — we wait for them
 * to finish. */
static void drain_order_queues(wg_peer_t *peer, bool reinit)
{
    void *elem;

    pthread_mutex_lock(&peer->queue.tx_drain_lock);
    while ((elem = wg_prev_queue_peek(&peer->queue.tx_order)) != NULL) {
        wg_outbound_elem_t *e = elem;
        /* Wait for the crypto worker to finish with this element. No
         * sequential thread has one in flight: it does inline crypto only
         * under the drain lock, which this function holds. */
        int spins = 0;
        while (!wg_elem_done(atomic_load_explicit(&e->state, memory_order_acquire))) {
            if (++spins > 1024)
                sched_yield();
        }
        wg_prev_queue_drop_peeked(&peer->queue.tx_order);
        wg_outbound_elem_free(elem);
    }
    /* Re-initialize for a potential restart while still holding the
     * drain lock: a sequential worker with this peer in its cache may
     * peek the queue as soon as the lock is released. Not while the peer
     * is being removed: a TUN or UDP thread still in its reader section
     * may be halfway through an enqueue (head swapped, link not yet
     * written), and resetting the queue under it would lose elements.
     * wg_peer_destroy drains what is left once those threads are gone. */
    if (reinit)
        wg_prev_queue_init(&peer->queue.tx_order, WG_PREV_QUEUE_MAX_PACKETS);
    pthread_mutex_unlock(&peer->queue.tx_drain_lock);

    pthread_mutex_lock(&peer->queue.rx_drain_lock);
    while ((elem = wg_prev_queue_peek(&peer->queue.rx_order)) != NULL) {
        wg_inbound_elem_t *e = elem;
        int spins = 0;
        while (!wg_elem_done(atomic_load_explicit(&e->state, memory_order_acquire))) {
            if (++spins > 1024)
                sched_yield();
        }
        wg_prev_queue_drop_peeked(&peer->queue.rx_order);
        wg_inbound_elem_free(elem);
    }
    if (reinit)
        wg_prev_queue_init(&peer->queue.rx_order, WG_PREV_QUEUE_MAX_PACKETS);
    pthread_mutex_unlock(&peer->queue.rx_drain_lock);
}

void wg_peer_stop(wg_peer_t *peer)
{
    pthread_mutex_lock(&peer->state_lock);

    if (!atomic_exchange(&peer->is_running, false)) {
        pthread_mutex_unlock(&peer->state_lock);
        return;
    }

    /* Stop timers synchronously. */
    wg_timers_stop(peer);

    /* Close staged queue to unblock any thread waiting on it. */
    wg_queue_close(peer->queue.staged);

    /* Flush staged queue. The queue struct remains valid (for destroy later
     * or potential restart via wg_peer_start). */
    wg_queue_flush(peer->queue.staged, wg_outbound_elem_free);

    /* Two statements: MSVC's atomic_load macro does not survive a
     * leading '!' (error C7707). */
    bool dead = atomic_load_explicit(&peer->is_dead, memory_order_seq_cst);
    drain_order_queues(peer, !dead);

    wg_peer_zero_and_flush(peer);

    pthread_mutex_unlock(&peer->state_lock);
}

void wg_peer_zero_and_flush(wg_peer_t *peer)
{
    struct wg_device *device = peer->device;

    /* Clear keypairs: empty the slots under the lock, then drop their
     * index entries and references outside it, as the other writers do,
     * so freeing a keypair never runs under kps->lock. */
    pthread_mutex_lock(&peer->keypairs.lock);
    wg_noise_keypair_t *kps[3] = {
        atomic_exchange(&peer->keypairs.previous, NULL),
        atomic_exchange(&peer->keypairs.current, NULL),
        atomic_exchange(&peer->keypairs.next, NULL),
    };
    pthread_mutex_unlock(&peer->keypairs.lock);

    for (int i = 0; i < 3; i++) {
        if (!kps[i])
            continue;
        wg_index_table_delete(&device->index_table, kps[i]->local_index);
        wg_noise_keypair_put(kps[i]);
    }

    /* Clear handshake state. handshake.lock is hs->lock, so clear with it held. */
    pthread_rwlock_wrlock(&peer->handshake.lock);
    wg_index_table_delete(&device->index_table, peer->handshake.local_index);
    wg_noise_handshake_clear_locked(&peer->handshake);
    pthread_rwlock_unlock(&peer->handshake.lock);
}

void wg_peer_expire_current_keypairs(wg_peer_t *peer)
{
    struct wg_device *device = peer->device;

    /* Clear handshake. handshake.lock is hs->lock, so clear with it held. */
    pthread_rwlock_wrlock(&peer->handshake.lock);
    wg_index_table_delete(&device->index_table, peer->handshake.local_index);
    wg_noise_handshake_clear_locked(&peer->handshake);
    pthread_rwlock_unlock(&peer->handshake.lock);

    /* Invalidate current and next keypairs by maxing out their counters */
    pthread_mutex_lock(&peer->keypairs.lock);

    wg_noise_keypair_t *curr = atomic_load(&peer->keypairs.current);
    if (curr)
        atomic_store(&curr->sending_counter, WG_REJECT_AFTER_MESSAGES);

    wg_noise_keypair_t *next = atomic_load(&peer->keypairs.next);
    if (next)
        atomic_store(&next->sending_counter, WG_REJECT_AFTER_MESSAGES);

    pthread_mutex_unlock(&peer->keypairs.lock);
}

void wg_peer_destroy(wg_peer_t *peer)
{
    if (!peer)
        return;

    /* Each timer runs on its own thread that holds the peer: join them
     * before anything is freed. A timer re-armed after wg_peer_stop() by
     * a thread still using the peer may have fired since. */
    wg_timers_destroy(peer);

    /* Drain and free per-peer queues */
    if (peer->queue.staged) {
        wg_queue_flush(peer->queue.staged, wg_outbound_elem_free);
        wg_queue_destroy(peer->queue.staged);
        free(peer->queue.staged);
    }
    pthread_mutex_destroy(&peer->queue.staged_send_lock);

    /* Drain prev_queues: a thread that was still using the peer after
     * wg_peer_stop() may have queued more, and crypto workers may still
     * be encrypting or decrypting those. */
    drain_order_queues(peer, false);
    pthread_mutex_destroy(&peer->queue.tx_drain_lock);
    pthread_mutex_destroy(&peer->queue.rx_drain_lock);

    /* Clean up handshake (clear state, then destroy lock) */
    wg_noise_handshake_clear(&peer->handshake);
    pthread_rwlock_destroy(&peer->handshake.lock);

    /* Clean up keypairs (clear state, then destroy lock) */
    wg_noise_keypairs_clear(&peer->keypairs);
    pthread_mutex_destroy(&peer->keypairs.lock);

    /* Clean up cookie generator */
    wg_cookie_generator_destroy(&peer->cookie_generator);

    /* Clean up endpoint */
    pthread_mutex_destroy(&peer->endpoint.lock);

    /* Clean up state lock */
    pthread_mutex_destroy(&peer->state_lock);

    free(peer);
}

/* ────────────────────────────────────────
 * Endpoint management
 * ──────────────────────────────────────── */

void wg_peer_set_endpoint_from_packet(wg_peer_t *peer, const wg_endpoint_t *ep)
{
    pthread_mutex_lock(&peer->endpoint.lock);

    if (peer->endpoint.disable_roaming) {
        pthread_mutex_unlock(&peer->endpoint.lock);
        return;
    }

    peer->endpoint.clear_src_on_tx = false;
    peer->endpoint.val = *ep;
    peer->endpoint.has_value = true;

    pthread_mutex_unlock(&peer->endpoint.lock);
}

bool wg_peer_get_endpoint(wg_peer_t *peer, wg_endpoint_t *out)
{
    pthread_mutex_lock(&peer->endpoint.lock);

    if (!peer->endpoint.has_value) {
        pthread_mutex_unlock(&peer->endpoint.lock);
        return false;
    }

    *out = peer->endpoint.val;
    pthread_mutex_unlock(&peer->endpoint.lock);
    return true;
}

/* ────────────────────────────────────────
 * Public API wrappers (declared in wireguard.h)
 * ──────────────────────────────────────── */

wg_error_t wg_peer_set_endpoint(wg_peer_t *peer, const wg_endpoint_t *ep)
{
    if (!peer || !ep)
        return WG_ERR_INVALID_ARGUMENT;

    pthread_mutex_lock(&peer->endpoint.lock);
    peer->endpoint.val = *ep;
    peer->endpoint.has_value = true;
    pthread_mutex_unlock(&peer->endpoint.lock);
    return WG_OK;
}

wg_error_t wg_peer_add_allowed_ip(wg_peer_t *peer, const void *ip, uint8_t cidr,
                                  int family)
{
    if (!peer || !ip)
        return WG_ERR_INVALID_ARGUMENT;

    return wg_allowedips_insert(&peer->device->allowedips, ip, cidr, family, peer);
}

wg_error_t wg_peer_set_persistent_keepalive(wg_peer_t *peer, uint16_t interval_sec)
{
    if (!peer)
        return WG_ERR_INVALID_ARGUMENT;

    atomic_store(&peer->persistent_keepalive_interval, (uint32_t)interval_sec);

    /* If device is up and interval > 0, arm the persistent keepalive timer. */
    if (interval_sec > 0 && peer->device && wg_device_is_up(peer->device) &&
        peer->timers.persistent_keepalive) {
        wg_timer_mod(peer->timers.persistent_keepalive,
                     (uint64_t)interval_sec * 1000000000ULL);
    }

    return WG_OK;
}

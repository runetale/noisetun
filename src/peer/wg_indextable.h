/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Index table: maps sender_index (uint32) to peer/keypair/handshake.
 *
 * Uses open-addressing hash table with linear probing.
 * Random indices are uniformly distributed, so simple modular hashing works.
 *
 * Reference: wireguard-go/device/indextable.go
 */

#ifndef WG_INDEXTABLE_H
#define WG_INDEXTABLE_H

#include "wg_error.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Entry type: tracks whether the index maps to a handshake or keypair. */
typedef enum {
    WG_INDEX_ENTRY_EMPTY = 0,
    WG_INDEX_ENTRY_HANDSHAKE = 1,
    WG_INDEX_ENTRY_KEYPAIR = 2,
} wg_index_entry_type_t;

/* A single slot in the index table. */
typedef struct {
    uint32_t index;
    wg_index_entry_type_t type;
    void *peer; /* opaque — Peer not yet fully defined */
    void *data; /* wg_noise_handshake_t* or wg_noise_keypair_t* */
} wg_index_entry_t;

/* Open-addressing hash table with linear probing. */
typedef struct {
    wg_index_entry_t *slots;
    size_t capacity; /* always a power of 2 */
    size_t count;
    pthread_rwlock_t lock;
} wg_index_table_t;

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_index_table_init(wg_index_table_t *table);
void wg_index_table_destroy(wg_index_table_t *table);

/* ────────────────────────────────────────
 * Operations (matching wireguard-go IndexTable API)
 * ──────────────────────────────────────── */

/*
 * Generate a random, collision-free index and insert an entry.
 * Uses the double-check lock pattern from wireguard-go.
 *
 * On success: *index_out is set to the allocated index,
 *             entry is stored with that index.
 */
wg_error_t wg_index_table_new_index(wg_index_table_t *table, void *peer, void *handshake,
                                    uint32_t *index_out);

/*
 * Transition an entry from handshake to keypair.
 * Keeps the same peer, sets data to keypair, type to KEYPAIR.
 * Matches wireguard-go SwapIndexForKeypair.
 */
void wg_index_table_swap_for_keypair(wg_index_table_t *table, uint32_t index,
                                     void *keypair);

/*
 * Look up an entry by index and copy it into *out.
 * Returns true if found, false if not.
 * Thread-safe: acquires read lock internally.
 */
bool wg_index_table_lookup_copy(wg_index_table_t *table, uint32_t index,
                                wg_index_entry_t *out);

/*
 * Look up a keypair entry by index, atomically incrementing the keypair's
 * refcount before returning. This prevents use-after-free when the entry
 * is deleted concurrently.
 *
 * On success: out->data has an owned reference (caller must keypair_put).
 * On failure (not found, not KEYPAIR type, or refcount was 0): returns false.
 *
 * keypair_get_fn: function pointer to atomically increment refcount.
 *                 Must return non-NULL on success, NULL if object is dead.
 */
typedef void *(*wg_keypair_get_fn)(void *kp);

bool wg_index_table_lookup_keypair(wg_index_table_t *table, uint32_t index,
                                   wg_index_entry_t *out, wg_keypair_get_fn get_fn);

/*
 * Remove an entry by index.
 */
void wg_index_table_delete(wg_index_table_t *table, uint32_t index);

/*
 * Remove every entry that points at `peer`. Used when a peer is removed,
 * to catch indices its handshake and keypair slots no longer track.
 * Scans the whole table.
 */
void wg_index_table_delete_peer(wg_index_table_t *table, const void *peer);

#endif /* WG_INDEXTABLE_H */

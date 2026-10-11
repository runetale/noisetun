/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Index table: open-addressing hash table (linear probing).
 *
 * Reference: wireguard-go/device/indextable.go
 */

#include "wg_indextable.h"

#include "wg_compiler.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/* Initial capacity (must be power of 2). */
#define WG_INDEX_TABLE_INITIAL_CAP 64

/* Load factor threshold: resize when count > capacity * 3/4. */
#define WG_INDEX_TABLE_LOAD_NUM 3
#define WG_INDEX_TABLE_LOAD_DEN 4

/* ────────────────────────────────────────
 * Internal helpers
 * ──────────────────────────────────────── */

static inline size_t slot_for(uint32_t index, size_t mask)
{
    /* Indices are random and uniformly distributed, so the low bits
     * are as good a hash as any. */
    return (size_t)index & mask;
}

static inline bool slot_is_empty(const wg_index_entry_t *s)
{
    return s->type == WG_INDEX_ENTRY_EMPTY;
}

/*
 * Find the slot containing `index`, or the first empty slot.
 * Caller must ensure capacity > count (i.e. there is at least one empty slot).
 */
static wg_index_entry_t *find_slot(wg_index_entry_t *slots, size_t capacity,
                                   uint32_t index)
{
    size_t mask = capacity - 1;
    size_t i = slot_for(index, mask);
    /* P2-16: guard against full table — loop at most `capacity` times. */
    for (size_t n = 0; n < capacity; n++) {
        wg_index_entry_t *s = &slots[i];
        if (wg_likely(s->index == index) || wg_unlikely(slot_is_empty(s)))
            return s;
        i = (i + 1) & mask;
    }
    /* Table is completely full (should not happen with load factor < 1). */
    return NULL;
}

/*
 * Grow the table to double its capacity and rehash all entries.
 * Called with write lock held.
 */
static wg_error_t table_grow(wg_index_table_t *table)
{
    size_t new_cap = table->capacity * 2;
    wg_index_entry_t *new_slots = calloc(new_cap, sizeof(wg_index_entry_t));
    if (!new_slots)
        return WG_ERR_NO_MEMORY;

    /* Rehash existing entries (early exit once all moved). */
    size_t moved = 0;
    for (size_t i = 0; i < table->capacity && moved < table->count; i++) {
        wg_index_entry_t *old = &table->slots[i];
        if (slot_is_empty(old))
            continue;
        wg_index_entry_t *dst = find_slot(new_slots, new_cap, old->index);
        if (dst)
            *dst = *old;
        moved++;
    }

    free(table->slots);
    table->slots = new_slots;
    table->capacity = new_cap;
    return WG_OK;
}

/*
 * Repair the table after a deletion (linear probing backward shift).
 * Called with write lock held. `hole` is the index of the just-emptied slot.
 */
static void table_repair(wg_index_table_t *table, size_t hole)
{
    size_t mask = table->capacity - 1;
    size_t i = (hole + 1) & mask;
    for (;;) {
        wg_index_entry_t *s = &table->slots[i];
        if (slot_is_empty(s))
            break;
        size_t natural = slot_for(s->index, mask);
        /* Check if `s` would prefer to be at `hole`.
         * This handles the wrap-around case correctly. */
        bool should_move;
        if (hole <= i)
            should_move = (natural <= hole || natural > i);
        else
            should_move = (natural <= hole && natural > i);
        if (should_move) {
            table->slots[hole] = *s;
            s->type = WG_INDEX_ENTRY_EMPTY;
            hole = i;
        }
        i = (i + 1) & mask;
    }
}

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_index_table_init(wg_index_table_t *table)
{
    table->slots = calloc(WG_INDEX_TABLE_INITIAL_CAP, sizeof(wg_index_entry_t));
    if (!table->slots)
        return WG_ERR_NO_MEMORY;
    table->capacity = WG_INDEX_TABLE_INITIAL_CAP;
    table->count = 0;
    pthread_rwlock_init(&table->lock, NULL);
    return WG_OK;
}

void wg_index_table_destroy(wg_index_table_t *table)
{
    pthread_rwlock_destroy(&table->lock);
    free(table->slots);
    table->slots = NULL;
    table->capacity = 0;
    table->count = 0;
}

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

wg_error_t wg_index_table_new_index(wg_index_table_t *table, void *peer, void *handshake,
                                    uint32_t *index_out)
{
    /*
     * Double-check lock pattern (matches wireguard-go NewIndexForHandshake):
     *   1. Generate random index
     *   2. RLock: check if used → if so, retry
     *   3. WLock: double-check + insert
     */
    for (;;) {
        uint32_t index;
        randombytes_buf(&index, sizeof(index));

        /* Fast check under read lock. */
        pthread_rwlock_rdlock(&table->lock);
        wg_index_entry_t *s = find_slot(table->slots, table->capacity, index);
        bool used = (s == NULL) || !slot_is_empty(s);
        pthread_rwlock_unlock(&table->lock);

        if (used)
            continue;

        /* Verify under write lock and insert. */
        pthread_rwlock_wrlock(&table->lock);

        /* Grow if needed. */
        if (table->count * WG_INDEX_TABLE_LOAD_DEN >=
            table->capacity * WG_INDEX_TABLE_LOAD_NUM) {
            wg_error_t err = table_grow(table);
            if (err != WG_OK) {
                pthread_rwlock_unlock(&table->lock);
                return err;
            }
        }

        s = find_slot(table->slots, table->capacity, index);
        if (s == NULL || !slot_is_empty(s)) {
            /* Table full or stolen between RLock and WLock — retry. */
            pthread_rwlock_unlock(&table->lock);
            continue;
        }

        s->index = index;
        s->type = WG_INDEX_ENTRY_HANDSHAKE;
        s->peer = peer;
        s->data = handshake;
        table->count++;

        pthread_rwlock_unlock(&table->lock);

        *index_out = index;
        return WG_OK;
    }
}

void wg_index_table_swap_for_keypair(wg_index_table_t *table, uint32_t index,
                                     void *keypair)
{
    pthread_rwlock_wrlock(&table->lock);
    wg_index_entry_t *s = find_slot(table->slots, table->capacity, index);
    /* Only a pending handshake: if the entry was deleted meanwhile (the
     * peer being removed), the index may already belong to someone else. */
    if (s && s->type == WG_INDEX_ENTRY_HANDSHAKE && s->index == index) {
        s->type = WG_INDEX_ENTRY_KEYPAIR;
        s->data = keypair;
    }
    pthread_rwlock_unlock(&table->lock);
}

bool wg_index_table_lookup_copy(wg_index_table_t *table, uint32_t index,
                                wg_index_entry_t *out)
{
    pthread_rwlock_rdlock(&table->lock);
    wg_index_entry_t *s = find_slot(table->slots, table->capacity, index);
    bool found = s && !slot_is_empty(s) && s->index == index;
    if (found)
        *out = *s;
    pthread_rwlock_unlock(&table->lock);
    return found;
}

bool wg_index_table_lookup_keypair(wg_index_table_t *table, uint32_t index,
                                   wg_index_entry_t *out, wg_keypair_get_fn get_fn)
{
    pthread_rwlock_rdlock(&table->lock);
    wg_index_entry_t *s = find_slot(table->slots, table->capacity, index);
    bool found = s && !slot_is_empty(s) && s->index == index;
    if (found) {
        if (s->type != WG_INDEX_ENTRY_KEYPAIR || !s->data) {
            found = false;
        } else {
            void *ref = get_fn(s->data);
            if (!ref) {
                found = false;
            } else {
                *out = *s;
                out->data = ref;
            }
        }
    }
    pthread_rwlock_unlock(&table->lock);
    return found;
}

void wg_index_table_delete(wg_index_table_t *table, uint32_t index)
{
    pthread_rwlock_wrlock(&table->lock);
    wg_index_entry_t *s = find_slot(table->slots, table->capacity, index);
    if (s && !slot_is_empty(s) && s->index == index) {
        size_t pos = (size_t)(s - table->slots);
        s->type = WG_INDEX_ENTRY_EMPTY;
        s->peer = NULL;
        s->data = NULL;
        table->count--;
        table_repair(table, pos);
    }
    pthread_rwlock_unlock(&table->lock);
}

void wg_index_table_delete_peer(wg_index_table_t *table, const void *peer)
{
    pthread_rwlock_wrlock(&table->lock);
    for (size_t i = 0; i < table->capacity;) {
        wg_index_entry_t *s = &table->slots[i];
        if (slot_is_empty(s) || s->peer != peer) {
            i++;
            continue;
        }
        s->type = WG_INDEX_ENTRY_EMPTY;
        s->peer = NULL;
        s->data = NULL;
        table->count--;
        /* The repair may move a later entry into slot i: look at it again.
         * Entries only move back towards the hole, so none is skipped. */
        table_repair(table, i);
    }
    pthread_rwlock_unlock(&table->lock);
}

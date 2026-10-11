/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Session keypair management.
 *
 * Reference: wireguard-go/device/noise-protocol.go (BeginSymmetricSession)
 */

#include "wg_session.h"

#include "../crypto/wg_crypto.h"
#include "../replay/wg_replay.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Internal: allocate and initialize a keypair
 * ──────────────────────────────────────── */
static wg_noise_keypair_t *keypair_alloc(void)
{
    wg_noise_keypair_t *kp = malloc(sizeof(*kp));
    if (!kp)
        return NULL;
    *kp = (wg_noise_keypair_t){0};
    atomic_init(&kp->refcount, 1);
    kp->internal_id = atomic_fetch_add(&wg_noise_keypair_counter, 1) + 1;
    return kp;
}

/* Helper: delete a keypair from index table and release reference. */
static void keypair_delete(wg_index_table_t *table, wg_noise_keypair_t *kp)
{
    if (!kp)
        return;
    wg_index_table_delete(table, kp->local_index);
    wg_noise_keypair_put(kp);
}

/* ────────────────────────────────────────
 * wg_begin_symmetric_session
 * ──────────────────────────────────────── */
wg_error_t wg_begin_symmetric_session(wg_noise_handshake_t *hs, wg_noise_keypairs_t *kps,
                                      wg_index_table_t *table)
{
    bool is_initiator;

    /* ── 1. Derive keys based on handshake state ── */
    pthread_rwlock_wrlock(&hs->lock);

    wg_noise_keypair_t *kp = keypair_alloc();
    if (!kp) {
        pthread_rwlock_unlock(&hs->lock);
        return WG_ERR_NO_MEMORY;
    }

    if (hs->pending.state == WG_HANDSHAKE_CONSUMED_RESPONSE) {
        is_initiator = true;
    } else if (hs->pending.state == WG_HANDSHAKE_CREATED_RESPONSE) {
        is_initiator = false;
    } else {
        pthread_rwlock_unlock(&hs->lock);
        free(kp);
        return WG_ERR_HANDSHAKE_STATE;
    }

    /* ── 2. Fill keypair fields ── */
    wg_noise_keypair_derive(kp, hs->pending.chaining_key, is_initiator);
    atomic_init(&kp->sending_counter, 0);
    wg_replay_counter_init(&kp->receiving_counter);
    kp->local_index = hs->local_index;
    kp->remote_index = hs->pending.remote_index;

    /* ── 3. Wipe the finished handshake (state becomes ZEROED) ── */
    wg_secure_zero(&hs->pending, sizeof(hs->pending));

    uint32_t local_index = hs->local_index;
    hs->local_index = 0;

    pthread_rwlock_unlock(&hs->lock);

    /* ── 4. Remap index: handshake → keypair ── */
    wg_index_table_swap_for_keypair(table, local_index, kp);

    /* ── 5. Rotate keypairs (matches wireguard-go logic) ──
     *
     * Safety: the gap between releasing hs->lock and acquiring kps->lock
     * is safe because old_previous/current/next are read INSIDE kps->lock
     * (below), not carried across the gap.  Any concurrent rotation by
     * another thread is serialised by kps->lock, so we always see a
     * consistent snapshot of the three pointers. */
    pthread_mutex_lock(&kps->lock);

    wg_noise_keypair_t *old_previous =
        atomic_load_explicit(&kps->previous, memory_order_relaxed);
    wg_noise_keypair_t *old_next = atomic_load_explicit(&kps->next, memory_order_relaxed);
    wg_noise_keypair_t *old_current =
        atomic_load_explicit(&kps->current, memory_order_relaxed);

    if (is_initiator) {
        if (old_next != NULL) {
            atomic_store_explicit(&kps->next, NULL, memory_order_relaxed);
            atomic_store_explicit(&kps->previous, old_next, memory_order_relaxed);
            /* old_current will be deleted below */
        } else {
            atomic_store_explicit(&kps->previous, old_current, memory_order_relaxed);
            old_current = NULL; /* don't delete — it's now previous */
        }
        /* Relaxed: whoever takes a reference to a slot's keypair holds
         * kps->lock (wg_noise_keypairs_get_current), which orders kp's
         * contents before them. */
        atomic_store_explicit(&kps->current, kp, memory_order_relaxed);
    } else {
        atomic_store_explicit(&kps->next, kp, memory_order_relaxed);
        atomic_store_explicit(&kps->previous, NULL, memory_order_relaxed);
        /* old_current stays — old_next and old_previous will be deleted */
        old_current = NULL;
    }

    pthread_mutex_unlock(&kps->lock);

    /* Release old keypairs outside the lock. */
    if (is_initiator) {
        keypair_delete(table, old_previous);
        keypair_delete(table, old_current);
    } else {
        keypair_delete(table, old_next);
        keypair_delete(table, old_previous);
    }

    return WG_OK;
}

/* ────────────────────────────────────────
 * Rekey judgment helpers
 * ──────────────────────────────────────── */

bool wg_keypair_needs_rekey(wg_noise_keypair_t *kp)
{
    if (!kp || !kp->has_keys)
        return true;

    /* Counter approaching limit? */
    uint64_t counter = atomic_load_explicit(&kp->sending_counter, memory_order_relaxed);
    if (counter >= WG_REKEY_AFTER_MESSAGES)
        return true;

    /* Key age exceeded? */
    uint64_t age_ns = wg_mono_ns() - kp->birthdate_ns;
    if (age_ns >= WG_REKEY_AFTER_TIME_NS)
        return true;

    return false;
}

bool wg_keypair_is_expired(const wg_noise_keypair_t *kp)
{
    if (!kp)
        return true;

    /* Both keys are derived together, so one age covers both directions.
     * A keypair without keys counts as expired. */
    if (!kp->has_keys)
        return true;
    if (wg_mono_ns() - kp->birthdate_ns >= WG_REJECT_AFTER_TIME_NS)
        return true;

    return false;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Transport keypairs: derivation at the end of a handshake, reference
 * counting, and the three slots a peer keeps.
 *
 * A peer holds up to three keypairs. current is the one packets are sent
 * with. next is a keypair from a handshake this side answered: it is not
 * used for sending until the initiator proves it has the keys, by sending
 * a transport packet with it. previous keeps
 * the keypair current replaced, for packets that were already in flight.
 */

#include "wg_noise.h"

#include <stdlib.h>
#include <string.h>

_Atomic uint64_t wg_noise_keypair_counter = 0;

void wg_noise_keypair_derive(wg_noise_keypair_t *kp, const uint8_t ck[WG_NOISE_HASH_LEN],
                             bool initiator)
{
    /* The first KDF2 output is the initiator's sending key. */
    uint8_t *first = initiator ? kp->sending_key : kp->receiving_key;
    uint8_t *second = initiator ? kp->receiving_key : kp->sending_key;

    wg_kdf2(first, second, ck, WG_NOISE_HASH_LEN, NULL, 0);
    kp->birthdate_ns = wg_mono_ns();
    kp->i_am_initiator = initiator;
    kp->has_keys = true;
}

/* ════════════════════════════════════════
 * Reference counting
 * ════════════════════════════════════════ */

wg_noise_keypair_t *wg_noise_keypair_get(wg_noise_keypair_t *kp)
{
    if (kp)
        atomic_fetch_add(&kp->refcount, 1);
    return kp;
}

void wg_noise_keypair_put(wg_noise_keypair_t *kp)
{
    if (!kp || atomic_fetch_sub(&kp->refcount, 1) != 1)
        return;
    /* That was the last reference. */
    wg_secure_zero(kp, sizeof(*kp));
    free(kp);
}

/* ════════════════════════════════════════
 * The per-peer slots
 * ════════════════════════════════════════ */

void wg_noise_keypairs_init(wg_noise_keypairs_t *kps)
{
    memset(kps, 0, sizeof(*kps));
    pthread_mutex_init(&kps->lock, NULL);
}

wg_noise_keypair_t *wg_noise_keypairs_get_current(wg_noise_keypairs_t *kps)
{
    wg_noise_keypair_t *kp;

    pthread_mutex_lock(&kps->lock);
    kp = wg_noise_keypair_get(atomic_load_explicit(&kps->current, memory_order_relaxed));
    pthread_mutex_unlock(&kps->lock);
    return kp;
}

void wg_noise_keypairs_clear(wg_noise_keypairs_t *kps)
{
    wg_noise_keypair_t *dropped[3];

    pthread_mutex_lock(&kps->lock);
    dropped[0] = atomic_exchange(&kps->current, NULL);
    dropped[1] = atomic_exchange(&kps->previous, NULL);
    dropped[2] = atomic_exchange(&kps->next, NULL);
    pthread_mutex_unlock(&kps->lock);

    /* The last put frees the keypair; keep that out of the lock. */
    for (size_t i = 0; i < sizeof(dropped) / sizeof(dropped[0]); i++)
        wg_noise_keypair_put(dropped[i]);
}

/*
 * Called for each authenticated transport packet. If it was decrypted
 * with the next keypair, the initiator has confirmed the handshake:
 * next becomes current, current becomes previous, and the old previous
 * is dropped. Returns whether that happened.
 */
bool wg_noise_received_with_keypair(wg_noise_keypairs_t *kps,
                                    wg_noise_keypair_t *received, wg_index_table_t *table)
{
    wg_noise_keypair_t *retired;

    /* Almost every packet uses current; skip the lock for those. */
    if (atomic_load_explicit(&kps->next, memory_order_acquire) != received)
        return false;

    pthread_mutex_lock(&kps->lock);
    if (atomic_load_explicit(&kps->next, memory_order_relaxed) != received) {
        /* Another thread promoted it first. */
        pthread_mutex_unlock(&kps->lock);
        return false;
    }
    /* Relaxed stores: anything that takes a reference from a slot holds
     * kps->lock (wg_noise_keypairs_get_current). */
    retired = atomic_exchange_explicit(
        &kps->previous, atomic_load_explicit(&kps->current, memory_order_relaxed),
        memory_order_relaxed);
    atomic_store_explicit(&kps->current, received, memory_order_relaxed);
    atomic_store_explicit(&kps->next, NULL, memory_order_relaxed);
    pthread_mutex_unlock(&kps->lock);

    if (retired) {
        /* The index table holds no reference: remove the entry before the
         * put, or a packet for that index could reach a freed keypair. */
        wg_index_table_delete(table, retired->local_index);
        wg_noise_keypair_put(retired);
    }
    return true;
}

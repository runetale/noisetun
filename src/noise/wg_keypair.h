/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Transport keypairs (wg_keypair.c).
 */

#ifndef WG_KEYPAIR_H
#define WG_KEYPAIR_H

#include "../peer/wg_indextable.h"
#include "../replay/wg_replay.h"
#include "wg_constants.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * The two transport keys from one completed handshake, with what goes
 * along with them: the counter used as the sending nonce, the receive
 * window, and the indices packets carry to find this keypair.
 *
 * Keypairs live on the heap and are reference counted. Workers and the
 * index table keep using one after rotation has moved it out of the
 * peer's slots; the last wg_noise_keypair_put() wipes and frees it.
 */
typedef struct wg_noise_keypair {
    uint8_t sending_key[WG_NOISE_SYMMETRIC_KEY_LEN];
    _Atomic uint64_t sending_counter;
    uint8_t receiving_key[WG_NOISE_SYMMETRIC_KEY_LEN];
    wg_replay_counter_t receiving_counter;

    uint64_t birthdate_ns; /* wg_mono_ns() when the keys were derived */
    bool has_keys;         /* set by wg_noise_keypair_derive() */
    bool i_am_initiator;
    uint32_t local_index;
    uint32_t remote_index;

    _Atomic int refcount;
    uint64_t internal_id;
} wg_noise_keypair_t;

/*
 * A peer's keypairs. current sends. next comes from a handshake this side
 * answered, and becomes current once the initiator uses it. previous is
 * the keypair current replaced, kept for packets still in flight.
 *
 * lock serialises changes to the slots. Taking a reference to a slot's
 * keypair also needs it (wg_noise_keypairs_get_current): a change drops
 * the slot's reference, which can free the keypair. The slots are atomic
 * so that a pointer can be compared without the lock.
 */
typedef struct {
    _Atomic(wg_noise_keypair_t *) current;
    _Atomic(wg_noise_keypair_t *) previous;
    _Atomic(wg_noise_keypair_t *) next;
    pthread_mutex_t lock;
} wg_noise_keypairs_t;

extern _Atomic uint64_t wg_noise_keypair_counter;

/*
 * Fill in kp's transport keys from the final chaining key:
 *   (T_send, T_recv) = KDF2(chaining_key, [empty])
 * seen from the initiator; the responder uses them the other way round.
 */
void wg_noise_keypair_derive(wg_noise_keypair_t *kp, const uint8_t ck[WG_NOISE_HASH_LEN],
                             bool initiator);

wg_noise_keypair_t *wg_noise_keypair_get(wg_noise_keypair_t *kp);
void wg_noise_keypair_put(wg_noise_keypair_t *kp);

void wg_noise_keypairs_init(wg_noise_keypairs_t *kps);
void wg_noise_keypairs_clear(wg_noise_keypairs_t *kps);

/*
 * Take a reference to the current keypair, or return NULL if there is
 * none. The caller must wg_noise_keypair_put() it. Reads under kps->lock:
 * a rotation may drop the slot's reference, and free the keypair, right
 * after an unlocked load of the pointer (#140).
 */
wg_noise_keypair_t *wg_noise_keypairs_get_current(wg_noise_keypairs_t *kps);

/*
 * For each authenticated transport packet: if it came under the next
 * keypair, promote next to current. Returns whether that happened.
 */
bool wg_noise_received_with_keypair(wg_noise_keypairs_t *kps,
                                    wg_noise_keypair_t *received,
                                    wg_index_table_t *table);

#endif /* WG_KEYPAIR_H */

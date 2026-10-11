/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * The WireGuard handshake (wg_noise.c). Transport keypairs are in
 * wg_keypair.h.
 */

#ifndef WG_NOISE_INTERNAL_H
#define WG_NOISE_INTERNAL_H

#include "../crypto/wg_crypto.h"
#include "wg_constants.h"
#include "wg_error.h"
#include "wg_messages.h"
#include "wg_types.h"
#include "wg_keypair.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>

/* The device's own key pair. */
typedef struct {
    uint8_t static_public[WG_KEY_LEN];
    uint8_t static_private[WG_KEY_LEN];
    pthread_rwlock_t lock;
    bool has_identity;
} wg_noise_static_identity_t;

/* Where the handshake in progress stands, named after the last message
 * this side created or consumed. */
typedef enum {
    WG_HANDSHAKE_ZEROED,
    WG_HANDSHAKE_CREATED_INITIATION,
    WG_HANDSHAKE_CONSUMED_INITIATION,
    WG_HANDSHAKE_CREATED_RESPONSE,
    WG_HANDSHAKE_CONSUMED_RESPONSE,
} wg_handshake_state_t;

/*
 * The handshake in progress: the Noise transcript (ck, h), the ephemeral
 * keys, and the index the peer chose. It is wiped as a whole when the
 * handshake completes or is abandoned; all zero is WG_HANDSHAKE_ZEROED.
 */
typedef struct {
    wg_handshake_state_t state;
    uint32_t remote_index;
    uint8_t chaining_key[WG_NOISE_HASH_LEN];
    uint8_t hash[WG_NOISE_HASH_LEN];
    uint8_t ephemeral_private[WG_KEY_LEN];
    uint8_t remote_ephemeral[WG_KEY_LEN];
} wg_noise_pending_t;

/* Handshake state for one peer. lock covers every field. */
typedef struct {
    pthread_rwlock_t lock;
    wg_noise_static_identity_t *static_identity;

    /* The peer, as configured. precomputed_static_static is DH(s, rs),
     * all zero while there is no local key or rs is unusable. */
    uint8_t remote_static[WG_KEY_LEN];
    uint8_t preshared_key[WG_NOISE_SYMMETRIC_KEY_LEN];
    uint8_t precomputed_static_static[WG_KEY_LEN];

    /* Kept from one handshake to the next. latest_timestamp is that of
     * the newest initiation accepted, for replay protection. local_index
     * is set by the caller, from the index table, before a message is
     * created. */
    uint8_t latest_timestamp[WG_TIMESTAMP_LEN];
    uint64_t last_initiation_consumption_ns;
    uint64_t last_sent_handshake_ns; /* monotonic, for rate limiting */
    uint32_t local_index;

    wg_noise_pending_t pending;
} wg_noise_handshake_t;

/* ────────────────────────────────────────
 * Pre-computed init hash and chaining key
 * (computed once at wg_noise_module_init)
 * ──────────────────────────────────────── */
extern uint8_t wg_noise_handshake_init_hash[WG_NOISE_HASH_LEN];
extern uint8_t wg_noise_handshake_init_chaining_key[WG_NOISE_HASH_LEN];

/* ────────────────────────────────────────
 * Module init
 * ──────────────────────────────────────── */
void wg_noise_module_init(void);

/* ────────────────────────────────────────
 * Static identity
 * ──────────────────────────────────────── */
void wg_noise_static_identity_init(wg_noise_static_identity_t *si);
void wg_noise_static_identity_set_private_key(wg_noise_static_identity_t *si,
                                              const uint8_t private_key[WG_KEY_LEN]);

/* ────────────────────────────────────────
 * Handshake lifecycle
 * ──────────────────────────────────────── */
void wg_noise_handshake_init(wg_noise_handshake_t *hs, wg_noise_static_identity_t *si,
                             const uint8_t peer_public_key[WG_KEY_LEN],
                             const uint8_t *peer_preshared_key);

void wg_noise_handshake_clear(wg_noise_handshake_t *hs);

/* Like wg_noise_handshake_clear, for a caller that already holds hs->lock
 * for writing. The rwlock is not recursive: locking it again from the same
 * thread fails, and the unlocks that follow corrupt it. */
void wg_noise_handshake_clear_locked(wg_noise_handshake_t *hs);

void wg_noise_precompute_static_static(wg_noise_handshake_t *hs);

/* ────────────────────────────────────────
 * Handshake message create / consume (HS-1/2/3)
 * ──────────────────────────────────────── */

/*
 * Create Handshake Initiation (148 bytes).
 * Noise pattern: -> e, es, s, ss, {t}
 *
 * hs->local_index must be set first (from the index table).
 * On success the handshake state advances to CREATED_INITIATION.
 */
wg_error_t wg_noise_handshake_create_initiation(wg_message_initiation_t *dst,
                                                wg_noise_handshake_t *hs);

/*
 * Consume Handshake Initiation received from a peer (legacy, 2-pass).
 *
 * Only tests call this; the device uses the two phases below. It does not
 * check the sender's static key against hs->remote_static: tests pass a
 * handshake with no peer key and read the key back from
 * decrypted_static_out.
 *
 * On success:
 *   - hs state advances to CONSUMED_INITIATION
 *   - decrypted_static_out is filled with the initiator's static public key
 *     (caller uses this to look up the peer)
 *   - The caller must then call wg_noise_precompute_static_static() if
 *     the peer's handshake was freshly initialised with the discovered key.
 */
wg_error_t
wg_noise_handshake_consume_initiation(wg_noise_handshake_t *hs,
                                      const wg_message_initiation_t *src,
                                      uint8_t decrypted_static_out[WG_KEY_LEN]);

/*
 * Intermediate state for 1-pass consume_initiation.
 * Passed from Phase 1 (decrypt static) to Phase 2 (commit to peer).
 * Contains sensitive crypto material — must be zeroed after use.
 */
typedef struct {
    uint8_t hash[WG_NOISE_HASH_LEN];
    uint8_t chaining_key[WG_NOISE_HASH_LEN];
    uint8_t remote_ephemeral[WG_KEY_LEN];
    uint8_t decrypted_static[WG_KEY_LEN];
    uint32_t sender_index;
} wg_initiation_half_t;

/*
 * Phase 1: Decrypt initiator's static public key using device identity.
 *
 * Performs: init hash → e → es DH → s decrypt.
 * The result (decrypted_static) is used by the caller for peer lookup.
 * On success, *half is populated with intermediate crypto state.
 */
wg_error_t
wg_noise_consume_initiation_decrypt_static(wg_noise_static_identity_t *identity,
                                           const wg_message_initiation_t *src,
                                           wg_initiation_half_t *half);

/*
 * Phase 2: Commit initiation to peer's handshake state.
 *
 * Performs: ss DH (using peer's precomputed_static_static) → timestamp
 * decrypt → replay check → commit.
 * Caller must zero *half after this call returns (success or failure).
 */
wg_error_t wg_noise_consume_initiation_commit(wg_noise_handshake_t *hs,
                                              const wg_message_initiation_t *src,
                                              wg_initiation_half_t *half);

/*
 * Create Handshake Response (92 bytes).
 * Noise pattern: <- e, ee, se, psk, {}
 *
 * Must be called after consume_initiation (state == CONSUMED_INITIATION).
 * On success the handshake state advances to CREATED_RESPONSE.
 */
wg_error_t wg_noise_handshake_create_response(wg_message_response_t *dst,
                                              wg_noise_handshake_t *hs);

/*
 * Consume Handshake Response received from a peer.
 *
 * Must be called after create_initiation (state == CREATED_INITIATION).
 * On success the handshake state advances to CONSUMED_RESPONSE.
 */
wg_error_t wg_noise_handshake_consume_response(wg_noise_handshake_t *hs,
                                               const wg_message_response_t *src);

/* ────────────────────────────────────────
 * Monotonic time helper
 * ──────────────────────────────────────── */
uint64_t wg_mono_ns(void);

#endif /* WG_NOISE_INTERNAL_H */

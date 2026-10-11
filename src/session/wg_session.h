/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Session keypair management: derive transport keys from handshake,
 * rotate keypairs, and rekey judgment.
 *
 * Reference: wireguard-go/device/noise-protocol.go (BeginSymmetricSession)
 *            wireguard-go/device/keypair.go
 */

#ifndef WG_SESSION_H
#define WG_SESSION_H

#include "../noise/wg_noise.h"
#include "../peer/wg_indextable.h"
#include "wg_error.h"

#include <stdbool.h>

/*
 * Derive transport keys from a completed handshake and install a new keypair.
 *
 * This is the C equivalent of wireguard-go's Peer.BeginSymmetricSession().
 *
 * On entry:
 *   hs       – handshake in state CONSUMED_RESPONSE (initiator)
 *              or CREATED_RESPONSE (responder)
 *   kps      – the peer's keypair set (current/previous/next)
 *   table    – the device's index table (for SwapIndexForKeypair)
 *
 * On success (WG_OK):
 *   - A new keypair is created and installed into kps
 *     (initiator → current, responder → next)
 *   - The handshake's chaining_key, hash, ephemeral_private are zeroed
 *   - The handshake state is set to ZEROED
 *   - The index table entry is swapped from handshake to keypair
 *   - Old keypairs are freed via wg_noise_keypair_put
 *
 * Errors:
 *   WG_ERR_HANDSHAKE_STATE – handshake not in a valid state for key derivation
 *   WG_ERR_NO_MEMORY       – keypair allocation failed
 */
wg_error_t wg_begin_symmetric_session(wg_noise_handshake_t *hs, wg_noise_keypairs_t *kps,
                                      wg_index_table_t *table);

/*
 * Check if the sending keypair needs rekeying.
 *
 * Returns true if:
 *   - sending_counter >= REKEY_AFTER_MESSAGES
 *   - sending key birthdate exceeds REKEY_AFTER_TIME
 */
bool wg_keypair_needs_rekey(wg_noise_keypair_t *kp);

/*
 * Check if a keypair has expired and should be rejected.
 *
 * Returns true if:
 *   - birthdate exceeds REJECT_AFTER_TIME
 */
bool wg_keypair_is_expired(const wg_noise_keypair_t *kp);

#endif /* WG_SESSION_H */

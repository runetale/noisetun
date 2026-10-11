/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Transport Data encrypt / decrypt (message type 0x04).
 *
 * Reference: wireguard-go/device/send.go (encrypt path)
 *            wireguard-go/device/receive.go (decrypt path)
 */

#ifndef WG_TRANSPORT_H
#define WG_TRANSPORT_H

#include "../noise/wg_noise.h"
#include "wg_error.h"
#include "wg_messages.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Encrypt a plaintext IP packet into a WireGuard transport message.
 *
 * On entry:
 *   kp            – active keypair (sending key + counter)
 *   dst           – output buffer, must hold at least
 *                   WG_MESSAGE_TRANSPORT_HEADER + src_len + WG_AEAD_TAG_SIZE
 *   dst_cap       – capacity of dst in bytes
 *   src           – plaintext IP packet (may be NULL if src_len == 0 for keepalive)
 *   src_len       – plaintext length in bytes
 *
 * On success (WG_OK):
 *   *dst_len      – total bytes written to dst (header + ciphertext + tag)
 *   kp->sending_counter is atomically incremented
 *
 * Errors:
 *   WG_ERR_COUNTER_OVERFLOW  – nonce exhausted (>= REJECT_AFTER_MESSAGES)
 *   WG_ERR_KEYPAIR_EXPIRED   – sending key not valid
 *   WG_ERR_ENCRYPT           – AEAD seal failed
 */
wg_error_t wg_transport_encrypt(wg_noise_keypair_t *kp, uint8_t *dst, size_t *dst_len,
                                size_t dst_cap, const uint8_t *src, size_t src_len);

/*
 * Decrypt a WireGuard transport message into plaintext.
 *
 * On entry:
 *   kp            – keypair whose receiving key matches the packet
 *   dst           – output buffer, must hold at least
 *                   msg_len - WG_MESSAGE_TRANSPORT_HEADER - WG_AEAD_TAG_SIZE
 *   dst_cap       – capacity of dst in bytes
 *   src           – raw transport message (header + ciphertext + tag)
 *   src_len       – total message length in bytes
 *
 * On success (WG_OK):
 *   *dst_len      – plaintext bytes written to dst
 *
 * Errors:
 *   WG_ERR_TRANSPORT_DECRYPT – message too short or AEAD open failed
 *   WG_ERR_KEYPAIR_EXPIRED   – receiving key not valid
 *   WG_ERR_REPLAY            – counter failed anti-replay check
 */
wg_error_t wg_transport_decrypt(wg_noise_keypair_t *kp, uint8_t *dst, size_t *dst_len,
                                size_t dst_cap, const uint8_t *src, size_t src_len);

#endif /* WG_TRANSPORT_H */

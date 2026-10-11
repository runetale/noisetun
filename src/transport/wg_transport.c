/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Transport Data encrypt / decrypt (message type 0x04).
 *
 * Encrypt path:
 *   1. Atomically fetch-and-increment sending_counter
 *   2. Check counter < REJECT_AFTER_MESSAGES
 *   3. Build 16-byte header: type(4) + receiver_index(4) + counter(8)
 *   4. ChaCha20-Poly1305 seal(sending_key, counter, plaintext)
 *
 * Decrypt path:
 *   1. Parse 16-byte header: receiver_index + counter
 *   2. ChaCha20-Poly1305 open(receiving_key, counter, ciphertext)
 *   3. Validate counter via anti-replay window (only after AEAD proves authenticity)
 *
 * IMPORTANT: AEAD must be verified before updating the replay window.
 * Otherwise an attacker can send forged packets with arbitrary counters
 * to advance the window and cause legitimate packets to be rejected.
 *
 * Reference: wireguard-go/device/send.go
 *            wireguard-go/device/receive.go
 */

#include "wg_transport.h"

#include "../crypto/wg_crypto.h"
#include "../replay/wg_replay.h"

#include <stdatomic.h>
#include <string.h>

wg_error_t wg_transport_encrypt(wg_noise_keypair_t *kp, uint8_t *dst, size_t *dst_len,
                                size_t dst_cap, const uint8_t *src, size_t src_len)
{
    /* Validate sending key */
    if (!kp->has_keys)
        return WG_ERR_KEYPAIR_EXPIRED;

    /* Atomically claim a nonce */
    uint64_t counter =
        atomic_fetch_add_explicit(&kp->sending_counter, 1, memory_order_relaxed);
    if (counter >= WG_REJECT_AFTER_MESSAGES)
        return WG_ERR_COUNTER_OVERFLOW;

    /* Check output buffer capacity */
    size_t needed = WG_MESSAGE_TRANSPORT_HEADER + src_len + WG_AEAD_TAG_SIZE;
    if (dst_cap < needed)
        return WG_ERR_ENCRYPT;

    /* Build transport header (16 bytes) */
    wg_message_transport_t *hdr = (wg_message_transport_t *)dst;
    hdr->header.type = wg_htole32(WG_MESSAGE_TRANSPORT);
    hdr->receiver_index = wg_htole32(kp->remote_index);
    hdr->counter = wg_htole64(counter);

    /* Encrypt payload after the 16-byte header */
    uint8_t *ciphertext = dst + WG_MESSAGE_TRANSPORT_HEADER;
    size_t ct_len = 0;

    wg_error_t err = wg_aead_encrypt(ciphertext, &ct_len, src, src_len, NULL,
                                     0, /* no additional data */
                                     counter, kp->sending_key);
    if (err != WG_OK)
        return WG_ERR_ENCRYPT;

    *dst_len = WG_MESSAGE_TRANSPORT_HEADER + ct_len;
    return WG_OK;
}

wg_error_t wg_transport_decrypt(wg_noise_keypair_t *kp, uint8_t *dst, size_t *dst_len,
                                size_t dst_cap, const uint8_t *src, size_t src_len)
{
    /* Minimum: 16-byte header + 16-byte AEAD tag (empty keepalive) */
    if (src_len < WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE)
        return WG_ERR_TRANSPORT_DECRYPT;

    /* Validate receiving key */
    if (!kp->has_keys)
        return WG_ERR_KEYPAIR_EXPIRED;

    /* Parse header */
    const wg_message_transport_t *hdr = (const wg_message_transport_t *)src;
    uint64_t counter = wg_le64toh(hdr->counter);

    /* Decrypt first — AEAD tag proves authenticity.
     * Replay window must NOT be updated until AEAD succeeds,
     * otherwise forged packets can pollute the window (DoS). */
    const uint8_t *ciphertext = src + WG_MESSAGE_TRANSPORT_HEADER;
    size_t ct_len = src_len - WG_MESSAGE_TRANSPORT_HEADER;

    /* Check output buffer can hold plaintext (ciphertext - tag) */
    size_t pt_len = ct_len - WG_AEAD_TAG_SIZE;
    if (dst_cap < pt_len && pt_len > 0)
        return WG_ERR_TRANSPORT_DECRYPT;

    size_t decrypted_len = 0;
    wg_error_t err = wg_aead_decrypt(dst, &decrypted_len, ciphertext, ct_len, NULL,
                                     0, /* no additional data */
                                     counter, kp->receiving_key);
    if (err != WG_OK)
        return WG_ERR_TRANSPORT_DECRYPT;

    /* Anti-replay check (only after AEAD proves authenticity) */
    if (!wg_replay_counter_validate(&kp->receiving_counter, counter,
                                    WG_REJECT_AFTER_MESSAGES))
        return WG_ERR_REPLAY;

    *dst_len = decrypted_len;
    return WG_OK;
}

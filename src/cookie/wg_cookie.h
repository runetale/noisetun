/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Cookie mechanism for WireGuard DoS protection.
 *
 * Two components:
 *   CookieChecker   — receiver side: verify mac1/mac2, create cookie replies
 *   CookieGenerator — sender side: add mac1/mac2, consume cookie replies
 *
 * Reference: wireguard-go/device/cookie.go
 */

#ifndef WG_COOKIE_H
#define WG_COOKIE_H

#include "../crypto/wg_crypto.h"
#include "wg_constants.h"
#include "wg_error.h"
#include "wg_messages.h"
#include "wg_types.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Labels for key derivation
 * ──────────────────────────────────────── */
#define WG_LABEL_MAC1   "mac1----"
#define WG_LABEL_COOKIE "cookie--"

/* Cookie secret refresh interval: 2 minutes in nanoseconds */
#define WG_COOKIE_REFRESH_NS (120ULL * 1000000000ULL)

/* ────────────────────────────────────────
 * CookieChecker — receiver (responder) side
 *
 * Validates mac1/mac2 on incoming handshake messages
 * and creates cookie reply messages when under load.
 * ──────────────────────────────────────── */
typedef struct {
    uint8_t mac1_key[WG_NOISE_HASH_LEN];                /* BLAKE2s("mac1----" || pk) */
    uint8_t encryption_key[WG_NOISE_SYMMETRIC_KEY_LEN]; /* BLAKE2s("cookie--" ||
                                                           pk) */
    uint8_t secret[WG_NOISE_HASH_LEN];                  /* random, rotated every 2 min */
    uint64_t secret_set_ns;                             /* wg_mono_ns() when set */
    pthread_rwlock_t lock;
} wg_cookie_checker_t;

/* ────────────────────────────────────────
 * CookieGenerator — sender (initiator) side
 *
 * Adds mac1/mac2 to outgoing handshake messages
 * and consumes cookie reply messages.
 * ──────────────────────────────────────── */
typedef struct {
    uint8_t mac1_key[WG_NOISE_HASH_LEN];                /* BLAKE2s("mac1----" || pk) */
    uint8_t encryption_key[WG_NOISE_SYMMETRIC_KEY_LEN]; /* BLAKE2s("cookie--" ||
                                                           pk) */
    uint8_t cookie[WG_COOKIE_LEN];                      /* 16-byte cookie from reply */
    uint64_t cookie_set_ns;                             /* wg_mono_ns() when received */
    bool has_last_mac1;
    uint8_t last_mac1[WG_COOKIE_LEN]; /* last mac1 we sent */
    pthread_rwlock_t lock;
} wg_cookie_generator_t;

/* ────────────────────────────────────────
 * CookieChecker API
 * ──────────────────────────────────────── */

/*
 * Initialise checker with the local device's static public key.
 * Derives mac1_key and encryption_key.
 */
void wg_cookie_checker_init(wg_cookie_checker_t *cc,
                            const uint8_t public_key[WG_KEY_LEN]);

/*
 * Destroy checker: zero sensitive material and release the rwlock.
 */
void wg_cookie_checker_destroy(wg_cookie_checker_t *cc);

/*
 * Verify mac1 on an incoming handshake message.
 * msg/msg_len is the full serialised message (initiation or response).
 * Returns true if mac1 is valid.
 */
bool wg_cookie_checker_check_mac1(wg_cookie_checker_t *cc, const uint8_t *msg,
                                  size_t msg_len);

/*
 * Verify mac2 on an incoming handshake message.
 * src/src_len is the sender's network address (for per-source cookie).
 * Returns true if mac2 is valid and secret has not expired.
 */
bool wg_cookie_checker_check_mac2(wg_cookie_checker_t *cc, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *src, size_t src_len);

/*
 * Create a Cookie Reply message.
 * msg/msg_len is the received handshake message (for extracting mac1 as AD).
 * recv is the sender_index from the incoming message.
 * src/src_len is the sender's network address.
 */
wg_error_t wg_cookie_checker_create_reply(wg_cookie_checker_t *cc,
                                          wg_message_cookie_reply_t *reply,
                                          const uint8_t *msg, size_t msg_len,
                                          uint32_t recv, const uint8_t *src,
                                          size_t src_len);

/* ────────────────────────────────────────
 * CookieGenerator API
 * ──────────────────────────────────────── */

/*
 * Initialise generator with the remote peer's static public key.
 * Derives the same mac1_key and encryption_key as the peer's checker.
 */
void wg_cookie_generator_init(wg_cookie_generator_t *cg,
                              const uint8_t public_key[WG_KEY_LEN]);

/*
 * Destroy generator: zero sensitive material and release the rwlock.
 */
void wg_cookie_generator_destroy(wg_cookie_generator_t *cg);

/*
 * Compute and append mac1 (always) and mac2 (if cookie is valid)
 * to the last 32 bytes of a serialised handshake message.
 */
void wg_cookie_generator_add_macs(wg_cookie_generator_t *cg, uint8_t *msg,
                                  size_t msg_len);

/*
 * Consume (decrypt) a Cookie Reply message.
 * On success, stores the cookie for future mac2 computation.
 * Returns WG_OK on success, WG_ERR_COOKIE_INVALID on decryption failure,
 * or WG_ERR_HANDSHAKE_STATE if no prior mac1 was sent.
 */
wg_error_t wg_cookie_generator_consume_reply(wg_cookie_generator_t *cg,
                                             const wg_message_cookie_reply_t *reply);

/* ────────────────────────────────────────
 * Monotonic time (defined in wg_noise.c)
 * ──────────────────────────────────────── */
uint64_t wg_mono_ns(void);

#endif /* WG_COOKIE_H */

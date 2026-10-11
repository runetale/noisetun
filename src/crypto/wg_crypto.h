/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Cryptographic primitives for WireGuard Noise IKpsk2.
 *
 * Wraps libsodium where possible. BLAKE2s MAC (keyed, variable-length)
 * requires a custom implementation because libsodium only exposes
 * BLAKE2b — the WireGuard spec mandates BLAKE2s.
 *
 * Reference: WireGuard whitepaper section 5.4 (HASH, MAC, HMAC, KDF)
 *            wireguard-go/device/noise-helpers.go
 */

#ifndef WG_CRYPTO_H
#define WG_CRYPTO_H

#include "wg_constants.h"
#include "wg_error.h"
#include "wg_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * BLAKE2s (256-bit, keyed HMAC variant)
 *
 * libsodium has no BLAKE2s — we use a minimal
 * standalone implementation (RFC 7693).
 * ──────────────────────────────────────── */

#define WG_BLAKE2S_BLOCK_SIZE 64
#define WG_BLAKE2S_HASH_SIZE  32
#define WG_BLAKE2S_KEY_SIZE   32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[WG_BLAKE2S_BLOCK_SIZE];
    size_t buflen;
    size_t outlen;
} wg_blake2s_state_t;

void wg_blake2s_init(wg_blake2s_state_t *state, size_t outlen);
void wg_blake2s_init_key(wg_blake2s_state_t *state, size_t outlen, const uint8_t *key,
                         size_t keylen);
void wg_blake2s_update(wg_blake2s_state_t *state, const uint8_t *in, size_t inlen);
void wg_blake2s_final(wg_blake2s_state_t *state, uint8_t *out);

void wg_blake2s(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                const uint8_t *key, size_t keylen);

/* ────────────────────────────────────────
 * HMAC-BLAKE2s
 * ──────────────────────────────────────── */

void wg_hmac(uint8_t out[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *in, size_t inlen);

void wg_hmac2(uint8_t out[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
              const uint8_t *in0, size_t in0len, const uint8_t *in1, size_t in1len);

/* ────────────────────────────────────────
 * KDF (HKDF-BLAKE2s, WireGuard-specific 1/2/3 output)
 * ──────────────────────────────────────── */

void wg_kdf1(uint8_t t0[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen);

void wg_kdf2(uint8_t t0[WG_BLAKE2S_HASH_SIZE], uint8_t t1[WG_BLAKE2S_HASH_SIZE],
             const uint8_t *key, size_t keylen, const uint8_t *input, size_t inputlen);

void wg_kdf3(uint8_t t0[WG_BLAKE2S_HASH_SIZE], uint8_t t1[WG_BLAKE2S_HASH_SIZE],
             uint8_t t2[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen);

/* ────────────────────────────────────────
 * Noise protocol helpers: MixHash, MixKey
 * ──────────────────────────────────────── */

void wg_mix_hash(uint8_t hash[WG_BLAKE2S_HASH_SIZE], const uint8_t *data, size_t len);

void wg_mix_key(uint8_t ck[WG_BLAKE2S_HASH_SIZE], uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN],
                const uint8_t *data, size_t len);

/* ────────────────────────────────────────
 * X25519 (Curve25519 Diffie-Hellman)
 * Uses libsodium crypto_scalarmult_curve25519.
 * ──────────────────────────────────────── */

wg_error_t wg_x25519(uint8_t out[32], const uint8_t private_key[32],
                     const uint8_t public_key[32]);

void wg_x25519_public_key(uint8_t public_key[32], const uint8_t private_key[32]);

wg_error_t wg_x25519_generate_private(uint8_t private_key[32]);

void wg_x25519_clamp(uint8_t key[32]);

/* ────────────────────────────────────────
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 * Uses libsodium crypto_aead_chacha20poly1305_ietf_*.
 * ──────────────────────────────────────── */

wg_error_t wg_aead_encrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce, const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN]);

wg_error_t wg_aead_decrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce, const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN]);

/* ────────────────────────────────────────
 * XChaCha20-Poly1305 (for cookie encryption)
 * ──────────────────────────────────────── */

wg_error_t wg_xchacha20poly1305_encrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                                        size_t src_len, const uint8_t *ad, size_t ad_len,
                                        const uint8_t nonce[24], const uint8_t key[32]);

wg_error_t wg_xchacha20poly1305_decrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                                        size_t src_len, const uint8_t *ad, size_t ad_len,
                                        const uint8_t nonce[24], const uint8_t key[32]);

/* ────────────────────────────────────────
 * MAC (for mac1/mac2 in handshake messages)
 * ──────────────────────────────────────── */

void wg_mac(uint8_t dst[WG_COOKIE_LEN], const uint8_t *key, size_t keylen,
            const uint8_t *in, size_t inlen);

/* ────────────────────────────────────────
 * TAI64N timestamp
 * ──────────────────────────────────────── */

void wg_tai64n_now(uint8_t out[WG_TIMESTAMP_LEN]);
bool wg_tai64n_after(const uint8_t a[WG_TIMESTAMP_LEN],
                     const uint8_t b[WG_TIMESTAMP_LEN]);

/* ────────────────────────────────────────
 * Secure memory helpers
 * ──────────────────────────────────────── */

void wg_secure_zero(void *ptr, size_t len);

bool wg_is_zero(const uint8_t *buf, size_t len);

#endif /* WG_CRYPTO_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Cookie mechanism for WireGuard DoS protection.
 *
 * Implements CookieChecker (receiver) and CookieGenerator (sender).
 *
 * Reference: wireguard-go/device/cookie.go
 */

#include "wg_cookie.h"

#include <sodium.h>
#include <string.h>

/* ════════════════════════════════════════
 * Internal helpers
 * ════════════════════════════════════════ */

/*
 * Derive mac1_key and encryption_key from a static public key.
 * Both CookieChecker and CookieGenerator use the same derivation.
 *
 *   mac1_key       = BLAKE2s-256("mac1----" || public_key)
 *   encryption_key = BLAKE2s-256("cookie--" || public_key)
 */
static void derive_keys(uint8_t mac1_key[WG_NOISE_HASH_LEN],
                        uint8_t encryption_key[WG_NOISE_SYMMETRIC_KEY_LEN],
                        const uint8_t public_key[WG_KEY_LEN])
{
    wg_blake2s_state_t state;

    /* mac1_key = BLAKE2s("mac1----" || pk) */
    wg_blake2s_init(&state, WG_NOISE_HASH_LEN);
    wg_blake2s_update(&state, (const uint8_t *)WG_LABEL_MAC1, sizeof(WG_LABEL_MAC1) - 1);
    wg_blake2s_update(&state, public_key, WG_KEY_LEN);
    wg_blake2s_final(&state, mac1_key);

    /* encryption_key = BLAKE2s("cookie--" || pk) */
    wg_blake2s_init(&state, WG_NOISE_HASH_LEN);
    wg_blake2s_update(&state, (const uint8_t *)WG_LABEL_COOKIE,
                      sizeof(WG_LABEL_COOKIE) - 1);
    wg_blake2s_update(&state, public_key, WG_KEY_LEN);
    wg_blake2s_final(&state, encryption_key);

    wg_secure_zero(&state, sizeof(state));
}

/* ════════════════════════════════════════
 * CookieChecker — receiver side
 * ════════════════════════════════════════ */

void wg_cookie_checker_init(wg_cookie_checker_t *cc, const uint8_t public_key[WG_KEY_LEN])
{
    memset(cc, 0, sizeof(*cc));
    pthread_rwlock_init(&cc->lock, NULL);
    derive_keys(cc->mac1_key, cc->encryption_key, public_key);
}

void wg_cookie_checker_destroy(wg_cookie_checker_t *cc)
{
    pthread_rwlock_destroy(&cc->lock);
    wg_secure_zero(cc, sizeof(*cc));
}

bool wg_cookie_checker_check_mac1(wg_cookie_checker_t *cc, const uint8_t *msg,
                                  size_t msg_len)
{
    if (msg_len < sizeof(wg_message_macs_t))
        return false;

    size_t smac2 = msg_len - WG_COOKIE_LEN;
    size_t smac1 = smac2 - WG_COOKIE_LEN;

    /* mac1_key is immutable after init — no lock needed. */
    uint8_t computed[WG_COOKIE_LEN];
    wg_mac(computed, cc->mac1_key, WG_NOISE_HASH_LEN, msg, smac1);

    bool ok = (sodium_memcmp(computed, msg + smac1, WG_COOKIE_LEN) == 0);
    wg_secure_zero(computed, sizeof(computed));
    return ok;
}

bool wg_cookie_checker_check_mac2(wg_cookie_checker_t *cc, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *src, size_t src_len)
{
    if (msg_len < sizeof(wg_message_macs_t))
        return false;

    pthread_rwlock_rdlock(&cc->lock);

    /* Secret must be fresh */
    uint64_t now = wg_mono_ns();
    if (cc->secret_set_ns == 0 || (now - cc->secret_set_ns) > WG_COOKIE_REFRESH_NS) {
        pthread_rwlock_unlock(&cc->lock);
        return false;
    }

    /* Derive per-source cookie: BLAKE2s-128(key=secret, data=src) */
    uint8_t cookie[WG_COOKIE_LEN];
    wg_mac(cookie, cc->secret, WG_NOISE_HASH_LEN, src, src_len);

    /* Compute expected mac2: BLAKE2s-128(key=cookie, data=msg[0..smac2]) */
    size_t smac2 = msg_len - WG_COOKIE_LEN;
    uint8_t computed[WG_COOKIE_LEN];
    wg_mac(computed, cookie, WG_COOKIE_LEN, msg, smac2);

    pthread_rwlock_unlock(&cc->lock);

    bool ok = (sodium_memcmp(computed, msg + smac2, WG_COOKIE_LEN) == 0);
    wg_secure_zero(cookie, sizeof(cookie));
    wg_secure_zero(computed, sizeof(computed));
    return ok;
}

wg_error_t wg_cookie_checker_create_reply(wg_cookie_checker_t *cc,
                                          wg_message_cookie_reply_t *reply,
                                          const uint8_t *msg, size_t msg_len,
                                          uint32_t recv, const uint8_t *src,
                                          size_t src_len)
{
    if (msg_len < sizeof(wg_message_macs_t))
        return WG_ERR_COOKIE_INVALID;

    pthread_rwlock_wrlock(&cc->lock);

    /* Rotate secret if expired or unset */
    uint64_t now = wg_mono_ns();
    if (cc->secret_set_ns == 0 || (now - cc->secret_set_ns) > WG_COOKIE_REFRESH_NS) {
        randombytes_buf(cc->secret, WG_NOISE_HASH_LEN);
        cc->secret_set_ns = now;
    }

    /* Derive per-source cookie: BLAKE2s-128(key=secret, data=src) */
    uint8_t cookie[WG_COOKIE_LEN];
    wg_mac(cookie, cc->secret, WG_NOISE_HASH_LEN, src, src_len);

    /* Extract mac1 from the incoming message as additional data */
    size_t smac2 = msg_len - WG_COOKIE_LEN;
    size_t smac1 = smac2 - WG_COOKIE_LEN;
    const uint8_t *ad = msg + smac1; /* mac1 field */

    /* Build reply */
    memset(reply, 0, sizeof(*reply));
    reply->header.type = wg_htole32(WG_MESSAGE_COOKIE_REPLY);
    reply->receiver_index = wg_htole32(recv);
    randombytes_buf(reply->nonce, WG_COOKIE_NONCE_LEN);

    /* Encrypt cookie with XChaCha20-Poly1305, AD = mac1 */
    wg_error_t err =
        wg_xchacha20poly1305_encrypt(reply->encrypted_cookie, NULL, cookie, WG_COOKIE_LEN,
                                     ad, WG_COOKIE_LEN, reply->nonce, cc->encryption_key);

    pthread_rwlock_unlock(&cc->lock);

    wg_secure_zero(cookie, sizeof(cookie));
    return err;
}

/* ════════════════════════════════════════
 * CookieGenerator — sender side
 * ════════════════════════════════════════ */

void wg_cookie_generator_init(wg_cookie_generator_t *cg,
                              const uint8_t public_key[WG_KEY_LEN])
{
    memset(cg, 0, sizeof(*cg));
    pthread_rwlock_init(&cg->lock, NULL);
    derive_keys(cg->mac1_key, cg->encryption_key, public_key);
}

void wg_cookie_generator_destroy(wg_cookie_generator_t *cg)
{
    pthread_rwlock_destroy(&cg->lock);
    wg_secure_zero(cg, sizeof(*cg));
}

void wg_cookie_generator_add_macs(wg_cookie_generator_t *cg, uint8_t *msg, size_t msg_len)
{
    if (msg_len < sizeof(wg_message_macs_t))
        return;

    size_t smac2 = msg_len - WG_COOKIE_LEN;
    size_t smac1 = smac2 - WG_COOKIE_LEN;
    uint8_t *mac1 = msg + smac1;
    uint8_t *mac2 = msg + smac2;

    pthread_rwlock_wrlock(&cg->lock);

    /* mac1 = BLAKE2s-128(key=mac1_key, data=msg[0..smac1]) */
    wg_mac(mac1, cg->mac1_key, WG_NOISE_HASH_LEN, msg, smac1);

    /* Save last mac1 for cookie reply decryption */
    memcpy(cg->last_mac1, mac1, WG_COOKIE_LEN);
    cg->has_last_mac1 = true;

    /* mac2 = BLAKE2s-128(key=cookie, data=msg[0..smac2]) if cookie is valid */
    uint64_t now = wg_mono_ns();
    if (cg->cookie_set_ns == 0 || (now - cg->cookie_set_ns) > WG_COOKIE_REFRESH_NS) {
        /* No valid cookie — mac2 stays zero */
        memset(mac2, 0, WG_COOKIE_LEN);
        pthread_rwlock_unlock(&cg->lock);
        return;
    }

    wg_mac(mac2, cg->cookie, WG_COOKIE_LEN, msg, smac2);

    pthread_rwlock_unlock(&cg->lock);
}

wg_error_t wg_cookie_generator_consume_reply(wg_cookie_generator_t *cg,
                                             const wg_message_cookie_reply_t *reply)
{
    pthread_rwlock_wrlock(&cg->lock);

    if (!cg->has_last_mac1) {
        pthread_rwlock_unlock(&cg->lock);
        return WG_ERR_HANDSHAKE_STATE;
    }

    /* Decrypt cookie: XChaCha20-Poly1305, AD = last_mac1 */
    uint8_t cookie[WG_COOKIE_LEN];
    size_t cookie_len;
    wg_error_t err = wg_xchacha20poly1305_decrypt(
        cookie, &cookie_len, reply->encrypted_cookie, WG_COOKIE_LEN + WG_AEAD_TAG_SIZE,
        cg->last_mac1, WG_COOKIE_LEN, reply->nonce, cg->encryption_key);

    if (err != WG_OK) {
        pthread_rwlock_unlock(&cg->lock);
        wg_secure_zero(cookie, sizeof(cookie));
        return WG_ERR_COOKIE_INVALID;
    }

    memcpy(cg->cookie, cookie, WG_COOKIE_LEN);
    cg->cookie_set_ns = wg_mono_ns();

    pthread_rwlock_unlock(&cg->lock);

    wg_secure_zero(cookie, sizeof(cookie));
    return WG_OK;
}

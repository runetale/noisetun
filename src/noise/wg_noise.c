/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * The WireGuard handshake, Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s:
 *
 *   <- s
 *   ...
 *   -> e, es, s, ss, {t}
 *   <- e, ee, se, psk, {}
 *
 * Written against the protocol documents:
 *   - The Noise Protocol Framework, revision 34: section 5.2 (SymmetricState),
 *     section 7 (the IK pattern) and section 9 (psk modifiers).
 *   - WireGuard: Next Generation Kernel Network Tunnel, section 5.4, whose
 *     formulas are quoted beside the code.
 *
 * Each message is written out token by token on top of a SymmetricState, the
 * layout BoringTun's handshake.rs uses (see NOTICE).
 */

#include "wg_noise.h"

#include <sodium.h>
#include <string.h>
#include <time.h>

uint8_t wg_noise_handshake_init_hash[WG_NOISE_HASH_LEN];
uint8_t wg_noise_handshake_init_chaining_key[WG_NOISE_HASH_LEN];

/*
 * The handshake's only inputs besides the keys: fresh ephemeral keys and
 * the time. tests/test_noise_vectors.c compiles this file with
 * WG_NOISE_FIXED_INPUTS and supplies both, to reproduce recorded
 * handshakes byte for byte. The library is never built that way.
 */
#ifdef WG_NOISE_FIXED_INPUTS
wg_error_t wg_noise_fixed_ephemeral(uint8_t private_key[WG_KEY_LEN]);
void wg_noise_fixed_timestamp(uint8_t out[WG_TIMESTAMP_LEN]);
#define new_ephemeral     wg_noise_fixed_ephemeral
#define current_timestamp wg_noise_fixed_timestamp
#else
#define new_ephemeral     wg_x25519_generate_private
#define current_timestamp wg_tai64n_now
#endif

void wg_noise_module_init(void)
{
    /* InitializeSymmetric(protocol_name): the name is longer than HASHLEN,
     * so h = ck = HASH(protocol_name). WireGuard then mixes its identifier
     * in as the prologue. */
    wg_blake2s(wg_noise_handshake_init_chaining_key, WG_NOISE_HASH_LEN,
               (const uint8_t *)WG_NOISE_CONSTRUCTION, sizeof(WG_NOISE_CONSTRUCTION) - 1,
               NULL, 0);
    memcpy(wg_noise_handshake_init_hash, wg_noise_handshake_init_chaining_key,
           WG_NOISE_HASH_LEN);
    wg_mix_hash(wg_noise_handshake_init_hash, (const uint8_t *)WG_NOISE_IDENTIFIER,
                sizeof(WG_NOISE_IDENTIFIER) - 1);
}

uint64_t wg_mono_ns(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

/* ════════════════════════════════════════
 * SymmetricState (Noise section 5.2)
 *
 * k is the CipherState key. Its nonce is always 0: every key the
 * handshake derives encrypts one message before the next MixKey
 * replaces it.
 * ════════════════════════════════════════ */

typedef struct {
    uint8_t ck[WG_NOISE_HASH_LEN];
    uint8_t h[WG_NOISE_HASH_LEN];
    uint8_t k[WG_NOISE_SYMMETRIC_KEY_LEN];
} symmetric_state_t;

/* Start a handshake whose responder has the static key rs: the protocol
 * name and prologue (precomputed), then the pre-message "<- s". */
static void ss_start(symmetric_state_t *ss, const uint8_t rs[WG_KEY_LEN])
{
    memset(ss, 0, sizeof(*ss));
    memcpy(ss->ck, wg_noise_handshake_init_chaining_key, WG_NOISE_HASH_LEN);
    memcpy(ss->h, wg_noise_handshake_init_hash, WG_NOISE_HASH_LEN);
    wg_mix_hash(ss->h, rs, WG_KEY_LEN);
}

/* Continue from the ck and h of an earlier message. */
static void ss_resume(symmetric_state_t *ss, const uint8_t ck[WG_NOISE_HASH_LEN],
                      const uint8_t h[WG_NOISE_HASH_LEN])
{
    memset(ss, 0, sizeof(*ss));
    memcpy(ss->ck, ck, WG_NOISE_HASH_LEN);
    memcpy(ss->h, h, WG_NOISE_HASH_LEN);
}

/* MixKey: ck, k = HKDF(ck, ikm, 2) */
static void ss_mix_key(symmetric_state_t *ss, const uint8_t *ikm, size_t ikm_len)
{
    wg_kdf2(ss->ck, ss->k, ss->ck, WG_NOISE_HASH_LEN, ikm, ikm_len);
}

/*
 * MixKey without deriving k: ck = HKDF(ck, ikm, 1). HKDF's first output
 * does not depend on how many follow, so ck comes out as MixKey's. Used
 * where the next MixKey or MixKeyAndHash replaces k before anything is
 * encrypted with it, which saves one HMAC.
 */
static void ss_mix_chaining_key(symmetric_state_t *ss, const uint8_t *ikm, size_t ikm_len)
{
    wg_kdf1(ss->ck, ss->ck, WG_NOISE_HASH_LEN, ikm, ikm_len);
}

/* MixKey(DH(priv, pub)), or only ck when need_key is false (see
 * ss_mix_chaining_key). Fails on a low-order public key, whose shared
 * secret is all zero. */
static bool ss_mix_dh(symmetric_state_t *ss, const uint8_t priv[WG_KEY_LEN],
                      const uint8_t pub[WG_KEY_LEN], bool need_key)
{
    uint8_t shared[WG_KEY_LEN];
    bool ok = wg_x25519(shared, priv, pub) == WG_OK;
    if (ok && need_key)
        ss_mix_key(ss, shared, sizeof(shared));
    else if (ok)
        ss_mix_chaining_key(ss, shared, sizeof(shared));
    wg_secure_zero(shared, sizeof(shared));
    return ok;
}

/* The ss token with DH(s, rs) computed in advance. All zero means there
 * was no local key, or rs was a low-order point. */
static bool ss_mix_static_static(symmetric_state_t *ss, const uint8_t shared[WG_KEY_LEN])
{
    if (wg_is_zero(shared, WG_KEY_LEN))
        return false;
    ss_mix_key(ss, shared, WG_KEY_LEN);
    return true;
}

/* MixKeyAndHash, for the psk token: ck, t, k = HKDF(ck, psk, 3); MixHash(t).
 * A peer without a preshared key uses 32 zero bytes. */
static void ss_mix_key_and_hash(symmetric_state_t *ss,
                                const uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    uint8_t t[WG_NOISE_HASH_LEN];
    wg_kdf3(ss->ck, t, ss->k, ss->ck, WG_NOISE_HASH_LEN, psk, WG_NOISE_SYMMETRIC_KEY_LEN);
    wg_mix_hash(ss->h, t, sizeof(t));
    wg_secure_zero(t, sizeof(t));
}

/* The e token in a psk handshake (Noise section 9.2): MixHash(e), and
 * MixKey(e) as well. In both messages a DH token follows and replaces k,
 * so only ck is mixed. */
static void ss_mix_ephemeral(symmetric_state_t *ss, const uint8_t e[WG_KEY_LEN])
{
    wg_mix_hash(ss->h, e, WG_KEY_LEN);
    ss_mix_chaining_key(ss, e, WG_KEY_LEN);
}

/* EncryptAndHash: c = AEAD(k, 0, plaintext, h); MixHash(c). The output is
 * len + WG_AEAD_TAG_SIZE bytes. */
static wg_error_t ss_encrypt_and_hash(symmetric_state_t *ss, uint8_t *out,
                                      const uint8_t *plaintext, size_t len)
{
    size_t out_len;
    wg_error_t err = wg_aead_encrypt(out, &out_len, plaintext, len, ss->h,
                                     WG_NOISE_HASH_LEN, 0, ss->k);
    if (err == WG_OK)
        wg_mix_hash(ss->h, out, out_len);
    return err;
}

/* DecryptAndHash: the reverse, hashing the ciphertext it was given. */
static wg_error_t ss_decrypt_and_hash(symmetric_state_t *ss, uint8_t *out,
                                      const uint8_t *ciphertext, size_t len)
{
    size_t out_len;
    if (wg_aead_decrypt(out, &out_len, ciphertext, len, ss->h, WG_NOISE_HASH_LEN, 0,
                        ss->k) != WG_OK)
        return WG_ERR_HANDSHAKE_DECRYPT;
    wg_mix_hash(ss->h, ciphertext, len);
    return WG_OK;
}

static void ss_wipe(symmetric_state_t *ss)
{
    wg_secure_zero(ss, sizeof(*ss));
}

/* ════════════════════════════════════════
 * Keys
 * ════════════════════════════════════════ */

void wg_noise_static_identity_init(wg_noise_static_identity_t *si)
{
    memset(si, 0, sizeof(*si));
    pthread_rwlock_init(&si->lock, NULL);
}

void wg_noise_static_identity_set_private_key(wg_noise_static_identity_t *si,
                                              const uint8_t private_key[WG_KEY_LEN])
{
    pthread_rwlock_wrlock(&si->lock);
    memcpy(si->static_private, private_key, WG_KEY_LEN);
    wg_x25519_clamp(si->static_private);
    wg_x25519_public_key(si->static_public, si->static_private);
    si->has_identity = true;
    pthread_rwlock_unlock(&si->lock);
}

/*
 * Copy the device key pair out, so that no handshake step runs with the
 * identity lock held; the lock order elsewhere is identity before
 * handshake. Either output may be NULL. Returns false while there is no
 * private key.
 */
static bool identity_copy(wg_noise_static_identity_t *si, uint8_t pub[WG_KEY_LEN],
                          uint8_t priv[WG_KEY_LEN])
{
    pthread_rwlock_rdlock(&si->lock);
    bool have = si->has_identity;
    if (have && pub)
        memcpy(pub, si->static_public, WG_KEY_LEN);
    if (have && priv)
        memcpy(priv, si->static_private, WG_KEY_LEN);
    pthread_rwlock_unlock(&si->lock);
    return have;
}

void wg_noise_precompute_static_static(wg_noise_handshake_t *hs)
{
    pthread_rwlock_wrlock(&hs->lock);
    bool ok = hs->static_identity->has_identity &&
              wg_x25519(hs->precomputed_static_static,
                        hs->static_identity->static_private, hs->remote_static) == WG_OK;
    if (!ok)
        wg_secure_zero(hs->precomputed_static_static, WG_KEY_LEN);
    pthread_rwlock_unlock(&hs->lock);
}

/* ════════════════════════════════════════
 * Per-peer handshake state
 * ════════════════════════════════════════ */

void wg_noise_handshake_init(wg_noise_handshake_t *hs, wg_noise_static_identity_t *si,
                             const uint8_t peer_public_key[WG_KEY_LEN],
                             const uint8_t *peer_preshared_key)
{
    memset(hs, 0, sizeof(*hs));
    pthread_rwlock_init(&hs->lock, NULL);
    hs->static_identity = si;
    hs->pending.state = WG_HANDSHAKE_ZEROED;
    memcpy(hs->remote_static, peer_public_key, WG_KEY_LEN);
    if (peer_preshared_key)
        memcpy(hs->preshared_key, peer_preshared_key, WG_NOISE_SYMMETRIC_KEY_LEN);
    wg_noise_precompute_static_static(hs);
}

/* Drop the state of the handshake in progress. The peer's keys and the
 * last accepted timestamp stay. */
static void forget_handshake(wg_noise_handshake_t *hs)
{
    wg_secure_zero(&hs->pending, sizeof(hs->pending));
}

void wg_noise_handshake_clear_locked(wg_noise_handshake_t *hs)
{
    forget_handshake(hs);
}

void wg_noise_handshake_clear(wg_noise_handshake_t *hs)
{
    pthread_rwlock_wrlock(&hs->lock);
    forget_handshake(hs);
    pthread_rwlock_unlock(&hs->lock);
}

static void save_state(wg_noise_handshake_t *hs, const symmetric_state_t *ss)
{
    memcpy(hs->pending.chaining_key, ss->ck, WG_NOISE_HASH_LEN);
    memcpy(hs->pending.hash, ss->h, WG_NOISE_HASH_LEN);
}

/* ════════════════════════════════════════
 * First message: -> e, es, s, ss, {t}
 * ════════════════════════════════════════ */

wg_error_t wg_noise_handshake_create_initiation(wg_message_initiation_t *dst,
                                                wg_noise_handshake_t *hs)
{
    symmetric_state_t ss;
    uint8_t s_pub[WG_KEY_LEN];
    uint8_t e_pub[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    wg_error_t err;

    if (!identity_copy(hs->static_identity, s_pub, NULL))
        return WG_ERR_INVALID_KEY;

    pthread_rwlock_wrlock(&hs->lock);

    /* initiator.chaining_key = HASH(CONSTRUCTION)
     * initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) ||
     *                       responder.static_public) */
    ss_start(&ss, hs->remote_static);

    /* e: initiator.ephemeral_private = DH_GENERATE()
     *    msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
     *    initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
     *    initiator.chaining_key = KDF1(initiator.chaining_key,
     *                                  msg.unencrypted_ephemeral) */
    err = new_ephemeral(hs->pending.ephemeral_private);
    if (err != WG_OK)
        goto fail;
    wg_x25519_public_key(e_pub, hs->pending.ephemeral_private);
    memcpy(dst->unencrypted_ephemeral, e_pub, WG_KEY_LEN);
    ss_mix_ephemeral(&ss, e_pub);

    /* es: (initiator.chaining_key, key) = KDF2(initiator.chaining_key,
     *         DH(initiator.ephemeral_private, responder.static_public)) */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_dh(&ss, hs->pending.ephemeral_private, hs->remote_static, true))
        goto fail;

    /* s: msg.encrypted_static = AEAD(key, 0, initiator.static_public,
     *                                initiator.hash)
     *    initiator.hash = HASH(initiator.hash || msg.encrypted_static) */
    err = ss_encrypt_and_hash(&ss, dst->encrypted_static, s_pub, WG_KEY_LEN);
    if (err != WG_OK)
        goto fail;

    /* ss: (initiator.chaining_key, key) = KDF2(initiator.chaining_key,
     *         DH(initiator.static_private, responder.static_public)) */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_static_static(&ss, hs->precomputed_static_static))
        goto fail;

    /* {t}: msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
     *      initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp) */
    current_timestamp(timestamp);
    err = ss_encrypt_and_hash(&ss, dst->encrypted_timestamp, timestamp, WG_TIMESTAMP_LEN);
    if (err != WG_OK)
        goto fail;

    dst->header.type = wg_htole32(WG_MESSAGE_INITIATION);
    dst->sender_index = wg_htole32(hs->local_index);
    save_state(hs, &ss);
    hs->pending.state = WG_HANDSHAKE_CREATED_INITIATION;
    goto done;

fail:
    forget_handshake(hs);
done:
    pthread_rwlock_unlock(&hs->lock);
    ss_wipe(&ss);
    wg_secure_zero(s_pub, sizeof(s_pub));
    wg_secure_zero(e_pub, sizeof(e_pub));
    wg_secure_zero(timestamp, sizeof(timestamp));
    return err;
}

/*
 * The responder's side up to s, which needs only the device keys: after
 * it, the initiator's static key says which peer sent the message.
 */
static wg_error_t read_initiation_static(const uint8_t s_pub[WG_KEY_LEN],
                                         const uint8_t s_priv[WG_KEY_LEN],
                                         const wg_message_initiation_t *src,
                                         wg_initiation_half_t *half)
{
    symmetric_state_t ss;
    wg_error_t err;

    ss_start(&ss, s_pub);

    /* e */
    memcpy(half->remote_ephemeral, src->unencrypted_ephemeral, WG_KEY_LEN);
    ss_mix_ephemeral(&ss, half->remote_ephemeral);

    /* es, from this side: DH(responder.static_private,
     *                        msg.unencrypted_ephemeral) */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_dh(&ss, s_priv, half->remote_ephemeral, true))
        goto out;

    /* s */
    err = ss_decrypt_and_hash(&ss, half->decrypted_static, src->encrypted_static,
                              WG_KEY_LEN + WG_AEAD_TAG_SIZE);
    if (err != WG_OK)
        goto out;

    half->sender_index = wg_le32toh(src->sender_index);
    memcpy(half->chaining_key, ss.ck, WG_NOISE_HASH_LEN);
    memcpy(half->hash, ss.h, WG_NOISE_HASH_LEN);
out:
    ss_wipe(&ss);
    return err;
}

/*
 * The rest of the first message, once the peer is known: ss and {t}.
 * The peer's handshake is only written if the timestamp is newer than
 * the last one accepted from it; an older or equal one is a replay.
 * keep_shared stores ss_shared as the peer's precomputed DH(s, rs).
 */
static wg_error_t finish_initiation(wg_noise_handshake_t *hs,
                                    const wg_message_initiation_t *src,
                                    const wg_initiation_half_t *half,
                                    const uint8_t ss_shared[WG_KEY_LEN], bool keep_shared)
{
    symmetric_state_t ss;
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    wg_error_t err;

    ss_resume(&ss, half->chaining_key, half->hash);

    /* ss */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_static_static(&ss, ss_shared))
        goto out;

    /* {t} */
    err = ss_decrypt_and_hash(&ss, timestamp, src->encrypted_timestamp,
                              WG_TIMESTAMP_LEN + WG_AEAD_TAG_SIZE);
    if (err != WG_OK)
        goto out;

    pthread_rwlock_wrlock(&hs->lock);
    bool seen = !wg_is_zero(hs->latest_timestamp, WG_TIMESTAMP_LEN);
    if (seen && !wg_tai64n_after(timestamp, hs->latest_timestamp)) {
        err = WG_ERR_TIMESTAMP;
    } else {
        memcpy(hs->latest_timestamp, timestamp, WG_TIMESTAMP_LEN);
        memcpy(hs->pending.remote_ephemeral, half->remote_ephemeral, WG_KEY_LEN);
        if (keep_shared)
            memcpy(hs->precomputed_static_static, ss_shared, WG_KEY_LEN);
        save_state(hs, &ss);
        hs->pending.remote_index = half->sender_index;
        hs->pending.state = WG_HANDSHAKE_CONSUMED_INITIATION;
    }
    pthread_rwlock_unlock(&hs->lock);
out:
    ss_wipe(&ss);
    wg_secure_zero(timestamp, sizeof(timestamp));
    return err;
}

wg_error_t
wg_noise_consume_initiation_decrypt_static(wg_noise_static_identity_t *identity,
                                           const wg_message_initiation_t *src,
                                           wg_initiation_half_t *half)
{
    uint8_t s_pub[WG_KEY_LEN];
    uint8_t s_priv[WG_KEY_LEN];

    if (!identity_copy(identity, s_pub, s_priv))
        return WG_ERR_INVALID_KEY;
    wg_error_t err = read_initiation_static(s_pub, s_priv, src, half);
    wg_secure_zero(s_pub, sizeof(s_pub));
    wg_secure_zero(s_priv, sizeof(s_priv));
    return err;
}

wg_error_t wg_noise_consume_initiation_commit(wg_noise_handshake_t *hs,
                                              const wg_message_initiation_t *src,
                                              wg_initiation_half_t *half)
{
    uint8_t shared[WG_KEY_LEN];

    pthread_rwlock_rdlock(&hs->lock);
    memcpy(shared, hs->precomputed_static_static, WG_KEY_LEN);
    pthread_rwlock_unlock(&hs->lock);

    wg_error_t err = finish_initiation(hs, src, half, shared, false);
    wg_secure_zero(shared, sizeof(shared));
    return err;
}

wg_error_t wg_noise_handshake_consume_initiation(wg_noise_handshake_t *hs,
                                                 const wg_message_initiation_t *src,
                                                 uint8_t decrypted_static_out[WG_KEY_LEN])
{
    wg_initiation_half_t half;
    uint8_t s_pub[WG_KEY_LEN];
    uint8_t s_priv[WG_KEY_LEN];
    uint8_t shared[WG_KEY_LEN];
    wg_error_t err;

    if (!identity_copy(hs->static_identity, s_pub, s_priv))
        return WG_ERR_INVALID_KEY;

    err = read_initiation_static(s_pub, s_priv, src, &half);
    if (err != WG_OK)
        goto out;

    /* The sender's static key was just learned, so DH(s, rs) is computed
     * here rather than taken from hs. */
    err = WG_ERR_DH_FAILED;
    if (wg_x25519(shared, s_priv, half.decrypted_static) != WG_OK)
        goto out;

    err = finish_initiation(hs, src, &half, shared, true);
    if (err == WG_OK)
        memcpy(decrypted_static_out, half.decrypted_static, WG_KEY_LEN);
out:
    wg_secure_zero(&half, sizeof(half));
    wg_secure_zero(s_pub, sizeof(s_pub));
    wg_secure_zero(s_priv, sizeof(s_priv));
    wg_secure_zero(shared, sizeof(shared));
    return err;
}

/* ════════════════════════════════════════
 * Second message: <- e, ee, se, psk, {}
 * ════════════════════════════════════════ */

wg_error_t wg_noise_handshake_create_response(wg_message_response_t *dst,
                                              wg_noise_handshake_t *hs)
{
    symmetric_state_t ss;
    uint8_t e_pub[WG_KEY_LEN];
    wg_error_t err;

    pthread_rwlock_wrlock(&hs->lock);
    ss_resume(&ss, hs->pending.chaining_key, hs->pending.hash);

    err = WG_ERR_HANDSHAKE_STATE;
    if (hs->pending.state != WG_HANDSHAKE_CONSUMED_INITIATION)
        goto fail;

    /* e: responder.ephemeral_private = DH_GENERATE()
     *    msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
     *    responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
     *    responder.chaining_key = KDF1(responder.chaining_key,
     *                                  msg.unencrypted_ephemeral) */
    err = new_ephemeral(hs->pending.ephemeral_private);
    if (err != WG_OK)
        goto fail;
    wg_x25519_public_key(e_pub, hs->pending.ephemeral_private);
    memcpy(dst->unencrypted_ephemeral, e_pub, WG_KEY_LEN);
    ss_mix_ephemeral(&ss, e_pub);

    /* ee: responder.chaining_key = KDF1(responder.chaining_key,
     *         DH(responder.ephemeral_private, initiator.ephemeral_public))
     * se: responder.chaining_key = KDF1(responder.chaining_key,
     *         DH(responder.ephemeral_private, initiator.static_public))
     * The key MixKey would derive is replaced by psk, so only ck is mixed. */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_dh(&ss, hs->pending.ephemeral_private, hs->pending.remote_ephemeral,
                   false))
        goto fail;
    if (!ss_mix_dh(&ss, hs->pending.ephemeral_private, hs->remote_static, false))
        goto fail;

    /* psk: (responder.chaining_key, temp, key) = KDF3(responder.chaining_key,
     *                                                  preshared_key)
     *      responder.hash = HASH(responder.hash || temp) */
    ss_mix_key_and_hash(&ss, hs->preshared_key);

    /* {}: msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
     *     responder.hash = HASH(responder.hash || msg.encrypted_nothing) */
    err = ss_encrypt_and_hash(&ss, dst->encrypted_nothing, NULL, 0);
    if (err != WG_OK)
        goto fail;

    dst->header.type = wg_htole32(WG_MESSAGE_RESPONSE);
    dst->sender_index = wg_htole32(hs->local_index);
    dst->receiver_index = wg_htole32(hs->pending.remote_index);
    save_state(hs, &ss);
    hs->pending.state = WG_HANDSHAKE_CREATED_RESPONSE;
    goto done;

fail:
    forget_handshake(hs);
done:
    pthread_rwlock_unlock(&hs->lock);
    ss_wipe(&ss);
    wg_secure_zero(e_pub, sizeof(e_pub));
    return err;
}

/*
 * The initiator's side of the second message. The inputs are copied out
 * of hs and hs is only written once the whole message verifies, so a
 * forged response leaves the pending initiation as it was. hs is also
 * left alone if, meanwhile, the response was consumed or a new
 * initiation replaced the one it answers (that one's hash differs).
 *
 * src->receiver_index is not compared with hs->local_index: the caller
 * found hs by that index.
 */
wg_error_t wg_noise_handshake_consume_response(wg_noise_handshake_t *hs,
                                               const wg_message_response_t *src)
{
    symmetric_state_t ss;
    uint8_t s_priv[WG_KEY_LEN];
    uint8_t e_priv[WG_KEY_LEN];
    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    uint8_t re[WG_KEY_LEN];
    uint8_t pending_h[WG_NOISE_HASH_LEN];
    uint8_t nothing[1];
    wg_error_t err;

    if (!identity_copy(hs->static_identity, NULL, s_priv))
        return WG_ERR_INVALID_KEY;

    pthread_rwlock_rdlock(&hs->lock);
    bool pending = hs->pending.state == WG_HANDSHAKE_CREATED_INITIATION;
    ss_resume(&ss, hs->pending.chaining_key, hs->pending.hash);
    memcpy(pending_h, hs->pending.hash, WG_NOISE_HASH_LEN);
    memcpy(e_priv, hs->pending.ephemeral_private, WG_KEY_LEN);
    memcpy(psk, hs->preshared_key, WG_NOISE_SYMMETRIC_KEY_LEN);
    pthread_rwlock_unlock(&hs->lock);

    err = WG_ERR_HANDSHAKE_STATE;
    if (!pending)
        goto out;

    /* e */
    memcpy(re, src->unencrypted_ephemeral, WG_KEY_LEN);
    ss_mix_ephemeral(&ss, re);

    /* ee: DH(initiator.ephemeral_private, msg.unencrypted_ephemeral)
     * se: DH(initiator.static_private, msg.unencrypted_ephemeral) */
    err = WG_ERR_DH_FAILED;
    if (!ss_mix_dh(&ss, e_priv, re, false))
        goto out;
    if (!ss_mix_dh(&ss, s_priv, re, false))
        goto out;

    /* psk */
    ss_mix_key_and_hash(&ss, psk);

    /* {} */
    err = ss_decrypt_and_hash(&ss, nothing, src->encrypted_nothing, WG_AEAD_TAG_SIZE);
    if (err != WG_OK)
        goto out;

    pthread_rwlock_wrlock(&hs->lock);
    if (hs->pending.state == WG_HANDSHAKE_CREATED_INITIATION &&
        sodium_memcmp(hs->pending.hash, pending_h, WG_NOISE_HASH_LEN) == 0) {
        save_state(hs, &ss);
        hs->pending.remote_index = wg_le32toh(src->sender_index);
        hs->pending.state = WG_HANDSHAKE_CONSUMED_RESPONSE;
    } else {
        err = WG_ERR_HANDSHAKE_STATE;
    }
    pthread_rwlock_unlock(&hs->lock);
out:
    ss_wipe(&ss);
    wg_secure_zero(s_priv, sizeof(s_priv));
    wg_secure_zero(e_priv, sizeof(e_priv));
    wg_secure_zero(psk, sizeof(psk));
    wg_secure_zero(re, sizeof(re));
    return err;
}

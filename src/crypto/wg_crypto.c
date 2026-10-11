/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Cryptographic primitives for WireGuard Noise IKpsk2.
 */

#include "wg_crypto.h"
#include "platform/wg_platform.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if WG_USE_OPENSSL
#include <openssl/evp.h>
#endif

/* ════════════════════════════════════════
 * BLAKE2s (RFC 7693) — standalone implementation
 *
 * libsodium only provides BLAKE2b. WireGuard mandates BLAKE2s-256
 * for its Noise protocol (hash, MAC, KDF).
 * ════════════════════════════════════════ */

static const uint32_t blake2s_iv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static inline uint32_t rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define G(r, i, a, b, c, d)                      \
    do {                                         \
        a += b + m[blake2s_sigma[r][2 * i + 0]]; \
        d = rotr32(d ^ a, 16);                   \
        c += d;                                  \
        b = rotr32(b ^ c, 12);                   \
        a += b + m[blake2s_sigma[r][2 * i + 1]]; \
        d = rotr32(d ^ a, 8);                    \
        c += d;                                  \
        b = rotr32(b ^ c, 7);                    \
    } while (0)

static void blake2s_compress(wg_blake2s_state_t *s,
                             const uint8_t block[WG_BLAKE2S_BLOCK_SIZE])
{
    uint32_t m[16], v[16];

    for (int i = 0; i < 16; i++)
        m[i] = load32_le(block + i * 4);

    for (int i = 0; i < 8; i++)
        v[i] = s->h[i];
    v[8] = blake2s_iv[0];
    v[9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ s->t[0];
    v[13] = blake2s_iv[5] ^ s->t[1];
    v[14] = blake2s_iv[6] ^ s->f[0];
    v[15] = blake2s_iv[7] ^ s->f[1];

    for (int r = 0; r < 10; r++) {
        G(r, 0, v[0], v[4], v[8], v[12]);
        G(r, 1, v[1], v[5], v[9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8], v[13]);
        G(r, 7, v[3], v[4], v[9], v[14]);
    }

    for (int i = 0; i < 8; i++)
        s->h[i] ^= v[i] ^ v[i + 8];
}

void wg_blake2s_init(wg_blake2s_state_t *state, size_t outlen)
{
    memset(state, 0, sizeof(*state));
    for (int i = 0; i < 8; i++)
        state->h[i] = blake2s_iv[i];
    state->h[0] ^= 0x01010000 ^ (uint32_t)outlen;
    state->outlen = outlen;
}

void wg_blake2s_init_key(wg_blake2s_state_t *state, size_t outlen, const uint8_t *key,
                         size_t keylen)
{
    wg_blake2s_init(state, outlen);
    state->h[0] ^= (uint32_t)keylen << 8;

    uint8_t block[WG_BLAKE2S_BLOCK_SIZE] = {0};
    memcpy(block, key, keylen);
    wg_blake2s_update(state, block, WG_BLAKE2S_BLOCK_SIZE);
    wg_secure_zero(block, sizeof(block));
}

void wg_blake2s_update(wg_blake2s_state_t *state, const uint8_t *in, size_t inlen)
{
    while (inlen > 0) {
        size_t left = state->buflen;
        size_t fill = WG_BLAKE2S_BLOCK_SIZE - left;

        if (inlen > fill) {
            memcpy(state->buf + left, in, fill);
            state->t[0] += WG_BLAKE2S_BLOCK_SIZE;
            if (state->t[0] == 0)
                state->t[1]++;
            blake2s_compress(state, state->buf);
            state->buflen = 0;
            in += fill;
            inlen -= fill;
        } else {
            memcpy(state->buf + left, in, inlen);
            state->buflen += inlen;
            break;
        }
    }
}

void wg_blake2s_final(wg_blake2s_state_t *state, uint8_t *out)
{
    state->t[0] += (uint32_t)state->buflen;
    if (state->t[0] < (uint32_t)state->buflen)
        state->t[1]++;
    state->f[0] = ~(uint32_t)0;

    memset(state->buf + state->buflen, 0, WG_BLAKE2S_BLOCK_SIZE - state->buflen);
    blake2s_compress(state, state->buf);

    for (size_t i = 0; i < state->outlen; i++)
        out[i] = (uint8_t)(state->h[i / 4] >> (8 * (i % 4)));

    wg_secure_zero(state, sizeof(*state));
}

void wg_blake2s(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                const uint8_t *key, size_t keylen)
{
    wg_blake2s_state_t state;
    if (key && keylen > 0)
        wg_blake2s_init_key(&state, outlen, key, keylen);
    else
        wg_blake2s_init(&state, outlen);
    wg_blake2s_update(&state, in, inlen);
    wg_blake2s_final(&state, out);
}

/* ════════════════════════════════════════
 * HMAC-BLAKE2s
 *
 * HMAC(key, msg) = BLAKE2s(opad || BLAKE2s(ipad || msg))
 * where ipad = key XOR 0x36..., opad = key XOR 0x5c...
 * ════════════════════════════════════════ */

void wg_hmac(uint8_t out[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *in, size_t inlen)
{
    wg_blake2s_state_t state;
    uint8_t x_key[WG_BLAKE2S_BLOCK_SIZE] = {0};
    uint8_t i_pad[WG_BLAKE2S_BLOCK_SIZE];
    uint8_t o_pad[WG_BLAKE2S_BLOCK_SIZE];

    if (keylen > WG_BLAKE2S_BLOCK_SIZE) {
        wg_blake2s(x_key, WG_BLAKE2S_HASH_SIZE, key, keylen, NULL, 0);
    } else {
        memcpy(x_key, key, keylen);
    }

    for (int i = 0; i < WG_BLAKE2S_BLOCK_SIZE; i++) {
        i_pad[i] = x_key[i] ^ 0x36;
        o_pad[i] = x_key[i] ^ 0x5c;
    }

    wg_blake2s_init(&state, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, i_pad, sizeof(i_pad));
    wg_blake2s_update(&state, in, inlen);
    wg_blake2s_final(&state, out);

    wg_blake2s_init(&state, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, o_pad, sizeof(o_pad));
    wg_blake2s_update(&state, out, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_final(&state, out);

    wg_secure_zero(x_key, sizeof(x_key));
    wg_secure_zero(i_pad, sizeof(i_pad));
    wg_secure_zero(o_pad, sizeof(o_pad));
}

void wg_hmac2(uint8_t out[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
              const uint8_t *in0, size_t in0len, const uint8_t *in1, size_t in1len)
{
    wg_blake2s_state_t state;
    uint8_t x_key[WG_BLAKE2S_BLOCK_SIZE] = {0};
    uint8_t i_pad[WG_BLAKE2S_BLOCK_SIZE];
    uint8_t o_pad[WG_BLAKE2S_BLOCK_SIZE];

    if (keylen > WG_BLAKE2S_BLOCK_SIZE) {
        wg_blake2s(x_key, WG_BLAKE2S_HASH_SIZE, key, keylen, NULL, 0);
    } else {
        memcpy(x_key, key, keylen);
    }

    for (int i = 0; i < WG_BLAKE2S_BLOCK_SIZE; i++) {
        i_pad[i] = x_key[i] ^ 0x36;
        o_pad[i] = x_key[i] ^ 0x5c;
    }

    wg_blake2s_init(&state, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, i_pad, sizeof(i_pad));
    wg_blake2s_update(&state, in0, in0len);
    wg_blake2s_update(&state, in1, in1len);
    wg_blake2s_final(&state, out);

    wg_blake2s_init(&state, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, o_pad, sizeof(o_pad));
    wg_blake2s_update(&state, out, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_final(&state, out);

    wg_secure_zero(x_key, sizeof(x_key));
    wg_secure_zero(i_pad, sizeof(i_pad));
    wg_secure_zero(o_pad, sizeof(o_pad));
}

/* ════════════════════════════════════════
 * KDF (HKDF-BLAKE2s)
 *
 * HKDF (RFC 5869) with HMAC-BLAKE2s, as the WireGuard whitepaper
 * defines KDF1/KDF2/KDF3: T0 = HMAC(key, input), then
 * T1 = HMAC(T0, 0x1), T2 = HMAC(T0, T1 || 0x2), T3 = HMAC(T0, T2 || 0x3).
 * ════════════════════════════════════════ */

void wg_kdf1(uint8_t t0[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen)
{
    uint8_t prk[WG_BLAKE2S_HASH_SIZE];
    wg_hmac(prk, key, keylen, input, inputlen);
    uint8_t one = 0x01;
    wg_hmac(t0, prk, WG_BLAKE2S_HASH_SIZE, &one, 1);
    wg_secure_zero(prk, sizeof(prk));
}

void wg_kdf2(uint8_t t0[WG_BLAKE2S_HASH_SIZE], uint8_t t1[WG_BLAKE2S_HASH_SIZE],
             const uint8_t *key, size_t keylen, const uint8_t *input, size_t inputlen)
{
    uint8_t prk[WG_BLAKE2S_HASH_SIZE];
    wg_hmac(prk, key, keylen, input, inputlen);

    uint8_t one = 0x01;
    wg_hmac(t0, prk, WG_BLAKE2S_HASH_SIZE, &one, 1);

    uint8_t two = 0x02;
    wg_hmac2(t1, prk, WG_BLAKE2S_HASH_SIZE, t0, WG_BLAKE2S_HASH_SIZE, &two, 1);

    wg_secure_zero(prk, sizeof(prk));
}

void wg_kdf3(uint8_t t0[WG_BLAKE2S_HASH_SIZE], uint8_t t1[WG_BLAKE2S_HASH_SIZE],
             uint8_t t2[WG_BLAKE2S_HASH_SIZE], const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen)
{
    uint8_t prk[WG_BLAKE2S_HASH_SIZE];
    wg_hmac(prk, key, keylen, input, inputlen);

    uint8_t one = 0x01;
    wg_hmac(t0, prk, WG_BLAKE2S_HASH_SIZE, &one, 1);

    uint8_t two = 0x02;
    wg_hmac2(t1, prk, WG_BLAKE2S_HASH_SIZE, t0, WG_BLAKE2S_HASH_SIZE, &two, 1);

    uint8_t three = 0x03;
    wg_hmac2(t2, prk, WG_BLAKE2S_HASH_SIZE, t1, WG_BLAKE2S_HASH_SIZE, &three, 1);

    wg_secure_zero(prk, sizeof(prk));
}

/* ════════════════════════════════════════
 * Noise helpers: MixHash, MixKey
 * ════════════════════════════════════════ */

void wg_mix_hash(uint8_t hash[WG_BLAKE2S_HASH_SIZE], const uint8_t *data, size_t len)
{
    wg_blake2s_state_t state;
    wg_blake2s_init(&state, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, hash, WG_BLAKE2S_HASH_SIZE);
    wg_blake2s_update(&state, data, len);
    wg_blake2s_final(&state, hash);
}

void wg_mix_key(uint8_t ck[WG_BLAKE2S_HASH_SIZE], uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN],
                const uint8_t *data, size_t len)
{
    wg_kdf2(ck, key, ck, WG_BLAKE2S_HASH_SIZE, data, len);
}

/* ════════════════════════════════════════
 * X25519 (via libsodium)
 * ════════════════════════════════════════ */

wg_error_t wg_x25519(uint8_t out[32], const uint8_t private_key[32],
                     const uint8_t public_key[32])
{
    if (crypto_scalarmult_curve25519(out, private_key, public_key) != 0)
        return WG_ERR_DH_FAILED;

    if (wg_is_zero(out, 32))
        return WG_ERR_INVALID_PUBKEY;

    return WG_OK;
}

void wg_x25519_public_key(uint8_t public_key[32], const uint8_t private_key[32])
{
    crypto_scalarmult_curve25519_base(public_key, private_key);
}

wg_error_t wg_x25519_generate_private(uint8_t private_key[32])
{
    randombytes_buf(private_key, 32);
    wg_x25519_clamp(private_key);
    return WG_OK;
}

void wg_x25519_clamp(uint8_t key[32])
{
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
}

/* ════════════════════════════════════════
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 *
 * WireGuard nonce: 64-bit counter in LE, padded to 12 bytes
 * (4 zero bytes || 8-byte LE counter)
 *
 * Two backends:
 *   WG_USE_OPENSSL=1 → OpenSSL EVP (fused NEON / AVX-512 assembly);
 *                      the CMake default on every platform
 *   otherwise        → libsodium (-DWG_USE_OPENSSL=OFF, as build_wgc.bat
 *                      does for Windows)
 * ════════════════════════════════════════ */

static void make_nonce(uint8_t nonce[12], uint64_t counter)
{
    memset(nonce, 0, 4);
    store32_le(nonce + 4, (uint32_t)(counter));
    store32_le(nonce + 8, (uint32_t)(counter >> 32));
}

#if WG_USE_OPENSSL

typedef struct {
    EVP_CIPHER_CTX *ctx;
    uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN];
    bool initialized;
} wg_evp_cache_t;

/* Constant-time key comparison for the per-packet cache check.
 * sodium_memcmp() walks bytes through a volatile pointer: ~9.8 ns per
 * 32-byte call against <1 ns for this (Apple M5 Max, experiment #44),
 * about 1% of a 1420-byte AEAD. The empty asm hides diff from the
 * optimizer so it cannot turn the OR chain into early-exit branches;
 * MSVC has no equivalent; build_wgc.bat builds Windows with libsodium. */
static inline bool evp_key_equal(const uint8_t a[WG_NOISE_SYMMETRIC_KEY_LEN],
                                 const uint8_t b[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    uint64_t diff = 0;
    for (size_t i = 0; i < WG_NOISE_SYMMETRIC_KEY_LEN; i += 8) {
        uint64_t wa, wb;
        memcpy(&wa, a + i, 8);
        memcpy(&wb, b + i, 8);
        diff |= wa ^ wb;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(diff));
#endif
    return diff == 0;
}

/* Each thread keeps its own contexts so the data path takes no lock.
 * _Thread_local has no destructor, so the contexts are also registered with
 * a thread-exit callback that frees them and wipes the cached keys. They
 * live on the heap because that callback can run after the thread's
 * _Thread_local storage is gone: neither macOS nor Windows orders it. */
typedef struct {
    wg_evp_cache_t enc;
    wg_evp_cache_t dec;
} wg_evp_caches_t;

/* After the thread-exit callback frees the caches, this still points at the
 * freed memory; it cannot be cleared there, because the callback may run
 * after the _Thread_local storage is gone. So AEAD must not run from another
 * thread-exit destructor on the same thread. Nothing in the tree does. */
static _Thread_local wg_evp_caches_t *tls_evp_caches;

static void evp_caches_free(void *arg)
{
    wg_evp_caches_t *c = arg;
    EVP_CIPHER_CTX_free(c->enc.ctx);
    EVP_CIPHER_CTX_free(c->dec.ctx);
    wg_secure_zero(c, sizeof(*c));
    free(c);
}

#ifdef _WIN32
static DWORD evp_caches_slot = FLS_OUT_OF_INDEXES;
static INIT_ONCE evp_caches_once = INIT_ONCE_STATIC_INIT;

static VOID WINAPI evp_caches_free_fls(PVOID arg)
{
    if (arg)
        evp_caches_free(arg);
}

static BOOL CALLBACK evp_caches_slot_init(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once;
    (void)param;
    (void)ctx;
    evp_caches_slot = FlsAlloc(evp_caches_free_fls);
    return TRUE;
}

static bool evp_caches_register(wg_evp_caches_t *c)
{
    InitOnceExecuteOnce(&evp_caches_once, evp_caches_slot_init, NULL, NULL);
    return evp_caches_slot != FLS_OUT_OF_INDEXES && FlsSetValue(evp_caches_slot, c);
}
#else
static pthread_key_t evp_caches_key;
static bool evp_caches_key_ok;
static pthread_once_t evp_caches_once = PTHREAD_ONCE_INIT;

static void evp_caches_key_init(void)
{
    evp_caches_key_ok = pthread_key_create(&evp_caches_key, evp_caches_free) == 0;
}

static bool evp_caches_register(wg_evp_caches_t *c)
{
    return pthread_once(&evp_caches_once, evp_caches_key_init) == 0 &&
           evp_caches_key_ok && pthread_setspecific(evp_caches_key, c) == 0;
}
#endif

static wg_evp_caches_t *evp_caches(void)
{
    wg_evp_caches_t *c = tls_evp_caches;
    if (c)
        return c;
    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    if (!evp_caches_register(c)) {
        free(c);
        return NULL;
    }
    tls_evp_caches = c;
    return c;
}

wg_error_t wg_aead_encrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce_val,
                           const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    uint8_t nonce[12];
    make_nonce(nonce, nonce_val);

    wg_evp_caches_t *caches = evp_caches();
    if (!caches)
        return WG_ERR_ENCRYPT;
    wg_evp_cache_t *c = &caches->enc;
    if (!c->ctx) {
        c->ctx = EVP_CIPHER_CTX_new();
        if (!c->ctx)
            return WG_ERR_ENCRYPT;
    }

    if (!c->initialized) {
        if (EVP_EncryptInit_ex(c->ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
            return WG_ERR_ENCRYPT;
        memcpy(c->key, key, WG_NOISE_SYMMETRIC_KEY_LEN);
        c->initialized = true;
    } else if (!evp_key_equal(c->key, key)) {
        if (EVP_EncryptInit_ex(c->ctx, NULL, NULL, key, nonce) != 1)
            return WG_ERR_ENCRYPT;
        memcpy(c->key, key, WG_NOISE_SYMMETRIC_KEY_LEN);
    } else {
        if (EVP_EncryptInit_ex(c->ctx, NULL, NULL, NULL, nonce) != 1)
            return WG_ERR_ENCRYPT;
    }

    int outl = 0;
    if (ad && ad_len > 0) {
        if (EVP_EncryptUpdate(c->ctx, NULL, &outl, ad, (int)ad_len) != 1)
            return WG_ERR_ENCRYPT;
    }
    if (EVP_EncryptUpdate(c->ctx, dst, &outl, src, (int)src_len) != 1)
        return WG_ERR_ENCRYPT;

    int finl = 0;
    if (EVP_EncryptFinal_ex(c->ctx, dst + outl, &finl) != 1)
        return WG_ERR_ENCRYPT;
    if (EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_AEAD_GET_TAG, 16, dst + outl + finl) != 1)
        return WG_ERR_ENCRYPT;

    if (dst_len)
        *dst_len = (size_t)(outl + finl + 16);
    return WG_OK;
}

wg_error_t wg_aead_decrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce_val,
                           const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    if (src_len < 16)
        return WG_ERR_TRANSPORT_DECRYPT;

    uint8_t nonce[12];
    make_nonce(nonce, nonce_val);
    size_t ct_len = src_len - 16;
    const uint8_t *tag = src + ct_len;

    wg_evp_caches_t *caches = evp_caches();
    if (!caches)
        return WG_ERR_TRANSPORT_DECRYPT;
    wg_evp_cache_t *c = &caches->dec;
    if (!c->ctx) {
        c->ctx = EVP_CIPHER_CTX_new();
        if (!c->ctx)
            return WG_ERR_TRANSPORT_DECRYPT;
    }

    if (!c->initialized) {
        if (EVP_DecryptInit_ex(c->ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
            return WG_ERR_TRANSPORT_DECRYPT;
        memcpy(c->key, key, WG_NOISE_SYMMETRIC_KEY_LEN);
        c->initialized = true;
    } else if (!evp_key_equal(c->key, key)) {
        if (EVP_DecryptInit_ex(c->ctx, NULL, NULL, key, nonce) != 1)
            return WG_ERR_TRANSPORT_DECRYPT;
        memcpy(c->key, key, WG_NOISE_SYMMETRIC_KEY_LEN);
    } else {
        if (EVP_DecryptInit_ex(c->ctx, NULL, NULL, NULL, nonce) != 1)
            return WG_ERR_TRANSPORT_DECRYPT;
    }

    /* The tag may be set any time before Final. Setting it before any
     * plaintext is written leaves one less failure after that point. */
    if (EVP_CIPHER_CTX_ctrl(c->ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1)
        return WG_ERR_TRANSPORT_DECRYPT;

    int outl = 0, finl = 0;
    if (ad && ad_len > 0) {
        if (EVP_DecryptUpdate(c->ctx, NULL, &outl, ad, (int)ad_len) != 1)
            return WG_ERR_TRANSPORT_DECRYPT;
    }

    /* From here on EVP_DecryptUpdate may have written plaintext to dst
     * (possibly only part of it) before the tag is checked in Final. Every
     * failure wipes dst so unauthenticated plaintext never outlives this
     * call (dst is often the reused receive buffer). */
    if (EVP_DecryptUpdate(c->ctx, dst, &outl, src, (int)ct_len) != 1)
        goto fail;
    if (EVP_DecryptFinal_ex(c->ctx, dst + outl, &finl) != 1)
        goto fail;

    if (dst_len)
        *dst_len = (size_t)(outl + finl);
    return WG_OK;

fail:
    wg_secure_zero(dst, ct_len);
    return WG_ERR_TRANSPORT_DECRYPT;
}

#else /* libsodium backend (fallback) */

wg_error_t wg_aead_encrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce_val,
                           const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    uint8_t nonce[12];
    make_nonce(nonce, nonce_val);

    unsigned long long clen;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(dst, &clen, src, src_len, ad, ad_len,
                                                  NULL, nonce, key) != 0)
        return WG_ERR_ENCRYPT;

    if (dst_len)
        *dst_len = (size_t)clen;
    return WG_OK;
}

wg_error_t wg_aead_decrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                           size_t src_len, const uint8_t *ad, size_t ad_len,
                           uint64_t nonce_val,
                           const uint8_t key[WG_NOISE_SYMMETRIC_KEY_LEN])
{
    uint8_t nonce[12];
    make_nonce(nonce, nonce_val);

    unsigned long long mlen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(dst, &mlen, NULL, src, src_len, ad,
                                                  ad_len, nonce, key) != 0)
        return WG_ERR_TRANSPORT_DECRYPT;

    if (dst_len)
        *dst_len = (size_t)mlen;
    return WG_OK;
}

#endif /* WG_USE_OPENSSL */

/* ════════════════════════════════════════
 * XChaCha20-Poly1305 (for cookie encryption)
 * ════════════════════════════════════════ */

wg_error_t wg_xchacha20poly1305_encrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                                        size_t src_len, const uint8_t *ad, size_t ad_len,
                                        const uint8_t nonce[24], const uint8_t key[32])
{
    unsigned long long clen;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(dst, &clen, src, src_len, ad, ad_len,
                                                   NULL, nonce, key) != 0)
        return WG_ERR_COOKIE_INVALID;

    if (dst_len)
        *dst_len = (size_t)clen;
    return WG_OK;
}

wg_error_t wg_xchacha20poly1305_decrypt(uint8_t *dst, size_t *dst_len, const uint8_t *src,
                                        size_t src_len, const uint8_t *ad, size_t ad_len,
                                        const uint8_t nonce[24], const uint8_t key[32])
{
    unsigned long long mlen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(dst, &mlen, NULL, src, src_len, ad,
                                                   ad_len, nonce, key) != 0)
        return WG_ERR_COOKIE_INVALID;

    if (dst_len)
        *dst_len = (size_t)mlen;
    return WG_OK;
}

/* ════════════════════════════════════════
 * MAC (keyed BLAKE2s, 16-byte output for mac1/mac2)
 * ════════════════════════════════════════ */

void wg_mac(uint8_t dst[WG_COOKIE_LEN], const uint8_t *key, size_t keylen,
            const uint8_t *in, size_t inlen)
{
    wg_blake2s(dst, WG_COOKIE_LEN, in, inlen, key, keylen);
}

/* ════════════════════════════════════════
 * TAI64N timestamp
 *
 * TAI64N = 8 bytes TAI64 + 4 bytes nanoseconds
 * TAI64 = seconds since 1970 + 2^62
 * ════════════════════════════════════════ */

void wg_tai64n_now(uint8_t out[WG_TIMESTAMP_LEN])
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    uint64_t sec = (uint64_t)ts.tv_sec + 0x400000000000000aULL;
    /* Mask low 24 bits to prevent timing side-channel leakage of clock
     * precision. wireguard-go: whitenerMask = 0x00FFFFFF, applied as nsec &^=
     * whitenerMask. Rounds down to ~16ms granularity (2^24 ns ≈ 16.7ms). */
    uint32_t nsec = (uint32_t)ts.tv_nsec & ~((uint32_t)0xFFFFFF);

    out[0] = (uint8_t)(sec >> 56);
    out[1] = (uint8_t)(sec >> 48);
    out[2] = (uint8_t)(sec >> 40);
    out[3] = (uint8_t)(sec >> 32);
    out[4] = (uint8_t)(sec >> 24);
    out[5] = (uint8_t)(sec >> 16);
    out[6] = (uint8_t)(sec >> 8);
    out[7] = (uint8_t)(sec);
    out[8] = (uint8_t)(nsec >> 24);
    out[9] = (uint8_t)(nsec >> 16);
    out[10] = (uint8_t)(nsec >> 8);
    out[11] = (uint8_t)(nsec);
}

bool wg_tai64n_after(const uint8_t a[WG_TIMESTAMP_LEN], const uint8_t b[WG_TIMESTAMP_LEN])
{
    return memcmp(a, b, WG_TIMESTAMP_LEN) > 0;
}

/* ════════════════════════════════════════
 * Secure memory helpers
 * ════════════════════════════════════════ */

void wg_secure_zero(void *ptr, size_t len)
{
    sodium_memzero(ptr, len);
}

bool wg_is_zero(const uint8_t *buf, size_t len)
{
    return sodium_is_zero(buf, len);
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * NOISE-1 verification: crypto primitives with known test vectors.
 */

#include "../include/wireguard.h"
#include "../src/crypto/wg_crypto.h"
#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ── Hex decode helper ── */

static size_t hex_decode(uint8_t *out, size_t out_max, const char *hex)
{
    size_t len = strlen(hex) / 2;
    assert(len <= out_max);
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02x", &byte);
        out[i] = (uint8_t)byte;
    }
    return len;
}

static void hex_encode(char *out, const uint8_t *in, size_t len)
{
    for (size_t i = 0; i < len; i++)
        snprintf(out + 2 * i, 3, "%02x", in[i]);
    out[2 * len] = '\0';
}

/* ── BLAKE2s test vectors ── */

static void test_blake2s_empty(void)
{
    static const uint8_t expected[32] = {
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21,
        0xd0, 0x42, 0x35, 0x4a, 0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1,
        0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
    };
    uint8_t out[32];
    wg_blake2s(out, 32, (const uint8_t *)"", 0, NULL, 0);
    assert(memcmp(out, expected, 32) == 0);
}

static void test_blake2s_abc(void)
{
    static const uint8_t expected[32] = {
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b,
        0xa3, 0x4e, 0xeb, 0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6,
        0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
    };
    uint8_t out[32];
    wg_blake2s(out, 32, (const uint8_t *)"abc", 3, NULL, 0);
    assert(memcmp(out, expected, 32) == 0);
}

static void test_blake2s_keyed(void)
{
    /* BLAKE2s-256 with 32-byte key and 1-byte input from RFC 7693 */
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t input[1] = {0x00};
    static const uint8_t expected[32] = {
        0x40, 0xd1, 0x5f, 0xee, 0x7c, 0x32, 0x88, 0x30, 0x16, 0x6a, 0xc3,
        0xf9, 0x18, 0x65, 0x0f, 0x80, 0x7e, 0x7e, 0x01, 0xe1, 0x77, 0x25,
        0x8c, 0xdc, 0x0a, 0x39, 0xb1, 0x1f, 0x59, 0x80, 0x66, 0xf1,
    };
    uint8_t out[32];
    wg_blake2s(out, 32, input, 1, key, 32);
    assert(memcmp(out, expected, 32) == 0);
}

static void test_blake2s_16byte_output(void)
{
    /* BLAKE2s with 16-byte output (used for MAC1/MAC2) */
    uint8_t key[32];
    memset(key, 0xaa, 32);
    uint8_t out[16];
    wg_blake2s(out, 16, (const uint8_t *)"test", 4, key, 32);
    assert(!wg_is_zero(out, 16));
}

/* ── HMAC-BLAKE2s tests ── */

static void test_hmac_deterministic(void)
{
    uint8_t key[32];
    memset(key, 0x0b, 32);
    uint8_t out1[32], out2[32];
    wg_hmac(out1, key, 32, (const uint8_t *)"Hi There", 8);
    wg_hmac(out2, key, 32, (const uint8_t *)"Hi There", 8);
    assert(memcmp(out1, out2, 32) == 0);
    assert(!wg_is_zero(out1, 32));
}

static void test_hmac_different_keys(void)
{
    uint8_t key1[32], key2[32];
    memset(key1, 0x01, 32);
    memset(key2, 0x02, 32);
    uint8_t out1[32], out2[32];
    wg_hmac(out1, key1, 32, (const uint8_t *)"msg", 3);
    wg_hmac(out2, key2, 32, (const uint8_t *)"msg", 3);
    assert(memcmp(out1, out2, 32) != 0);
}

static void test_hmac_empty_input(void)
{
    uint8_t key[32];
    memset(key, 0xaa, 32);
    uint8_t out[32];
    wg_hmac(out, key, 32, NULL, 0);
    assert(!wg_is_zero(out, 32));

    /* Same key, same empty input → same output */
    uint8_t out2[32];
    wg_hmac(out2, key, 32, (const uint8_t *)"", 0);
    assert(memcmp(out, out2, 32) == 0);
}

static void test_hmac2_vs_concat(void)
{
    uint8_t key[32];
    memset(key, 0xcc, 32);
    uint8_t in0[] = "part1";
    uint8_t in1[] = "part2";

    uint8_t hmac2_out[32];
    wg_hmac2(hmac2_out, key, 32, in0, 5, in1, 5);

    /* HMAC of concatenation should match HMAC2 */
    uint8_t concat[10];
    memcpy(concat, in0, 5);
    memcpy(concat + 5, in1, 5);
    uint8_t hmac_out[32];
    wg_hmac(hmac_out, key, 32, concat, 10);

    assert(memcmp(hmac2_out, hmac_out, 32) == 0);
}

/* ── KDF tests with known vectors from wireguard-go/device/kdf_test.go ── */

typedef struct {
    const char *key;
    const char *input;
    const char *t0;
    const char *t1;
    const char *t2;
} kdf_test_vector_t;

static const kdf_test_vector_t kdf_vectors[] = {
    {
        .key = "746573742d6b6579",
        .input = "746573742d696e707574",
        .t0 = "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
        .t1 = "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
        .t2 = "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
    },
    {
        .key = "776972656775617264",
        .input = "776972656775617264",
        .t0 = "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
        .t1 = "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
        .t2 = "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
    },
    {
        .key = "",
        .input = "",
        .t0 = "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
        .t1 = "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
        .t2 = "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
    },
};

static void test_kdf3_vectors(void)
{
    for (size_t i = 0; i < sizeof(kdf_vectors) / sizeof(kdf_vectors[0]); i++) {
        const kdf_test_vector_t *v = &kdf_vectors[i];
        uint8_t key[64], input[64];
        size_t keylen = hex_decode(key, sizeof(key), v->key);
        size_t inputlen = hex_decode(input, sizeof(input), v->input);

        uint8_t t0[32], t1[32], t2[32];
        wg_kdf3(t0, t1, t2, key, keylen, input, inputlen);

        char hex_out[65];
        hex_encode(hex_out, t0, 32);
        assert(strcmp(hex_out, v->t0) == 0);
        hex_encode(hex_out, t1, 32);
        assert(strcmp(hex_out, v->t1) == 0);
        hex_encode(hex_out, t2, 32);
        assert(strcmp(hex_out, v->t2) == 0);
    }
}

static void test_kdf2_vectors(void)
{
    for (size_t i = 0; i < sizeof(kdf_vectors) / sizeof(kdf_vectors[0]); i++) {
        const kdf_test_vector_t *v = &kdf_vectors[i];
        uint8_t key[64], input[64];
        size_t keylen = hex_decode(key, sizeof(key), v->key);
        size_t inputlen = hex_decode(input, sizeof(input), v->input);

        uint8_t t0[32], t1[32];
        wg_kdf2(t0, t1, key, keylen, input, inputlen);

        char hex_out[65];
        hex_encode(hex_out, t0, 32);
        assert(strcmp(hex_out, v->t0) == 0);
        hex_encode(hex_out, t1, 32);
        assert(strcmp(hex_out, v->t1) == 0);
    }
}

static void test_kdf1_vectors(void)
{
    for (size_t i = 0; i < sizeof(kdf_vectors) / sizeof(kdf_vectors[0]); i++) {
        const kdf_test_vector_t *v = &kdf_vectors[i];
        uint8_t key[64], input[64];
        size_t keylen = hex_decode(key, sizeof(key), v->key);
        size_t inputlen = hex_decode(input, sizeof(input), v->input);

        uint8_t t0[32];
        wg_kdf1(t0, key, keylen, input, inputlen);

        char hex_out[65];
        hex_encode(hex_out, t0, 32);
        assert(strcmp(hex_out, v->t0) == 0);
    }
}

/* ── X25519 ── */

static void test_x25519_roundtrip(void)
{
    uint8_t sk_a[32], pk_a[32];
    uint8_t sk_b[32], pk_b[32];
    uint8_t shared_a[32], shared_b[32];

    assert(wg_x25519_generate_private(sk_a) == WG_OK);
    wg_x25519_public_key(pk_a, sk_a);

    assert(wg_x25519_generate_private(sk_b) == WG_OK);
    wg_x25519_public_key(pk_b, sk_b);

    assert(wg_x25519(shared_a, sk_a, pk_b) == WG_OK);
    assert(wg_x25519(shared_b, sk_b, pk_a) == WG_OK);
    assert(memcmp(shared_a, shared_b, 32) == 0);
}

static void test_x25519_zero_pubkey(void)
{
    uint8_t sk[32], zero_pk[32] = {0};
    uint8_t out[32];
    wg_x25519_generate_private(sk);
    assert(wg_x25519(out, sk, zero_pk) != WG_OK);
}

/* ── AEAD (ChaCha20-Poly1305) ── */

static void test_aead_roundtrip(void)
{
    uint8_t key[32];
    randombytes_buf(key, 32);

    const uint8_t plaintext[] = "Hello, WireGuard!";
    const uint8_t ad[] = "additional data";
    size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[64];
    size_t ct_len;
    assert(wg_aead_encrypt(ciphertext, &ct_len, plaintext, pt_len, ad, sizeof(ad) - 1, 42,
                           key) == WG_OK);
    assert(ct_len == pt_len + 16);

    uint8_t decrypted[64];
    size_t dec_len;
    assert(wg_aead_decrypt(decrypted, &dec_len, ciphertext, ct_len, ad, sizeof(ad) - 1,
                           42, key) == WG_OK);
    assert(dec_len == pt_len);
    assert(memcmp(decrypted, plaintext, pt_len) == 0);
}

static void test_aead_tamper(void)
{
    uint8_t key[32];
    randombytes_buf(key, 32);

    const uint8_t pt[] = "data";
    uint8_t ct[32];
    size_t ct_len;
    wg_aead_encrypt(ct, &ct_len, pt, 4, NULL, 0, 0, key);

    ct[0] ^= 0xff;

    uint8_t out[32];
    size_t out_len;
    assert(wg_aead_decrypt(out, &out_len, ct, ct_len, NULL, 0, 0, key) ==
           WG_ERR_TRANSPORT_DECRYPT);
}

/* The receive path decrypts in place into a reused buffer. A forged packet
 * must not leave unauthenticated plaintext behind in it. */
static void test_aead_tamper_wipes_output(void)
{
    uint8_t key[32];
    randombytes_buf(key, 32);

    enum { PT_LEN = 1420 };
    uint8_t pt[PT_LEN];
    randombytes_buf(pt, sizeof(pt));
    uint8_t buf[PT_LEN + 16];
    size_t ct_len;
    assert(wg_aead_encrypt(buf, &ct_len, pt, PT_LEN, NULL, 0, 7, key) == WG_OK);

    buf[ct_len - 1] ^= 0x01; /* corrupt the tag only */

    size_t out_len = 0;
    assert(wg_aead_decrypt(buf, &out_len, buf, ct_len, NULL, 0, 7, key) ==
           WG_ERR_TRANSPORT_DECRYPT);
    assert(wg_is_zero(buf, PT_LEN));
}

/* The OpenSSL backend caches the last key per thread and compares it on
 * every call. Keys differing only in the first or last 8-byte word must
 * still force a re-key, and switching back must work. */
static void test_aead_key_switch(void)
{
    uint8_t k_a[32], k_first[32], k_last[32];
    randombytes_buf(k_a, 32);
    memcpy(k_first, k_a, 32);
    k_first[0] ^= 0x80;
    memcpy(k_last, k_a, 32);
    k_last[31] ^= 0x01;

    const uint8_t *keys[] = {k_a, k_first, k_a, k_last, k_a};
    const uint8_t pt[] = "key switch";
    uint8_t ct[5][sizeof(pt) - 1 + 16];
    size_t ct_len;

    for (int i = 0; i < 5; i++)
        assert(wg_aead_encrypt(ct[i], &ct_len, pt, sizeof(pt) - 1, NULL, 0, 1, keys[i]) ==
               WG_OK);

    /* Same key and nonce give the same ciphertext; any other key does not. */
    assert(memcmp(ct[0], ct[2], ct_len) == 0);
    assert(memcmp(ct[0], ct[4], ct_len) == 0);
    assert(memcmp(ct[0], ct[1], ct_len) != 0);
    assert(memcmp(ct[0], ct[3], ct_len) != 0);

    uint8_t out[sizeof(pt)];
    size_t out_len;
    for (int i = 0; i < 5; i++) {
        assert(wg_aead_decrypt(out, &out_len, ct[i], ct_len, NULL, 0, 1, keys[i]) ==
               WG_OK);
        assert(out_len == sizeof(pt) - 1 && memcmp(out, pt, out_len) == 0);
    }
    assert(wg_aead_decrypt(out, &out_len, ct[1], ct_len, NULL, 0, 1, k_a) ==
           WG_ERR_TRANSPORT_DECRYPT);
    assert(wg_aead_decrypt(out, &out_len, ct[3], ct_len, NULL, 0, 1, k_a) ==
           WG_ERR_TRANSPORT_DECRYPT);
}

/* Each thread creates its own AEAD contexts on first use. Under ASan with
 * detect_leaks=1, LeakSanitizer fails this test if they outlive the thread. */
static void *aead_thread(void *arg)
{
    (void)arg;
    test_aead_roundtrip();
    test_aead_tamper();
    test_aead_tamper_wipes_output();
    test_aead_key_switch();
    return NULL;
}

static void test_aead_thread_exit(void)
{
    enum { THREADS = 4 };
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++)
        assert(pthread_create(&threads[i], NULL, aead_thread, NULL) == 0);
    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);
}

/* ── XChaCha20-Poly1305 (cookie) ── */

static void test_xchacha_roundtrip(void)
{
    uint8_t key[32], nonce[24];
    randombytes_buf(key, 32);
    randombytes_buf(nonce, 24);

    const uint8_t pt[] = "cookie_plaintext";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[64];
    size_t ct_len;

    assert(wg_xchacha20poly1305_encrypt(ct, &ct_len, pt, pt_len, NULL, 0, nonce, key) ==
           WG_OK);

    uint8_t dec[64];
    size_t dec_len;
    assert(wg_xchacha20poly1305_decrypt(dec, &dec_len, ct, ct_len, NULL, 0, nonce, key) ==
           WG_OK);
    assert(dec_len == pt_len);
    assert(memcmp(dec, pt, pt_len) == 0);
}

/* ── TAI64N ── */

static void test_tai64n(void)
{
    uint8_t ts1[12], ts2[12];
    wg_tai64n_now(ts1);
    for (volatile int i = 0; i < 100000; i++)
        ;
    wg_tai64n_now(ts2);

    assert(!wg_is_zero(ts1, 12));
    assert(memcmp(ts2, ts1, 12) >= 0);
}

/* ── MixHash / MixKey ── */

static void test_mix_hash(void)
{
    uint8_t hash[32];
    memset(hash, 0x11, 32);
    uint8_t original[32];
    memcpy(original, hash, 32);

    wg_mix_hash(hash, (const uint8_t *)"test", 4);
    assert(memcmp(hash, original, 32) != 0);
}

static void test_mix_key(void)
{
    uint8_t ck[32], key[32];
    memset(ck, 0x22, 32);
    memset(key, 0x00, 32);

    wg_mix_key(ck, key, (const uint8_t *)"ikm", 3);
    assert(!wg_is_zero(ck, 32));
    assert(!wg_is_zero(key, 32));
}

/* ── MAC (16 bytes) ── */

static void test_mac(void)
{
    uint8_t key[32];
    memset(key, 0x55, 32);
    uint8_t mac[16];
    wg_mac(mac, key, 32, (const uint8_t *)"msg", 3);
    assert(!wg_is_zero(mac, 16));
}

/* ── secure_zero / key_zero ── */

static void test_secure_zero(void)
{
    uint8_t buf[64];
    memset(buf, 0xff, 64);
    wg_secure_zero(buf, 64);
    assert(wg_is_zero(buf, 64));
}

static void test_key_zero(void)
{
    wg_key_t k;
    memset(k.key, 0xff, WG_KEY_LEN);
    wg_key_zero(&k);
    assert(wg_is_zero(k.key, WG_KEY_LEN));
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    /* BLAKE2s */
    test_blake2s_empty();
    test_blake2s_abc();
    test_blake2s_keyed();
    test_blake2s_16byte_output();

    /* HMAC-BLAKE2s */
    test_hmac_deterministic();
    test_hmac_different_keys();
    test_hmac_empty_input();
    test_hmac2_vs_concat();

    /* KDF with known vectors from wireguard-go */
    test_kdf3_vectors();
    test_kdf2_vectors();
    test_kdf1_vectors();

    /* X25519 */
    test_x25519_roundtrip();
    test_x25519_zero_pubkey();

    /* AEAD */
    test_aead_roundtrip();
    test_aead_tamper();
    test_aead_tamper_wipes_output();
    test_aead_key_switch();
    test_aead_thread_exit();

    /* XChaCha */
    test_xchacha_roundtrip();

    /* TAI64N */
    test_tai64n();

    /* Noise helpers */
    test_mix_hash();
    test_mix_key();

    /* MAC */
    test_mac();

    /* Memory */
    test_secure_zero();
    test_key_zero();

    printf("All NOISE-1 crypto tests passed (with known vectors).\n");
    return 0;
}

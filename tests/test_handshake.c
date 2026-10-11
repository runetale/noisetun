/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * HS-1 verification: Handshake Initiation create / consume round-trip.
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helper: set up an initiator–responder pair
 * ──────────────────────────────────────── */
typedef struct {
    wg_noise_static_identity_t si_i; /* initiator identity */
    wg_noise_static_identity_t si_r; /* responder identity */
    wg_noise_handshake_t hs_i;       /* initiator handshake */
    wg_noise_handshake_t hs_r;       /* responder handshake */
} test_pair_t;

static void pair_init(test_pair_t *p, const uint8_t *psk)
{
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_module_init();

    /* Initiator identity */
    wg_noise_static_identity_init(&p->si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&p->si_i, sk_i);

    /* Responder identity */
    wg_noise_static_identity_init(&p->si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&p->si_r, sk_r);

    /* Initiator's handshake: knows responder's static public key */
    wg_noise_handshake_init(&p->hs_i, &p->si_i, p->si_r.static_public, psk);

    /* Responder's handshake: knows initiator's static public key.
     * consume_initiation will overwrite the Noise state (hash, ck, etc.)
     * but remote_static and preshared_key must be set for HS-2. */
    wg_noise_handshake_init(&p->hs_r, &p->si_r, p->si_i.static_public, psk);

    wg_secure_zero(sk_i, WG_KEY_LEN);
    wg_secure_zero(sk_r, WG_KEY_LEN);
}

static void pair_destroy(test_pair_t *p)
{
    pthread_rwlock_destroy(&p->hs_i.lock);
    pthread_rwlock_destroy(&p->hs_r.lock);
    pthread_rwlock_destroy(&p->si_i.lock);
    pthread_rwlock_destroy(&p->si_r.lock);
}

/* ────────────────────────────────────────
 * Test 1: basic create → consume round-trip
 * ──────────────────────────────────────── */
static void test_create_consume_roundtrip(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    /* Assign a random local index (placeholder for index allocator) */
    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    /* Create initiation */
    wg_message_initiation_t msg;
    memset(&msg, 0, sizeof(msg));
    wg_error_t err = wg_noise_handshake_create_initiation(&msg, &p.hs_i);
    assert(err == WG_OK);

    /* Verify message structure */
    assert(wg_le32toh(msg.header.type) == WG_MESSAGE_INITIATION);
    assert(wg_le32toh(msg.sender_index) == p.hs_i.local_index);
    assert(!wg_is_zero(msg.unencrypted_ephemeral, WG_KEY_LEN));
    assert(!wg_is_zero(msg.encrypted_static, sizeof(msg.encrypted_static)));
    assert(!wg_is_zero(msg.encrypted_timestamp, sizeof(msg.encrypted_timestamp)));

    /* Verify handshake state advanced */
    assert(p.hs_i.pending.state == WG_HANDSHAKE_CREATED_INITIATION);

    /* Consume initiation */
    uint8_t decrypted_static[WG_KEY_LEN];
    err = wg_noise_handshake_consume_initiation(&p.hs_r, &msg, decrypted_static);
    assert(err == WG_OK);

    /* Verify the decrypted static key matches the initiator's public key */
    assert(memcmp(decrypted_static, p.si_i.static_public, WG_KEY_LEN) == 0);

    /* Verify responder handshake state */
    assert(p.hs_r.pending.state == WG_HANDSHAKE_CONSUMED_INITIATION);
    assert(p.hs_r.pending.remote_index == p.hs_i.local_index);
    assert(!wg_is_zero(p.hs_r.pending.remote_ephemeral, WG_KEY_LEN));
    assert(!wg_is_zero(p.hs_r.pending.hash, WG_NOISE_HASH_LEN));
    assert(!wg_is_zero(p.hs_r.pending.chaining_key, WG_NOISE_HASH_LEN));
    assert(!wg_is_zero(p.hs_r.latest_timestamp, WG_TIMESTAMP_LEN));

    pair_destroy(&p);
    printf("  PASS: create_consume_roundtrip\n");
}

/* ────────────────────────────────────────
 * Test 2: Noise state (hash, ck) must match
 *         between initiator and responder
 * ──────────────────────────────────────── */
static void test_noise_state_agreement(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    wg_message_initiation_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(wg_noise_handshake_create_initiation(&msg, &p.hs_i) == WG_OK);

    uint8_t decrypted_static[WG_KEY_LEN];
    assert(wg_noise_handshake_consume_initiation(&p.hs_r, &msg, decrypted_static) ==
           WG_OK);

    /* After create+consume, both sides must agree on hash and chaining_key.
     * This is essential: the response message continues from this shared state.
     */
    assert(memcmp(p.hs_i.pending.hash, p.hs_r.pending.hash, WG_NOISE_HASH_LEN) == 0);
    assert(memcmp(p.hs_i.pending.chaining_key, p.hs_r.pending.chaining_key,
                  WG_NOISE_HASH_LEN) == 0);

    pair_destroy(&p);
    printf("  PASS: noise_state_agreement\n");
}

/* ────────────────────────────────────────
 * Test 3: with preshared key
 * ──────────────────────────────────────── */
static void test_with_preshared_key(void)
{
    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    randombytes_buf(psk, sizeof(psk));

    test_pair_t p;
    pair_init(&p, psk);

    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    wg_message_initiation_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(wg_noise_handshake_create_initiation(&msg, &p.hs_i) == WG_OK);

    uint8_t decrypted_static[WG_KEY_LEN];
    assert(wg_noise_handshake_consume_initiation(&p.hs_r, &msg, decrypted_static) ==
           WG_OK);

    assert(memcmp(decrypted_static, p.si_i.static_public, WG_KEY_LEN) == 0);
    assert(memcmp(p.hs_i.pending.hash, p.hs_r.pending.hash, WG_NOISE_HASH_LEN) == 0);
    assert(memcmp(p.hs_i.pending.chaining_key, p.hs_r.pending.chaining_key,
                  WG_NOISE_HASH_LEN) == 0);

    pair_destroy(&p);
    printf("  PASS: with_preshared_key\n");
}

/* ────────────────────────────────────────
 * Test 4: tampered message must fail
 * ──────────────────────────────────────── */
static void test_tampered_message_fails(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    wg_message_initiation_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(wg_noise_handshake_create_initiation(&msg, &p.hs_i) == WG_OK);

    /* Tamper: flip a byte in the encrypted static field */
    wg_message_initiation_t bad_msg;
    memcpy(&bad_msg, &msg, sizeof(msg));
    bad_msg.encrypted_static[10] ^= 0xFF;

    uint8_t decrypted_static[WG_KEY_LEN];
    wg_error_t err =
        wg_noise_handshake_consume_initiation(&p.hs_r, &bad_msg, decrypted_static);
    assert(err != WG_OK);

    /* Tamper: flip a byte in the encrypted timestamp */
    memcpy(&bad_msg, &msg, sizeof(msg));
    bad_msg.encrypted_timestamp[5] ^= 0xFF;

    /* Reset responder state for retry */
    p.hs_r.pending.state = WG_HANDSHAKE_ZEROED;
    err = wg_noise_handshake_consume_initiation(&p.hs_r, &bad_msg, decrypted_static);
    assert(err != WG_OK);

    /* Tamper: flip ephemeral key (breaks DH) */
    memcpy(&bad_msg, &msg, sizeof(msg));
    bad_msg.unencrypted_ephemeral[0] ^= 0xFF;

    p.hs_r.pending.state = WG_HANDSHAKE_ZEROED;
    err = wg_noise_handshake_consume_initiation(&p.hs_r, &bad_msg, decrypted_static);
    assert(err != WG_OK);

    pair_destroy(&p);
    printf("  PASS: tampered_message_fails\n");
}

/* ────────────────────────────────────────
 * Test 5: wrong responder rejects
 * ──────────────────────────────────────── */
static void test_wrong_responder_rejects(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    wg_message_initiation_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(wg_noise_handshake_create_initiation(&msg, &p.hs_i) == WG_OK);

    /* Create a third party with different keys */
    wg_noise_static_identity_t si_wrong;
    wg_noise_static_identity_init(&si_wrong);
    uint8_t sk_wrong[WG_KEY_LEN];
    wg_x25519_generate_private(sk_wrong);
    wg_noise_static_identity_set_private_key(&si_wrong, sk_wrong);

    wg_noise_handshake_t hs_wrong;
    memset(&hs_wrong, 0, sizeof(hs_wrong));
    pthread_rwlock_init(&hs_wrong.lock, NULL);
    hs_wrong.static_identity = &si_wrong;
    hs_wrong.pending.state = WG_HANDSHAKE_ZEROED;

    uint8_t decrypted_static[WG_KEY_LEN];
    wg_error_t err =
        wg_noise_handshake_consume_initiation(&hs_wrong, &msg, decrypted_static);
    assert(err != WG_OK);

    pthread_rwlock_destroy(&hs_wrong.lock);
    pthread_rwlock_destroy(&si_wrong.lock);
    wg_secure_zero(sk_wrong, WG_KEY_LEN);
    pair_destroy(&p);
    printf("  PASS: wrong_responder_rejects\n");
}

/* ────────────────────────────────────────
 * Test 6: no identity must fail
 * ──────────────────────────────────────── */
static void test_no_identity_fails(void)
{
    wg_noise_module_init();

    wg_noise_static_identity_t si;
    wg_noise_static_identity_init(&si);
    /* Don't set a private key — has_identity remains false */

    uint8_t peer_pk[WG_KEY_LEN];
    randombytes_buf(peer_pk, WG_KEY_LEN);

    wg_noise_handshake_t hs;
    memset(&hs, 0, sizeof(hs));
    pthread_rwlock_init(&hs.lock, NULL);
    hs.static_identity = &si;
    hs.pending.state = WG_HANDSHAKE_ZEROED;
    memcpy(hs.remote_static, peer_pk, WG_KEY_LEN);

    wg_message_initiation_t msg;
    wg_error_t err = wg_noise_handshake_create_initiation(&msg, &hs);
    assert(err == WG_ERR_INVALID_KEY);

    pthread_rwlock_destroy(&hs.lock);
    pthread_rwlock_destroy(&si.lock);
    printf("  PASS: no_identity_fails\n");
}

/* ────────────────────────────────────────
 * Test 7: message size is exactly 148 bytes
 * ──────────────────────────────────────── */
static void test_message_size(void)
{
    assert(sizeof(wg_message_initiation_t) == WG_MESSAGE_INITIATION_SIZE);
    assert(sizeof(wg_message_initiation_t) == 148);
    printf("  PASS: message_size\n");
}

/* ────────────────────────────────────────
 * Test 8: multiple create/consume cycles produce
 *         different ephemeral keys and ciphertexts
 * ──────────────────────────────────────── */
static void test_different_ephemeral_each_time(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    randombytes_buf(&p.hs_i.local_index, sizeof(p.hs_i.local_index));

    wg_message_initiation_t msg1, msg2;
    memset(&msg1, 0, sizeof(msg1));
    memset(&msg2, 0, sizeof(msg2));

    assert(wg_noise_handshake_create_initiation(&msg1, &p.hs_i) == WG_OK);

    /* Reset initiator handshake for second attempt */
    wg_noise_handshake_clear(&p.hs_i);
    wg_noise_precompute_static_static(&p.hs_i);

    assert(wg_noise_handshake_create_initiation(&msg2, &p.hs_i) == WG_OK);

    /* Ephemeral keys must differ */
    assert(memcmp(msg1.unencrypted_ephemeral, msg2.unencrypted_ephemeral, WG_KEY_LEN) !=
           0);

    /* Ciphertexts must differ (different ephemeral → different DH → different
     * keys) */
    assert(memcmp(msg1.encrypted_static, msg2.encrypted_static,
                  sizeof(msg1.encrypted_static)) != 0);

    pair_destroy(&p);
    printf("  PASS: different_ephemeral_each_time\n");
}

/* ════════════════════════════════════════
 * HS-2 Handshake Response tests
 * ════════════════════════════════════════ */

/*
 * Helper: run HS-1 exchange (create + consume initiation).
 * Returns with both hs_i and hs_r ready for HS-2.
 */
static void run_hs1(test_pair_t *p)
{
    randombytes_buf(&p->hs_i.local_index, sizeof(p->hs_i.local_index));

    wg_message_initiation_t init_msg;
    memset(&init_msg, 0, sizeof(init_msg));
    assert(wg_noise_handshake_create_initiation(&init_msg, &p->hs_i) == WG_OK);

    uint8_t decrypted_static[WG_KEY_LEN];
    assert(wg_noise_handshake_consume_initiation(&p->hs_r, &init_msg, decrypted_static) ==
           WG_OK);
    assert(memcmp(decrypted_static, p->si_i.static_public, WG_KEY_LEN) == 0);
}

/* ────────────────────────────────────────
 * Test 9: HS-1 → HS-2 full round-trip (no PSK)
 * ──────────────────────────────────────── */
static void test_hs2_roundtrip(void)
{
    test_pair_t p;
    pair_init(&p, NULL);
    run_hs1(&p);

    /* Assign responder local index */
    randombytes_buf(&p.hs_r.local_index, sizeof(p.hs_r.local_index));

    /* Create response */
    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    wg_error_t err = wg_noise_handshake_create_response(&resp, &p.hs_r);
    assert(err == WG_OK);

    /* Verify message structure */
    assert(wg_le32toh(resp.header.type) == WG_MESSAGE_RESPONSE);
    assert(wg_le32toh(resp.sender_index) == p.hs_r.local_index);
    assert(wg_le32toh(resp.receiver_index) == p.hs_i.local_index);
    assert(!wg_is_zero(resp.unencrypted_ephemeral, WG_KEY_LEN));
    assert(!wg_is_zero(resp.encrypted_nothing, sizeof(resp.encrypted_nothing)));
    assert(p.hs_r.pending.state == WG_HANDSHAKE_CREATED_RESPONSE);

    /* Consume response */
    err = wg_noise_handshake_consume_response(&p.hs_i, &resp);
    assert(err == WG_OK);
    assert(p.hs_i.pending.state == WG_HANDSHAKE_CONSUMED_RESPONSE);
    assert(p.hs_i.pending.remote_index == p.hs_r.local_index);

    pair_destroy(&p);
    printf("  PASS: hs2_roundtrip\n");
}

/* ────────────────────────────────────────
 * Test 10: HS-2 Noise state agreement
 * ──────────────────────────────────────── */
static void test_hs2_noise_state_agreement(void)
{
    test_pair_t p;
    pair_init(&p, NULL);
    run_hs1(&p);

    randombytes_buf(&p.hs_r.local_index, sizeof(p.hs_r.local_index));

    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    assert(wg_noise_handshake_create_response(&resp, &p.hs_r) == WG_OK);
    assert(wg_noise_handshake_consume_response(&p.hs_i, &resp) == WG_OK);

    /* After HS-2, both sides must agree on hash and chaining_key */
    assert(memcmp(p.hs_i.pending.hash, p.hs_r.pending.hash, WG_NOISE_HASH_LEN) == 0);
    assert(memcmp(p.hs_i.pending.chaining_key, p.hs_r.pending.chaining_key,
                  WG_NOISE_HASH_LEN) == 0);

    pair_destroy(&p);
    printf("  PASS: hs2_noise_state_agreement\n");
}

/* ────────────────────────────────────────
 * Test 11: HS-2 with preshared key
 * ──────────────────────────────────────── */
static void test_hs2_with_preshared_key(void)
{
    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    randombytes_buf(psk, sizeof(psk));

    test_pair_t p;
    pair_init(&p, psk);
    run_hs1(&p);

    randombytes_buf(&p.hs_r.local_index, sizeof(p.hs_r.local_index));

    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    assert(wg_noise_handshake_create_response(&resp, &p.hs_r) == WG_OK);
    assert(wg_noise_handshake_consume_response(&p.hs_i, &resp) == WG_OK);

    /* State agreement with PSK */
    assert(memcmp(p.hs_i.pending.hash, p.hs_r.pending.hash, WG_NOISE_HASH_LEN) == 0);
    assert(memcmp(p.hs_i.pending.chaining_key, p.hs_r.pending.chaining_key,
                  WG_NOISE_HASH_LEN) == 0);

    pair_destroy(&p);
    printf("  PASS: hs2_with_preshared_key\n");
}

/* ────────────────────────────────────────
 * Test 12: transport key derivation after HS-2
 * ──────────────────────────────────────── */
static void test_hs2_derive_transport_keys(void)
{
    test_pair_t p;
    pair_init(&p, NULL);
    run_hs1(&p);

    randombytes_buf(&p.hs_r.local_index, sizeof(p.hs_r.local_index));

    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    assert(wg_noise_handshake_create_response(&resp, &p.hs_r) == WG_OK);
    assert(wg_noise_handshake_consume_response(&p.hs_i, &resp) == WG_OK);

    /* Derive transport keys on both sides */
    wg_noise_keypair_t kp_i, kp_r;
    memset(&kp_i, 0, sizeof(kp_i));
    memset(&kp_r, 0, sizeof(kp_r));
    wg_noise_keypair_derive(&kp_i, p.hs_i.pending.chaining_key, true);
    wg_noise_keypair_derive(&kp_r, p.hs_r.pending.chaining_key, false);

    /* What one side sends with, the other receives with. */
    assert(kp_i.has_keys && kp_r.has_keys);
    assert(kp_i.i_am_initiator && !kp_r.i_am_initiator);
    assert(memcmp(kp_i.sending_key, kp_r.receiving_key, WG_NOISE_SYMMETRIC_KEY_LEN) == 0);
    assert(memcmp(kp_i.receiving_key, kp_r.sending_key, WG_NOISE_SYMMETRIC_KEY_LEN) == 0);
    assert(memcmp(kp_i.sending_key, kp_i.receiving_key, WG_NOISE_SYMMETRIC_KEY_LEN) != 0);

    wg_secure_zero(&kp_i, sizeof(kp_i));
    wg_secure_zero(&kp_r, sizeof(kp_r));
    pair_destroy(&p);
    printf("  PASS: hs2_derive_transport_keys\n");
}

/* ────────────────────────────────────────
 * Test 13: tampered response must fail
 * ──────────────────────────────────────── */
static void test_hs2_tampered_response_fails(void)
{
    test_pair_t p;
    pair_init(&p, NULL);
    run_hs1(&p);

    randombytes_buf(&p.hs_r.local_index, sizeof(p.hs_r.local_index));

    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    assert(wg_noise_handshake_create_response(&resp, &p.hs_r) == WG_OK);

    /* Tamper: flip a byte in encrypted_nothing (AEAD tag) */
    wg_message_response_t bad_resp;
    memcpy(&bad_resp, &resp, sizeof(resp));
    bad_resp.encrypted_nothing[5] ^= 0xFF;

    wg_error_t err = wg_noise_handshake_consume_response(&p.hs_i, &bad_resp);
    assert(err != WG_OK);

    /* Tamper: flip ephemeral key (breaks DH) */
    memcpy(&bad_resp, &resp, sizeof(resp));
    bad_resp.unencrypted_ephemeral[0] ^= 0xFF;

    /* Reset initiator state for retry */
    pair_destroy(&p);
    pair_init(&p, NULL);
    run_hs1(&p);
    err = wg_noise_handshake_consume_response(&p.hs_i, &bad_resp);
    assert(err != WG_OK);

    pair_destroy(&p);
    printf("  PASS: hs2_tampered_response_fails\n");
}

/* ────────────────────────────────────────
 * Test 14: wrong handshake state must fail
 * ──────────────────────────────────────── */
static void test_hs2_wrong_state_fails(void)
{
    test_pair_t p;
    pair_init(&p, NULL);

    /* Try to create response without consuming initiation first */
    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    assert(wg_noise_handshake_create_response(&resp, &p.hs_r) == WG_ERR_HANDSHAKE_STATE);

    /* Try to consume response without creating initiation first */
    assert(wg_noise_handshake_consume_response(&p.hs_i, &resp) == WG_ERR_HANDSHAKE_STATE);

    pair_destroy(&p);
    printf("  PASS: hs2_wrong_state_fails\n");
}

/* ────────────────────────────────────────
 * Test 15: response message size is exactly 92 bytes
 * ──────────────────────────────────────── */
static void test_hs2_message_size(void)
{
    assert(sizeof(wg_message_response_t) == WG_MESSAGE_RESPONSE_SIZE);
    assert(sizeof(wg_message_response_t) == 92);
    printf("  PASS: hs2_message_size\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("HS-1 Handshake Initiation tests:\n");

    test_create_consume_roundtrip();
    test_noise_state_agreement();
    test_with_preshared_key();
    test_tampered_message_fails();
    test_wrong_responder_rejects();
    test_no_identity_fails();
    test_message_size();
    test_different_ephemeral_each_time();

    printf("All HS-1 tests passed.\n\n");

    printf("HS-2 Handshake Response tests:\n");

    test_hs2_roundtrip();
    test_hs2_noise_state_agreement();
    test_hs2_with_preshared_key();
    test_hs2_derive_transport_keys();
    test_hs2_tampered_response_fails();
    test_hs2_wrong_state_fails();
    test_hs2_message_size();

    printf("All HS-2 tests passed.\n");
    return 0;
}

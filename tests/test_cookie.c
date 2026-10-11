/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * HS-3 verification: Cookie mechanism (mac1/mac2/cookie reply).
 */

#include "../src/cookie/wg_cookie.h"
#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helper: build a dummy handshake initiation message
 * with proper Noise crypto, then apply macs.
 * ──────────────────────────────────────── */
typedef struct {
    wg_noise_static_identity_t si_i;
    wg_noise_static_identity_t si_r;
    wg_noise_handshake_t hs_i;
    wg_cookie_checker_t checker;     /* responder side */
    wg_cookie_generator_t generator; /* initiator side */
} test_ctx_t;

static void ctx_init(test_ctx_t *c)
{
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_module_init();

    /* Initiator identity */
    wg_noise_static_identity_init(&c->si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&c->si_i, sk_i);

    /* Responder identity */
    wg_noise_static_identity_init(&c->si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&c->si_r, sk_r);

    /* Initiator handshake */
    wg_noise_handshake_init(&c->hs_i, &c->si_i, c->si_r.static_public, NULL);
    randombytes_buf(&c->hs_i.local_index, sizeof(c->hs_i.local_index));

    /* Cookie checker on responder side: init with responder's public key */
    wg_cookie_checker_init(&c->checker, c->si_r.static_public);

    /* Cookie generator on initiator side: init with responder's public key */
    wg_cookie_generator_init(&c->generator, c->si_r.static_public);

    wg_secure_zero(sk_i, WG_KEY_LEN);
    wg_secure_zero(sk_r, WG_KEY_LEN);
}

static void ctx_destroy(test_ctx_t *c)
{
    pthread_rwlock_destroy(&c->hs_i.lock);
    pthread_rwlock_destroy(&c->si_i.lock);
    pthread_rwlock_destroy(&c->si_r.lock);
    wg_cookie_checker_destroy(&c->checker);
    wg_cookie_generator_destroy(&c->generator);
}

/*
 * Helper: create an initiation message and apply macs.
 * Returns the serialised message in buf with macs applied.
 */
static void make_initiation(test_ctx_t *c, uint8_t buf[WG_MESSAGE_INITIATION_SIZE])
{
    wg_message_initiation_t *msg = (wg_message_initiation_t *)buf;
    memset(msg, 0, sizeof(*msg));
    wg_error_t err = wg_noise_handshake_create_initiation(msg, &c->hs_i);
    assert(err == WG_OK);

    /* Apply mac1 (and mac2 if cookie available) */
    wg_cookie_generator_add_macs(&c->generator, buf, WG_MESSAGE_INITIATION_SIZE);
}

/* ────────────────────────────────────────
 * Test 1: mac1 computation and verification
 * ──────────────────────────────────────── */
static void test_mac1_roundtrip(void)
{
    test_ctx_t c;
    ctx_init(&c);

    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    /* mac1 should be non-zero */
    wg_message_initiation_t *msg = (wg_message_initiation_t *)buf;
    assert(!wg_is_zero(msg->macs.mac1, WG_COOKIE_LEN));

    /* mac2 should be zero (no cookie yet) */
    assert(wg_is_zero(msg->macs.mac2, WG_COOKIE_LEN));

    /* Checker should verify mac1 */
    assert(wg_cookie_checker_check_mac1(&c.checker, buf, WG_MESSAGE_INITIATION_SIZE));

    ctx_destroy(&c);
    printf("  PASS: mac1_roundtrip\n");
}

/* ────────────────────────────────────────
 * Test 2: tampered message fails mac1 check
 * ──────────────────────────────────────── */
static void test_mac1_tampered_fails(void)
{
    test_ctx_t c;
    ctx_init(&c);

    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    /* Tamper with a byte in the message body (not macs) */
    buf[20] ^= 0xFF;
    assert(!wg_cookie_checker_check_mac1(&c.checker, buf, WG_MESSAGE_INITIATION_SIZE));

    ctx_destroy(&c);
    printf("  PASS: mac1_tampered_fails\n");
}

/* ────────────────────────────────────────
 * Test 3: wrong key fails mac1 check
 * ──────────────────────────────────────── */
static void test_mac1_wrong_key_fails(void)
{
    test_ctx_t c;
    ctx_init(&c);

    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    /* Create a checker with a different public key */
    uint8_t wrong_pk[WG_KEY_LEN];
    randombytes_buf(wrong_pk, WG_KEY_LEN);
    wg_cookie_checker_t wrong_checker;
    wg_cookie_checker_init(&wrong_checker, wrong_pk);

    assert(
        !wg_cookie_checker_check_mac1(&wrong_checker, buf, WG_MESSAGE_INITIATION_SIZE));

    wg_cookie_checker_destroy(&wrong_checker);
    ctx_destroy(&c);
    printf("  PASS: mac1_wrong_key_fails\n");
}

/* ────────────────────────────────────────
 * Test 4: full cookie reply round-trip
 *   1. Initiator sends message with mac1 (mac2=0)
 *   2. Responder creates cookie reply
 *   3. Initiator consumes cookie reply
 *   4. Initiator resends with valid mac2
 *   5. Responder verifies mac2
 * ──────────────────────────────────────── */
static void test_cookie_reply_roundtrip(void)
{
    test_ctx_t c;
    ctx_init(&c);

    /* Step 1: create initiation with mac1 */
    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    assert(wg_cookie_checker_check_mac1(&c.checker, buf, WG_MESSAGE_INITIATION_SIZE));

    /* mac2 should fail (no secret set yet on checker, no cookie on sender) */
    uint8_t src_addr[] = {192, 168, 1, 100};
    assert(!wg_cookie_checker_check_mac2(&c.checker, buf, WG_MESSAGE_INITIATION_SIZE,
                                         src_addr, sizeof(src_addr)));

    /* Step 2: responder creates cookie reply */
    wg_message_cookie_reply_t reply;
    uint32_t sender_index = ((wg_message_initiation_t *)buf)->sender_index;
    wg_error_t err = wg_cookie_checker_create_reply(
        &c.checker, &reply, buf, WG_MESSAGE_INITIATION_SIZE, wg_le32toh(sender_index),
        src_addr, sizeof(src_addr));
    assert(err == WG_OK);

    /* Verify reply structure */
    assert(wg_le32toh(reply.header.type) == WG_MESSAGE_COOKIE_REPLY);
    assert(!wg_is_zero(reply.nonce, WG_COOKIE_NONCE_LEN));
    assert(!wg_is_zero(reply.encrypted_cookie, WG_COOKIE_LEN + WG_AEAD_TAG_SIZE));

    /* Step 3: initiator consumes cookie reply */
    assert(wg_cookie_generator_consume_reply(&c.generator, &reply) == WG_OK);

    /* Step 4: initiator re-creates initiation with mac2 */
    /* Reset handshake state for new initiation */
    wg_noise_handshake_clear(&c.hs_i);
    wg_noise_precompute_static_static(&c.hs_i);
    randombytes_buf(&c.hs_i.local_index, sizeof(c.hs_i.local_index));

    uint8_t buf2[WG_MESSAGE_INITIATION_SIZE];
    wg_message_initiation_t *msg2 = (wg_message_initiation_t *)buf2;
    memset(msg2, 0, sizeof(*msg2));
    assert(wg_noise_handshake_create_initiation(msg2, &c.hs_i) == WG_OK);
    wg_cookie_generator_add_macs(&c.generator, buf2, WG_MESSAGE_INITIATION_SIZE);

    /* mac2 should now be non-zero */
    assert(!wg_is_zero(msg2->macs.mac2, WG_COOKIE_LEN));

    /* Step 5: responder verifies both macs */
    assert(wg_cookie_checker_check_mac1(&c.checker, buf2, WG_MESSAGE_INITIATION_SIZE));
    assert(wg_cookie_checker_check_mac2(&c.checker, buf2, WG_MESSAGE_INITIATION_SIZE,
                                        src_addr, sizeof(src_addr)));

    ctx_destroy(&c);
    printf("  PASS: cookie_reply_roundtrip\n");
}

/* ────────────────────────────────────────
 * Test 5: mac2 from wrong source address fails
 * ──────────────────────────────────────── */
static void test_mac2_wrong_source_fails(void)
{
    test_ctx_t c;
    ctx_init(&c);

    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    /* Create cookie reply for address A */
    uint8_t addr_a[] = {10, 0, 0, 1};
    wg_message_cookie_reply_t reply;
    uint32_t sender_index = ((wg_message_initiation_t *)buf)->sender_index;
    assert(wg_cookie_checker_create_reply(
               &c.checker, &reply, buf, WG_MESSAGE_INITIATION_SIZE,
               wg_le32toh(sender_index), addr_a, sizeof(addr_a)) == WG_OK);

    /* Consume and resend */
    assert(wg_cookie_generator_consume_reply(&c.generator, &reply) == WG_OK);

    wg_noise_handshake_clear(&c.hs_i);
    wg_noise_precompute_static_static(&c.hs_i);
    randombytes_buf(&c.hs_i.local_index, sizeof(c.hs_i.local_index));

    uint8_t buf2[WG_MESSAGE_INITIATION_SIZE];
    memset(buf2, 0, sizeof(buf2));
    assert(wg_noise_handshake_create_initiation((wg_message_initiation_t *)buf2,
                                                &c.hs_i) == WG_OK);
    wg_cookie_generator_add_macs(&c.generator, buf2, WG_MESSAGE_INITIATION_SIZE);

    /* mac2 should verify for address A */
    assert(wg_cookie_checker_check_mac2(&c.checker, buf2, WG_MESSAGE_INITIATION_SIZE,
                                        addr_a, sizeof(addr_a)));

    /* mac2 should FAIL for address B */
    uint8_t addr_b[] = {10, 0, 0, 2};
    assert(!wg_cookie_checker_check_mac2(&c.checker, buf2, WG_MESSAGE_INITIATION_SIZE,
                                         addr_b, sizeof(addr_b)));

    ctx_destroy(&c);
    printf("  PASS: mac2_wrong_source_fails\n");
}

/* ────────────────────────────────────────
 * Test 6: tampered cookie reply fails consume
 * ──────────────────────────────────────── */
static void test_tampered_cookie_reply_fails(void)
{
    test_ctx_t c;
    ctx_init(&c);

    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    uint8_t src[] = {1, 2, 3, 4};
    wg_message_cookie_reply_t reply;
    uint32_t sender_index = ((wg_message_initiation_t *)buf)->sender_index;
    assert(wg_cookie_checker_create_reply(
               &c.checker, &reply, buf, WG_MESSAGE_INITIATION_SIZE,
               wg_le32toh(sender_index), src, sizeof(src)) == WG_OK);

    /* Tamper with encrypted cookie */
    wg_message_cookie_reply_t bad_reply;
    memcpy(&bad_reply, &reply, sizeof(reply));
    bad_reply.encrypted_cookie[5] ^= 0xFF;

    assert(wg_cookie_generator_consume_reply(&c.generator, &bad_reply) != WG_OK);

    /* Tamper with nonce */
    memcpy(&bad_reply, &reply, sizeof(reply));
    bad_reply.nonce[0] ^= 0xFF;

    assert(wg_cookie_generator_consume_reply(&c.generator, &bad_reply) != WG_OK);

    /* Original should still work */
    assert(wg_cookie_generator_consume_reply(&c.generator, &reply) == WG_OK);

    ctx_destroy(&c);
    printf("  PASS: tampered_cookie_reply_fails\n");
}

/* ────────────────────────────────────────
 * Test 7: consume reply without prior mac1 fails
 * ──────────────────────────────────────── */
static void test_consume_reply_no_mac1_fails(void)
{
    test_ctx_t c;
    ctx_init(&c);

    /* Create a valid cookie reply using a separate generator that sent a
     * message */
    uint8_t buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, buf);

    uint8_t src[] = {5, 6, 7, 8};
    wg_message_cookie_reply_t reply;
    uint32_t sender_index = ((wg_message_initiation_t *)buf)->sender_index;
    assert(wg_cookie_checker_create_reply(
               &c.checker, &reply, buf, WG_MESSAGE_INITIATION_SIZE,
               wg_le32toh(sender_index), src, sizeof(src)) == WG_OK);

    /* A fresh generator (no prior mac1) should reject the reply */
    wg_cookie_generator_t fresh_gen;
    wg_cookie_generator_init(&fresh_gen, c.si_r.static_public);
    assert(wg_cookie_generator_consume_reply(&fresh_gen, &reply) ==
           WG_ERR_HANDSHAKE_STATE);

    wg_cookie_generator_destroy(&fresh_gen);
    ctx_destroy(&c);
    printf("  PASS: consume_reply_no_mac1_fails\n");
}

/* ────────────────────────────────────────
 * Test 8: cookie reply message size is exactly 64 bytes
 * ──────────────────────────────────────── */
static void test_cookie_reply_message_size(void)
{
    assert(sizeof(wg_message_cookie_reply_t) == WG_MESSAGE_COOKIE_REPLY_SIZE);
    assert(sizeof(wg_message_cookie_reply_t) == 64);
    printf("  PASS: cookie_reply_message_size\n");
}

/* ────────────────────────────────────────
 * Test 9: mac1 works on response messages too
 * ──────────────────────────────────────── */
static void test_mac1_response_message(void)
{
    test_ctx_t c;
    ctx_init(&c);

    /* Set up a full HS-1 → HS-2 to get a valid response message */
    uint8_t init_buf[WG_MESSAGE_INITIATION_SIZE];
    make_initiation(&c, init_buf);

    /* Responder side: consume initiation */
    wg_noise_handshake_t hs_r;
    wg_noise_handshake_init(&hs_r, &c.si_r, c.si_i.static_public, NULL);
    uint8_t decrypted_static[WG_KEY_LEN];
    assert(wg_noise_handshake_consume_initiation(
               &hs_r, (wg_message_initiation_t *)init_buf, decrypted_static) == WG_OK);

    randombytes_buf(&hs_r.local_index, sizeof(hs_r.local_index));

    /* Create response */
    uint8_t resp_buf[WG_MESSAGE_RESPONSE_SIZE];
    wg_message_response_t *resp = (wg_message_response_t *)resp_buf;
    memset(resp, 0, sizeof(*resp));
    assert(wg_noise_handshake_create_response(resp, &hs_r) == WG_OK);

    /* Generator for responder (uses initiator's public key as remote) */
    wg_cookie_generator_t resp_gen;
    wg_cookie_generator_init(&resp_gen, c.si_i.static_public);
    wg_cookie_generator_add_macs(&resp_gen, resp_buf, WG_MESSAGE_RESPONSE_SIZE);

    assert(!wg_is_zero(resp->macs.mac1, WG_COOKIE_LEN));

    /* Checker on initiator side (uses initiator's own public key) */
    wg_cookie_checker_t init_checker;
    wg_cookie_checker_init(&init_checker, c.si_i.static_public);

    assert(
        wg_cookie_checker_check_mac1(&init_checker, resp_buf, WG_MESSAGE_RESPONSE_SIZE));

    wg_cookie_generator_destroy(&resp_gen);
    wg_cookie_checker_destroy(&init_checker);
    pthread_rwlock_destroy(&hs_r.lock);
    ctx_destroy(&c);
    printf("  PASS: mac1_response_message\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("HS-3 Cookie mechanism tests:\n");

    test_mac1_roundtrip();
    test_mac1_tampered_fails();
    test_mac1_wrong_key_fails();
    test_cookie_reply_roundtrip();
    test_mac2_wrong_source_fails();
    test_tampered_cookie_reply_fails();
    test_consume_reply_no_mac1_fails();
    test_cookie_reply_message_size();
    test_mac1_response_message();

    printf("All HS-3 tests passed.\n");
    return 0;
}

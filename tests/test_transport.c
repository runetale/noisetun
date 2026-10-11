/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TX-1 verification: Transport Data encrypt / decrypt round-trip.
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include "../src/replay/wg_replay.h"
#include "../src/transport/wg_transport.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helper: create a keypair from a completed handshake
 * ──────────────────────────────────────── */
typedef struct {
    wg_noise_static_identity_t si_i;
    wg_noise_static_identity_t si_r;
    wg_noise_handshake_t hs_i;
    wg_noise_handshake_t hs_r;
} test_pair_t;

static void pair_init(test_pair_t *p, const uint8_t *psk)
{
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_module_init();

    wg_noise_static_identity_init(&p->si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&p->si_i, sk_i);

    wg_noise_static_identity_init(&p->si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&p->si_r, sk_r);

    wg_noise_handshake_init(&p->hs_i, &p->si_i, p->si_r.static_public, psk);
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

/*
 * Complete a full handshake and derive two keypairs:
 *   kp_i: initiator's keypair (sends with first key, receives with second)
 *   kp_r: responder's keypair (sends with second key, receives with first)
 */
static void do_handshake(test_pair_t *p, wg_noise_keypair_t *kp_i,
                         wg_noise_keypair_t *kp_r)
{
    wg_error_t err;

    /* Assign random indices */
    randombytes_buf(&p->hs_i.local_index, sizeof(p->hs_i.local_index));

    /* Initiator creates initiation */
    wg_message_initiation_t init_msg;
    memset(&init_msg, 0, sizeof(init_msg));
    err = wg_noise_handshake_create_initiation(&init_msg, &p->hs_i);
    assert(err == WG_OK);

    /* Responder consumes initiation */
    uint8_t decrypted_static[WG_KEY_LEN];
    err = wg_noise_handshake_consume_initiation(&p->hs_r, &init_msg, decrypted_static);
    assert(err == WG_OK);

    /* Responder creates response */
    randombytes_buf(&p->hs_r.local_index, sizeof(p->hs_r.local_index));
    wg_message_response_t resp_msg;
    memset(&resp_msg, 0, sizeof(resp_msg));
    err = wg_noise_handshake_create_response(&resp_msg, &p->hs_r);
    assert(err == WG_OK);

    /* Initiator consumes response */
    err = wg_noise_handshake_consume_response(&p->hs_i, &resp_msg);
    assert(err == WG_OK);

    /* Derive transport keys for initiator */
    memset(kp_i, 0, sizeof(*kp_i));
    wg_noise_keypair_derive(kp_i, p->hs_i.pending.chaining_key, true);
    kp_i->local_index = p->hs_i.local_index;
    kp_i->remote_index = p->hs_i.pending.remote_index;
    atomic_store(&kp_i->sending_counter, 0);
    wg_replay_counter_init(&kp_i->receiving_counter);

    /* Derive transport keys for responder (reversed) */
    memset(kp_r, 0, sizeof(*kp_r));
    wg_noise_keypair_derive(kp_r, p->hs_r.pending.chaining_key, false);
    kp_r->local_index = p->hs_r.local_index;
    kp_r->remote_index = p->hs_r.pending.remote_index;
    atomic_store(&kp_r->sending_counter, 0);
    wg_replay_counter_init(&kp_r->receiving_counter);
}

/* ────────────────────────────────────────
 * Test 1: basic encrypt → decrypt round-trip
 * ──────────────────────────────────────── */
static void test_encrypt_decrypt_roundtrip(void)
{
    printf("  test_encrypt_decrypt_roundtrip ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    /* Plaintext: a fake IP packet */
    const uint8_t plaintext[] = "Hello, WireGuard transport layer!";
    size_t pt_len = sizeof(plaintext);

    /* Encrypt (initiator → responder) */
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + sizeof(plaintext) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    wg_error_t err =
        wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet), plaintext, pt_len);
    assert(err == WG_OK);
    assert(pkt_len == WG_MESSAGE_TRANSPORT_HEADER + pt_len + WG_AEAD_TAG_SIZE);

    /* Verify header fields */
    const wg_message_transport_t *hdr = (const wg_message_transport_t *)packet;
    assert(wg_le32toh(hdr->header.type) == WG_MESSAGE_TRANSPORT);
    assert(wg_le32toh(hdr->receiver_index) == kp_i.remote_index);
    assert(wg_le64toh(hdr->counter) == 0);

    /* Decrypt (responder receives) */
    uint8_t decrypted[sizeof(plaintext)];
    size_t dec_len = 0;

    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_OK);
    assert(dec_len == pt_len);
    assert(memcmp(decrypted, plaintext, pt_len) == 0);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 2: counter increments correctly
 * ──────────────────────────────────────── */
static void test_counter_increment(void)
{
    printf("  test_counter_increment ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    const uint8_t data[] = "test";
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    /* Send 3 packets, counter should be 0, 1, 2 */
    for (uint64_t i = 0; i < 3; i++) {
        wg_error_t err = wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet),
                                              data, sizeof(data));
        assert(err == WG_OK);

        const wg_message_transport_t *hdr = (const wg_message_transport_t *)packet;
        assert(wg_le64toh(hdr->counter) == i);
    }

    assert(atomic_load(&kp_i.sending_counter) == 3);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 3: replay detection
 * ──────────────────────────────────────── */
static void test_replay_rejection(void)
{
    printf("  test_replay_rejection ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    const uint8_t data[] = "replay test";
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    /* Encrypt a packet */
    wg_error_t err =
        wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet), data, sizeof(data));
    assert(err == WG_OK);

    /* First decrypt should succeed */
    uint8_t decrypted[sizeof(data)];
    size_t dec_len = 0;
    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_OK);

    /* Replaying the same packet should fail */
    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_ERR_REPLAY);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 4: keepalive (empty payload)
 * ──────────────────────────────────────── */
static void test_keepalive_empty_payload(void)
{
    printf("  test_keepalive_empty_payload ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    /* Encrypt empty payload (keepalive) */
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    wg_error_t err =
        wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet), NULL, 0);
    assert(err == WG_OK);
    assert(pkt_len == WG_MESSAGE_TRANSPORT_HEADER + WG_AEAD_TAG_SIZE);

    /* Decrypt keepalive */
    uint8_t decrypted[1]; /* won't be written */
    size_t dec_len = 0;
    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_OK);
    assert(dec_len == 0);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 5: bidirectional (both sides encrypt/decrypt)
 * ──────────────────────────────────────── */
static void test_bidirectional(void)
{
    printf("  test_bidirectional ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    /* Initiator → Responder */
    const uint8_t msg_i[] = "from initiator";
    uint8_t pkt_i[WG_MESSAGE_TRANSPORT_HEADER + sizeof(msg_i) + WG_AEAD_TAG_SIZE];
    size_t pkt_i_len = 0;

    wg_error_t err = wg_transport_encrypt(&kp_i, pkt_i, &pkt_i_len, sizeof(pkt_i), msg_i,
                                          sizeof(msg_i));
    assert(err == WG_OK);

    uint8_t dec_i[sizeof(msg_i)];
    size_t dec_i_len = 0;
    err = wg_transport_decrypt(&kp_r, dec_i, &dec_i_len, sizeof(dec_i), pkt_i, pkt_i_len);
    assert(err == WG_OK);
    assert(memcmp(dec_i, msg_i, sizeof(msg_i)) == 0);

    /* Responder → Initiator */
    const uint8_t msg_r[] = "from responder";
    uint8_t pkt_r[WG_MESSAGE_TRANSPORT_HEADER + sizeof(msg_r) + WG_AEAD_TAG_SIZE];
    size_t pkt_r_len = 0;

    err = wg_transport_encrypt(&kp_r, pkt_r, &pkt_r_len, sizeof(pkt_r), msg_r,
                               sizeof(msg_r));
    assert(err == WG_OK);

    uint8_t dec_r[sizeof(msg_r)];
    size_t dec_r_len = 0;
    err = wg_transport_decrypt(&kp_i, dec_r, &dec_r_len, sizeof(dec_r), pkt_r, pkt_r_len);
    assert(err == WG_OK);
    assert(memcmp(dec_r, msg_r, sizeof(msg_r)) == 0);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 6: tampered ciphertext fails decryption
 * ──────────────────────────────────────── */
static void test_tampered_ciphertext(void)
{
    printf("  test_tampered_ciphertext ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    const uint8_t data[] = "tamper test";
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    wg_error_t err =
        wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet), data, sizeof(data));
    assert(err == WG_OK);

    /* Flip a bit in the encrypted payload */
    packet[WG_MESSAGE_TRANSPORT_HEADER + 2] ^= 0x01;

    uint8_t decrypted[sizeof(data)];
    size_t dec_len = 0;
    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_ERR_TRANSPORT_DECRYPT);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 7: out-of-order delivery (within replay window)
 * ──────────────────────────────────────── */
static void test_out_of_order(void)
{
    printf("  test_out_of_order ... ");

    test_pair_t p;
    pair_init(&p, NULL);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    const uint8_t data[] = "ooo";

    /* Encrypt 3 packets */
    uint8_t pkt0[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    uint8_t pkt1[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    uint8_t pkt2[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t len0 = 0, len1 = 0, len2 = 0;

    assert(wg_transport_encrypt(&kp_i, pkt0, &len0, sizeof(pkt0), data, sizeof(data)) ==
           WG_OK);
    assert(wg_transport_encrypt(&kp_i, pkt1, &len1, sizeof(pkt1), data, sizeof(data)) ==
           WG_OK);
    assert(wg_transport_encrypt(&kp_i, pkt2, &len2, sizeof(pkt2), data, sizeof(data)) ==
           WG_OK);

    /* Decrypt in reverse order: 2, 0, 1 */
    uint8_t dec[sizeof(data)];
    size_t dec_len = 0;

    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt2, len2) == WG_OK);
    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt0, len0) == WG_OK);
    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt1, len1) == WG_OK);

    /* All three should reject on replay */
    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt0, len0) ==
           WG_ERR_REPLAY);
    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt1, len1) ==
           WG_ERR_REPLAY);
    assert(wg_transport_decrypt(&kp_r, dec, &dec_len, sizeof(dec), pkt2, len2) ==
           WG_ERR_REPLAY);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 8: with preshared key
 * ──────────────────────────────────────── */
static void test_with_psk(void)
{
    printf("  test_with_psk ... ");

    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    randombytes_buf(psk, sizeof(psk));

    test_pair_t p;
    pair_init(&p, psk);

    wg_noise_keypair_t kp_i, kp_r;
    do_handshake(&p, &kp_i, &kp_r);

    const uint8_t data[] = "psk transport test";
    uint8_t packet[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    wg_error_t err =
        wg_transport_encrypt(&kp_i, packet, &pkt_len, sizeof(packet), data, sizeof(data));
    assert(err == WG_OK);

    uint8_t decrypted[sizeof(data)];
    size_t dec_len = 0;
    err = wg_transport_decrypt(&kp_r, decrypted, &dec_len, sizeof(decrypted), packet,
                               pkt_len);
    assert(err == WG_OK);
    assert(memcmp(decrypted, data, sizeof(data)) == 0);

    wg_replay_counter_destroy(&kp_i.receiving_counter);
    wg_replay_counter_destroy(&kp_r.receiving_counter);
    pair_destroy(&p);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * main
 * ──────────────────────────────────────── */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init() failed\n");
        return 1;
    }

    printf("test_transport:\n");
    test_encrypt_decrypt_roundtrip();
    test_counter_increment();
    test_replay_rejection();
    test_keepalive_empty_payload();
    test_bidirectional();
    test_tampered_ciphertext();
    test_out_of_order();
    test_with_psk();
    printf("All transport tests passed.\n");

    return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * NOISE-2 verification: handshake state machine.
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include <assert.h>
#include <stddef.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void test_module_init(void)
{
    wg_noise_module_init();

    assert(!wg_is_zero(wg_noise_handshake_init_hash, WG_NOISE_HASH_LEN));
    assert(!wg_is_zero(wg_noise_handshake_init_chaining_key, WG_NOISE_HASH_LEN));
    assert(memcmp(wg_noise_handshake_init_hash, wg_noise_handshake_init_chaining_key,
                  WG_NOISE_HASH_LEN) != 0);
}

static void test_static_identity(void)
{
    wg_noise_static_identity_t si;
    wg_noise_static_identity_init(&si);
    assert(!si.has_identity);

    uint8_t sk[WG_KEY_LEN];
    wg_x25519_generate_private(sk);

    wg_noise_static_identity_set_private_key(&si, sk);
    assert(si.has_identity);
    assert(!wg_is_zero(si.static_public, WG_KEY_LEN));

    uint8_t expected_pk[WG_KEY_LEN];
    wg_x25519_public_key(expected_pk, si.static_private);
    assert(memcmp(si.static_public, expected_pk, WG_KEY_LEN) == 0);

    pthread_rwlock_destroy(&si.lock);
}

static void test_handshake_init_clear(void)
{
    wg_noise_static_identity_t si;
    wg_noise_static_identity_init(&si);
    uint8_t sk[WG_KEY_LEN];
    wg_x25519_generate_private(sk);
    wg_noise_static_identity_set_private_key(&si, sk);

    uint8_t peer_sk[WG_KEY_LEN], peer_pk[WG_KEY_LEN];
    wg_x25519_generate_private(peer_sk);
    wg_x25519_public_key(peer_pk, peer_sk);

    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN] = {0};

    wg_noise_handshake_t hs;
    wg_noise_handshake_init(&hs, &si, peer_pk, psk);

    assert(hs.pending.state == WG_HANDSHAKE_ZEROED);
    assert(hs.static_identity == &si);
    assert(memcmp(hs.remote_static, peer_pk, WG_KEY_LEN) == 0);
    assert(!wg_is_zero(hs.precomputed_static_static, WG_KEY_LEN));

    wg_noise_handshake_clear(&hs);
    assert(hs.pending.state == WG_HANDSHAKE_ZEROED);
    assert(wg_is_zero(hs.pending.ephemeral_private, WG_KEY_LEN));
    assert(wg_is_zero(hs.pending.hash, WG_NOISE_HASH_LEN));
    assert(wg_is_zero(hs.pending.chaining_key, WG_NOISE_HASH_LEN));

    pthread_rwlock_destroy(&hs.lock);
    pthread_rwlock_destroy(&si.lock);
}

static void test_precomputed_static_static_symmetric(void)
{
    wg_noise_static_identity_t si_a, si_b;
    wg_noise_static_identity_init(&si_a);
    wg_noise_static_identity_init(&si_b);

    uint8_t sk_a[WG_KEY_LEN], sk_b[WG_KEY_LEN];
    wg_x25519_generate_private(sk_a);
    wg_x25519_generate_private(sk_b);
    wg_noise_static_identity_set_private_key(&si_a, sk_a);
    wg_noise_static_identity_set_private_key(&si_b, sk_b);

    wg_noise_handshake_t hs_a, hs_b;
    wg_noise_handshake_init(&hs_a, &si_a, si_b.static_public, NULL);
    wg_noise_handshake_init(&hs_b, &si_b, si_a.static_public, NULL);

    assert(memcmp(hs_a.precomputed_static_static, hs_b.precomputed_static_static,
                  WG_KEY_LEN) == 0);

    pthread_rwlock_destroy(&hs_a.lock);
    pthread_rwlock_destroy(&hs_b.lock);
    pthread_rwlock_destroy(&si_a.lock);
    pthread_rwlock_destroy(&si_b.lock);
}

/* A flipped bit anywhere in a handshake message makes it fail, and the
 * receiver's handshake is left as it was. */
static void test_tampered_messages(void)
{
    wg_noise_static_identity_t si_a, si_b;
    uint8_t sk_a[WG_KEY_LEN], sk_b[WG_KEY_LEN];
    wg_noise_static_identity_init(&si_a);
    wg_noise_static_identity_init(&si_b);
    wg_x25519_generate_private(sk_a);
    wg_x25519_generate_private(sk_b);
    wg_noise_static_identity_set_private_key(&si_a, sk_a);
    wg_noise_static_identity_set_private_key(&si_b, sk_b);

    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    randombytes_buf(psk, sizeof(psk));

    wg_noise_handshake_t hs_a, hs_b; /* A's view of B, B's view of A */
    wg_noise_handshake_init(&hs_a, &si_a, si_b.static_public, psk);
    wg_noise_handshake_init(&hs_b, &si_b, si_a.static_public, psk);

    wg_message_initiation_t init;
    assert(wg_noise_handshake_create_initiation(&init, &hs_a) == WG_OK);

    /* Every byte after the header and sender index is authenticated. */
    uint8_t decrypted_static[WG_KEY_LEN];
    size_t init_from = offsetof(wg_message_initiation_t, unencrypted_ephemeral);
    size_t init_to = offsetof(wg_message_initiation_t, encrypted_timestamp) +
                     sizeof(init.encrypted_timestamp);
    for (size_t i = init_from; i < init_to; i++) {
        wg_message_initiation_t bad = init;
        ((uint8_t *)&bad)[i] ^= 0x01;
        assert(wg_noise_handshake_consume_initiation(&hs_b, &bad, decrypted_static) !=
               WG_OK);
        assert(hs_b.pending.state == WG_HANDSHAKE_ZEROED);
        assert(wg_is_zero(hs_b.latest_timestamp, WG_TIMESTAMP_LEN));
    }

    assert(wg_noise_handshake_consume_initiation(&hs_b, &init, decrypted_static) ==
           WG_OK);
    assert(memcmp(decrypted_static, si_a.static_public, WG_KEY_LEN) == 0);

    /* The same initiation again is a replay. */
    assert(wg_noise_handshake_consume_initiation(&hs_b, &init, decrypted_static) ==
           WG_ERR_TIMESTAMP);

    wg_message_response_t resp;
    assert(wg_noise_handshake_create_response(&resp, &hs_b) == WG_OK);

    uint8_t pending_hash[WG_NOISE_HASH_LEN];
    memcpy(pending_hash, hs_a.pending.hash, WG_NOISE_HASH_LEN);
    size_t resp_from = offsetof(wg_message_response_t, unencrypted_ephemeral);
    size_t resp_to = offsetof(wg_message_response_t, encrypted_nothing) +
                     sizeof(resp.encrypted_nothing);
    for (size_t i = resp_from; i < resp_to; i++) {
        wg_message_response_t bad = resp;
        ((uint8_t *)&bad)[i] ^= 0x01;
        assert(wg_noise_handshake_consume_response(&hs_a, &bad) != WG_OK);
        assert(hs_a.pending.state == WG_HANDSHAKE_CREATED_INITIATION);
        assert(memcmp(hs_a.pending.hash, pending_hash, WG_NOISE_HASH_LEN) == 0);
    }

    assert(wg_noise_handshake_consume_response(&hs_a, &resp) == WG_OK);
    assert(memcmp(hs_a.pending.chaining_key, hs_b.pending.chaining_key,
                  WG_NOISE_HASH_LEN) == 0);
    assert(memcmp(hs_a.pending.hash, hs_b.pending.hash, WG_NOISE_HASH_LEN) == 0);

    /* A response is accepted once. */
    assert(wg_noise_handshake_consume_response(&hs_a, &resp) == WG_ERR_HANDSHAKE_STATE);

    pthread_rwlock_destroy(&hs_a.lock);
    pthread_rwlock_destroy(&hs_b.lock);
    pthread_rwlock_destroy(&si_a.lock);
    pthread_rwlock_destroy(&si_b.lock);
}

static void test_keypairs(void)
{
    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);

    assert(kps.current == NULL);
    assert(kps.previous == NULL);
    assert(kps.next == NULL);

    wg_noise_keypair_t *kp = calloc(1, sizeof(wg_noise_keypair_t));
    assert(kp != NULL);
    atomic_store(&kp->refcount, 1);
    kp->internal_id = 42;

    wg_noise_keypair_t *got = wg_noise_keypair_get(kp);
    assert(got == kp);
    assert(atomic_load(&kp->refcount) == 2);

    wg_noise_keypair_put(kp);
    assert(atomic_load(&kp->refcount) == 1);

    wg_noise_keypair_put(kp);

    wg_noise_keypairs_clear(&kps);
    pthread_mutex_destroy(&kps.lock);
}

static void test_derive_keys(void)
{
    uint8_t ck[WG_NOISE_HASH_LEN];
    randombytes_buf(ck, WG_NOISE_HASH_LEN);

    wg_noise_keypair_t kp;
    memset(&kp, 0, sizeof(kp));
    wg_noise_keypair_derive(&kp, ck, true);

    assert(kp.has_keys);
    assert(kp.i_am_initiator);
    assert(!wg_is_zero(kp.sending_key, WG_NOISE_SYMMETRIC_KEY_LEN));
    assert(!wg_is_zero(kp.receiving_key, WG_NOISE_SYMMETRIC_KEY_LEN));
    assert(memcmp(kp.sending_key, kp.receiving_key, WG_NOISE_SYMMETRIC_KEY_LEN) != 0);
    assert(kp.birthdate_ns > 0);

    /* The responder gets the same two keys, the other way round. */
    wg_noise_keypair_t kr;
    memset(&kr, 0, sizeof(kr));
    wg_noise_keypair_derive(&kr, ck, false);
    assert(!kr.i_am_initiator);
    assert(memcmp(kp.sending_key, kr.receiving_key, WG_NOISE_SYMMETRIC_KEY_LEN) == 0);
    assert(memcmp(kp.receiving_key, kr.sending_key, WG_NOISE_SYMMETRIC_KEY_LEN) == 0);
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    test_module_init();
    test_static_identity();
    test_handshake_init_clear();
    test_precomputed_static_static_symmetric();
    test_tampered_messages();
    test_keypairs();
    test_derive_keys();

    printf("All NOISE-2 tests passed.\n");
    return 0;
}

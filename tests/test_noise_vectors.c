/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Runetale Inc.
 *
 * The handshake against vectors recorded from wireguard-go
 * (tests/vectors/wg_noise_vectors.h, see tests/vectors/gen/README.md).
 *
 * This test compiles src/noise/wg_noise.c itself with
 * WG_NOISE_FIXED_INPUTS, so that the ephemeral keys and the timestamp come
 * from the vector. Everything else is the library. For each vector:
 *   - the initiation wg-c creates equals wireguard-go's, byte for byte,
 *     mac1 included, and so do the hash and chaining key after it;
 *   - wg-c consumes wireguard-go's initiation (through the two-phase path
 *     the device uses) and reaches the same hash and chaining key;
 *   - the same for the response, in both directions;
 *   - both sides derive wireguard-go's transport keys.
 */

#include "../src/cookie/wg_cookie.h"
#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include "vectors/wg_noise_vectors.h"

#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Fixed inputs for wg_noise.c
 * ──────────────────────────────────────── */

static const uint8_t *fixed_ephemerals[2];
static size_t fixed_ephemerals_used;
static const uint8_t *fixed_time;

wg_error_t wg_noise_fixed_ephemeral(uint8_t private_key[WG_KEY_LEN]);
void wg_noise_fixed_timestamp(uint8_t out[WG_TIMESTAMP_LEN]);

wg_error_t wg_noise_fixed_ephemeral(uint8_t private_key[WG_KEY_LEN])
{
    assert(fixed_ephemerals_used < 2);
    memcpy(private_key, fixed_ephemerals[fixed_ephemerals_used++], WG_KEY_LEN);
    return WG_OK;
}

void wg_noise_fixed_timestamp(uint8_t out[WG_TIMESTAMP_LEN])
{
    memcpy(out, fixed_time, WG_TIMESTAMP_LEN);
}

/* ──────────────────────────────────────── */

static void expect_equal(const char *vector, const char *what, const uint8_t *got,
                         const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) == 0)
        return;
    fprintf(stderr, "FAIL: %s: %s differs from wireguard-go\n", vector, what);
    for (size_t i = 0; i < len; i++) {
        if (got[i] != want[i]) {
            fprintf(stderr, "  first difference at byte %zu: 0x%02x, want 0x%02x\n", i,
                    got[i], want[i]);
            break;
        }
    }
    assert(0);
}

static void run_vector(const wg_noise_vector_t *v)
{
    wg_noise_static_identity_t si_i, si_r;
    wg_noise_handshake_t hs_i, hs_r; /* the initiator's view of the responder, and back */
    wg_cookie_generator_t cg_i, cg_r;
    const uint8_t *psk = v->preshared_key;

    fixed_ephemerals[0] = v->initiator_ephemeral_private;
    fixed_ephemerals[1] = v->responder_ephemeral_private;
    fixed_ephemerals_used = 0;
    fixed_time = v->timestamp;

    wg_noise_static_identity_init(&si_i);
    wg_noise_static_identity_init(&si_r);
    wg_noise_static_identity_set_private_key(&si_i, v->initiator_static_private);
    wg_noise_static_identity_set_private_key(&si_r, v->responder_static_private);
    expect_equal(v->name, "initiator public key", si_i.static_public,
                 v->initiator_static_public, WG_KEY_LEN);
    expect_equal(v->name, "responder public key", si_r.static_public,
                 v->responder_static_public, WG_KEY_LEN);

    wg_noise_handshake_init(&hs_i, &si_i, v->responder_static_public, psk);
    wg_noise_handshake_init(&hs_r, &si_r, v->initiator_static_public, psk);
    wg_cookie_generator_init(&cg_i, v->responder_static_public);
    wg_cookie_generator_init(&cg_r, v->initiator_static_public);

    /* ── Initiation, created by wg-c ── */
    wg_message_initiation_t init;
    memset(&init, 0, sizeof(init));
    hs_i.local_index = v->initiator_index;
    assert(wg_noise_handshake_create_initiation(&init, &hs_i) == WG_OK);
    wg_cookie_generator_add_macs(&cg_i, (uint8_t *)&init, sizeof(init));
    expect_equal(v->name, "initiation", (const uint8_t *)&init, v->initiation,
                 sizeof(init));
    expect_equal(v->name, "initiator hash after initiation", hs_i.pending.hash,
                 v->initiation_hash, WG_NOISE_HASH_LEN);
    expect_equal(v->name, "initiator chaining key after initiation",
                 hs_i.pending.chaining_key, v->initiation_chaining_key,
                 WG_NOISE_HASH_LEN);

    /* ── Initiation, wireguard-go's, consumed by wg-c ── */
    wg_message_initiation_t go_init;
    memcpy(&go_init, v->initiation, sizeof(go_init));
    wg_initiation_half_t half;
    assert(wg_noise_consume_initiation_decrypt_static(&si_r, &go_init, &half) == WG_OK);
    expect_equal(v->name, "decrypted initiator static", half.decrypted_static,
                 v->initiator_static_public, WG_KEY_LEN);
    assert(half.sender_index == v->initiator_index);
    assert(wg_noise_consume_initiation_commit(&hs_r, &go_init, &half) == WG_OK);
    wg_secure_zero(&half, sizeof(half));
    assert(hs_r.pending.state == WG_HANDSHAKE_CONSUMED_INITIATION);
    expect_equal(v->name, "responder hash after initiation", hs_r.pending.hash,
                 v->initiation_hash, WG_NOISE_HASH_LEN);
    expect_equal(v->name, "responder chaining key after initiation",
                 hs_r.pending.chaining_key, v->initiation_chaining_key,
                 WG_NOISE_HASH_LEN);
    expect_equal(v->name, "accepted timestamp", hs_r.latest_timestamp, v->timestamp,
                 WG_TIMESTAMP_LEN);

    /* ── Response, created by wg-c ── */
    wg_message_response_t resp;
    memset(&resp, 0, sizeof(resp));
    hs_r.local_index = v->responder_index;
    assert(wg_noise_handshake_create_response(&resp, &hs_r) == WG_OK);
    wg_cookie_generator_add_macs(&cg_r, (uint8_t *)&resp, sizeof(resp));
    expect_equal(v->name, "response", (const uint8_t *)&resp, v->response, sizeof(resp));
    expect_equal(v->name, "responder hash after response", hs_r.pending.hash,
                 v->response_hash, WG_NOISE_HASH_LEN);
    expect_equal(v->name, "responder chaining key after response",
                 hs_r.pending.chaining_key, v->response_chaining_key, WG_NOISE_HASH_LEN);

    /* ── Response, wireguard-go's, consumed by wg-c ── */
    wg_message_response_t go_resp;
    memcpy(&go_resp, v->response, sizeof(go_resp));
    assert(wg_noise_handshake_consume_response(&hs_i, &go_resp) == WG_OK);
    assert(hs_i.pending.state == WG_HANDSHAKE_CONSUMED_RESPONSE);
    assert(hs_i.pending.remote_index == v->responder_index);
    expect_equal(v->name, "initiator hash after response", hs_i.pending.hash,
                 v->response_hash, WG_NOISE_HASH_LEN);
    expect_equal(v->name, "initiator chaining key after response",
                 hs_i.pending.chaining_key, v->response_chaining_key, WG_NOISE_HASH_LEN);

    /* ── Transport keys ── */
    wg_noise_keypair_t kp_i, kp_r;
    memset(&kp_i, 0, sizeof(kp_i));
    memset(&kp_r, 0, sizeof(kp_r));
    wg_noise_keypair_derive(&kp_i, hs_i.pending.chaining_key, true);
    wg_noise_keypair_derive(&kp_r, hs_r.pending.chaining_key, false);
    expect_equal(v->name, "initiator sending key", kp_i.sending_key,
                 v->initiator_send_key, WG_NOISE_SYMMETRIC_KEY_LEN);
    expect_equal(v->name, "initiator receiving key", kp_i.receiving_key,
                 v->initiator_recv_key, WG_NOISE_SYMMETRIC_KEY_LEN);
    expect_equal(v->name, "responder sending key", kp_r.sending_key,
                 v->initiator_recv_key, WG_NOISE_SYMMETRIC_KEY_LEN);
    expect_equal(v->name, "responder receiving key", kp_r.receiving_key,
                 v->initiator_send_key, WG_NOISE_SYMMETRIC_KEY_LEN);

    assert(fixed_ephemerals_used == 2);

    wg_secure_zero(&kp_i, sizeof(kp_i));
    wg_secure_zero(&kp_r, sizeof(kp_r));
    wg_cookie_generator_destroy(&cg_i);
    wg_cookie_generator_destroy(&cg_r);
    wg_noise_handshake_clear(&hs_i);
    wg_noise_handshake_clear(&hs_r);
    pthread_rwlock_destroy(&hs_i.lock);
    pthread_rwlock_destroy(&hs_r.lock);
    pthread_rwlock_destroy(&si_i.lock);
    pthread_rwlock_destroy(&si_r.lock);
    printf("  PASS: %s\n", v->name);
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("test_noise_vectors (wireguard-go 0.0.20250522):\n");
    for (size_t i = 0; i < sizeof(wg_noise_vectors) / sizeof(wg_noise_vectors[0]); i++)
        run_vector(&wg_noise_vectors[i]);
    return 0;
}

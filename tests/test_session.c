/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * SESS-1 verification: Session keypair management.
 * Tests begin_symmetric_session, keypair rotation, rekey judgment.
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_indextable.h"
#include "../src/replay/wg_replay.h"
#include "../src/session/wg_session.h"
#include "../src/transport/wg_transport.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helper: set up initiator–responder handshake pair
 * ──────────────────────────────────────── */
typedef struct {
    wg_noise_static_identity_t si_i;
    wg_noise_static_identity_t si_r;
    wg_noise_handshake_t hs_i;
    wg_noise_handshake_t hs_r;
    wg_index_table_t table;
} test_ctx_t;

static void ctx_init(test_ctx_t *ctx, const uint8_t *psk)
{
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_module_init();

    wg_noise_static_identity_init(&ctx->si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&ctx->si_i, sk_i);

    wg_noise_static_identity_init(&ctx->si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&ctx->si_r, sk_r);

    wg_noise_handshake_init(&ctx->hs_i, &ctx->si_i, ctx->si_r.static_public, psk);
    wg_noise_handshake_init(&ctx->hs_r, &ctx->si_r, ctx->si_i.static_public, psk);

    assert(wg_index_table_init(&ctx->table) == WG_OK);

    wg_secure_zero(sk_i, WG_KEY_LEN);
    wg_secure_zero(sk_r, WG_KEY_LEN);
}

static void ctx_destroy(test_ctx_t *ctx)
{
    wg_index_table_destroy(&ctx->table);
    pthread_rwlock_destroy(&ctx->hs_i.lock);
    pthread_rwlock_destroy(&ctx->hs_r.lock);
    pthread_rwlock_destroy(&ctx->si_i.lock);
    pthread_rwlock_destroy(&ctx->si_r.lock);
}

/*
 * Complete the 4-message handshake and register indices in the table.
 */
static void do_handshake(test_ctx_t *ctx)
{
    wg_error_t err;

    /* Allocate index for initiator. */
    uint32_t idx_i;
    err = wg_index_table_new_index(&ctx->table, NULL, &ctx->hs_i, &idx_i);
    assert(err == WG_OK);
    ctx->hs_i.local_index = idx_i;

    /* Create initiation. */
    wg_message_initiation_t init_msg;
    memset(&init_msg, 0, sizeof(init_msg));
    err = wg_noise_handshake_create_initiation(&init_msg, &ctx->hs_i);
    assert(err == WG_OK);

    /* Consume initiation. */
    uint8_t decrypted_static[WG_KEY_LEN];
    err = wg_noise_handshake_consume_initiation(&ctx->hs_r, &init_msg, decrypted_static);
    assert(err == WG_OK);

    /* Allocate index for responder. */
    uint32_t idx_r;
    err = wg_index_table_new_index(&ctx->table, NULL, &ctx->hs_r, &idx_r);
    assert(err == WG_OK);
    ctx->hs_r.local_index = idx_r;

    /* Create response. */
    wg_message_response_t resp_msg;
    memset(&resp_msg, 0, sizeof(resp_msg));
    err = wg_noise_handshake_create_response(&resp_msg, &ctx->hs_r);
    assert(err == WG_OK);

    /* Consume response. */
    err = wg_noise_handshake_consume_response(&ctx->hs_i, &resp_msg);
    assert(err == WG_OK);
}

/* ────────────────────────────────────────
 * Test 1: begin_symmetric_session + transport round-trip
 * ──────────────────────────────────────── */
static void test_session_roundtrip(void)
{
    printf("  test_session_roundtrip ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    /* Initiator: begin session → current keypair. */
    wg_noise_keypairs_t kps_i;
    wg_noise_keypairs_init(&kps_i);
    wg_error_t err = wg_begin_symmetric_session(&ctx.hs_i, &kps_i, &ctx.table);
    assert(err == WG_OK);

    /* Responder: begin session → next keypair. */
    wg_noise_keypairs_t kps_r;
    wg_noise_keypairs_init(&kps_r);
    err = wg_begin_symmetric_session(&ctx.hs_r, &kps_r, &ctx.table);
    assert(err == WG_OK);

    /* Initiator should have current set. */
    wg_noise_keypair_t *kp_i = atomic_load_explicit(&kps_i.current, memory_order_acquire);
    assert(kp_i != NULL);
    assert(kp_i->i_am_initiator == true);

    /* Responder should have next set (not current). */
    wg_noise_keypair_t *kp_r_next =
        atomic_load_explicit(&kps_r.next, memory_order_acquire);
    assert(kp_r_next != NULL);
    assert(kp_r_next->i_am_initiator == false);
    assert(atomic_load(&kps_r.current) == NULL);

    /* Transport: initiator → responder. */
    const uint8_t plaintext[] = "session test payload";
    uint8_t pkt[WG_MESSAGE_TRANSPORT_HEADER + sizeof(plaintext) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    err = wg_transport_encrypt(kp_i, pkt, &pkt_len, sizeof(pkt), plaintext,
                               sizeof(plaintext));
    assert(err == WG_OK);

    uint8_t dec[sizeof(plaintext)];
    size_t dec_len = 0;
    err = wg_transport_decrypt(kp_r_next, dec, &dec_len, sizeof(dec), pkt, pkt_len);
    assert(err == WG_OK);
    assert(dec_len == sizeof(plaintext));
    assert(memcmp(dec, plaintext, sizeof(plaintext)) == 0);

    /* ReceivedWithKeypair should promote next → current. */
    bool rotated = wg_noise_received_with_keypair(&kps_r, kp_r_next, &ctx.table);
    assert(rotated);
    assert(atomic_load(&kps_r.current) == kp_r_next);
    assert(atomic_load(&kps_r.next) == NULL);

    wg_noise_keypairs_clear(&kps_i);
    wg_noise_keypairs_clear(&kps_r);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 2: invalid handshake state → error
 * ──────────────────────────────────────── */
static void test_invalid_state(void)
{
    printf("  test_invalid_state ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);

    /* Don't do handshake — state is ZEROED. */
    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);
    wg_error_t err = wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table);
    assert(err == WG_ERR_HANDSHAKE_STATE);

    wg_noise_keypairs_clear(&kps);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 3: handshake state is zeroed after session begin
 * ──────────────────────────────────────── */
static void test_handshake_zeroed(void)
{
    printf("  test_handshake_zeroed ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);
    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table) == WG_OK);

    /* Handshake secrets should be zeroed. */
    assert(ctx.hs_i.pending.state == WG_HANDSHAKE_ZEROED);
    assert(wg_is_zero(ctx.hs_i.pending.chaining_key, WG_NOISE_HASH_LEN));
    assert(wg_is_zero(ctx.hs_i.pending.hash, WG_NOISE_HASH_LEN));
    assert(wg_is_zero(ctx.hs_i.pending.ephemeral_private, WG_KEY_LEN));

    /* Second call should fail. */
    wg_error_t err = wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table);
    assert(err == WG_ERR_HANDSHAKE_STATE);

    wg_noise_keypairs_clear(&kps);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 4: index table swap (handshake → keypair)
 * ──────────────────────────────────────── */
static void test_index_table_swap(void)
{
    printf("  test_index_table_swap ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    uint32_t saved_index = ctx.hs_i.local_index;

    /* Before session: entry should be HANDSHAKE type. */
    wg_index_entry_t entry;
    assert(wg_index_table_lookup_copy(&ctx.table, saved_index, &entry));
    assert(entry.type == WG_INDEX_ENTRY_HANDSHAKE);

    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);
    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table) == WG_OK);

    /* After session: entry should be KEYPAIR type. */
    assert(wg_index_table_lookup_copy(&ctx.table, saved_index, &entry));
    assert(entry.type == WG_INDEX_ENTRY_KEYPAIR);

    wg_noise_keypairs_clear(&kps);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 5: initiator keypair rotation (2 handshakes)
 * ──────────────────────────────────────── */
static void test_initiator_rotation(void)
{
    printf("  test_initiator_rotation ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);

    /* First session: current = kp1, previous = NULL. */
    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table) == WG_OK);
    wg_noise_keypair_t *kp1 = atomic_load(&kps.current);
    assert(kp1 != NULL);
    assert(atomic_load(&kps.previous) == NULL);

    /* Do another handshake. */
    ctx_destroy(&ctx);
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    /* Second session: current = kp2, previous = kp1. */
    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table) == WG_OK);
    wg_noise_keypair_t *kp2 = atomic_load(&kps.current);
    assert(kp2 != NULL);
    assert(kp2 != kp1);
    assert(atomic_load(&kps.previous) == kp1);

    wg_noise_keypairs_clear(&kps);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 6: rekey judgment — fresh key should not need rekey
 * ──────────────────────────────────────── */
static void test_rekey_fresh(void)
{
    printf("  test_rekey_fresh ... ");

    test_ctx_t ctx;
    ctx_init(&ctx, NULL);
    do_handshake(&ctx);

    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);
    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps, &ctx.table) == WG_OK);

    wg_noise_keypair_t *kp = atomic_load(&kps.current);
    assert(!wg_keypair_needs_rekey(kp));
    assert(!wg_keypair_is_expired(kp));

    wg_noise_keypairs_clear(&kps);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 7: NULL keypair checks
 * ──────────────────────────────────────── */
static void test_rekey_null(void)
{
    printf("  test_rekey_null ... ");

    assert(wg_keypair_needs_rekey(NULL) == true);
    assert(wg_keypair_is_expired(NULL) == true);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 8: with PSK
 * ──────────────────────────────────────── */
static void test_session_with_psk(void)
{
    printf("  test_session_with_psk ... ");

    uint8_t psk[WG_NOISE_SYMMETRIC_KEY_LEN];
    randombytes_buf(psk, sizeof(psk));

    test_ctx_t ctx;
    ctx_init(&ctx, psk);
    do_handshake(&ctx);

    wg_noise_keypairs_t kps_i, kps_r;
    wg_noise_keypairs_init(&kps_i);
    wg_noise_keypairs_init(&kps_r);

    assert(wg_begin_symmetric_session(&ctx.hs_i, &kps_i, &ctx.table) == WG_OK);
    assert(wg_begin_symmetric_session(&ctx.hs_r, &kps_r, &ctx.table) == WG_OK);

    /* Transport round-trip with PSK-derived keys. */
    wg_noise_keypair_t *kp_i = atomic_load(&kps_i.current);
    wg_noise_keypair_t *kp_r = atomic_load(&kps_r.next);

    const uint8_t data[] = "psk session test";
    uint8_t pkt[WG_MESSAGE_TRANSPORT_HEADER + sizeof(data) + WG_AEAD_TAG_SIZE];
    size_t pkt_len = 0;

    assert(wg_transport_encrypt(kp_i, pkt, &pkt_len, sizeof(pkt), data, sizeof(data)) ==
           WG_OK);

    uint8_t dec[sizeof(data)];
    size_t dec_len = 0;
    assert(wg_transport_decrypt(kp_r, dec, &dec_len, sizeof(dec), pkt, pkt_len) == WG_OK);
    assert(memcmp(dec, data, sizeof(data)) == 0);

    wg_noise_keypairs_clear(&kps_i);
    wg_noise_keypairs_clear(&kps_r);
    ctx_destroy(&ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * main
 * ──────────────────────────────────────── */
/* Take the current keypair while another thread keeps replacing it and
 * dropping the old one's last reference, as a rekey does (#140). An
 * unlocked load of current followed by get can touch a keypair freed in
 * between; ASan reports that within a few thousand rotations. */
typedef struct {
    wg_noise_keypairs_t kps;
    atomic_bool stop;
} rotate_ctx_t;

static wg_noise_keypair_t *rotate_new_keypair(void)
{
    wg_noise_keypair_t *kp = calloc(1, sizeof(*kp));
    assert(kp);
    atomic_init(&kp->refcount, 1);
    return kp;
}

static void *rotate_reader(void *arg)
{
    rotate_ctx_t *c = arg;
    while (!atomic_load(&c->stop)) {
        wg_noise_keypair_t *kp = wg_noise_keypairs_get_current(&c->kps);
        if (kp) {
            assert(atomic_load(&kp->refcount) >= 1);
            wg_noise_keypair_put(kp);
        }
    }
    return NULL;
}

static void test_get_current_during_rotation(void)
{
    printf("  %-50s", "get current keypair during rotation");
    fflush(stdout);

    rotate_ctx_t c;
    wg_noise_keypairs_init(&c.kps);
    atomic_init(&c.stop, false);

    pthread_t readers[2];
    for (int i = 0; i < 2; i++)
        assert(pthread_create(&readers[i], NULL, rotate_reader, &c) == 0);

    for (int i = 0; i < 200000; i++) {
        wg_noise_keypair_t *kp = rotate_new_keypair();
        pthread_mutex_lock(&c.kps.lock);
        wg_noise_keypair_t *old =
            atomic_exchange_explicit(&c.kps.current, kp, memory_order_relaxed);
        pthread_mutex_unlock(&c.kps.lock);
        wg_noise_keypair_put(old); /* the slot's reference, often the last */
    }

    atomic_store(&c.stop, true);
    for (int i = 0; i < 2; i++)
        pthread_join(readers[i], NULL);
    wg_noise_keypairs_clear(&c.kps);
    pthread_mutex_destroy(&c.kps.lock);
    printf("PASS\n");
}

/* When a received packet confirms `next`, the old `previous` keypair is
 * released. Its index must leave the table first: the table holds no
 * reference, so a later packet to that index would otherwise take a
 * reference to freed memory. */
static void *index_get_ref(void *kp)
{
    return wg_noise_keypair_get(kp);
}

static wg_noise_keypair_t *indexed_keypair(wg_index_table_t *table, uint32_t *index)
{
    static int fake_peer, fake_hs;
    assert(wg_index_table_new_index(table, &fake_peer, &fake_hs, index) == WG_OK);
    wg_noise_keypair_t *kp = calloc(1, sizeof(*kp));
    assert(kp);
    atomic_init(&kp->refcount, 1); /* the slot's reference */
    kp->local_index = *index;
    wg_index_table_swap_for_keypair(table, *index, kp);
    return kp;
}

static void test_received_with_keypair_drops_index(void)
{
    printf("  %-50s", "confirming next drops the old previous's index");
    fflush(stdout);

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);
    wg_noise_keypairs_t kps;
    wg_noise_keypairs_init(&kps);

    uint32_t i_prev, i_cur, i_next;
    atomic_store(&kps.previous, indexed_keypair(&table, &i_prev));
    atomic_store(&kps.current, indexed_keypair(&table, &i_cur));
    wg_noise_keypair_t *next = indexed_keypair(&table, &i_next);
    atomic_store(&kps.next, next);

    assert(wg_noise_received_with_keypair(&kps, next, &table));

    /* The released keypair is gone from the table; the others remain. */
    wg_index_entry_t e;
    assert(!wg_index_table_lookup_keypair(&table, i_prev, &e, index_get_ref));
    assert(wg_index_table_lookup_keypair(&table, i_cur, &e, index_get_ref));
    wg_noise_keypair_put(e.data);
    assert(wg_index_table_lookup_keypair(&table, i_next, &e, index_get_ref));
    wg_noise_keypair_put(e.data);

    wg_noise_keypairs_clear(&kps);
    pthread_mutex_destroy(&kps.lock);
    wg_index_table_destroy(&table);
    printf("PASS\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init() failed\n");
        return 1;
    }

    printf("test_session:\n");
    test_session_roundtrip();
    test_invalid_state();
    test_handshake_zeroed();
    test_index_table_swap();
    test_initiator_rotation();
    test_rekey_fresh();
    test_rekey_null();
    test_session_with_psk();
    test_get_current_during_rotation();
    test_received_with_keypair_drops_index();
    printf("All session tests passed.\n");

    return 0;
}

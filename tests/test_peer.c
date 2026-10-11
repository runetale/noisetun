/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for peer state machine (wg_peer).
 */

#include "device/wg_device.h"
#include "noise/wg_noise.h"
#include "peer/wg_peer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

#define ASSERT_OK(expr)       assert((expr) == WG_OK)
#define ASSERT_ERR(expr, err) assert((expr) == (err))
#define TEST(name)               \
    do {                         \
        printf("  %-50s", name); \
        fflush(stdout);          \
    } while (0)
#define PASS()            \
    do {                  \
        printf("PASS\n"); \
    } while (0)

/* Set up a minimal device for testing.
 * Zero the whole struct first, then init pthread primitives and subsystems. */
static void setup_device(wg_device_t *dev)
{
    memset(dev, 0, sizeof(*dev));
    atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_DOWN);
    pthread_mutex_init(&dev->state_lock, NULL);

    wg_noise_static_identity_init(&dev->static_identity);

    /* Generate device private key */
    uint8_t priv[WG_KEY_LEN];
    randombytes_buf(priv, WG_KEY_LEN);
    wg_noise_static_identity_set_private_key(&dev->static_identity, priv);

    ASSERT_OK(wg_peer_map_init(&dev->peers));
    ASSERT_OK(wg_allowedips_init(&dev->allowedips));
    ASSERT_OK(wg_index_table_init(&dev->index_table));

    wg_cookie_checker_init(&dev->cookie_checker, dev->static_identity.static_public);
    pthread_rwlock_init(&dev->net.lock, NULL);
    atomic_store(&dev->tun.mtu, (int32_t)WG_DEFAULT_MTU);
}

static void teardown_device(wg_device_t *dev)
{
    wg_index_table_destroy(&dev->index_table);
    wg_allowedips_destroy(&dev->allowedips);
    wg_peer_map_destroy(&dev->peers);
    wg_cookie_checker_destroy(&dev->cookie_checker);
    pthread_rwlock_destroy(&dev->static_identity.lock);
    pthread_rwlock_destroy(&dev->net.lock);
    pthread_mutex_destroy(&dev->state_lock);
}

/* ────────────────────────────────────────
 * Test: create and destroy peer
 * ──────────────────────────────────────── */

static void test_create_peer(void)
{
    TEST("create peer");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, NULL, &peer));
    assert(peer != NULL);
    assert(peer->device == &dev);
    assert(wg_peer_map_count(&dev.peers) == 1);

    /* Verify handshake remote_static matches public_key */
    assert(memcmp(peer->handshake.remote_static, pub, WG_KEY_LEN) == 0);

    /* Clean up */
    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: duplicate peer rejected
 * ──────────────────────────────────────── */

static void test_duplicate_peer(void)
{
    TEST("duplicate peer rejected");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer1 = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, NULL, &peer1));

    /* Second peer with same key should fail */
    wg_peer_t *peer2 = NULL;
    ASSERT_ERR(wg_peer_new(&dev, pub, NULL, &peer2), WG_ERR_DUPLICATE_PEER);
    assert(peer2 == NULL);
    assert(wg_peer_map_count(&dev.peers) == 1);

    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer1);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: multiple peers
 * ──────────────────────────────────────── */

static void test_multiple_peers(void)
{
    TEST("multiple peers");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t keys[5][WG_KEY_LEN];
    wg_peer_t *peers[5];

    for (int i = 0; i < 5; i++) {
        randombytes_buf(keys[i], WG_KEY_LEN);
        ASSERT_OK(wg_peer_new(&dev, keys[i], NULL, &peers[i]));
    }
    assert(wg_peer_map_count(&dev.peers) == 5);

    /* Lookup each peer by key */
    for (int i = 0; i < 5; i++) {
        struct wg_peer *found = wg_peer_map_lookup(&dev.peers, keys[i]);
        assert(found == peers[i]);
    }

    /* Remove and destroy */
    for (int i = 0; i < 5; i++) {
        wg_peer_map_remove(&dev.peers, keys[i]);
        wg_peer_destroy(peers[i]);
    }
    assert(wg_peer_map_count(&dev.peers) == 0);

    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: peer with preshared key
 * ──────────────────────────────────────── */

static void test_preshared_key(void)
{
    TEST("peer with preshared key");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    uint8_t psk[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);
    randombytes_buf(psk, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, psk, &peer));

    /* Verify PSK was stored in handshake */
    assert(memcmp(peer->handshake.preshared_key, psk, WG_KEY_LEN) == 0);

    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: start and stop
 * ──────────────────────────────────────── */

static void test_start_stop(void)
{
    TEST("start/stop lifecycle");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, NULL, &peer));

    assert(!atomic_load(&peer->is_running));

    wg_peer_start(peer);
    assert(atomic_load(&peer->is_running));

    /* Idempotent start */
    wg_peer_start(peer);
    assert(atomic_load(&peer->is_running));

    wg_peer_stop(peer);
    assert(!atomic_load(&peer->is_running));

    /* Idempotent stop */
    wg_peer_stop(peer);
    assert(!atomic_load(&peer->is_running));

    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: handshake lock stays usable after clearing
 *
 * wg_peer_zero_and_flush and wg_peer_expire_current_keypairs held
 * handshake.lock while calling wg_noise_handshake_clear, which locks the
 * same rwlock again. On glibc the inner wrlock fails with EDEADLK, the inner
 * unlock releases the outer lock, and the outer unlock then underflows the
 * reader count: no writer gets the lock again, and every handshake with the
 * peer stops. wg_peer_stop reaches the same path.
 * ──────────────────────────────────────── */

static void assert_handshake_lock_free(wg_peer_t *peer)
{
    assert(pthread_rwlock_trywrlock(&peer->handshake.lock) == 0);
    pthread_rwlock_unlock(&peer->handshake.lock);
    assert(pthread_rwlock_tryrdlock(&peer->handshake.lock) == 0);
    pthread_rwlock_unlock(&peer->handshake.lock);
}

static void test_handshake_lock_after_clear(void)
{
    TEST("handshake lock usable after zero/expire/stop");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, NULL, &peer));

    wg_peer_zero_and_flush(peer);
    assert_handshake_lock_free(peer);

    wg_peer_expire_current_keypairs(peer);
    assert_handshake_lock_free(peer);

    wg_peer_start(peer);
    wg_peer_stop(peer);
    assert_handshake_lock_free(peer);

    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: endpoint management
 * ──────────────────────────────────────── */

static void test_endpoint(void)
{
    TEST("endpoint set/get");

    wg_device_t dev;
    setup_device(&dev);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, pub, NULL, &peer));

    /* No endpoint initially */
    wg_endpoint_t ep;
    assert(!wg_peer_get_endpoint(peer, &ep));

    /* Set endpoint */
    wg_endpoint_t new_ep;
    memset(&new_ep, 0, sizeof(new_ep));
    new_ep.addr.sa4.sin_family = AF_INET;
    new_ep.addr.sa4.sin_port = htons(51820);
    new_ep.addr.sa4.sin_addr.s_addr = htonl(0x0A000001); /* 10.0.0.1 */

    wg_peer_set_endpoint_from_packet(peer, &new_ep);

    assert(wg_peer_get_endpoint(peer, &ep));
    assert(ep.addr.sa4.sin_family == AF_INET);
    assert(ep.addr.sa4.sin_port == htons(51820));

    wg_peer_map_remove(&dev.peers, pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: static-static DH precomputation
 * ──────────────────────────────────────── */

static void test_static_static_dh(void)
{
    TEST("static-static DH precomputation");

    wg_device_t dev;
    setup_device(&dev);

    /* Generate a proper keypair for the peer */
    uint8_t peer_priv[WG_KEY_LEN], peer_pub[WG_KEY_LEN];
    randombytes_buf(peer_priv, WG_KEY_LEN);
    peer_priv[0] &= 248;
    peer_priv[31] &= 127;
    peer_priv[31] |= 64;
    crypto_scalarmult_base(peer_pub, peer_priv);

    wg_peer_t *peer = NULL;
    ASSERT_OK(wg_peer_new(&dev, peer_pub, NULL, &peer));

    /* Precomputed static-static should not be zero */
    uint8_t zero[WG_KEY_LEN] = {0};
    assert(memcmp(peer->handshake.precomputed_static_static, zero, WG_KEY_LEN) != 0);

    wg_peer_map_remove(&dev.peers, peer_pub);
    wg_peer_destroy(peer);
    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Test: closed device rejects new peers
 * ──────────────────────────────────────── */

static void test_closed_device(void)
{
    TEST("closed device rejects new peers");

    wg_device_t dev;
    setup_device(&dev);
    atomic_store(&dev.state, (uint32_t)WG_DEVICE_STATE_CLOSED);

    uint8_t pub[WG_KEY_LEN];
    randombytes_buf(pub, WG_KEY_LEN);

    wg_peer_t *peer = NULL;
    ASSERT_ERR(wg_peer_new(&dev, pub, NULL, &peer), WG_ERR_DEVICE_CLOSED);

    teardown_device(&dev);
    PASS();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_peer ===\n");

    test_create_peer();
    test_duplicate_peer();
    test_multiple_peers();
    test_preshared_key();
    test_start_stop();
    test_handshake_lock_after_clear();
    test_endpoint();
    test_static_static_dh();
    test_closed_device();

    printf("All peer tests passed.\n");
    return 0;
}

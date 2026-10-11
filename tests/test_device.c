/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for wg_device (device lifecycle).
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/device/wg_device.h"
#include "../src/peer/wg_peer.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PASS(name) printf("  PASS: %s\n", name)

/* ────────────────────────────────────────
 * Helpers: generate keypair
 * ──────────────────────────────────────── */

static void gen_keypair(wg_key_t *priv, wg_key_t *pub)
{
    crypto_box_keypair(pub->key, priv->key);
    /* Clamp private key for X25519. */
    priv->key[0] &= 248;
    priv->key[31] &= 127;
    priv->key[31] |= 64;
    crypto_scalarmult_base(pub->key, priv->key);
}

/* ────────────────────────────────────────
 * Test: create and close device
 * ──────────────────────────────────────── */
static void test_new_close(void)
{
    wg_device_t *dev = NULL;
    wg_error_t err = wg_device_new(&dev, NULL, NULL, NULL);
    assert(err == WG_OK);
    assert(dev != NULL);
    assert(wg_device_get_state(dev) == WG_DEVICE_STATE_DOWN);

    wg_device_close(dev);
    PASS("new_close");
}

/* ────────────────────────────────────────
 * Test: state transitions DOWN -> UP -> DOWN
 * ──────────────────────────────────────── */
static void test_up_down(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    assert(wg_device_get_state(dev) == WG_DEVICE_STATE_DOWN);

    assert(wg_device_up(dev) == WG_OK);
    assert(wg_device_get_state(dev) == WG_DEVICE_STATE_UP);

    /* The RTC worker arrays hold _Alignas(64) queues. They exist only when
     * crypto runs on workers, which up_locked skips on 4 CPUs or fewer. */
    if (!dev->inline_crypto) {
        assert(dev->rtc.send && dev->rtc.recv);
        assert((uintptr_t)dev->rtc.send % _Alignof(wg_rtc_send_worker_t) == 0);
        assert((uintptr_t)dev->rtc.recv % _Alignof(wg_rtc_recv_worker_t) == 0);
    } else {
        assert(!dev->rtc.send && !dev->rtc.recv);
    }

    assert(wg_device_down(dev) == WG_OK);
    assert(wg_device_get_state(dev) == WG_DEVICE_STATE_DOWN);

    /* Up again. */
    assert(wg_device_up(dev) == WG_OK);
    assert(wg_device_is_up(dev));

    wg_device_close(dev);
    PASS("up_down");
}

/* ────────────────────────────────────────
 * Test: close is terminal
 * ──────────────────────────────────────── */
static void test_close_terminal(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    assert(wg_device_up(dev) == WG_OK);
    wg_device_close(dev);

    /* dev is freed — just verify we got here without crash. */
    PASS("close_terminal");
}

/* ────────────────────────────────────────
 * Test: idempotent up/down
 * ──────────────────────────────────────── */
static void test_idempotent(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* Double up */
    assert(wg_device_up(dev) == WG_OK);
    assert(wg_device_up(dev) == WG_OK);
    assert(wg_device_is_up(dev));

    /* Double down */
    assert(wg_device_down(dev) == WG_OK);
    assert(wg_device_down(dev) == WG_OK);
    assert(wg_device_get_state(dev) == WG_DEVICE_STATE_DOWN);

    wg_device_close(dev);
    PASS("idempotent");
}

/* ────────────────────────────────────────
 * Test: set private key
 * ──────────────────────────────────────── */
static void test_set_private_key(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_key_t priv, pub;
    gen_keypair(&priv, &pub);

    assert(wg_device_set_private_key(dev, &priv) == WG_OK);

    /* Verify identity is set. */
    assert(dev->static_identity.has_identity == true);
    assert(memcmp(dev->static_identity.static_private, priv.key, WG_KEY_LEN) == 0);
    assert(memcmp(dev->static_identity.static_public, pub.key, WG_KEY_LEN) == 0);

    /* Setting same key again is a no-op. */
    assert(wg_device_set_private_key(dev, &priv) == WG_OK);

    wg_device_close(dev);
    PASS("set_private_key");
}

/* ────────────────────────────────────────
 * Test: add and lookup peer
 * ──────────────────────────────────────── */
static void test_add_lookup_peer(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* Set device identity first. */
    wg_key_t dev_priv, dev_pub;
    gen_keypair(&dev_priv, &dev_pub);
    wg_device_set_private_key(dev, &dev_priv);

    /* Create a peer. */
    wg_key_t peer_priv, peer_pub;
    gen_keypair(&peer_priv, &peer_pub);

    wg_peer_t *peer = NULL;
    wg_error_t err = wg_peer_new(dev, peer_pub.key, NULL, &peer);
    assert(err == WG_OK);
    assert(peer != NULL);

    /* Lookup. */
    struct wg_peer *found = wg_device_lookup_peer(dev, peer_pub.key);
    assert(found == peer);

    /* Lookup non-existent. */
    wg_key_t other_priv, other_pub;
    gen_keypair(&other_priv, &other_pub);
    assert(wg_device_lookup_peer(dev, other_pub.key) == NULL);

    wg_device_close(dev);
    PASS("add_lookup_peer");
}

/* ────────────────────────────────────────
 * Test: remove peer
 * ──────────────────────────────────────── */
static void test_remove_peer(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_key_t dev_priv, dev_pub;
    gen_keypair(&dev_priv, &dev_pub);
    wg_device_set_private_key(dev, &dev_priv);

    wg_key_t peer_priv, peer_pub;
    gen_keypair(&peer_priv, &peer_pub);

    wg_peer_t *peer = NULL;
    assert(wg_peer_new(dev, peer_pub.key, NULL, &peer) == WG_OK);
    assert(wg_peer_map_count(&dev->peers) == 1);

    wg_device_remove_peer(dev, &peer_pub);
    assert(wg_peer_map_count(&dev->peers) == 0);
    assert(wg_device_lookup_peer(dev, peer_pub.key) == NULL);

    wg_device_close(dev);
    PASS("remove_peer");
}

/* ────────────────────────────────────────
 * Test: remove all peers
 * ──────────────────────────────────────── */
static void test_remove_all_peers(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_key_t dev_priv, dev_pub;
    gen_keypair(&dev_priv, &dev_pub);
    wg_device_set_private_key(dev, &dev_priv);

    /* Add multiple peers. */
    for (int i = 0; i < 5; i++) {
        wg_key_t ppriv, ppub;
        gen_keypair(&ppriv, &ppub);
        wg_peer_t *p = NULL;
        assert(wg_peer_new(dev, ppub.key, NULL, &p) == WG_OK);
    }
    assert(wg_peer_map_count(&dev->peers) == 5);

    wg_device_remove_all_peers(dev);
    assert(wg_peer_map_count(&dev->peers) == 0);

    wg_device_close(dev);
    PASS("remove_all_peers");
}

/* ────────────────────────────────────────
 * Test: is_under_load
 * ──────────────────────────────────────── */
static void test_is_under_load(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* Empty handshake queue: not under load. */
    assert(wg_device_is_under_load(dev) == false);

    /* Fill handshake queue to >= 1/8 capacity. */
    size_t threshold = WG_QUEUE_HANDSHAKE_SIZE / 8;
    for (size_t i = 0; i < threshold; i++) {
        /* Push dummy values — we just need the count. */
        int dummy;
        wg_queue_try_push(dev->queue.handshake, &dummy);
    }

    assert(wg_device_is_under_load(dev) == true);

    /* Drain the queue. */
    wg_queue_flush(dev->queue.handshake, NULL);

    /* Should still be "under load" because of the grace period. */
    assert(wg_device_is_under_load(dev) == true);

    wg_device_close(dev);
    PASS("is_under_load");
}

/* ────────────────────────────────────────
 * Test: set_private_key removes conflicting peer
 * ──────────────────────────────────────── */
static void test_set_key_removes_self_peer(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* Set initial device key. */
    wg_key_t dev_priv1, dev_pub1;
    gen_keypair(&dev_priv1, &dev_pub1);
    wg_device_set_private_key(dev, &dev_priv1);

    /* Add peer with a different key. */
    wg_key_t peer_priv, peer_pub;
    gen_keypair(&peer_priv, &peer_pub);
    wg_peer_t *p = NULL;
    assert(wg_peer_new(dev, peer_pub.key, NULL, &p) == WG_OK);
    assert(wg_peer_map_count(&dev->peers) == 1);

    /* Now set device key to match the peer's public key.
     * This should remove the peer whose remote_static == new device pubkey.
     * The peer's remote_static is peer_pub, and we're setting device key
     * to peer_priv whose public is peer_pub. */
    wg_device_set_private_key(dev, &peer_priv);

    /* The peer should have been removed because its remote_static
     * matches the new device public key (peer_pub). */
    assert(wg_peer_map_count(&dev->peers) == 0);

    wg_device_close(dev);
    PASS("set_key_removes_self_peer");
}

/* ────────────────────────────────────────
 * Test: set_private_key with a peer that stays
 *
 * set_private_key held every peer's handshake.lock for reading while
 * wg_noise_precompute_static_static took the same lock for writing, so
 * changing the key while a non-conflicting peer remained never returned.
 * The call runs on a thread with a deadline, so a regression fails here
 * instead of hanging the test run.
 * ──────────────────────────────────────── */
struct set_key_call {
    wg_device_t *dev;
    const wg_key_t *key;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool done;
};

static void *set_key_thread(void *arg)
{
    struct set_key_call *call = arg;
    wg_device_set_private_key(call->dev, call->key);
    pthread_mutex_lock(&call->mu);
    call->done = true;
    pthread_cond_signal(&call->cv);
    pthread_mutex_unlock(&call->mu);
    return NULL;
}

static void test_set_key_keeps_other_peer(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_key_t dev_priv1, dev_pub1;
    gen_keypair(&dev_priv1, &dev_pub1);
    wg_device_set_private_key(dev, &dev_priv1);

    wg_key_t peer_priv, peer_pub;
    gen_keypair(&peer_priv, &peer_pub);
    wg_peer_t *p = NULL;
    assert(wg_peer_new(dev, peer_pub.key, NULL, &p) == WG_OK);

    /* A new device key that does not match the peer, so the peer stays. */
    wg_key_t dev_priv2, dev_pub2;
    gen_keypair(&dev_priv2, &dev_pub2);

    struct set_key_call call = {.dev = dev, .key = &dev_priv2, .done = false};
    pthread_mutex_init(&call.mu, NULL);
    pthread_cond_init(&call.cv, NULL);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, set_key_thread, &call) == 0);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 10;
    pthread_mutex_lock(&call.mu);
    while (!call.done) {
        if (pthread_cond_timedwait(&call.cv, &call.mu, &deadline) == ETIMEDOUT)
            break;
    }
    bool done = call.done;
    pthread_mutex_unlock(&call.mu);
    if (!done) {
        fprintf(stderr, "  FAIL: set_key_keeps_other_peer: "
                        "wg_device_set_private_key did not return within 10s\n");
        exit(1);
    }
    pthread_join(thread, NULL);

    assert(wg_peer_map_count(&dev->peers) == 1);

    /* The handshake lock is free again. */
    assert(pthread_rwlock_trywrlock(&p->handshake.lock) == 0);
    pthread_rwlock_unlock(&p->handshake.lock);

    /* The static-static DH was recomputed with the new device key. */
    uint8_t expected[WG_KEY_LEN];
    assert(wg_x25519(expected, dev_priv2.key, peer_pub.key) == WG_OK);
    assert(sodium_memcmp(p->handshake.precomputed_static_static, expected, WG_KEY_LEN) ==
           0);

    pthread_cond_destroy(&call.cv);
    pthread_mutex_destroy(&call.mu);
    wg_device_close(dev);
    PASS("set_key_keeps_other_peer");
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

    printf("=== test_device ===\n");

    test_new_close();
    test_up_down();
    test_close_terminal();
    test_idempotent();
    test_set_private_key();
    test_add_lookup_peer();
    test_remove_peer();
    test_remove_all_peers();
    test_is_under_load();
    test_set_key_removes_self_peer();
    test_set_key_keeps_other_peer();

    printf("All device tests passed.\n");
    return 0;
}

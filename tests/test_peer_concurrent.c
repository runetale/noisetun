/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Concurrent stress tests for wg_peer operations.
 * Detects data races and deadlocks under TSan.
 */

#include "device/wg_device.h"
#include "noise/wg_noise.h"
#include "peer/wg_peer.h"

#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

typedef struct {
    wg_device_t *dev;
    int thread_id;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static void setup_device(wg_device_t *dev)
{
    memset(dev, 0, sizeof(*dev));
    atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_DOWN);
    pthread_mutex_init(&dev->state_lock, NULL);

    wg_noise_static_identity_init(&dev->static_identity);

    uint8_t priv[WG_KEY_LEN];
    randombytes_buf(priv, WG_KEY_LEN);
    wg_noise_static_identity_set_private_key(&dev->static_identity, priv);

    assert(wg_peer_map_init(&dev->peers) == WG_OK);
    assert(wg_allowedips_init(&dev->allowedips) == WG_OK);
    assert(wg_index_table_init(&dev->index_table) == WG_OK);

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
 * Worker: add and remove peers
 * ──────────────────────────────────────── */
static void *worker_add_remove(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Generate a unique key per thread+iteration */
        wg_key_t pub;
        memset(pub.key, 0, WG_KEY_LEN);
        pub.key[0] = (uint8_t)targ->thread_id;
        pub.key[1] = (uint8_t)(i & 0xFF);
        pub.key[2] = (uint8_t)((i >> 8) & 0xFF);

        wg_peer_t *peer = NULL;
        wg_error_t err = wg_peer_new(targ->dev, pub.key, NULL, &peer);

        if (err == WG_OK && peer != NULL) {
            /* Use wg_device_remove_peer which properly acquires peers.lock */
            wg_device_remove_peer(targ->dev, &pub);
        }
        /* WG_ERR_MAX_PEERS (duplicate) is expected under contention */

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: concurrent lookups on pre-created peers
 * ──────────────────────────────────────── */
#define NUM_PRELOADED_PEERS 10

typedef struct {
    wg_device_t *dev;
    uint8_t keys[NUM_PRELOADED_PEERS][WG_KEY_LEN];
    int thread_id;
} lookup_arg_t;

static void *worker_lookup(void *arg)
{
    lookup_arg_t *larg = (lookup_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        int key_idx = (i + larg->thread_id) % NUM_PRELOADED_PEERS;
        wg_device_lookup_peer(larg->dev, larg->keys[key_idx]);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent peer add/remove
 * ──────────────────────────────────────── */
static void test_concurrent_add_remove(void)
{
    printf("  %-50s", "concurrent_peer_add_remove");
    fflush(stdout);

    wg_device_t dev;
    setup_device(&dev);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].dev = &dev;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_add_remove, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    teardown_device(&dev);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent peer lookups
 * ──────────────────────────────────────── */
static void test_concurrent_lookup(void)
{
    printf("  %-50s", "concurrent_peer_lookup");
    fflush(stdout);

    wg_device_t dev;
    setup_device(&dev);

    /* Pre-create peers */
    uint8_t keys[NUM_PRELOADED_PEERS][WG_KEY_LEN];
    wg_peer_t *peers_arr[NUM_PRELOADED_PEERS];

    for (int i = 0; i < NUM_PRELOADED_PEERS; i++) {
        memset(keys[i], 0, WG_KEY_LEN);
        keys[i][0] = 0xFF;
        keys[i][1] = (uint8_t)i;
        assert(wg_peer_new(&dev, keys[i], NULL, &peers_arr[i]) == WG_OK);
    }

    pthread_t threads[NUM_THREADS];
    lookup_arg_t largs[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        largs[i].dev = &dev;
        largs[i].thread_id = i;
        memcpy(largs[i].keys, keys, sizeof(keys));
        pthread_create(&threads[i], NULL, worker_lookup, &largs[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    /* Verify all peers still present */
    for (int i = 0; i < NUM_PRELOADED_PEERS; i++) {
        assert(wg_device_lookup_peer(&dev, keys[i]) != NULL);
    }

    /* Clean up */
    for (int i = 0; i < NUM_PRELOADED_PEERS; i++) {
        wg_peer_map_remove(&dev.peers, keys[i]);
        wg_allowedips_remove_by_peer(&dev.allowedips, peers_arr[i]);
        wg_peer_destroy(peers_arr[i]);
    }
    teardown_device(&dev);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent add + lookup (mixed readers/writers)
 * ──────────────────────────────────────── */
static void *worker_add_only(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t pub[WG_KEY_LEN];
        memset(pub, 0, WG_KEY_LEN);
        pub[0] = (uint8_t)(0x80 | targ->thread_id);
        pub[1] = (uint8_t)(i & 0xFF);
        pub[2] = (uint8_t)((i >> 8) & 0xFF);

        wg_peer_t *peer = NULL;
        wg_peer_new(targ->dev, pub, NULL, &peer);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void *worker_lookup_random(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t pub[WG_KEY_LEN];
        memset(pub, 0, WG_KEY_LEN);
        pub[0] = (uint8_t)(0x80 | (i % (NUM_THREADS / 2)));
        pub[1] = (uint8_t)(i & 0xFF);

        wg_device_lookup_peer(targ->dev, pub);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void test_concurrent_add_lookup(void)
{
    printf("  %-50s", "concurrent_peer_add_lookup");
    fflush(stdout);

    wg_device_t dev;
    setup_device(&dev);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].dev = &dev;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        if (i < NUM_THREADS / 2)
            pthread_create(&threads[i], NULL, worker_add_only, &args[i]);
        else
            pthread_create(&threads[i], NULL, worker_lookup_random, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);

    /* Clean up all peers added by writers */
    wg_device_remove_all_peers(&dev);
    teardown_device(&dev);

    printf("PASS\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("Peer Concurrent Stress Tests:\n");

    test_concurrent_add_remove();
    test_concurrent_lookup();
    test_concurrent_add_lookup();

    printf("All peer concurrent tests passed.\n");
    return 0;
}

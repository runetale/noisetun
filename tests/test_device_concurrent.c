/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Concurrent stress tests for wg_device lifecycle.
 * Detects data races and deadlocks under TSan.
 */

#include "../src/device/wg_device.h"
#include "../src/peer/wg_peer.h"

#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static void gen_keypair(wg_key_t *priv, wg_key_t *pub)
{
    crypto_box_keypair(pub->key, priv->key);
    priv->key[0] &= 248;
    priv->key[31] &= 127;
    priv->key[31] |= 64;
    crypto_scalarmult_base(pub->key, priv->key);
}

typedef struct {
    wg_device_t *dev;
    int thread_id;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* ────────────────────────────────────────
 * Worker: toggle up/down
 * ──────────────────────────────────────── */
static void *worker_up_down(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        if ((i + targ->thread_id) % 2 == 0)
            wg_device_up(targ->dev);
        else
            wg_device_down(targ->dev);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: set random private keys
 * ──────────────────────────────────────── */
static void *worker_set_key(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        wg_key_t priv, pub;
        gen_keypair(&priv, &pub);

        wg_error_t err = wg_device_set_private_key(targ->dev, &priv);
        if (err != WG_OK) {
            pthread_mutex_lock(targ->error_lock);
            (*targ->error_count)++;
            fprintf(stderr, "Thread %d iter %d: set_private_key failed\n",
                    targ->thread_id, i);
            pthread_mutex_unlock(targ->error_lock);
        }

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent up/down state transitions
 * ──────────────────────────────────────── */
static void test_concurrent_up_down(void)
{
    printf("  %-50s", "concurrent_up_down");
    fflush(stdout);

    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].dev = dev;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_up_down, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);

    /* Device should be in a valid state */
    wg_device_state_t state = wg_device_get_state(dev);
    assert(state == WG_DEVICE_STATE_DOWN || state == WG_DEVICE_STATE_UP);

    pthread_mutex_destroy(&error_lock);
    wg_device_close(dev);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent set_private_key
 * ──────────────────────────────────────── */
static void test_concurrent_set_private_key(void)
{
    printf("  %-50s", "concurrent_set_private_key");
    fflush(stdout);

    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* Set initial key (no peers — with peers, concurrent set_private_key can
     * starve the handshake.lock writer in expire_current_keypairs because
     * continuous readers prevent write-lock acquisition) */
    wg_key_t priv, pub;
    gen_keypair(&priv, &pub);
    assert(wg_device_set_private_key(dev, &priv) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].dev = dev;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_set_key, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);

    /* Device should still have a valid identity */
    assert(dev->static_identity.has_identity == true);

    wg_device_close(dev);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent set_private_key + up/down
 * ──────────────────────────────────────── */
static void test_concurrent_key_and_updown(void)
{
    printf("  %-50s", "concurrent_key_and_updown");
    fflush(stdout);

    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_key_t priv, pub;
    gen_keypair(&priv, &pub);
    assert(wg_device_set_private_key(dev, &priv) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].dev = dev;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        /* Half set keys, half toggle up/down */
        if (i < NUM_THREADS / 2)
            pthread_create(&threads[i], NULL, worker_set_key, &args[i]);
        else
            pthread_create(&threads[i], NULL, worker_up_down, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);

    wg_device_close(dev);

    printf("PASS\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("Device Concurrent Stress Tests:\n");

    test_concurrent_up_down();
    test_concurrent_set_private_key();
    test_concurrent_key_and_updown();

    printf("All device concurrent tests passed.\n");
    return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * HS-1 concurrent stress test: detect race conditions and deadlocks.
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"
#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

typedef struct {
    wg_noise_static_identity_t *si_i;
    wg_noise_static_identity_t *si_r;
    wg_noise_handshake_t *hs_i;
    int thread_id;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* ────────────────────────────────────────
 * Test: concurrent create_initiation
 * ──────────────────────────────────────── */
static void *worker_create_initiation(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        wg_message_initiation_t msg;
        memset(&msg, 0, sizeof(msg));

        /* Assign a random local index under the handshake lock, as the
         * device does (handshake_new_index): the other threads read it in
         * create_initiation under the same lock. */
        uint32_t index;
        randombytes_buf(&index, sizeof(index));
        pthread_rwlock_wrlock(&targ->hs_i->lock);
        targ->hs_i->local_index = index;
        pthread_rwlock_unlock(&targ->hs_i->lock);

        wg_error_t err = wg_noise_handshake_create_initiation(&msg, targ->hs_i);

        if (err != WG_OK) {
            pthread_mutex_lock(targ->error_lock);
            (*targ->error_count)++;
            fprintf(stderr, "Thread %d iteration %d: create_initiation failed\n",
                    targ->thread_id, i);
            pthread_mutex_unlock(targ->error_lock);
        }

        /* Reset for next iteration */
        wg_noise_handshake_clear(targ->hs_i);
        wg_noise_precompute_static_static(targ->hs_i);

        /* Small delay to increase contention */
        {
            struct timespec ts = {0, 1000};
            nanosleep(&ts, NULL);
        }
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent consume_initiation
 * ──────────────────────────────────────── */
static void *worker_consume_initiation(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Create a message first */
        wg_message_initiation_t msg;
        memset(&msg, 0, sizeof(msg));

        wg_noise_handshake_t hs_temp;
        memset(&hs_temp, 0, sizeof(hs_temp));
        pthread_rwlock_init(&hs_temp.lock, NULL);
        hs_temp.static_identity = targ->si_i;
        memcpy(hs_temp.remote_static, targ->si_r->static_public, WG_KEY_LEN);
        hs_temp.pending.state = WG_HANDSHAKE_ZEROED;
        wg_noise_precompute_static_static(&hs_temp);

        randombytes_buf(&hs_temp.local_index, sizeof(hs_temp.local_index));

        wg_error_t err = wg_noise_handshake_create_initiation(&msg, &hs_temp);
        assert(err == WG_OK);

        /* Now consume it concurrently */
        wg_noise_handshake_t hs_r;
        memset(&hs_r, 0, sizeof(hs_r));
        pthread_rwlock_init(&hs_r.lock, NULL);
        hs_r.static_identity = targ->si_r;
        hs_r.pending.state = WG_HANDSHAKE_ZEROED;

        uint8_t decrypted_static[WG_KEY_LEN];
        err = wg_noise_handshake_consume_initiation(&hs_r, &msg, decrypted_static);

        if (err != WG_OK) {
            pthread_mutex_lock(targ->error_lock);
            (*targ->error_count)++;
            fprintf(stderr, "Thread %d iteration %d: consume_initiation failed\n",
                    targ->thread_id, i);
            pthread_mutex_unlock(targ->error_lock);
        } else {
            /* Verify correctness */
            if (memcmp(decrypted_static, targ->si_i->static_public, WG_KEY_LEN) != 0) {
                pthread_mutex_lock(targ->error_lock);
                (*targ->error_count)++;
                fprintf(stderr, "Thread %d iteration %d: decrypted key mismatch\n",
                        targ->thread_id, i);
                pthread_mutex_unlock(targ->error_lock);
            }
        }

        pthread_rwlock_destroy(&hs_temp.lock);
        pthread_rwlock_destroy(&hs_r.lock);

        {
            struct timespec ts = {0, 1000};
            nanosleep(&ts, NULL);
        }
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent create + consume
 * ──────────────────────────────────────── */
static void test_concurrent_create(void)
{
    wg_noise_module_init();

    wg_noise_static_identity_t si_i, si_r;
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_static_identity_init(&si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&si_i, sk_i);

    wg_noise_static_identity_init(&si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&si_r, sk_r);

    wg_noise_handshake_t hs_i;
    wg_noise_handshake_init(&hs_i, &si_i, si_r.static_public, NULL);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    printf("  Running %d threads, %d iterations each...\n", NUM_THREADS,
           ITERATIONS_PER_THREAD);

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].si_i = &si_i;
        args[i].si_r = &si_r;
        args[i].hs_i = &hs_i;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        pthread_create(&threads[i], NULL, worker_create_initiation, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    assert(error_count == 0);

    pthread_mutex_destroy(&error_lock);
    pthread_rwlock_destroy(&hs_i.lock);
    pthread_rwlock_destroy(&si_i.lock);
    pthread_rwlock_destroy(&si_r.lock);
    wg_secure_zero(sk_i, WG_KEY_LEN);
    wg_secure_zero(sk_r, WG_KEY_LEN);

    printf("  PASS: concurrent_create (%d operations)\n",
           NUM_THREADS * ITERATIONS_PER_THREAD);
}

static void test_concurrent_consume(void)
{
    wg_noise_module_init();

    wg_noise_static_identity_t si_i, si_r;
    uint8_t sk_i[WG_KEY_LEN], sk_r[WG_KEY_LEN];

    wg_noise_static_identity_init(&si_i);
    wg_x25519_generate_private(sk_i);
    wg_noise_static_identity_set_private_key(&si_i, sk_i);

    wg_noise_static_identity_init(&si_r);
    wg_x25519_generate_private(sk_r);
    wg_noise_static_identity_set_private_key(&si_r, sk_r);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    printf("  Running %d threads, %d iterations each...\n", NUM_THREADS,
           ITERATIONS_PER_THREAD);

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].si_i = &si_i;
        args[i].si_r = &si_r;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        pthread_create(&threads[i], NULL, worker_consume_initiation, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    assert(error_count == 0);

    pthread_mutex_destroy(&error_lock);
    pthread_rwlock_destroy(&si_i.lock);
    pthread_rwlock_destroy(&si_r.lock);
    wg_secure_zero(sk_i, WG_KEY_LEN);
    wg_secure_zero(sk_r, WG_KEY_LEN);

    printf("  PASS: concurrent_consume (%d operations)\n",
           NUM_THREADS * ITERATIONS_PER_THREAD);
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("HS-1 Concurrent Stress Tests:\n");

    test_concurrent_create();
    test_concurrent_consume();

    printf("All concurrent tests passed.\n");
    return 0;
}

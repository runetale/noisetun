/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Concurrent stress tests for wg_ratelimiter.
 * Detects data races and deadlocks under TSan.
 */

#include "../src/ratelimiter/wg_ratelimiter.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

typedef struct {
    wg_ratelimiter_t *rl;
    int thread_id;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* ────────────────────────────────────────
 * Worker: mixed IPs — each thread uses 4 different IPs
 * ──────────────────────────────────────── */
static void *worker_allow_mixed(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* 4 unique IPs per thread: 10.<thread_id>.<i%4>.1 */
        for (int j = 0; j < 4; j++) {
            uint8_t ip[4] = {10, (uint8_t)targ->thread_id, (uint8_t)j, 1};
            /* Result doesn't matter — we're testing for races, not logic */
            wg_ratelimiter_allow(targ->rl, ip, 4);
        }

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: same IP — maximum contention on single entry
 * ──────────────────────────────────────── */
static void *worker_allow_same_ip(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    const uint8_t ip[4] = {192, 168, 1, 1};

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        wg_ratelimiter_allow(targ->rl, ip, 4);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent allow with mixed IPs
 * ──────────────────────────────────────── */
static void test_concurrent_allow_mixed(void)
{
    printf("  %-50s", "concurrent_allow_mixed");
    fflush(stdout);

    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].rl = &rl;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_allow_mixed, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_ratelimiter_close(&rl);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent allow with same IP (max contention)
 * ──────────────────────────────────────── */
static void test_concurrent_allow_same_ip(void)
{
    printf("  %-50s", "concurrent_allow_same_ip");
    fflush(stdout);

    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].rl = &rl;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_allow_same_ip, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_ratelimiter_close(&rl);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent allow with IPv6
 * ──────────────────────────────────────── */
static void *worker_allow_ipv6(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                           0,    0,    0, 0, 0, 0, 0, (uint8_t)targ->thread_id};
        wg_ratelimiter_allow(targ->rl, ip6, 16);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void test_concurrent_allow_ipv6(void)
{
    printf("  %-50s", "concurrent_allow_ipv6");
    fflush(stdout);

    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].rl = &rl;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_allow_ipv6, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_ratelimiter_close(&rl);

    printf("PASS\n");
}

int main(void)
{
    printf("RateLimiter Concurrent Stress Tests:\n");

    test_concurrent_allow_mixed();
    test_concurrent_allow_same_ip();
    test_concurrent_allow_ipv6();

    printf("All ratelimiter concurrent tests passed.\n");
    return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Concurrent stress tests for wg_allowedips.
 * Detects data races and deadlocks under TSan.
 */

#include "peer/wg_allowedips.h"
#include "peer/wg_peer.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

/* Dummy peers — we only use their addresses for identity */
static struct wg_peer peer_a, peer_b, peer_c, peer_d;
static struct wg_peer *peers[] = {&peer_a, &peer_b, &peer_c, &peer_d};
#define NUM_PEERS 4

typedef struct {
    wg_allowedips_t *table;
    int thread_id;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* ────────────────────────────────────────
 * Worker: insert prefixes
 * ──────────────────────────────────────── */
static void *worker_insert(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Each thread inserts to its own /24 subnet: 10.<thread_id>.<i>.0/24 */
        uint8_t ip[4] = {10, (uint8_t)targ->thread_id, (uint8_t)(i % 256), 0};
        struct wg_peer *peer = peers[targ->thread_id % NUM_PEERS];

        wg_error_t err = wg_allowedips_insert(targ->table, ip, 24, AF_INET, peer);
        if (err != WG_OK) {
            pthread_mutex_lock(targ->error_lock);
            (*targ->error_count)++;
            fprintf(stderr, "Thread %d iter %d: insert failed\n", targ->thread_id, i);
            pthread_mutex_unlock(targ->error_lock);
        }

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: lookup IPs
 * ──────────────────────────────────────── */
static void *worker_lookup(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Look up IPs from various subnets */
        uint8_t ip[4] = {10, (uint8_t)(i % NUM_THREADS), (uint8_t)(i % 256), 1};
        /* Result may or may not be found — that's fine, we test for races */
        wg_allowedips_lookup(targ->table, ip, AF_INET);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: insert then remove by peer
 * ──────────────────────────────────────── */
static void *worker_insert_remove(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    struct wg_peer *peer = peers[targ->thread_id % NUM_PEERS];

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Insert a prefix */
        uint8_t ip[4] = {172, 16, (uint8_t)targ->thread_id, (uint8_t)(i % 256)};
        wg_allowedips_insert(targ->table, ip, 32, AF_INET, peer);

        /* Every 10 iterations, remove all entries for this peer */
        if (i % 10 == 0)
            wg_allowedips_remove_by_peer(targ->table, peer);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent insert + lookup
 * ──────────────────────────────────────── */
static void test_concurrent_insert_lookup(void)
{
    printf("  %-50s", "concurrent_insert_lookup");
    fflush(stdout);

    wg_allowedips_t table;
    assert(wg_allowedips_init(&table) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].table = &table;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        /* Half insert, half lookup */
        if (i < NUM_THREADS / 2)
            pthread_create(&threads[i], NULL, worker_insert, &args[i]);
        else
            pthread_create(&threads[i], NULL, worker_lookup, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_allowedips_destroy(&table);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent insert + remove_by_peer
 * ──────────────────────────────────────── */
static void test_concurrent_insert_remove(void)
{
    printf("  %-50s", "concurrent_insert_remove");
    fflush(stdout);

    wg_allowedips_t table;
    assert(wg_allowedips_init(&table) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].table = &table;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_insert_remove, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_allowedips_destroy(&table);

    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: concurrent IPv6 insert + lookup
 * ──────────────────────────────────────── */
static void *worker_insert_ipv6(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t ip6[16] = {0xfd,
                           0x00,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           (uint8_t)targ->thread_id,
                           (uint8_t)(i % 256),
                           0,
                           0};
        struct wg_peer *peer = peers[targ->thread_id % NUM_PEERS];
        wg_allowedips_insert(targ->table, ip6, 96, AF_INET6, peer);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void *worker_lookup_ipv6(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t ip6[16] = {0xfd,
                           0x00,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           0,
                           (uint8_t)(i % NUM_THREADS),
                           (uint8_t)(i % 256),
                           0,
                           1};
        wg_allowedips_lookup(targ->table, ip6, AF_INET6);

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void test_concurrent_ipv6(void)
{
    printf("  %-50s", "concurrent_ipv6_insert_lookup");
    fflush(stdout);

    wg_allowedips_t table;
    assert(wg_allowedips_init(&table) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].table = &table;
        args[i].thread_id = i;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;

        if (i < NUM_THREADS / 2)
            pthread_create(&threads[i], NULL, worker_insert_ipv6, &args[i]);
        else
            pthread_create(&threads[i], NULL, worker_lookup_ipv6, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_allowedips_destroy(&table);

    printf("PASS\n");
}

int main(void)
{
    printf("AllowedIPs Concurrent Stress Tests:\n");

    test_concurrent_insert_lookup();
    test_concurrent_insert_remove();
    test_concurrent_ipv6();

    printf("All allowedips concurrent tests passed.\n");
    return 0;
}

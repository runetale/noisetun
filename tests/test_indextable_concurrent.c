/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Concurrent stress tests for wg_index_table.
 * Detects data races and deadlocks under TSan.
 */

#include "../src/peer/wg_indextable.h"

#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS           8
#define ITERATIONS_PER_THREAD 100

typedef struct {
    wg_index_table_t *table;
    int thread_id;
    uint32_t indices[ITERATIONS_PER_THREAD]; /* allocated indices */
    int alloc_count;
    int *error_count;
    pthread_mutex_t *error_lock;
} thread_arg_t;

/* Dummy peer/handshake/keypair objects */
static int dummy_peers[NUM_THREADS];
static int dummy_handshakes[NUM_THREADS];
static int dummy_keypairs[NUM_THREADS];

/* ────────────────────────────────────────
 * Worker: allocate indices
 * ──────────────────────────────────────── */
static void *worker_new_index(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;
    targ->alloc_count = 0;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint32_t index = 0;
        wg_error_t err =
            wg_index_table_new_index(targ->table, &dummy_peers[targ->thread_id],
                                     &dummy_handshakes[targ->thread_id], &index);

        if (err != WG_OK) {
            pthread_mutex_lock(targ->error_lock);
            (*targ->error_count)++;
            fprintf(stderr, "Thread %d iter %d: new_index failed\n", targ->thread_id, i);
            pthread_mutex_unlock(targ->error_lock);
        } else {
            targ->indices[targ->alloc_count++] = index;
        }

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Worker: mixed insert/lookup/delete
 * ──────────────────────────────────────── */
static void *worker_mixed_ops(void *arg)
{
    thread_arg_t *targ = (thread_arg_t *)arg;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        /* Allocate */
        uint32_t index = 0;
        wg_error_t err =
            wg_index_table_new_index(targ->table, &dummy_peers[targ->thread_id],
                                     &dummy_handshakes[targ->thread_id], &index);

        if (err == WG_OK) {
            /* Lookup */
            wg_index_entry_t entry;
            wg_index_table_lookup_copy(targ->table, index, &entry);

            /* Swap to keypair on even iterations */
            if (i % 2 == 0) {
                wg_index_table_swap_for_keypair(targ->table, index,
                                                &dummy_keypairs[targ->thread_id]);
            }

            /* Delete */
            wg_index_table_delete(targ->table, index);
        }

        struct timespec ts = {0, 1000};
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * Test: concurrent index allocation (uniqueness)
 * ──────────────────────────────────────── */
static void test_concurrent_new_index(void)
{
    printf("  %-50s", "concurrent_new_index");
    fflush(stdout);

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int error_count = 0;
    pthread_mutex_t error_lock;
    pthread_mutex_init(&error_lock, NULL);

    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].table = &table;
        args[i].thread_id = i;
        args[i].alloc_count = 0;
        args[i].error_count = &error_count;
        args[i].error_lock = &error_lock;
        pthread_create(&threads[i], NULL, worker_new_index, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);

    /* Verify all allocated indices are unique */
    int total = 0;
    for (int i = 0; i < NUM_THREADS; i++)
        total += args[i].alloc_count;

    uint32_t *all_indices = malloc((size_t)total * sizeof(uint32_t));
    assert(all_indices != NULL);

    int idx = 0;
    for (int i = 0; i < NUM_THREADS; i++)
        for (int j = 0; j < args[i].alloc_count; j++)
            all_indices[idx++] = args[i].indices[j];

    /* Simple O(n^2) uniqueness check — fine for 800 elements */
    for (int i = 0; i < total; i++)
        for (int j = i + 1; j < total; j++)
            assert(all_indices[i] != all_indices[j]);

    free(all_indices);
    pthread_mutex_destroy(&error_lock);
    wg_index_table_destroy(&table);

    printf("PASS (%d indices)\n", total);
}

/* ────────────────────────────────────────
 * Test: concurrent mixed operations
 * ──────────────────────────────────────── */
static void test_concurrent_mixed_ops(void)
{
    printf("  %-50s", "concurrent_mixed_ops");
    fflush(stdout);

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

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
        pthread_create(&threads[i], NULL, worker_mixed_ops, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(error_count == 0);
    pthread_mutex_destroy(&error_lock);
    wg_index_table_destroy(&table);

    printf("PASS\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    printf("IndexTable Concurrent Stress Tests:\n");

    test_concurrent_new_index();
    test_concurrent_mixed_ops();

    printf("All indextable concurrent tests passed.\n");
    return 0;
}

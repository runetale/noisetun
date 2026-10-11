/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for memory pools (wg_wait_pool).
 */

#include "device/wg_pools.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

#define ASSERT_OK(expr) assert((expr) == WG_OK)
#define TEST(name)               \
    do {                         \
        printf("  %-50s", name); \
        fflush(stdout);          \
    } while (0)
#define PASS()            \
    do {                  \
        printf("PASS\n"); \
    } while (0)

static int alloc_count;

static void *test_alloc(void *ctx)
{
    (void)ctx;
    alloc_count++;
    return malloc(64);
}

static void test_free(void *obj, void *ctx)
{
    (void)ctx;
    free(obj);
}

static void test_reset(void *obj, void *ctx)
{
    (void)ctx;
    memset(obj, 0, 64);
}

/* ────────────────────────────────────────
 * Test: basic get/put
 * ──────────────────────────────────────── */

static void test_basic_get_put(void)
{
    TEST("basic get/put");

    wg_wait_pool_t pool;
    alloc_count = 0;
    ASSERT_OK(wg_wait_pool_init(&pool, 0, test_alloc, test_free, NULL, NULL));

    /* First get should allocate */
    void *obj1 = wg_wait_pool_get(&pool);
    assert(obj1 != NULL);
    assert(alloc_count == 1);

    /* Put it back, then get again — should reuse */
    wg_wait_pool_put(&pool, obj1);
    void *obj2 = wg_wait_pool_get(&pool);
    assert(obj2 == obj1);
    assert(alloc_count == 1); /* no new allocation */

    wg_wait_pool_put(&pool, obj2);
    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Test: reset callback
 * ──────────────────────────────────────── */

static void test_reset_callback(void)
{
    TEST("reset callback on put");

    wg_wait_pool_t pool;
    ASSERT_OK(wg_wait_pool_init(&pool, 0, test_alloc, test_free, test_reset, NULL));

    void *obj = wg_wait_pool_get(&pool);
    memset(obj, 0xFF, 64);

    /* After put+get, the object should be zeroed by reset */
    wg_wait_pool_put(&pool, obj);
    void *obj2 = wg_wait_pool_get(&pool);
    assert(obj2 == obj);

    /* Check that reset zeroed the buffer */
    uint8_t *bytes = (uint8_t *)obj2;
    for (int i = 0; i < 64; i++)
        assert(bytes[i] == 0);

    wg_wait_pool_put(&pool, obj2);
    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Test: multiple objects
 * ──────────────────────────────────────── */

static void test_multiple_objects(void)
{
    TEST("multiple objects in pool");

    wg_wait_pool_t pool;
    alloc_count = 0;
    ASSERT_OK(wg_wait_pool_init(&pool, 0, test_alloc, test_free, NULL, NULL));

    void *objs[10];
    for (int i = 0; i < 10; i++) {
        objs[i] = wg_wait_pool_get(&pool);
        assert(objs[i] != NULL);
    }
    assert(alloc_count == 10);

    /* Return all */
    for (int i = 0; i < 10; i++)
        wg_wait_pool_put(&pool, objs[i]);

    /* Get again — should reuse (no new allocs) */
    for (int i = 0; i < 10; i++)
        objs[i] = wg_wait_pool_get(&pool);
    assert(alloc_count == 10);

    for (int i = 0; i < 10; i++)
        wg_wait_pool_put(&pool, objs[i]);
    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Test: backpressure (max limit)
 * ──────────────────────────────────────── */

typedef struct {
    wg_wait_pool_t *pool;
    void *result;
} backpressure_arg_t;

static void *backpressure_get_thread(void *arg)
{
    backpressure_arg_t *ba = (backpressure_arg_t *)arg;
    ba->result = wg_wait_pool_get(ba->pool);
    return NULL;
}

static void test_backpressure(void)
{
    TEST("backpressure (max=2)");

    wg_wait_pool_t pool;
    ASSERT_OK(wg_wait_pool_init(&pool, 2, test_alloc, test_free, NULL, NULL));

    /* Get 2 objects (at max) */
    void *obj1 = wg_wait_pool_get(&pool);
    void *obj2 = wg_wait_pool_get(&pool);
    assert(obj1 && obj2);

    /* Third get should block */
    backpressure_arg_t ba = {.pool = &pool, .result = NULL};
    pthread_t t;
    pthread_create(&t, NULL, backpressure_get_thread, &ba);

    /* Give it time to block */
    struct timespec ts = {0, 20000000}; /* 20ms */
    nanosleep(&ts, NULL);

    /* Return one — should unblock */
    wg_wait_pool_put(&pool, obj1);
    pthread_join(t, NULL);
    assert(ba.result != NULL);

    wg_wait_pool_put(&pool, obj2);
    wg_wait_pool_put(&pool, ba.result);
    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Test: close wakes a Get waiting at the cap
 *
 * A device joins the threads that may wait in Get before it returns the
 * objects they wait for; close must wake them (with NULL).
 * ──────────────────────────────────────── */

static void test_close_wakes_waiter(void)
{
    TEST("close wakes a Get waiting at the cap");

    wg_wait_pool_t pool;
    ASSERT_OK(wg_wait_pool_init(&pool, 1, test_alloc, test_free, NULL, NULL));
    void *held = wg_wait_pool_get(&pool);
    assert(held);

    backpressure_arg_t ba = {.pool = &pool, .result = (void *)1};
    pthread_t t;
    pthread_create(&t, NULL, backpressure_get_thread, &ba);
    struct timespec ts = {0, 20000000}; /* 20ms: let it wait */
    nanosleep(&ts, NULL);

    wg_wait_pool_close(&pool);
    pthread_join(t, NULL);
    assert(ba.result == NULL);
    /* Still closed: a Get at the cap fails at once. */
    assert(wg_wait_pool_get(&pool) == NULL);

    /* Reopened, it behaves as before. */
    wg_wait_pool_reopen(&pool);
    wg_wait_pool_put(&pool, held);
    void *again = wg_wait_pool_get(&pool);
    assert(again != NULL);
    wg_wait_pool_put(&pool, again);
    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Test: NULL put is ignored
 * ──────────────────────────────────────── */

static void test_null_put(void)
{
    TEST("NULL put is ignored");

    wg_wait_pool_t pool;
    ASSERT_OK(wg_wait_pool_init(&pool, 0, test_alloc, test_free, NULL, NULL));

    wg_wait_pool_put(&pool, NULL); /* should not crash */

    wg_wait_pool_destroy(&pool);
    PASS();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    printf("=== test_pools ===\n");

    test_basic_get_put();
    test_reset_callback();
    test_multiple_objects();
    test_backpressure();
    test_close_wakes_waiter();
    test_null_put();

    printf("All pool tests passed.\n");
    return 0;
}

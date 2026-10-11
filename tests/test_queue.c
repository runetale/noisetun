/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for bounded queue (wg_queue).
 */

#include "device/wg_queue.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* ────────────────────────────────────────
 * Test: basic push/pop
 * ──────────────────────────────────────── */

static void test_basic_push_pop(void)
{
    TEST("basic push/pop");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 4));

    int a = 1, b = 2, c = 3;
    ASSERT_OK(wg_queue_push(&q, &a));
    ASSERT_OK(wg_queue_push(&q, &b));
    ASSERT_OK(wg_queue_push(&q, &c));

    assert(wg_queue_count(&q) == 3);

    void *out;
    ASSERT_OK(wg_queue_pop(&q, &out));
    assert(out == &a);
    ASSERT_OK(wg_queue_pop(&q, &out));
    assert(out == &b);
    ASSERT_OK(wg_queue_pop(&q, &out));
    assert(out == &c);

    assert(wg_queue_count(&q) == 0);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: try_push when full
 * ──────────────────────────────────────── */

static void test_try_push_full(void)
{
    TEST("try_push returns QUEUE_FULL when full");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 2));

    int a = 1, b = 2, c = 3;
    ASSERT_OK(wg_queue_try_push(&q, &a));
    ASSERT_OK(wg_queue_try_push(&q, &b));
    ASSERT_ERR(wg_queue_try_push(&q, &c), WG_ERR_QUEUE_FULL);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: try_pop when empty
 * ──────────────────────────────────────── */

static void test_try_pop_empty(void)
{
    TEST("try_pop returns QUEUE_EMPTY when empty");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 4));

    void *out;
    ASSERT_ERR(wg_queue_try_pop(&q, &out), WG_ERR_QUEUE_EMPTY);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: close wakes blocked pop
 * ──────────────────────────────────────── */

typedef struct {
    wg_queue_t *q;
    wg_error_t result;
} pop_arg_t;

static void *pop_thread(void *arg)
{
    pop_arg_t *pa = (pop_arg_t *)arg;
    void *out;
    pa->result = wg_queue_pop(pa->q, &out);
    return NULL;
}

static void test_close_wakes_pop(void)
{
    TEST("close wakes blocked pop");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 4));

    pop_arg_t pa = {.q = &q, .result = WG_OK};
    pthread_t t;
    pthread_create(&t, NULL, pop_thread, &pa);

    /* Give the thread time to block */
    struct timespec ts = {0, 10000000}; /* 10ms */
    nanosleep(&ts, NULL);

    wg_queue_close(&q);
    pthread_join(t, NULL);

    assert(pa.result == WG_ERR_DEVICE_CLOSED);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: close allows draining remaining items
 * ──────────────────────────────────────── */

static void test_close_drain(void)
{
    TEST("close allows draining remaining items");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 4));

    int a = 42;
    ASSERT_OK(wg_queue_push(&q, &a));
    wg_queue_close(&q);

    /* Should still be able to pop existing items */
    void *out;
    ASSERT_OK(wg_queue_pop(&q, &out));
    assert(out == &a);

    /* Now empty + closed */
    ASSERT_ERR(wg_queue_pop(&q, &out), WG_ERR_DEVICE_CLOSED);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: wrap-around (FIFO order across ring boundary)
 * ──────────────────────────────────────── */

static void test_wraparound(void)
{
    TEST("FIFO order across ring wrap-around");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 4));

    int vals[8];
    for (int i = 0; i < 8; i++)
        vals[i] = i;

    /* Fill and drain twice to force wrap */
    for (int round = 0; round < 2; round++) {
        for (int i = 0; i < 4; i++)
            ASSERT_OK(wg_queue_push(&q, &vals[i]));

        for (int i = 0; i < 4; i++) {
            void *out;
            ASSERT_OK(wg_queue_pop(&q, &out));
            assert(*(int *)out == i);
        }
    }

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: concurrent producer/consumer
 * ──────────────────────────────────────── */

#define NUM_ITEMS 10000

typedef struct {
    wg_queue_t *q;
    int *items;
} producer_arg_t;

static void *producer_thread(void *arg)
{
    producer_arg_t *pa = (producer_arg_t *)arg;
    for (int i = 0; i < NUM_ITEMS; i++)
        wg_queue_push(pa->q, &pa->items[i]);
    return NULL;
}

static void test_concurrent_producer_consumer(void)
{
    TEST("concurrent producer/consumer (10000 items)");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 64));

    int *items = malloc(NUM_ITEMS * sizeof(int));
    for (int i = 0; i < NUM_ITEMS; i++)
        items[i] = i;

    producer_arg_t pa = {.q = &q, .items = items};
    pthread_t producer;
    pthread_create(&producer, NULL, producer_thread, &pa);

    /* Consumer */
    for (int i = 0; i < NUM_ITEMS; i++) {
        void *out;
        ASSERT_OK(wg_queue_pop(&q, &out));
        assert(*(int *)out == i);
    }

    pthread_join(producer, NULL);
    assert(wg_queue_count(&q) == 0);

    free(items);
    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Test: flush
 * ──────────────────────────────────────── */

static int flush_count;

static void flush_fn(void *item)
{
    (void)item;
    flush_count++;
}

static void test_flush(void)
{
    TEST("flush with free callback");

    wg_queue_t q;
    ASSERT_OK(wg_queue_init(&q, 8));

    int a = 1, b = 2, c = 3;
    ASSERT_OK(wg_queue_push(&q, &a));
    ASSERT_OK(wg_queue_push(&q, &b));
    ASSERT_OK(wg_queue_push(&q, &c));

    flush_count = 0;
    wg_queue_flush(&q, flush_fn);
    assert(flush_count == 3);
    assert(wg_queue_count(&q) == 0);

    wg_queue_destroy(&q);
    PASS();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    printf("=== test_queue ===\n");

    test_basic_push_pop();
    test_try_push_full();
    test_try_pop_empty();
    test_close_wakes_pop();
    test_close_drain();
    test_wraparound();
    test_concurrent_producer_consumer();
    test_flush();

    printf("All queue tests passed.\n");
    return 0;
}

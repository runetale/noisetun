/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * The per-peer order queue (src/device/wg_prev_queue.c): FIFO order,
 * capacity, peek / walk-ahead, the sentinel being re-queued when the queue
 * drains, and many producers against one consumer. Run it under TSan too.
 */

#include "../src/device/wg_prev_queue.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PASS(name) printf("  PASS: %s\n", name)

typedef struct {
    wg_prev_link_t link; /* must be first */
    int producer;
    uint32_t seq;
} item_t;

static void test_fifo_and_capacity(void)
{
    wg_prev_queue_t q;
    wg_prev_queue_init(&q, 4);
    item_t it[6];
    assert(wg_prev_queue_dequeue(&q) == NULL);
    for (int i = 0; i < 4; i++) {
        it[i].seq = (uint32_t)i;
        assert(wg_prev_queue_enqueue(&q, &it[i]));
    }
    assert(!wg_prev_queue_enqueue(&q, &it[4])); /* full */
    for (int i = 0; i < 4; i++)
        assert(wg_prev_queue_dequeue(&q) == &it[i]);
    assert(wg_prev_queue_dequeue(&q) == NULL);
    assert(wg_prev_queue_enqueue(&q, &it[5])); /* room again */
    assert(wg_prev_queue_dequeue(&q) == &it[5]);
    assert(wg_prev_queue_dequeue(&q) == NULL);
    PASS("FIFO order, refuses when full, reusable after draining");
}

static void test_one_at_a_time(void)
{
    /* Every dequeue of the only element re-queues the sentinel. */
    wg_prev_queue_t q;
    wg_prev_queue_init(&q, 8);
    item_t a, b;
    for (int i = 0; i < 1000; i++) {
        item_t *x = (i & 1) ? &a : &b;
        assert(wg_prev_queue_enqueue(&q, x));
        assert(wg_prev_queue_dequeue(&q) == x);
        assert(wg_prev_queue_dequeue(&q) == NULL);
    }
    PASS("single element in, single element out, repeatedly");
}

static void test_peek_and_walk(void)
{
    wg_prev_queue_t q;
    wg_prev_queue_init(&q, 16);
    item_t it[5];
    for (int i = 0; i < 5; i++)
        assert(wg_prev_queue_enqueue(&q, &it[i]));

    item_t *p = wg_prev_queue_peek(&q);
    assert(p == &it[0] && wg_prev_queue_peek(&q) == &it[0]);
    /* Walking ahead passes every element in order and takes none out. */
    int n = 0;
    for (item_t *w = p; w; w = wg_prev_queue_walk_next(&q, w))
        assert(w == &it[n++]);
    assert(n == 5);
    wg_prev_queue_drop_peeked(&q);
    assert(wg_prev_queue_peek(&q) == &it[1]);
    wg_prev_queue_drop_peeked(&q);

    /* Drain to one element, then walk across the re-queued sentinel. */
    for (int i = 2; i < 5; i++) {
        assert(wg_prev_queue_peek(&q) == &it[i]);
        wg_prev_queue_drop_peeked(&q);
    }
    item_t late;
    assert(wg_prev_queue_enqueue(&q, &it[0]));
    assert(wg_prev_queue_peek(&q) == &it[0]); /* sentinel re-queued behind it */
    assert(wg_prev_queue_enqueue(&q, &late));
    assert(wg_prev_queue_walk_next(&q, &it[0]) == &late);
    wg_prev_queue_drop_peeked(&q);
    assert(wg_prev_queue_peek(&q) == &late);
    wg_prev_queue_drop_peeked(&q);
    assert(wg_prev_queue_peek(&q) == NULL);
    PASS("peek is stable, walk_next sees later elements and skips the sentinel");
}

#define PRODUCERS    4
#define PER_PRODUCER 200000

static wg_prev_queue_t mq;
static item_t *items;
static atomic_int producers_done;

static void *producer(void *arg)
{
    int id = (int)(intptr_t)arg;
    for (uint32_t s = 0; s < PER_PRODUCER; s++) {
        item_t *it = &items[(size_t)id * PER_PRODUCER + s];
        it->producer = id;
        it->seq = s;
        while (!wg_prev_queue_enqueue(&mq, it))
            sched_yield(); /* full: the small capacity makes this common */
    }
    atomic_fetch_add(&producers_done, 1);
    return NULL;
}

static void test_many_producers(void)
{
    items = calloc((size_t)PRODUCERS * PER_PRODUCER, sizeof(*items));
    assert(items);
    wg_prev_queue_init(&mq, 64);
    atomic_store(&producers_done, 0);
    pthread_t t[PRODUCERS];
    for (int i = 0; i < PRODUCERS; i++)
        assert(pthread_create(&t[i], NULL, producer, (void *)(intptr_t)i) == 0);

    uint32_t next[PRODUCERS] = {0};
    long got = 0, walks = 0;
    while (got < (long)PRODUCERS * PER_PRODUCER) {
        item_t *it = wg_prev_queue_peek(&mq);
        if (!it) {
            sched_yield();
            continue;
        }
        /* Now and then look ahead, as the sequential thread does: what it
         * sees must also be in per-producer order. */
        if ((got & 1023) == 0) {
            uint32_t seen[PRODUCERS];
            for (int i = 0; i < PRODUCERS; i++)
                seen[i] = next[i];
            for (item_t *w = it; w; w = wg_prev_queue_walk_next(&mq, w)) {
                assert(w->seq == seen[w->producer]);
                seen[w->producer]++;
                walks++;
            }
        }
        assert(it->seq == next[it->producer]); /* per-producer order kept */
        next[it->producer]++;
        wg_prev_queue_drop_peeked(&mq);
        got++;
    }
    for (int i = 0; i < PRODUCERS; i++) {
        pthread_join(t[i], NULL);
        assert(next[i] == PER_PRODUCER);
    }
    assert(wg_prev_queue_dequeue(&mq) == NULL);
    assert(atomic_load(&mq.count) == 0);
    free(items);
    printf("    (%ld elements, %ld looked at while walking ahead)\n", got, walks);
    PASS("4 producers x 200000 against one consumer: nothing lost, order kept");
}

int main(void)
{
    printf("=== test_prev_queue ===\n");
    test_fifo_and_capacity();
    test_one_at_a_time();
    test_peek_and_walk();
    test_many_producers();
    printf("All prev_queue tests passed.\n");
    return 0;
}

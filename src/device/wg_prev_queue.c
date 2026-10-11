/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Per-peer order queue (Vyukov intrusive MPSC queue); see wg_prev_queue.h.
 */

#include "wg_prev_queue.h"

void wg_prev_queue_init(wg_prev_queue_t *q, int capacity)
{
    atomic_store_explicit(&q->sentinel.next, NULL, memory_order_relaxed);
    atomic_store_explicit(&q->back, &q->sentinel, memory_order_relaxed);
    q->front = &q->sentinel;
    q->peeked = NULL;
    atomic_store_explicit(&q->count, 0, memory_order_relaxed);
    q->capacity = capacity;
}

/* Make node the new back and link the previous back to it.
 *
 * Between the exchange and the store the node is "in flight": it is the
 * back, but nothing points at it yet, and the consumer stops short of it.
 * The exchange is acq_rel rather than release: the previous back may be
 * another producer's node, and our store into its link must come after
 * that producer's own initialisation of it. */
static void append(wg_prev_queue_t *q, wg_prev_link_t *node)
{
    atomic_store_explicit(&node->next, NULL, memory_order_relaxed);
    wg_prev_link_t *prev = atomic_exchange_explicit(&q->back, node, memory_order_acq_rel);
    atomic_store_explicit(&prev->next, node, memory_order_release);
}

bool wg_prev_queue_enqueue(wg_prev_queue_t *q, void *elem)
{
    /* Reserve a slot first, so a full queue refuses without touching the
     * list. */
    int n = atomic_load_explicit(&q->count, memory_order_relaxed);
    do {
        if (n >= q->capacity)
            return false;
    } while (!atomic_compare_exchange_weak_explicit(
        &q->count, &n, n + 1, memory_order_relaxed, memory_order_relaxed));
    append(q, (wg_prev_link_t *)elem);
    return true;
}

void *wg_prev_queue_dequeue(wg_prev_queue_t *q)
{
    wg_prev_link_t *node = q->front;
    wg_prev_link_t *after = atomic_load_explicit(&node->next, memory_order_acquire);

    /* The sentinel is never handed out: step past it. */
    if (node == &q->sentinel) {
        if (!after)
            return NULL; /* empty */
        node = after;
        q->front = node;
        after = atomic_load_explicit(&node->next, memory_order_acquire);
    }

    if (!after) {
        /* node is the last linked node. If it is not also the back, a
         * producer has swapped in behind it and not linked yet; try
         * again later rather than wait. */
        if (node != atomic_load_explicit(&q->back, memory_order_acquire))
            return NULL;
        /* Queue the sentinel behind node, so that taking node out still
         * leaves one node in the list for producers to link to. */
        append(q, &q->sentinel);
        after = atomic_load_explicit(&node->next, memory_order_acquire);
        if (!after)
            return NULL; /* a producer got in between; next call */
    }

    q->front = after;
    atomic_fetch_sub_explicit(&q->count, 1, memory_order_relaxed);
    return node;
}

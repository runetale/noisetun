/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Per-peer order queue: a bounded, intrusive, lock-free queue with many
 * producers and one consumer.
 *
 * Packets are appended in the order they were read (TUN or UDP) and taken
 * out in that same order by the peer's sequential thread, while crypto
 * workers finish them in any order. The algorithm is Dmitry Vyukov's
 * intrusive MPSC node-based queue (1024cores.net, "Intrusive MPSC
 * node-based queue"): a producer swaps itself in as the new back with one
 * atomic exchange and then links the old back to itself; the consumer
 * walks from the front along those links. A sentinel node keeps the list
 * non-empty, so neither side ever sees a null back.
 * Vyukov's published code is used under the Apache License 2.0 (it is
 * also offered under the Simplified BSD License); see NOTICE.
 *
 * An element carries its link as its first member, so a link pointer and
 * an element pointer are the same address.
 */

#ifndef WG_PREV_QUEUE_H
#define WG_PREV_QUEUE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

/* The link every queued element starts with. */
typedef struct wg_prev_link {
    _Atomic(struct wg_prev_link *) next;
} wg_prev_link_t;

typedef struct wg_prev_queue {
    /* Last node; producers exchange themselves in here. */
    _Atomic(wg_prev_link_t *) back;
    /* Consumer only: the next node to hand out, and a cached peek. */
    wg_prev_link_t *front;
    wg_prev_link_t *peeked;
    /* Number of queued elements, bounded by capacity. */
    _Atomic int count;
    int capacity;
    wg_prev_link_t sentinel;
} wg_prev_queue_t;

/* Elements per peer queue. A sequential thread that is descheduled for a
 * while must not make producers drop: 8192 is about 12 ms at 660k
 * packets/s. */
#define WG_PREV_QUEUE_MAX_PACKETS 8192

/* Empty the queue and set its capacity. Not safe against concurrent use. */
void wg_prev_queue_init(wg_prev_queue_t *q, int capacity);

/* Any thread: append elem (its first member is a wg_prev_link_t). Returns
 * false, without queueing it, when the queue is full. */
bool wg_prev_queue_enqueue(wg_prev_queue_t *q, void *elem);

/* Consumer only: take the front element, or NULL if there is none yet (an
 * element whose producer has not finished linking it counts as none). */
void *wg_prev_queue_dequeue(wg_prev_queue_t *q);

/* Consumer only: the front element without consuming it; the same element
 * until wg_prev_queue_drop_peeked(). */
static inline void *wg_prev_queue_peek(wg_prev_queue_t *q)
{
    if (!q->peeked)
        q->peeked = wg_prev_queue_dequeue(q);
    return q->peeked;
}

/* Consumer only: consume the element wg_prev_queue_peek() returned. */
static inline void wg_prev_queue_drop_peeked(wg_prev_queue_t *q)
{
    q->peeked = NULL;
}

/* Consumer only: the element queued after elem (the peeked element or one
 * reached from it), or NULL at the current end. Lets the consumer look
 * ahead without taking anything out; elements it passes stay queued. */
static inline void *wg_prev_queue_walk_next(wg_prev_queue_t *q, void *elem)
{
    wg_prev_link_t *n =
        atomic_load_explicit(&((wg_prev_link_t *)elem)->next, memory_order_acquire);
    if (n == &q->sentinel)
        n = atomic_load_explicit(&n->next, memory_order_acquire);
    return n;
}

#endif /* WG_PREV_QUEUE_H */

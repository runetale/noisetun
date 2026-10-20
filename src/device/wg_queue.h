/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Bounded queues for packet processing pipeline.
 *
 * Three queue types:
 *   outbound  — QueueOutboundElementsContainer (encryption)
 *   inbound   — QueueInboundElementsContainer  (decryption)
 *   handshake — QueueHandshakeElement
 *
 * Each queue is bounded (capacity), thread-safe (mutex + condvar),
 * and supports close notification.
 *
 * Reference: wireguard-go/device/channels.go
 */

#ifndef WG_QUEUE_H
#define WG_QUEUE_H

#include "wg_constants.h"
#include "wg_error.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Generic bounded FIFO queue (ring buffer)
 *
 * Stores void* elements. Capacity is fixed at creation.
 * Thread-safe with mutex + condvars for blocking push/pop.
 * ──────────────────────────────────────── */
typedef struct {
    void **items;
    size_t capacity;
    size_t head;  /* next pop index */
    size_t tail;  /* next push index */
    size_t count; /* number of items in queue */
    bool closed;

    /* Waiter counts: track threads sleeping on each condvar so
     * push/pop can skip the condvar signal syscall when no thread
     * is actually blocked.  Protected by `lock`. */
    unsigned pop_waiters;  /* threads blocked in pop() waiting for items */
    unsigned push_waiters; /* threads blocked in push() waiting for space */

    /* Lock-free count hint for spin-wait optimization.
     * Updated with release/acquire semantics so pop_batch can spin
     * on this without acquiring the mutex. */
    _Atomic size_t count_hint;

    pthread_mutex_t lock;
    pthread_cond_t not_empty; /* signalled on push or close */
    pthread_cond_t not_full;  /* signalled on pop or close */
    /* The clock not_empty's timed waits measure against: CLOCK_MONOTONIC
     * where the condvar could be set to it, CLOCK_REALTIME otherwise. */
    int not_empty_clock;
} wg_queue_t;

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

/*
 * Initialise a queue with the given capacity.
 * Allocates the internal ring buffer.
 */
wg_error_t wg_queue_init(wg_queue_t *q, size_t capacity);

/*
 * Destroy the queue: free internal buffer, destroy mutex/condvars.
 * The queue must not be in use by other threads.
 */
void wg_queue_destroy(wg_queue_t *q);

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

/*
 * Push an item into the queue (blocking if full).
 * Returns WG_OK on success.
 * Returns WG_ERR_DEVICE_CLOSED if the queue was closed while waiting.
 */
wg_error_t wg_queue_push(wg_queue_t *q, void *item);

/*
 * Try to push an item without blocking.
 * Returns WG_OK on success.
 * Returns WG_ERR_QUEUE_FULL if the queue is full.
 * Returns WG_ERR_DEVICE_CLOSED if the queue is closed.
 */
wg_error_t wg_queue_try_push(wg_queue_t *q, void *item);

/*
 * Pop an item from the queue (blocking if empty).
 * Returns WG_OK on success, *out set to the popped item.
 * Returns WG_ERR_DEVICE_CLOSED if the queue was closed while waiting
 * (and the queue is empty).
 */
wg_error_t wg_queue_pop(wg_queue_t *q, void **out);

/*
 * Try to pop an item without blocking.
 * Returns WG_OK on success, *out set to the popped item.
 * Returns WG_ERR_QUEUE_EMPTY if the queue is empty.
 * Returns WG_ERR_DEVICE_CLOSED if the queue is closed and empty.
 */
wg_error_t wg_queue_try_pop(wg_queue_t *q, void **out);

/*
 * Pop an item with a timeout (milliseconds).
 * Returns WG_OK on success, *out set to the popped item.
 * Returns WG_ERR_TIMEOUT if the timeout expires before an item is available.
 * Returns WG_ERR_DEVICE_CLOSED if the queue was closed while waiting.
 */
wg_error_t wg_queue_pop_timeout(wg_queue_t *q, void **out, int timeout_ms);

/*
 * Push multiple items without blocking (single lock acquisition).
 * Returns the number of items successfully pushed (0..count).
 * Stops early if the queue fills up or is closed.
 */
int wg_queue_try_push_batch(wg_queue_t *q, void **items, int count);

/*
 * Pop multiple items (single lock acquisition).
 * Blocks until at least one item is available (like wg_queue_pop),
 * then greedily pops up to `max` items without re-blocking.
 * Returns the number of items popped, or -1 if the queue is closed
 * and empty.
 */
int wg_queue_pop_batch(wg_queue_t *q, void **out, int max);

/*
 * Try to pop multiple items without blocking (single lock acquisition).
 * Returns the number of items popped (0 if empty).
 * Returns -1 if the queue is closed and empty.
 */
int wg_queue_try_pop_batch(wg_queue_t *q, void **out, int max);

/*
 * Close the queue: wake all waiting threads.
 * Subsequent pushes will fail. Pops will drain remaining items,
 * then return WG_ERR_DEVICE_CLOSED.
 */
void wg_queue_close(wg_queue_t *q);

/*
 * Flush: pop and discard all remaining items.
 * If free_fn is non-NULL, call it on each item before discarding.
 */
void wg_queue_flush(wg_queue_t *q, void (*free_fn)(void *));

/*
 * Return the current number of items in the queue.
 */
size_t wg_queue_count(wg_queue_t *q);

/*
 * Return whether the queue has been closed.
 */
bool wg_queue_is_closed(wg_queue_t *q);

#endif /* WG_QUEUE_H */

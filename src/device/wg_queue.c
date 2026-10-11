/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Bounded queues for packet processing pipeline.
 *
 * Reference: wireguard-go/device/channels.go
 */

#include "wg_queue.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_queue_init(wg_queue_t *q, size_t capacity)
{
    memset(q, 0, sizeof(*q));

    q->items = calloc(capacity, sizeof(void *));
    if (!q->items)
        return WG_ERR_NO_MEMORY;

    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->closed = false;
    q->pop_waiters = 0;
    q->push_waiters = 0;

    if (pthread_mutex_init(&q->lock, NULL) != 0)
        goto fail_items;
    if (pthread_cond_init(&q->not_empty, NULL) != 0)
        goto fail_mutex;
    if (pthread_cond_init(&q->not_full, NULL) != 0)
        goto fail_not_empty;

    return WG_OK;

fail_not_empty:
    pthread_cond_destroy(&q->not_empty);
fail_mutex:
    pthread_mutex_destroy(&q->lock);
fail_items:
    free(q->items);
    q->items = NULL;
    return WG_ERR_NO_MEMORY;
}

void wg_queue_destroy(wg_queue_t *q)
{
    if (!q)
        return;

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);

    free(q->items);
    q->items = NULL;
    q->capacity = 0;
    q->count = 0;
}

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

wg_error_t wg_queue_push(wg_queue_t *q, void *item)
{
    pthread_mutex_lock(&q->lock);

    while (q->count == q->capacity && !q->closed) {
        q->push_waiters++;
        pthread_cond_wait(&q->not_full, &q->lock);
        q->push_waiters--;
    }

    if (q->closed) {
        pthread_mutex_unlock(&q->lock);
        return WG_ERR_DEVICE_CLOSED;
    }

    q->items[q->tail] = item;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;

    if (q->pop_waiters > 0)
        pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return WG_OK;
}

wg_error_t wg_queue_try_push(wg_queue_t *q, void *item)
{
    pthread_mutex_lock(&q->lock);

    if (q->closed) {
        pthread_mutex_unlock(&q->lock);
        return WG_ERR_DEVICE_CLOSED;
    }

    if (q->count == q->capacity) {
        pthread_mutex_unlock(&q->lock);
        return WG_ERR_QUEUE_FULL;
    }

    q->items[q->tail] = item;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;

    if (q->pop_waiters > 0)
        pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return WG_OK;
}

wg_error_t wg_queue_pop(wg_queue_t *q, void **out)
{
    pthread_mutex_lock(&q->lock);

    while (q->count == 0 && !q->closed) {
        q->pop_waiters++;
        pthread_cond_wait(&q->not_empty, &q->lock);
        q->pop_waiters--;
    }

    if (q->count == 0 && q->closed) {
        pthread_mutex_unlock(&q->lock);
        *out = NULL;
        return WG_ERR_DEVICE_CLOSED;
    }

    *out = q->items[q->head];
    q->items[q->head] = NULL;
    q->head = (q->head + 1) % q->capacity;
    q->count--;

    if (q->push_waiters > 0)
        pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return WG_OK;
}

wg_error_t wg_queue_try_pop(wg_queue_t *q, void **out)
{
    pthread_mutex_lock(&q->lock);

    if (q->count == 0) {
        *out = NULL;
        wg_error_t err = q->closed ? WG_ERR_DEVICE_CLOSED : WG_ERR_QUEUE_EMPTY;
        pthread_mutex_unlock(&q->lock);
        return err;
    }

    *out = q->items[q->head];
    q->items[q->head] = NULL;
    q->head = (q->head + 1) % q->capacity;
    q->count--;

    if (q->push_waiters > 0)
        pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return WG_OK;
}

wg_error_t wg_queue_pop_timeout(wg_queue_t *q, void **out, int timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&q->lock);

    while (q->count == 0 && !q->closed) {
        q->pop_waiters++;
        int rc = pthread_cond_timedwait(&q->not_empty, &q->lock, &deadline);
        q->pop_waiters--;
        if (rc == ETIMEDOUT || rc == EINVAL) {
            *out = NULL;
            pthread_mutex_unlock(&q->lock);
            return WG_ERR_TIMEOUT;
        }
    }

    if (q->count == 0 && q->closed) {
        pthread_mutex_unlock(&q->lock);
        *out = NULL;
        return WG_ERR_DEVICE_CLOSED;
    }

    *out = q->items[q->head];
    q->items[q->head] = NULL;
    q->head = (q->head + 1) % q->capacity;
    q->count--;

    if (q->push_waiters > 0)
        pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return WG_OK;
}

int wg_queue_try_push_batch(wg_queue_t *q, void **items, int count)
{
    if (count <= 0)
        return 0;

    pthread_mutex_lock(&q->lock);

    if (q->closed) {
        pthread_mutex_unlock(&q->lock);
        return 0;
    }

    int pushed = 0;
    while (pushed < count && q->count < q->capacity) {
        q->items[q->tail] = items[pushed];
        q->tail = (q->tail + 1) % q->capacity;
        q->count++;
        pushed++;
    }

    if (pushed > 0 && q->pop_waiters > 0)
        pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return pushed;
}

int wg_queue_pop_batch(wg_queue_t *q, void **out, int max)
{
    if (max <= 0)
        return 0;

    pthread_mutex_lock(&q->lock);

    /* Block until at least one item is available. */
    while (q->count == 0 && !q->closed) {
        q->pop_waiters++;
        pthread_cond_wait(&q->not_empty, &q->lock);
        q->pop_waiters--;
    }

    if (q->count == 0 && q->closed) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    /* Greedily pop up to max items. */
    int popped = 0;
    while (popped < max && q->count > 0) {
        out[popped] = q->items[q->head];
        q->items[q->head] = NULL;
        q->head = (q->head + 1) % q->capacity;
        q->count--;
        popped++;
    }

    if (popped > 0 && q->push_waiters > 0)
        pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return popped;
}

int wg_queue_try_pop_batch(wg_queue_t *q, void **out, int max)
{
    if (max <= 0)
        return 0;

    pthread_mutex_lock(&q->lock);

    if (q->count == 0) {
        int ret = q->closed ? -1 : 0;
        pthread_mutex_unlock(&q->lock);
        return ret;
    }

    int popped = 0;
    while (popped < max && q->count > 0) {
        out[popped] = q->items[q->head];
        q->items[q->head] = NULL;
        q->head = (q->head + 1) % q->capacity;
        q->count--;
        popped++;
    }

    if (popped > 0 && q->push_waiters > 0)
        pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return popped;
}

void wg_queue_close(wg_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    q->closed = true;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}

void wg_queue_flush(wg_queue_t *q, void (*free_fn)(void *))
{
    pthread_mutex_lock(&q->lock);

    while (q->count > 0) {
        void *item = q->items[q->head];
        q->items[q->head] = NULL;
        q->head = (q->head + 1) % q->capacity;
        q->count--;

        if (free_fn && item)
            free_fn(item);
    }

    pthread_mutex_unlock(&q->lock);
}

size_t wg_queue_count(wg_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    size_t n = q->count;
    pthread_mutex_unlock(&q->lock);
    return n;
}

bool wg_queue_is_closed(wg_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    bool closed = q->closed;
    pthread_mutex_unlock(&q->lock);
    return closed;
}

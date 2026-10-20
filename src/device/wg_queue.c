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
 * Timed waits on the monotonic clock
 *
 * The same arrangement as the timers (wg_timers.c): the deadline is
 * monotonic, and each platform is asked in the way it understands.
 * A deadline on CLOCK_REALTIME measured against the Windows shim's
 * monotonic clock lay decades ahead, and a pop that nothing answered
 * never came back.
 * ──────────────────────────────────────── */

static uint64_t queue_mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int queue_cond_init_mono(pthread_cond_t *cond, int *cond_clock)
{
#ifdef __APPLE__
    /* No pthread_condattr_setclock: queue_timedwait waits relative to
     * the monotonic clock instead. */
    *cond_clock = CLOCK_REALTIME;
    return pthread_cond_init(cond, NULL);
#else
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    int rc;
    if (!WG_CONDATTR_SETCLOCK_WORKS || pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
        *cond_clock = CLOCK_REALTIME;
        rc = pthread_cond_init(cond, NULL);
    } else {
        *cond_clock = CLOCK_MONOTONIC;
        rc = pthread_cond_init(cond, &attr);
    }
    pthread_condattr_destroy(&attr);
    return rc;
#endif
}

static int queue_timedwait(pthread_cond_t *cond, pthread_mutex_t *lock, int cond_clock,
                           uint64_t deadline_ns)
{
    uint64_t now = queue_mono_now_ns();
    uint64_t remain = deadline_ns > now ? deadline_ns - now : 0;
#ifdef __APPLE__
    (void)cond_clock;
    struct timespec rel;
    rel.tv_sec = (time_t)(remain / 1000000000ULL);
    rel.tv_nsec = (long)(remain % 1000000000ULL);
    return pthread_cond_timedwait_relative_np(cond, lock, &rel);
#else
    struct timespec ts;
    uint64_t abs_ns;
    if (cond_clock == CLOCK_MONOTONIC) {
        abs_ns = deadline_ns;
    } else {
        /* The condvar kept the default clock: what remains, as a
         * deadline on that clock (see cond_timedwait_mono in
         * wg_timers.c). */
        clock_gettime(cond_clock, &ts);
        abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec + remain;
    }
    ts.tv_sec = (time_t)(abs_ns / 1000000000ULL);
    ts.tv_nsec = (long)(abs_ns % 1000000000ULL);
    return pthread_cond_timedwait(cond, lock, &ts);
#endif
}

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
    if (queue_cond_init_mono(&q->not_empty, &q->not_empty_clock) != 0)
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
    if (timeout_ms < 0)
        timeout_ms = 0;
    uint64_t deadline_ns = queue_mono_now_ns() + (uint64_t)timeout_ms * 1000000ULL;

    pthread_mutex_lock(&q->lock);

    while (q->count == 0 && !q->closed) {
        q->pop_waiters++;
        int rc = queue_timedwait(&q->not_empty, &q->lock, q->not_empty_clock, deadline_ns);
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

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Memory Pools — pre-allocated, reusable buffer pool with backpressure.
 * Lock-free Treiber stack fast-path for max == 0 pools.
 *
 * Reference: wireguard-go/device/pools.go
 */

#include "wg_pools.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_STACK_CAPACITY 16

/* ────────────────────────────────────────
 * Lock-free helpers
 * ──────────────────────────────────────── */

/* Get/set the intrusive next pointer inside an element. */
/* The link is read by a popper that may lose the race for obj to
 * another popper, which then writes it: relaxed atomics, not plain
 * accesses (the lost read is discarded when the CAS fails). They compile
 * to plain loads and stores. */
static inline _Atomic(void *) *lf_next_ptr(wg_wait_pool_t *p, void *obj)
{
    return (_Atomic(void *) *)((char *)obj + p->next_offset);
}

static inline void *lf_next_load(wg_wait_pool_t *p, void *obj)
{
    return atomic_load_explicit(lf_next_ptr(p, obj), memory_order_relaxed);
}

static inline void lf_next_store(wg_wait_pool_t *p, void *obj, void *next)
{
    atomic_store_explicit(lf_next_ptr(p, obj), next, memory_order_relaxed);
}

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_wait_pool_init(wg_wait_pool_t *p, uint32_t max, wg_pool_alloc_fn alloc_fn,
                             wg_pool_free_fn free_fn, wg_pool_reset_fn reset_fn,
                             void *ctx)
{
    memset(p, 0, sizeof(*p));

    p->stack = calloc(INITIAL_STACK_CAPACITY, sizeof(void *));
    if (!p->stack)
        return WG_ERR_NO_MEMORY;

    p->stack_capacity = INITIAL_STACK_CAPACITY;
    p->stack_count = 0;

    p->alloc_fn = alloc_fn;
    p->free_fn = free_fn;
    p->reset_fn = reset_fn;
    p->ctx = ctx;

    p->max = max;
    p->out = 0;

    p->lf_enabled = false;
    atomic_store(&p->lf_head, 0);

    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->cond, NULL);

    return WG_OK;
}

void wg_wait_pool_enable_lockfree(wg_wait_pool_t *p, size_t next_offset)
{
    p->next_offset = next_offset;
    p->lf_enabled = true;
    atomic_store(&p->lf_head, 0);
}

void wg_wait_pool_close(wg_wait_pool_t *p)
{
    if (!p || p->lf_enabled)
        return; /* the lock-free pool never waits */
    pthread_mutex_lock(&p->lock);
    p->closed = true;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->lock);
}

void wg_wait_pool_reopen(wg_wait_pool_t *p)
{
    if (!p || p->lf_enabled)
        return;
    pthread_mutex_lock(&p->lock);
    p->closed = false;
    pthread_mutex_unlock(&p->lock);
}

void wg_wait_pool_destroy(wg_wait_pool_t *p)
{
    if (!p)
        return;

    /* Drain lock-free stack first */
    if (p->lf_enabled) {
        uint64_t head = atomic_load(&p->lf_head);
        while (wg_lf_ptr(head)) {
            void *obj = wg_lf_ptr(head);
            void *next = lf_next_load(p, obj);
            if (p->free_fn)
                p->free_fn(obj, p->ctx);
            head = (uint64_t)(uintptr_t)next; /* raw pointer, no tag needed */
        }
    }

    /* Free all mutex-stack objects (pre-lockfree or fallback) */
    for (size_t i = 0; i < p->stack_count; i++) {
        if (p->free_fn && p->stack[i])
            p->free_fn(p->stack[i], p->ctx);
    }

    free(p->stack);
    p->stack = NULL;
    p->stack_count = 0;
    p->stack_capacity = 0;

    pthread_cond_destroy(&p->cond);
    pthread_mutex_destroy(&p->lock);
}

/* ────────────────────────────────────────
 * Lock-free operations (Treiber stack)
 * ──────────────────────────────────────── */

static void *lf_pool_get(wg_wait_pool_t *p)
{
    uint64_t old_head = atomic_load_explicit(&p->lf_head, memory_order_acquire);
    for (;;) {
        void *obj = wg_lf_ptr(old_head);
        if (!obj) {
            /* Stack empty — allocate new */
            return p->alloc_fn(p->ctx);
        }
        void *next = lf_next_load(p, obj);
        uint64_t new_head = wg_lf_make(next, old_head);
        if (atomic_compare_exchange_weak_explicit(&p->lf_head, &old_head, new_head,
                                                  memory_order_acquire,
                                                  memory_order_acquire)) {
            lf_next_store(p, obj, NULL);
            return obj;
        }
        /* CAS failed — old_head updated by CAS, retry */
    }
}

static void lf_pool_put(wg_wait_pool_t *p, void *obj)
{
    if (p->reset_fn)
        p->reset_fn(obj, p->ctx);

    uint64_t old_head = atomic_load_explicit(&p->lf_head, memory_order_relaxed);
    for (;;) {
        lf_next_store(p, obj, wg_lf_ptr(old_head));
        uint64_t new_head = wg_lf_make(obj, old_head);
        if (atomic_compare_exchange_weak_explicit(&p->lf_head, &old_head, new_head,
                                                  memory_order_release,
                                                  memory_order_relaxed)) {
            return;
        }
    }
}

static int lf_pool_put_batch(wg_wait_pool_t *p, void **objs, int count)
{
    if (count <= 0)
        return 0;

    /* Reset all objects */
    if (p->reset_fn) {
        for (int i = 0; i < count; i++) {
            if (objs[i])
                p->reset_fn(objs[i], p->ctx);
        }
    }

    /* Build local chain: objs[0] -> objs[1] -> ... -> objs[n-1] */
    int valid = 0;
    int first = -1, last = -1;
    for (int i = 0; i < count; i++) {
        if (!objs[i])
            continue;
        if (first < 0)
            first = i;
        if (last >= 0)
            lf_next_store(p, objs[last], objs[i]);
        last = i;
        valid++;
    }

    if (valid == 0)
        return 0;

    /* Push entire chain with single CAS: tail->next = old_head, head = first */
    uint64_t old_head = atomic_load_explicit(&p->lf_head, memory_order_relaxed);
    for (;;) {
        lf_next_store(p, objs[last], wg_lf_ptr(old_head));
        uint64_t new_head = wg_lf_make(objs[first], old_head);
        if (atomic_compare_exchange_weak_explicit(&p->lf_head, &old_head, new_head,
                                                  memory_order_release,
                                                  memory_order_relaxed)) {
            return valid;
        }
    }
}

/* ────────────────────────────────────────
 * Mutex-based operations (original, used when max > 0 or lf not enabled)
 * ──────────────────────────────────────── */

static void *pool_get(wg_wait_pool_t *p, bool wait)
{
    /* Lock-free fast path */
    if (p->lf_enabled)
        return lf_pool_get(p);

    pthread_mutex_lock(&p->lock);

    /* Backpressure: wait if at max outstanding, unless shutting down. */
    if (p->max != 0) {
        while (wait && p->out >= p->max && !p->closed)
            pthread_cond_wait(&p->cond, &p->lock);
        if (p->out >= p->max) {
            pthread_mutex_unlock(&p->lock);
            return NULL;
        }
    }

    p->out++;

    /* Try to reuse a pooled object */
    void *obj = NULL;
    if (p->stack_count > 0) {
        p->stack_count--;
        obj = p->stack[p->stack_count];
        p->stack[p->stack_count] = NULL;
    }

    pthread_mutex_unlock(&p->lock);

    /* Allocate a new object if none available */
    if (!obj) {
        obj = p->alloc_fn(p->ctx);
        if (!obj) {
            /* alloc failed — roll back the outstanding count to avoid
             * a permanent leak that would eventually deadlock. */
            pthread_mutex_lock(&p->lock);
            p->out--;
            if (p->max != 0)
                pthread_cond_signal(&p->cond);
            pthread_mutex_unlock(&p->lock);
            return NULL;
        }
    }

    return obj;
}

void *wg_wait_pool_get(wg_wait_pool_t *p)
{
    return pool_get(p, true);
}

void *wg_wait_pool_try_get(wg_wait_pool_t *p)
{
    return pool_get(p, false);
}

void wg_wait_pool_put(wg_wait_pool_t *p, void *obj)
{
    if (!obj)
        return;

    /* Lock-free fast path */
    if (p->lf_enabled) {
        lf_pool_put(p, obj);
        return;
    }

    /* Reset the object before recycling */
    if (p->reset_fn)
        p->reset_fn(obj, p->ctx);

    pthread_mutex_lock(&p->lock);

    /* Grow the stack if needed */
    if (p->stack_count == p->stack_capacity) {
        size_t new_cap = p->stack_capacity * 2;
        void **new_stack = realloc(p->stack, new_cap * sizeof(void *));
        if (new_stack) {
            p->stack = new_stack;
            p->stack_capacity = new_cap;
        } else {
            /* Cannot grow: free the object instead of leaking */
            if (p->free_fn)
                p->free_fn(obj, p->ctx);
            p->out--;
            if (p->max != 0)
                pthread_cond_signal(&p->cond);
            pthread_mutex_unlock(&p->lock);
            return;
        }
    }

    p->stack[p->stack_count++] = obj;

    p->out--;
    if (p->max != 0)
        pthread_cond_signal(&p->cond);

    pthread_mutex_unlock(&p->lock);
}

int wg_wait_pool_put_batch(wg_wait_pool_t *p, void **objs, int count)
{
    /* Lock-free fast path */
    if (p->lf_enabled)
        return lf_pool_put_batch(p, objs, count);

    if (count <= 0)
        return 0;

    /* Reset all objects outside the lock. */
    if (p->reset_fn) {
        for (int i = 0; i < count; i++) {
            if (objs[i])
                p->reset_fn(objs[i], p->ctx);
        }
    }

    pthread_mutex_lock(&p->lock);

    /* Grow the stack if needed. */
    size_t needed = p->stack_count + (size_t)count;
    if (needed > p->stack_capacity) {
        size_t new_cap = p->stack_capacity;
        while (new_cap < needed)
            new_cap *= 2;
        void **new_stack = realloc(p->stack, new_cap * sizeof(void *));
        if (new_stack) {
            p->stack = new_stack;
            p->stack_capacity = new_cap;
        }
        /* If realloc fails, we'll free overflow objects below. */
    }

    int returned = 0;
    for (int i = 0; i < count; i++) {
        if (!objs[i])
            continue;
        if (p->stack_count < p->stack_capacity) {
            p->stack[p->stack_count++] = objs[i];
            returned++;
        } else {
            /* Stack full (realloc failed) — free instead of leaking. */
            if (p->free_fn)
                p->free_fn(objs[i], p->ctx);
        }
        p->out--;
    }

    if (p->max != 0 && returned > 0)
        pthread_cond_broadcast(&p->cond);

    pthread_mutex_unlock(&p->lock);
    return returned;
}

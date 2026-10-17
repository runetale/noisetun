/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Memory Pools — pre-allocated, reusable buffer pool with backpressure.
 *
 * WaitPool is the C equivalent of Go's sync.Pool + sync.Cond:
 *   - Pre-allocated objects are recycled via a free-list.
 *   - When the pool is exhausted and a maximum is set,
 *     Get() blocks until an object is returned via Put().
 *
 * Reference: wireguard-go/device/pools.go
 */

#ifndef WG_POOLS_H
#define WG_POOLS_H

#include "wg_error.h"

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Object allocator callback
 * ──────────────────────────────────────── */

/* Called to create a new object when the pool is empty. */
typedef void *(*wg_pool_alloc_fn)(void *ctx);

/* Called to destroy an object when the pool is destroyed. */
typedef void (*wg_pool_free_fn)(void *obj, void *ctx);

/* Called to reset an object before returning it to the pool. Optional. */
typedef void (*wg_pool_reset_fn)(void *obj, void *ctx);

/* ────────────────────────────────────────
 * WaitPool
 * ──────────────────────────────────────── */
/* ────────────────────────────────────────
 * Lock-free Treiber stack (tagged pointer)
 *
 * Tagged pointer packs a 16-bit ABA counter in the upper bits
 * and a 48-bit pointer in the lower bits.  Safe on x86_64 and
 * ARM64 where userspace addresses fit in 48 bits.
 * ──────────────────────────────────────── */
#define WG_LF_PTR_MASK  0x0000FFFFFFFFFFFFULL
#define WG_LF_TAG_SHIFT 48

static inline void *wg_lf_ptr(uint64_t tagged)
{
    return (void *)(uintptr_t)(tagged & WG_LF_PTR_MASK);
}

static inline uint64_t wg_lf_make(void *ptr, uint64_t old_tagged)
{
    uint64_t tag = ((old_tagged >> WG_LF_TAG_SHIFT) + 1) & 0xFFFF;
    return ((uint64_t)(uintptr_t)ptr & WG_LF_PTR_MASK) | (tag << WG_LF_TAG_SHIFT);
}

typedef struct wg_wait_pool {
    /* Free-list: stack of available objects */
    void **stack;
    size_t stack_count;
    size_t stack_capacity;

    /* Allocation callbacks */
    wg_pool_alloc_fn alloc_fn;
    wg_pool_free_fn free_fn;
    wg_pool_reset_fn reset_fn;
    void *ctx;

    /* Backpressure: max outstanding Get() calls */
    uint32_t max; /* 0 = unlimited */
    uint32_t out; /* currently checked-out count */
    bool closed;  /* wg_wait_pool_close(): Get at the cap fails */

    pthread_mutex_t lock;
    pthread_cond_t cond; /* signalled when out decreases */

    /* Lock-free Treiber stack (enabled by wg_wait_pool_enable_lockfree) */
    _Atomic uint64_t lf_head; /* tagged pointer: ABA counter | ptr */
    size_t next_offset;       /* offsetof(_pool_next) in element */
    bool lf_enabled;
} wg_wait_pool_t;

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

/*
 * Initialise a WaitPool.
 *
 * max       — maximum concurrent Get() calls (0 = unlimited).
 * alloc_fn  — allocator for new objects (required).
 * free_fn   — destructor for objects (may be NULL).
 * reset_fn  — reset callback before Put() recycles (may be NULL).
 * ctx       — opaque context passed to all callbacks.
 */
wg_error_t wg_wait_pool_init(wg_wait_pool_t *p, uint32_t max, wg_pool_alloc_fn alloc_fn,
                             wg_pool_free_fn free_fn, wg_pool_reset_fn reset_fn,
                             void *ctx);

/*
 * Enable lock-free mode for pools with max == 0.
 * Elements must have a `void *_pool_next` field at the given offset.
 * Must be called before any Get/Put operations.
 */
void wg_wait_pool_enable_lockfree(wg_wait_pool_t *p, size_t next_offset);

/*
 * Wake every Get waiting at the cap and make it return NULL, and fail any
 * later Get that would wait, until wg_wait_pool_reopen(). For shutting
 * down: the threads that would wait must be joined before the objects
 * they wait for are returned. Put works as before.
 */
void wg_wait_pool_close(wg_wait_pool_t *p);
void wg_wait_pool_reopen(wg_wait_pool_t *p);

/*
 * Destroy the pool: free all pooled objects, destroy synchronisation primitives.
 * Caller must ensure no concurrent Get/Put operations.
 */
void wg_wait_pool_destroy(wg_wait_pool_t *p);

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

/*
 * Get an object from the pool.
 *
 * If pooled objects are available, returns one immediately.
 * If no pooled objects exist, allocates a new one via alloc_fn.
 * If max > 0 and out >= max, blocks until an object is returned via Put().
 *
 * Returns NULL only if alloc_fn returns NULL.
 */
void *wg_wait_pool_get(wg_wait_pool_t *p);

/*
 * Like wg_wait_pool_get, but returns NULL instead of blocking when max
 * objects are out.
 */
void *wg_wait_pool_try_get(wg_wait_pool_t *p);

/*
 * Return an object to the pool.
 *
 * If reset_fn is set, it is called before the object is pooled.
 * Signals one waiting Get() caller if max > 0.
 */
void wg_wait_pool_put(wg_wait_pool_t *p, void *obj);

/*
 * Return multiple objects to the pool in one lock acquisition.
 * Each object is reset via reset_fn before recycling.
 * Returns the number of objects successfully returned.
 */
int wg_wait_pool_put_batch(wg_wait_pool_t *p, void **objs, int count);

/*
 * The batch a worker that holds batch objects at once may use: at most a
 * quarter of a capped pool, so the rest stays for staged packets and
 * packets in flight. A batch above the cap would wait forever for itself.
 */
static inline int wg_wait_pool_batch_limit(const wg_wait_pool_t *p, int batch)
{
    if (!p || p->max == 0 || batch <= (int)(p->max / 4))
        return batch;
    return p->max >= 4 ? (int)(p->max / 4) : 1;
}

#endif /* WG_POOLS_H */

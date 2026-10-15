/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Token-bucket rate limiter: per-source-IP rate limiting.
 *
 * Reference: wireguard-go/ratelimiter/ratelimiter.go
 */

#include "wg_ratelimiter.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────
 * Monotonic clock helper
 * ──────────────────────────────────────── */

static int64_t mono_now_ns(void)
{
#ifdef __APPLE__
    /* macOS: clock_gettime with CLOCK_MONOTONIC is available since 10.12 */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#elif defined(_WIN32)
    /* Windows: QueryPerformanceCounter */
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (int64_t)(count.QuadPart * 1000000000LL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#endif
}

/* ────────────────────────────────────────
 * Hash function (FNV-1a over IP bytes)
 * ──────────────────────────────────────── */

static uint32_t ip_hash(const uint8_t *ip, uint8_t len)
{
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < len; i++) {
        h ^= ip[i];
        h *= 16777619u;
    }
    return h;
}

/* ────────────────────────────────────────
 * Entry helpers
 * ──────────────────────────────────────── */

static wg_ratelimiter_entry_t *entry_alloc(const uint8_t *ip, uint8_t addr_len)
{
    wg_ratelimiter_entry_t *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;

    memcpy(e->ip, ip, addr_len);
    e->addr_len = addr_len;
    e->last_time_ns = mono_now_ns();
    e->tokens = WG_RATELIMIT_MAX_TOKENS_NS - WG_RATELIMIT_PACKET_COST_NS;
    e->next = NULL;
    pthread_mutex_init(&e->lock, NULL);

    return e;
}

static void entry_free(wg_ratelimiter_entry_t *e)
{
    if (e) {
        pthread_mutex_destroy(&e->lock);
        free(e);
    }
}

static bool ip_equal(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    return memcmp(a, b, len) == 0;
}

/* ────────────────────────────────────────
 * Timed condvar wait (cross-platform)
 * ──────────────────────────────────────── */

static int cond_timedwait_mono(pthread_cond_t *cond, pthread_mutex_t *mutex,
                               int cond_clock, int64_t timeout_ns)
{
#ifdef __APPLE__
    (void)cond_clock;
    /* macOS: use relative timeout */
    struct timespec rel;
    rel.tv_sec = (time_t)(timeout_ns / 1000000000LL);
    rel.tv_nsec = (long)(timeout_ns % 1000000000LL);
    return pthread_cond_timedwait_relative_np(cond, mutex, &rel);
#else
    /* The default clock if setclock was refused or ignored (ESP-IDF,
     * WG_CONDATTR_SETCLOCK_WORKS): a monotonic deadline on a realtime
     * condvar is long past once the wall clock is set, and the GC thread
     * would spin. */
    struct timespec abs;
    clock_gettime(cond_clock, &abs);
    abs.tv_sec += (time_t)(timeout_ns / 1000000000LL);
    abs.tv_nsec += (long)(timeout_ns % 1000000000LL);
    if (abs.tv_nsec >= 1000000000L) {
        abs.tv_sec += 1;
        abs.tv_nsec -= 1000000000L;
    }
    return pthread_cond_timedwait(cond, mutex, &abs);
#endif
}

/* ────────────────────────────────────────
 * GC: remove entries older than 1 second
 * Returns true if the table is now empty.
 * ──────────────────────────────────────── */

static bool ratelimiter_cleanup(wg_ratelimiter_t *rl)
{
    int64_t now = mono_now_ns();

    pthread_rwlock_wrlock(&rl->lock);
    for (int i = 0; i < WG_RATELIMIT_TABLE_SIZE; i++) {
        wg_ratelimiter_entry_t **pp = &rl->buckets[i];
        while (*pp) {
            wg_ratelimiter_entry_t *e = *pp;
            pthread_mutex_lock(&e->lock);
            bool stale = (now - e->last_time_ns) > WG_RATELIMIT_GC_INTERVAL_NS;
            pthread_mutex_unlock(&e->lock);

            if (stale) {
                *pp = e->next;
                rl->entry_count--;
                entry_free(e);
            } else {
                pp = &e->next;
            }
        }
    }
    bool empty = (rl->entry_count == 0);
    pthread_rwlock_unlock(&rl->lock);

    return empty;
}

/* ────────────────────────────────────────
 * GC thread
 *
 * Mirrors the Go goroutine:
 *   - Starts with ticker stopped
 *   - A signal on gc_cond starts the ticker
 *   - When cleanup returns empty, stop the ticker
 *   - Closing (gc_running = false) exits
 * ──────────────────────────────────────── */

static void *gc_thread_fn(void *arg)
{
    wg_ratelimiter_t *rl = arg;

    pthread_mutex_lock(&rl->gc_mutex);
    while (rl->gc_running) {
        if (!rl->gc_active) {
            /* Ticker stopped — wait for signal or shutdown. */
            pthread_cond_wait(&rl->gc_cond, &rl->gc_mutex);
            continue;
        }

        /* Ticker active — wait 1 second then clean up. */
        int rc = cond_timedwait_mono(&rl->gc_cond, &rl->gc_mutex, rl->gc_clock,
                                     WG_RATELIMIT_GC_INTERVAL_NS);
        if (!rl->gc_running)
            break;

        if (rc == ETIMEDOUT) {
            /* Timeout = ticker tick. Run cleanup. */
            pthread_mutex_unlock(&rl->gc_mutex);
            bool empty = ratelimiter_cleanup(rl);
            pthread_mutex_lock(&rl->gc_mutex);
            if (empty)
                rl->gc_active = false;
        }
        /* If rc == 0 (signalled), it's a reset — restart the wait. */
    }
    pthread_mutex_unlock(&rl->gc_mutex);

    return NULL;
}

/* ────────────────────────────────────────
 * Free all entries in the table.
 * Caller must hold write lock.
 * ──────────────────────────────────────── */

static void table_clear_locked(wg_ratelimiter_t *rl)
{
    for (int i = 0; i < WG_RATELIMIT_TABLE_SIZE; i++) {
        wg_ratelimiter_entry_t *e = rl->buckets[i];
        while (e) {
            wg_ratelimiter_entry_t *next = e->next;
            entry_free(e);
            e = next;
        }
        rl->buckets[i] = NULL;
    }
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_ratelimiter_init(wg_ratelimiter_t *rl)
{
    memset(rl, 0, sizeof(*rl));
    pthread_rwlock_init(&rl->lock, NULL);

    pthread_mutex_init(&rl->gc_mutex, NULL);

    /* Use CLOCK_MONOTONIC condvar on Linux for reliable timed waits. */
#if !defined(__APPLE__) && !defined(_WIN32)
    {
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);
        if (!WG_CONDATTR_SETCLOCK_WORKS ||
            pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
            /* Fallback to default clock if CLOCK_MONOTONIC unsupported. */
            pthread_cond_init(&rl->gc_cond, NULL);
            rl->gc_clock = CLOCK_REALTIME;
        } else {
            pthread_cond_init(&rl->gc_cond, &attr);
            rl->gc_clock = CLOCK_MONOTONIC;
        }
        pthread_condattr_destroy(&attr);
    }
#else
    pthread_cond_init(&rl->gc_cond, NULL);
    rl->gc_clock = CLOCK_MONOTONIC; /* the Windows shim measures on it */
#endif

    rl->gc_running = true;
    rl->gc_active = false;

    int rc = pthread_create(&rl->gc_thread, NULL, gc_thread_fn, rl);
    if (rc != 0) {
        pthread_cond_destroy(&rl->gc_cond);
        pthread_mutex_destroy(&rl->gc_mutex);
        pthread_rwlock_destroy(&rl->lock);
        return WG_ERR_NO_MEMORY;
    }

    rl->initialized = true;
    return WG_OK;
}

void wg_ratelimiter_close(wg_ratelimiter_t *rl)
{
    /* Signal GC thread to stop. */
    pthread_mutex_lock(&rl->gc_mutex);
    rl->gc_running = false;
    pthread_cond_signal(&rl->gc_cond);
    pthread_mutex_unlock(&rl->gc_mutex);

    pthread_join(rl->gc_thread, NULL);

    /* Free all entries. */
    pthread_rwlock_wrlock(&rl->lock);
    table_clear_locked(rl);
    pthread_rwlock_unlock(&rl->lock);

    pthread_cond_destroy(&rl->gc_cond);
    pthread_mutex_destroy(&rl->gc_mutex);
    pthread_rwlock_destroy(&rl->lock);
    rl->initialized = false;
}

bool wg_ratelimiter_allow(wg_ratelimiter_t *rl, const uint8_t *ip, uint8_t addr_len)
{
    /* P1-7: validate addr_len to prevent OOB read. */
    if (addr_len != 4 && addr_len != 16)
        return false;

    uint32_t h = ip_hash(ip, addr_len) % WG_RATELIMIT_TABLE_SIZE;

    /*
     * P0-1 fix: hold read lock through the entire token update so the
     * GC thread cannot free the entry while we're accessing it.
     * The per-entry mutex protects token state; the rwlock protects the
     * hash chain structure (entry lifetime).
     */
    pthread_rwlock_rdlock(&rl->lock);
    wg_ratelimiter_entry_t *entry = rl->buckets[h];
    while (entry) {
        if (entry->addr_len == addr_len && ip_equal(entry->ip, ip, addr_len))
            break;
        entry = entry->next;
    }

    if (entry) {
        /* Existing entry: update tokens while holding read lock. */
        pthread_mutex_lock(&entry->lock);
        int64_t now = mono_now_ns();
        entry->tokens += (now - entry->last_time_ns);
        entry->last_time_ns = now;
        if (entry->tokens > WG_RATELIMIT_MAX_TOKENS_NS)
            entry->tokens = WG_RATELIMIT_MAX_TOKENS_NS;

        /* P1-6: use >= instead of > so exactly packetCost tokens is allowed. */
        bool allowed = false;
        if (entry->tokens >= WG_RATELIMIT_PACKET_COST_NS) {
            entry->tokens -= WG_RATELIMIT_PACKET_COST_NS;
            allowed = true;
        }
        pthread_mutex_unlock(&entry->lock);
        pthread_rwlock_unlock(&rl->lock);
        return allowed;
    }
    pthread_rwlock_unlock(&rl->lock);

    /* New source IP: create entry.
     * No stale references are carried across this lock upgrade gap —
     * new_entry is freshly allocated, and the double-check below re-scans
     * the chain under write lock.  The GC thread cannot cause UAF here
     * because we hold no pointer to any existing entry at this point. */
    wg_ratelimiter_entry_t *new_entry = entry_alloc(ip, addr_len);
    if (!new_entry)
        return false;

    pthread_rwlock_wrlock(&rl->lock);
    /* Double-check: another thread may have inserted while we upgraded. */
    entry = rl->buckets[h];
    while (entry) {
        if (entry->addr_len == addr_len && ip_equal(entry->ip, ip, addr_len))
            break;
        entry = entry->next;
    }
    if (entry) {
        /* Someone else inserted it. Free ours, use theirs under write lock. */
        pthread_mutex_lock(&entry->lock);
        int64_t now = mono_now_ns();
        entry->tokens += (now - entry->last_time_ns);
        entry->last_time_ns = now;
        if (entry->tokens > WG_RATELIMIT_MAX_TOKENS_NS)
            entry->tokens = WG_RATELIMIT_MAX_TOKENS_NS;

        bool allowed = false;
        if (entry->tokens >= WG_RATELIMIT_PACKET_COST_NS) {
            entry->tokens -= WG_RATELIMIT_PACKET_COST_NS;
            allowed = true;
        }
        pthread_mutex_unlock(&entry->lock);
        pthread_rwlock_unlock(&rl->lock);
        entry_free(new_entry);
        return allowed;
    }

    bool was_empty = (rl->entry_count == 0);

    new_entry->next = rl->buckets[h];
    rl->buckets[h] = new_entry;
    rl->entry_count++;

    pthread_rwlock_unlock(&rl->lock);

    /* If this was the first entry, activate the GC ticker. */
    if (was_empty) {
        pthread_mutex_lock(&rl->gc_mutex);
        rl->gc_active = true;
        pthread_cond_signal(&rl->gc_cond);
        pthread_mutex_unlock(&rl->gc_mutex);
    }

    return true; /* first packet from new source is always allowed */
}

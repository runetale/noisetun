/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Token-bucket rate limiter: per-source-IP rate limiting for
 * handshake initiation flood protection.
 *
 * 20 packets/second with burst of 5 packets.
 * A background GC thread removes stale entries every second.
 *
 * Reference: wireguard-go/ratelimiter/ratelimiter.go
 */

#ifndef WG_RATELIMITER_H
#define WG_RATELIMITER_H

#include "wg_error.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Constants
 * ──────────────────────────────────────── */
#define WG_RATELIMIT_PACKETS_PER_SECOND 20
#define WG_RATELIMIT_PACKETS_BURSTABLE  5
#define WG_RATELIMIT_PACKET_COST_NS \
    (1000000000LL / WG_RATELIMIT_PACKETS_PER_SECOND) /* 50ms */
#define WG_RATELIMIT_MAX_TOKENS_NS \
    (WG_RATELIMIT_PACKET_COST_NS * WG_RATELIMIT_PACKETS_BURSTABLE)
#define WG_RATELIMIT_GC_INTERVAL_NS 1000000000LL /* 1 second */

/* ────────────────────────────────────────
 * Rate limiter entry (per source IP)
 * ──────────────────────────────────────── */
typedef struct wg_ratelimiter_entry {
    uint8_t ip[16];       /* IP key: 4 bytes for IPv4, 16 for IPv6 */
    uint8_t addr_len;     /* 4 or 16 */
    int64_t last_time_ns; /* monotonic nanoseconds */
    int64_t tokens;       /* token count in nanoseconds */
    pthread_mutex_t lock;
    struct wg_ratelimiter_entry *next; /* chain for hash collision */
} wg_ratelimiter_entry_t;

/* ────────────────────────────────────────
 * Rate limiter table (chained hash map)
 * ──────────────────────────────────────── */
#ifndef WG_RATELIMIT_TABLE_SIZE
#define WG_RATELIMIT_TABLE_SIZE 4096 /* a build for a small device can set fewer */
#endif

typedef struct {
    wg_ratelimiter_entry_t *buckets[WG_RATELIMIT_TABLE_SIZE];
    size_t entry_count; /* total number of entries across all buckets */
    pthread_rwlock_t lock;

    /* GC thread */
    pthread_t gc_thread;
    pthread_mutex_t gc_mutex;
    pthread_cond_t gc_cond;
    int gc_clock;     /* clock gc_cond's timed waits count on: CLOCK_MONOTONIC
                         unless pthread_condattr_setclock refused it */
    bool gc_running;  /* true while GC thread should run */
    bool gc_active;   /* true when table is non-empty (ticker active) */
    bool initialized; /* set to true after first successful init */
} wg_ratelimiter_t;

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

/*
 * Initialise the rate limiter and start the GC thread.
 * Can be called multiple times (resets state).
 */
wg_error_t wg_ratelimiter_init(wg_ratelimiter_t *rl);

/*
 * Stop the GC thread and free all entries.
 */
void wg_ratelimiter_close(wg_ratelimiter_t *rl);

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

/*
 * Check whether a packet from the given IP is allowed.
 *
 * ip       — network-order IP bytes (4 for IPv4, 16 for IPv6)
 * addr_len — 4 or 16
 *
 * Returns true if the packet is within the rate limit.
 */
bool wg_ratelimiter_allow(wg_ratelimiter_t *rl, const uint8_t *ip, uint8_t addr_len);

#endif /* WG_RATELIMITER_H */

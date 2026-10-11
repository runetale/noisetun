/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for wg_ratelimiter (token bucket rate limiter).
 */

#include "../src/ratelimiter/wg_ratelimiter.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PASS(name) printf("  PASS: %s\n", name)

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static const uint8_t ip4_a[] = {10, 0, 0, 1};
static const uint8_t ip4_b[] = {10, 0, 0, 2};
static const uint8_t ip6_a[] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* ────────────────────────────────────────
 * Test: init and close
 * ──────────────────────────────────────── */
static void test_init_close(void)
{
    wg_ratelimiter_t rl;
    wg_error_t err = wg_ratelimiter_init(&rl);
    assert(err == WG_OK);
    wg_ratelimiter_close(&rl);
    PASS("init_close");
}

/* ────────────────────────────────────────
 * Test: first packet from new IP is always allowed
 * ──────────────────────────────────────── */
static void test_first_packet_allowed(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    assert(wg_ratelimiter_allow(&rl, ip4_a, 4) == true);
    assert(wg_ratelimiter_allow(&rl, ip4_b, 4) == true);
    assert(wg_ratelimiter_allow(&rl, ip6_a, 16) == true);

    wg_ratelimiter_close(&rl);
    PASS("first_packet_allowed");
}

/* ────────────────────────────────────────
 * Test: burst of 5 allowed, then blocked
 * ──────────────────────────────────────── */
static void test_burst_limit(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    /* First packet uses 1 token (burst=5, cost=1 → 4 remain after first). */
    assert(wg_ratelimiter_allow(&rl, ip4_a, 4) == true); /* new entry, 4 tokens */

    /* Rapid fire: should get a few more, then be blocked.
     * We have 4 remaining tokens (maxTokens - packetCost initially).
     * Each call costs 1 token (50ms worth).
     * Since calls are near-instant, minimal token replenishment. */
    int allowed = 1; /* counting the first */
    for (int i = 0; i < 10; i++) {
        if (wg_ratelimiter_allow(&rl, ip4_a, 4))
            allowed++;
    }

    /* Should have allowed exactly 5 (burst size). */
    assert(allowed == 5);

    wg_ratelimiter_close(&rl);
    PASS("burst_limit");
}

/* ────────────────────────────────────────
 * Test: different IPs have independent limits
 * ──────────────────────────────────────── */
static void test_independent_ips(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    /* Exhaust ip4_a's burst. */
    for (int i = 0; i < 10; i++)
        wg_ratelimiter_allow(&rl, ip4_a, 4);

    /* ip4_b should still be allowed. */
    assert(wg_ratelimiter_allow(&rl, ip4_b, 4) == true);

    wg_ratelimiter_close(&rl);
    PASS("independent_ips");
}

/* ────────────────────────────────────────
 * Test: tokens replenish over time
 * ──────────────────────────────────────── */
static void test_token_replenish(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    /* Exhaust burst. */
    for (int i = 0; i < 10; i++)
        wg_ratelimiter_allow(&rl, ip4_a, 4);

    /* Should be blocked now. */
    assert(wg_ratelimiter_allow(&rl, ip4_a, 4) == false);

    /* Wait 60ms (> packetCost of 50ms) to replenish 1 token. */
    struct timespec ts = {0, 60000000};
    nanosleep(&ts, NULL);

    /* Should be allowed again. */
    assert(wg_ratelimiter_allow(&rl, ip4_a, 4) == true);

    wg_ratelimiter_close(&rl);
    PASS("token_replenish");
}

/* ────────────────────────────────────────
 * Test: IPv6 addresses work
 * ──────────────────────────────────────── */
static void test_ipv6(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    assert(wg_ratelimiter_allow(&rl, ip6_a, 16) == true);

    /* Exhaust burst. */
    int allowed = 1;
    for (int i = 0; i < 10; i++) {
        if (wg_ratelimiter_allow(&rl, ip6_a, 16))
            allowed++;
    }
    assert(allowed == 5);

    wg_ratelimiter_close(&rl);
    PASS("ipv6");
}

/* ────────────────────────────────────────
 * Test: GC cleans up stale entries
 * ──────────────────────────────────────── */
static void test_gc_cleanup(void)
{
    wg_ratelimiter_t rl;
    assert(wg_ratelimiter_init(&rl) == WG_OK);

    /* Add an entry. */
    wg_ratelimiter_allow(&rl, ip4_a, 4);

    /* Wait > 1 second for GC to run. */
    struct timespec ts = {1, 200000000}; /* 1.2s */
    nanosleep(&ts, NULL);

    /* After GC, the entry should be gone. A new Allow should act as first packet. */
    assert(wg_ratelimiter_allow(&rl, ip4_a, 4) == true);

    /* And we should get the full burst again. */
    int allowed = 1;
    for (int i = 0; i < 10; i++) {
        if (wg_ratelimiter_allow(&rl, ip4_a, 4))
            allowed++;
    }
    assert(allowed == 5);

    wg_ratelimiter_close(&rl);
    PASS("gc_cleanup");
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    printf("=== test_ratelimiter ===\n");

    test_init_close();
    test_first_packet_allowed();
    test_burst_limit();
    test_independent_ips();
    test_token_replenish();
    test_ipv6();
    test_gc_cleanup();

    printf("All ratelimiter tests passed.\n");
    return 0;
}

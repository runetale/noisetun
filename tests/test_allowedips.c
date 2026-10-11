/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for AllowedIPs routing table (wg_allowedips).
 */

#include "peer/wg_allowedips.h"
#include "peer/wg_peer.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

#define ASSERT_OK(expr) assert((expr) == WG_OK)
#define TEST(name)               \
    do {                         \
        printf("  %-50s", name); \
        fflush(stdout);          \
    } while (0)
#define PASS()            \
    do {                  \
        printf("PASS\n"); \
    } while (0)

/* Dummy peers — we only use their addresses for identity */
static struct wg_peer peer_a, peer_b, peer_c;

static void parse_ipv4(const char *s, uint8_t out[4])
{
    struct in_addr addr;
    assert(inet_pton(AF_INET, s, &addr) == 1);
    memcpy(out, &addr, 4);
}

static void parse_ipv6(const char *s, uint8_t out[16])
{
    struct in6_addr addr;
    assert(inet_pton(AF_INET6, s, &addr) == 1);
    memcpy(out, &addr, 16);
}

/* ────────────────────────────────────────
 * Test: basic IPv4 insert and lookup
 * ──────────────────────────────────────── */

static void test_ipv4_basic(void)
{
    TEST("IPv4 basic insert/lookup");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[4];

    /* peer_a: 10.0.0.0/8 */
    parse_ipv4("10.0.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 8, AF_INET, &peer_a));

    /* peer_b: 10.1.0.0/16 */
    parse_ipv4("10.1.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 16, AF_INET, &peer_b));

    /* Lookup 10.1.2.3 should match /16 (peer_b — longest match) */
    uint8_t ip[4];
    parse_ipv4("10.1.2.3", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    /* Lookup 10.2.3.4 should match /8 (peer_a) */
    parse_ipv4("10.2.3.4", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    /* Lookup 192.168.1.1 should not match */
    parse_ipv4("192.168.1.1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == NULL);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: longest prefix match
 * ──────────────────────────────────────── */

static void test_longest_prefix(void)
{
    TEST("IPv4 longest-prefix match");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[4];

    /* peer_a: 0.0.0.0/0 (default route) */
    parse_ipv4("0.0.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 0, AF_INET, &peer_a));

    /* peer_b: 192.168.0.0/16 */
    parse_ipv4("192.168.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 16, AF_INET, &peer_b));

    /* peer_c: 192.168.1.0/24 */
    parse_ipv4("192.168.1.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 24, AF_INET, &peer_c));

    uint8_t ip[4];

    /* 192.168.1.100 -> peer_c (/24) */
    parse_ipv4("192.168.1.100", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_c);

    /* 192.168.2.100 -> peer_b (/16) */
    parse_ipv4("192.168.2.100", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    /* 8.8.8.8 -> peer_a (/0 default) */
    parse_ipv4("8.8.8.8", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: exact /32 match
 * ──────────────────────────────────────── */

static void test_exact_host(void)
{
    TEST("IPv4 exact /32 host route");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[4];

    parse_ipv4("10.0.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 8, AF_INET, &peer_a));

    parse_ipv4("10.0.0.1", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 32, AF_INET, &peer_b));

    uint8_t ip[4];

    /* 10.0.0.1 -> peer_b (/32) */
    parse_ipv4("10.0.0.1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    /* 10.0.0.2 -> peer_a (/8) */
    parse_ipv4("10.0.0.2", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: IPv6
 * ──────────────────────────────────────── */

static void test_ipv6_basic(void)
{
    TEST("IPv6 basic insert/lookup");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[16];

    parse_ipv6("fd00::", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 16, AF_INET6, &peer_a));

    parse_ipv6("fd00:1::", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 32, AF_INET6, &peer_b));

    uint8_t ip[16];

    /* fd00:1::5 -> peer_b (/32) */
    parse_ipv6("fd00:1::5", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET6) == &peer_b);

    /* fd00:2::1 -> peer_a (/16) */
    parse_ipv6("fd00:2::1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET6) == &peer_a);

    /* 2001:db8::1 -> NULL */
    parse_ipv6("2001:db8::1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET6) == NULL);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: update existing prefix
 * ──────────────────────────────────────── */

static void test_update_prefix(void)
{
    TEST("update existing prefix changes peer");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[4];
    parse_ipv4("10.0.0.0", net);

    ASSERT_OK(wg_allowedips_insert(&table, net, 8, AF_INET, &peer_a));

    uint8_t ip[4];
    parse_ipv4("10.1.2.3", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    /* Update same prefix to peer_b */
    ASSERT_OK(wg_allowedips_insert(&table, net, 8, AF_INET, &peer_b));
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: remove by peer
 * ──────────────────────────────────────── */

static void test_remove_by_peer(void)
{
    TEST("remove_by_peer removes all entries");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    uint8_t net[4];

    parse_ipv4("10.0.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 8, AF_INET, &peer_a));

    parse_ipv4("172.16.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 12, AF_INET, &peer_a));

    parse_ipv4("192.168.0.0", net);
    ASSERT_OK(wg_allowedips_insert(&table, net, 16, AF_INET, &peer_b));

    /* Remove all of peer_a's entries */
    wg_allowedips_remove_by_peer(&table, &peer_a);

    uint8_t ip[4];

    /* 10.1.2.3 -> NULL (removed) */
    parse_ipv4("10.1.2.3", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == NULL);

    /* 172.16.1.1 -> NULL (removed) */
    parse_ipv4("172.16.1.1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == NULL);

    /* 192.168.1.1 -> peer_b (not removed) */
    parse_ipv4("192.168.1.1", ip);
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Test: many prefixes
 * ──────────────────────────────────────── */

static void test_many_prefixes(void)
{
    TEST("many prefixes (256 /24s)");

    wg_allowedips_t table;
    ASSERT_OK(wg_allowedips_init(&table));

    /* Insert 256 /24 prefixes: 10.0.0.0/24 through 10.0.255.0/24 */
    for (int i = 0; i < 256; i++) {
        uint8_t net[4] = {10, 0, (uint8_t)i, 0};
        struct wg_peer *p = (i % 2 == 0) ? &peer_a : &peer_b;
        ASSERT_OK(wg_allowedips_insert(&table, net, 24, AF_INET, p));
    }

    /* Verify some lookups */
    uint8_t ip[4];

    ip[0] = 10;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 42;
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    ip[2] = 1;
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    ip[2] = 100;
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_a);

    ip[2] = 255;
    assert(wg_allowedips_lookup(&table, ip, AF_INET) == &peer_b);

    wg_allowedips_destroy(&table);
    PASS();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    printf("=== test_allowedips ===\n");

    test_ipv4_basic();
    test_longest_prefix();
    test_exact_host();
    test_ipv6_basic();
    test_update_prefix();
    test_remove_by_peer();
    test_many_prefixes();

    printf("All AllowedIPs tests passed.\n");
    return 0;
}

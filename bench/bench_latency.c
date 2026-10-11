/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Latency benchmark for the WireGuard stack.
 *
 * Measures one-way transit latency through the full encrypt/decrypt
 * pipeline using ChannelBind + ChannelTUN. Reports min/max/median/p99.
 *
 * Usage: bench_latency [iterations] [packet_size]
 *   iterations:   number of round-trips (default: 10000)
 *   packet_size:  payload size in bytes (default: 64)
 */

#include "../src/bind/wg_bind.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_channel.h"

#include <arpa/inet.h>
#include <assert.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────
 * Helpers (shared with bench_throughput.c)
 * ──────────────────────────────────────── */

static void gen_keypair(wg_key_t *priv, wg_key_t *pub)
{
    crypto_box_keypair(pub->key, priv->key);
}

static uint16_t inet_checksum(const uint8_t *buf, size_t len, uint16_t initial)
{
    uint32_t v = initial;
    for (size_t i = 0; i + 1 < len; i += 2)
        v += ((uint32_t)buf[i] << 8) | buf[i + 1];
    if (len & 1)
        v += (uint32_t)buf[len - 1] << 8;
    while (v > 0xFFFF)
        v = (v >> 16) + (v & 0xFFFF);
    return (uint16_t)~v;
}

#define IPV4_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8

static size_t build_icmpv4_ping(uint8_t *out, size_t cap,
                                uint32_t dst_ip, uint32_t src_ip,
                                uint16_t seq)
{
    const size_t payload_len = 4;
    const size_t total = IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + payload_len;
    assert(cap >= total);
    memset(out, 0, total);

    uint8_t payload[4];
    payload[0] = 0x05; payload[1] = 0x39;
    payload[2] = (uint8_t)(seq >> 8); payload[3] = (uint8_t)seq;

    uint8_t *icmp = out + IPV4_HEADER_SIZE;
    icmp[0] = 8; icmp[1] = 0;
    uint16_t icmp_cksum = inet_checksum(icmp, ICMP_HEADER_SIZE,
                                        inet_checksum(payload, payload_len, 0));
    icmp[2] = (uint8_t)(icmp_cksum >> 8);
    icmp[3] = (uint8_t)(icmp_cksum & 0xFF);
    memcpy(out + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE, payload, payload_len);

    uint8_t *ip = out;
    ip[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4);
    uint16_t total_len = htons((uint16_t)total);
    memcpy(ip + 2, &total_len, 2);
    ip[8] = 65; ip[9] = 1;
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    uint16_t ip_cksum = inet_checksum(ip, IPV4_HEADER_SIZE, 0);
    ip[10] = (uint8_t)(ip_cksum >> 8);
    ip[11] = (uint8_t)(ip_cksum & 0xFF);

    return total;
}

static void bench_log(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    (void)ctx; (void)level; (void)fmt;
}

/* ────────────────────────────────────────
 * Benchmark pair
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_channel_tun_t *tun;
    wg_channel_bind_t *bind;
    uint32_t ip;
} bench_peer_t;

typedef struct {
    bench_peer_t peer[2];
} bench_pair_t;

static void setup_pair(bench_pair_t *pair)
{
    wg_key_t priv[2], pub[2];
    gen_keypair(&priv[0], &pub[0]);
    gen_keypair(&priv[1], &pub[1]);

    pair->peer[0].ip = 0x01000001;
    pair->peer[1].ip = 0x01000002;

    wg_error_t err = wg_channel_bind_pair(&pair->peer[0].bind,
                                           &pair->peer[1].bind);
    assert(err == WG_OK);

    for (int i = 0; i < 2; i++) {
        err = wg_channel_tun_create(&pair->peer[i].tun, WG_DEFAULT_MTU);
        assert(err == WG_OK);
    }

    for (int i = 0; i < 2; i++) {
        wg_tun_ops_t tun_ops = wg_channel_tun_ops(pair->peer[i].tun);
        wg_bind_ops_t bind_ops = wg_channel_bind_ops(pair->peer[i].bind);
        wg_logger_t logger = {.log = bench_log, .ctx = NULL};

        err = wg_device_new(&pair->peer[i].dev, &tun_ops, &bind_ops, &logger);
        assert(err == WG_OK);
        err = wg_device_set_private_key(pair->peer[i].dev, &priv[i]);
        assert(err == WG_OK);
    }

    for (int i = 0; i < 2; i++) {
        int other = i ^ 1;
        wg_peer_t *peer = NULL;
        err = wg_peer_new(pair->peer[i].dev, pub[other].key, NULL, &peer);
        assert(err == WG_OK);

        wg_endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr.sa4.sin_family = AF_INET;
        ep.addr.sa4.sin_port = htons((uint16_t)(other + 1));
        ep.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);
        err = wg_peer_set_endpoint(peer, &ep);
        assert(err == WG_OK);

        uint32_t allowed_ip = htonl(pair->peer[other].ip);
        err = wg_peer_add_allowed_ip(peer, &allowed_ip, 32, AF_INET);
        assert(err == WG_OK);
    }

    for (int i = 0; i < 2; i++) {
        err = wg_device_up(pair->peer[i].dev);
        assert(err == WG_OK);
    }
}

static void teardown_pair(bench_pair_t *pair)
{
    /* Close both devices before destroying either bind: the other
     * device's sender would otherwise push into a freed receive queue. */
    for (int i = 0; i < 2; i++)
        wg_device_close(pair->peer[i].dev);
    for (int i = 0; i < 2; i++) {
        wg_channel_tun_destroy(pair->peer[i].tun);
        wg_channel_bind_destroy(pair->peer[i].bind);
    }
}

/* ────────────────────────────────────────
 * Time helpers
 * ──────────────────────────────────────── */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* qsort comparator for uint64_t */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int iterations = 10000;

    if (argc > 1)
        iterations = atoi(argv[1]);
    if (iterations <= 0) iterations = 10000;

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("╔═══════════════════════════════════════════╗\n");
    printf("║       noisetun Latency Benchmark         ║\n");
    printf("╚═══════════════════════════════════════════╝\n\n");

    bench_pair_t pair;
    setup_pair(&pair);

    uint8_t pkt[128];
    size_t pkt_len = build_icmpv4_ping(pkt, sizeof(pkt),
                                       pair.peer[0].ip,
                                       pair.peer[1].ip, 0);

    printf("  Packet size:    %zu bytes\n", pkt_len);
    printf("  Iterations:     %d\n", iterations);
    printf("  Direction:      peer[1] -> peer[0]\n\n");

    /* Warm up: establish handshake. */
    printf("  Warming up (handshake)...\n");
    {
        wg_error_t e = wg_channel_tun_send(pair.peer[1].tun, pkt, pkt_len);
        assert(e == WG_OK);
        uint8_t *recv_data = NULL;
        size_t recv_len = 0;
        e = wg_channel_tun_recv_timeout(pair.peer[0].tun, &recv_data, &recv_len, 10000);
        assert(e == WG_OK);
        free(recv_data);
    }
    printf("  Handshake complete.\n\n");

    /* Latency measurements. */
    uint64_t *latencies = malloc((size_t)iterations * sizeof(uint64_t));
    assert(latencies);

    printf("  Measuring latency...\n");

    for (int i = 0; i < iterations; i++) {
        uint64_t t0 = now_ns();

        wg_error_t e = wg_channel_tun_send(pair.peer[1].tun, pkt, pkt_len);
        assert(e == WG_OK);

        uint8_t *recv_data = NULL;
        size_t recv_len = 0;
        e = wg_channel_tun_recv_timeout(pair.peer[0].tun, &recv_data, &recv_len, 5000);
        assert(e == WG_OK);
        free(recv_data);

        uint64_t t1 = now_ns();
        latencies[i] = t1 - t0;
    }

    /* Sort for percentile calculation. */
    qsort(latencies, (size_t)iterations, sizeof(uint64_t), cmp_u64);

    uint64_t min_ns = latencies[0];
    uint64_t max_ns = latencies[iterations - 1];
    uint64_t median_ns = latencies[iterations / 2];
    uint64_t p99_ns = latencies[(int)((double)iterations * 0.99)];
    uint64_t p95_ns = latencies[(int)((double)iterations * 0.95)];

    /* Compute average. */
    uint64_t sum = 0;
    for (int i = 0; i < iterations; i++)
        sum += latencies[i];
    double avg_ns = (double)sum / (double)iterations;

    printf("\n");
    printf("  ┌─────────────────────────────────────────┐\n");
    printf("  │  Latency Results (one-way transit)      │\n");
    printf("  ├─────────────────────────────────────────┤\n");
    printf("  │  Min:       %8.1f us                 │\n", (double)min_ns / 1e3);
    printf("  │  Max:       %8.1f us                 │\n", (double)max_ns / 1e3);
    printf("  │  Average:   %8.1f us                 │\n", avg_ns / 1e3);
    printf("  │  Median:    %8.1f us                 │\n", (double)median_ns / 1e3);
    printf("  │  P95:       %8.1f us                 │\n", (double)p95_ns / 1e3);
    printf("  │  P99:       %8.1f us                 │\n", (double)p99_ns / 1e3);
    printf("  └─────────────────────────────────────────┘\n");

    free(latencies);
    teardown_pair(&pair);

    return 0;
}

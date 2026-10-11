/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Throughput benchmark for the WireGuard stack.
 *
 * Measures packets/sec and MB/sec through the full encrypt/decrypt
 * pipeline using ChannelBind + ChannelTUN (no real I/O overhead).
 *
 * Usage: bench_throughput [duration_secs] [payload_size]
 *   duration_secs: how long to run (default: 10)
 *   payload_size:  UDP payload in bytes (default: 1392). The IP packet is
 *                  28 bytes larger and must fit the MTU (1420), so at
 *                  most 1392; a larger packet is dropped by the TUN reader.
 */

#include "../src/bind/wg_bind.h"
#include "../src/device/wg_device.h"
#include "../src/device/wg_stats.h"
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
 * Helpers (from test_device_ping_pong.c)
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

static size_t build_ipv4_udp(uint8_t *out, size_t cap,
                             uint32_t dst_ip, uint32_t src_ip,
                             size_t payload_size)
{
    /* Build a minimal IPv4/UDP packet with given payload size. */
    const size_t udp_header = 8;
    const size_t total = IPV4_HEADER_SIZE + udp_header + payload_size;
    assert(cap >= total);
    memset(out, 0, total);

    /* Fill payload with pattern. */
    for (size_t i = 0; i < payload_size; i++)
        out[IPV4_HEADER_SIZE + udp_header + i] = (uint8_t)(i & 0xFF);

    /* UDP header */
    uint8_t *udp = out + IPV4_HEADER_SIZE;
    uint16_t sport = htons(12345);
    uint16_t dport = htons(54321);
    uint16_t udp_len = htons((uint16_t)(udp_header + payload_size));
    memcpy(udp + 0, &sport, 2);
    memcpy(udp + 2, &dport, 2);
    memcpy(udp + 4, &udp_len, 2);
    /* udp checksum = 0 (optional for IPv4) */

    /* IPv4 header */
    uint8_t *ip = out;
    ip[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4);
    uint16_t total_len = htons((uint16_t)total);
    memcpy(ip + 2, &total_len, 2);
    ip[8] = 65;   /* TTL */
    ip[9] = 17;   /* protocol: UDP */
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    uint16_t ip_cksum = inet_checksum(ip, IPV4_HEADER_SIZE, 0);
    ip[10] = (uint8_t)(ip_cksum >> 8);
    ip[11] = (uint8_t)(ip_cksum & 0xFF);

    return total;
}

/* Silent logger for benchmarks. */
static void bench_log(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    (void)ctx; (void)level; (void)fmt;
}

/* ────────────────────────────────────────
 * Benchmark pair setup
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

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ────────────────────────────────────────
 * Main benchmark
 * ──────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int duration_secs = 10;
    size_t payload_size = 1420 - IPV4_HEADER_SIZE - 8; /* default: fill 1420B packet */

    if (argc > 1)
        duration_secs = atoi(argv[1]);
    if (argc > 2)
        payload_size = (size_t)atoi(argv[2]);

    if (duration_secs <= 0) duration_secs = 10;

    /* The TUN reader drops packets over the MTU, and the warm-up below
     * would then time out with nothing but an assert (#147). */
    if (IPV4_HEADER_SIZE + 8 + payload_size > WG_DEFAULT_MTU) {
        fprintf(stderr,
                "payload_size %zu gives a %zu-byte packet, over the %d-byte MTU; "
                "use at most %d\n",
                payload_size, IPV4_HEADER_SIZE + 8 + payload_size, WG_DEFAULT_MTU,
                WG_DEFAULT_MTU - IPV4_HEADER_SIZE - 8);
        return 2;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("╔═══════════════════════════════════════════╗\n");
    printf("║       noisetun Throughput Benchmark       ║\n");
    printf("╚═══════════════════════════════════════════╝\n\n");

    bench_pair_t pair;
    setup_pair(&pair);

    /* Build a packet. */
    size_t pkt_size = IPV4_HEADER_SIZE + 8 + payload_size;
    uint8_t *pkt = malloc(pkt_size);
    assert(pkt);

    size_t actual_size = build_ipv4_udp(pkt, pkt_size,
                                        pair.peer[0].ip,
                                        pair.peer[1].ip,
                                        payload_size);

    printf("  Packet size:    %zu bytes\n", actual_size);
    printf("  Duration:       %d seconds\n", duration_secs);
    printf("  Direction:      peer[1] -> peer[0]\n\n");

    /* Warm up: establish handshake with one packet. */
    printf("  Warming up (handshake)...\n");
    {
        wg_error_t err = wg_channel_tun_send(pair.peer[1].tun, pkt, actual_size);
        assert(err == WG_OK);
        uint8_t *recv_data = NULL;
        size_t recv_len = 0;
        err = wg_channel_tun_recv_timeout(pair.peer[0].tun, &recv_data, &recv_len, 10000);
        assert(err == WG_OK);
        free(recv_data);
    }
    printf("  Handshake complete.\n\n");

    /* Benchmark loop. */
    printf("  Running benchmark...\n");
    uint64_t packets_sent = 0;
    uint64_t packets_recv = 0;
    uint64_t bytes_recv = 0;

    double start = now_sec();
    double deadline = start + (double)duration_secs;

    while (now_sec() < deadline) {
        /* Send a batch of packets. */
        const int batch = 100;
        for (int i = 0; i < batch; i++) {
            wg_error_t err = wg_channel_tun_send(pair.peer[1].tun, pkt, actual_size);
            if (err == WG_OK)
                packets_sent++;
        }

        /* Drain received packets. */
        for (;;) {
            uint8_t *recv_data = NULL;
            size_t recv_len = 0;
            wg_error_t err = wg_channel_tun_try_recv(pair.peer[0].tun,
                                                      &recv_data, &recv_len);
            if (err != WG_OK)
                break;
            packets_recv++;
            bytes_recv += recv_len;
            free(recv_data);
        }
    }

    /* Drain remaining. */
    for (int i = 0; i < 1000; i++) {
        uint8_t *recv_data = NULL;
        size_t recv_len = 0;
        wg_error_t err = wg_channel_tun_try_recv(pair.peer[0].tun,
                                                  &recv_data, &recv_len);
        if (err != WG_OK)
            break;
        packets_recv++;
        bytes_recv += recv_len;
        free(recv_data);
    }

    double elapsed = now_sec() - start;

    /* Report. */
    double pps = (double)packets_recv / elapsed;
    double mbps = ((double)bytes_recv * 8.0) / (elapsed * 1e6);
    double mBps = (double)bytes_recv / (elapsed * 1e6);

    printf("\n");
    printf("  ┌─────────────────────────────────────────┐\n");
    printf("  │  Results                                 │\n");
    printf("  ├─────────────────────────────────────────┤\n");
    printf("  │  Elapsed:       %8.2f s               │\n", elapsed);
    printf("  │  Packets sent:  %8llu                  │\n", (unsigned long long)packets_sent);
    printf("  │  Packets recv:  %8llu                  │\n", (unsigned long long)packets_recv);
    printf("  │  Throughput:    %8.0f pkt/s            │\n", pps);
    printf("  │  Throughput:    %8.2f Mbps             │\n", mbps);
    printf("  │  Throughput:    %8.2f MB/s             │\n", mBps);
    printf("  │  Loss:          %8.2f %%               │\n",
           packets_sent > 0 ? (1.0 - (double)packets_recv / (double)packets_sent) * 100.0 : 0.0);
    printf("  └─────────────────────────────────────────┘\n");

    /* Pipeline stats for both devices. */
    printf("\n  === Sender device (peer[1]) ===");
    wg_stats_dump(&pair.peer[1].dev->stats, &pair.peer[1].dev->net.bind, stdout);
    printf("\n  === Receiver device (peer[0]) ===");
    wg_stats_dump(&pair.peer[0].dev->stats, &pair.peer[0].dev->net.bind, stdout);

    free(pkt);
    teardown_pair(&pair);

    return 0;
}

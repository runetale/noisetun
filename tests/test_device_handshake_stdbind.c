/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Handshake + data transfer test using real UDP sockets (StdBind).
 *
 * Creates two WireGuard devices connected via StdNetBind (real UDP on
 * localhost) and ChannelTUN (in-memory). Verifies:
 *   1. Handshake completes over real UDP
 *   2. Data transits correctly in both directions
 *
 * This test exercises the real network I/O path on both macOS and Linux
 * without requiring root (binds to ephemeral ports on 127.0.0.1).
 *
 * Reference: wireguard-go/device/device_test.go
 */

#include "../src/bind/wg_bind_std.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_channel.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>

#define PASS(name) printf("  PASS: %s\n", name)
#define TIMEOUT_MS 30000 /* 30 seconds — real network + ASAN overhead */

/* ────────────────────────────────────────
 * Helpers
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

static size_t build_icmpv4_ping(uint8_t *out, size_t cap, uint32_t dst_ip,
                                uint32_t src_ip, uint16_t seq)
{
    const size_t payload_len = 4;
    const size_t total = IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + payload_len;
    assert(cap >= total);
    memset(out, 0, total);

    uint8_t payload[4];
    payload[0] = 0x05;
    payload[1] = 0x39;
    payload[2] = (uint8_t)(seq >> 8);
    payload[3] = (uint8_t)seq;

    uint8_t *icmp = out + IPV4_HEADER_SIZE;
    icmp[0] = 8;
    icmp[1] = 0;
    uint16_t icmp_cksum =
        inet_checksum(icmp, ICMP_HEADER_SIZE, inet_checksum(payload, payload_len, 0));
    icmp[2] = (uint8_t)(icmp_cksum >> 8);
    icmp[3] = (uint8_t)(icmp_cksum & 0xFF);
    memcpy(out + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE, payload, payload_len);

    uint8_t *ip = out;
    ip[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4);
    uint16_t total_len = htons((uint16_t)total);
    memcpy(ip + 2, &total_len, 2);
    ip[8] = 65;
    ip[9] = 1;
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    uint16_t ip_cksum = inet_checksum(ip, IPV4_HEADER_SIZE, 0);
    ip[10] = (uint8_t)(ip_cksum >> 8);
    ip[11] = (uint8_t)(ip_cksum & 0xFF);

    return total;
}

/* ────────────────────────────────────────
 * Logger (silent — reduce noise in test output)
 * ──────────────────────────────────────── */

static void test_log(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    (void)ctx;
    (void)level;
    (void)fmt;
}

/* ────────────────────────────────────────
 * Test pair: two devices with real UDP (StdBind)
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_channel_tun_t *tun;
    wg_std_bind_t *bind;
    uint16_t port;
    uint32_t ip; /* host byte order */
} test_peer_t;

typedef struct {
    test_peer_t peer[2];
} test_pair_t;

static uint16_t find_free_port(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    socklen_t len = sizeof(addr);
    rc = getsockname(fd, (struct sockaddr *)&addr, &len);
    assert(rc == 0);

    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static void setup_pair(test_pair_t *pair)
{
    wg_key_t priv[2], pub[2];
    gen_keypair(&priv[0], &pub[0]);
    gen_keypair(&priv[1], &pub[1]);

    pair->peer[0].ip = 0x01000001; /* 1.0.0.1 */
    pair->peer[1].ip = 0x01000002; /* 1.0.0.2 */

    /* Find two free ports. */
    pair->peer[0].port = find_free_port();
    pair->peer[1].port = find_free_port();
    while (pair->peer[1].port == pair->peer[0].port)
        pair->peer[1].port = find_free_port();

    for (int i = 0; i < 2; i++) {
        wg_error_t err = wg_channel_tun_create(&pair->peer[i].tun, WG_DEFAULT_MTU);
        assert(err == WG_OK);
    }

    for (int i = 0; i < 2; i++) {
        wg_error_t err = wg_std_bind_new(&pair->peer[i].bind);
        assert(err == WG_OK);
    }

    for (int i = 0; i < 2; i++) {
        wg_tun_ops_t tun_ops = wg_channel_tun_ops(pair->peer[i].tun);
        wg_bind_ops_t bind_ops = wg_std_bind_ops(pair->peer[i].bind);
        wg_logger_t logger = {.log = test_log, .ctx = NULL};

        wg_error_t err = wg_device_new(&pair->peer[i].dev, &tun_ops, &bind_ops, &logger);
        assert(err == WG_OK);

        err = wg_device_set_private_key(pair->peer[i].dev, &priv[i]);
        assert(err == WG_OK);
    }

    /* Set listen ports before device_up. */
    for (int i = 0; i < 2; i++) {
        pthread_rwlock_wrlock(&pair->peer[i].dev->net.lock);
        pair->peer[i].dev->net.port = pair->peer[i].port;
        pthread_rwlock_unlock(&pair->peer[i].dev->net.lock);
    }

    /* Add peers. */
    for (int i = 0; i < 2; i++) {
        int other = i ^ 1;
        wg_peer_t *peer = NULL;
        wg_error_t err = wg_peer_new(pair->peer[i].dev, pub[other].key, NULL, &peer);
        assert(err == WG_OK);

        wg_endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr.sa4.sin_family = AF_INET;
        ep.addr.sa4.sin_port = htons(pair->peer[other].port);
        ep.addr.sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        err = wg_peer_set_endpoint(peer, &ep);
        assert(err == WG_OK);

        uint32_t allowed_ip = htonl(pair->peer[other].ip);
        err = wg_peer_add_allowed_ip(peer, &allowed_ip, 32, AF_INET);
        assert(err == WG_OK);
    }

    /* Bring both devices up. */
    for (int i = 0; i < 2; i++) {
        wg_error_t err = wg_device_up(pair->peer[i].dev);
        assert(err == WG_OK);
    }

    /* Allow worker threads to start and enter blocking calls. */
    usleep(200000); /* 200ms */
}

static void teardown_pair(test_pair_t *pair)
{
    for (int i = 0; i < 2; i++) {
        wg_device_close(pair->peer[i].dev);
        wg_channel_tun_destroy(pair->peer[i].tun);
        wg_std_bind_destroy(pair->peer[i].bind);
    }
}

/* ────────────────────────────────────────
 * Send and verify
 * ──────────────────────────────────────── */

static void send_and_verify(test_pair_t *pair, int from, int to, uint16_t seq)
{
    uint8_t pkt[128];
    size_t pkt_len =
        build_icmpv4_ping(pkt, sizeof(pkt), pair->peer[to].ip, pair->peer[from].ip, seq);

    wg_error_t err = wg_channel_tun_send(pair->peer[from].tun, pkt, pkt_len);
    assert(err == WG_OK);

    uint8_t *recv_data = NULL;
    size_t recv_len = 0;
    err = wg_channel_tun_recv_timeout(pair->peer[to].tun, &recv_data, &recv_len,
                                      TIMEOUT_MS);
    if (err != WG_OK) {
        fprintf(stderr, "  FAIL: send_and_verify(%d->%d, seq=%d): %s\n", from, to, seq,
                wg_error_str(err));
        assert(0 && "packet did not transit over real UDP");
    }

    assert(recv_len == pkt_len);
    assert(memcmp(recv_data, pkt, pkt_len) == 0);
    free(recv_data);
}

/* ────────────────────────────────────────
 * Test: handshake + data transfer over real UDP
 *
 * Single pair, multiple packets both directions.
 * ──────────────────────────────────────── */
static void test_handshake_and_data_over_udp(void)
{
    test_pair_t pair;
    setup_pair(&pair);

    printf("  Ports: dev0=%u, dev1=%u\n", pair.peer[0].port, pair.peer[1].port);

    /* First packet triggers handshake initiation. */
    send_and_verify(&pair, 1, 0, 0);
    PASS("handshake_initiation_over_udp (1->0)");

    /* Reverse direction (uses established session). */
    send_and_verify(&pair, 0, 1, 1);
    PASS("data_reverse_direction (0->1)");

    /* A few more packets to confirm stability. */
    send_and_verify(&pair, 1, 0, 2);
    send_and_verify(&pair, 0, 1, 3);
    PASS("bidirectional_data");

    teardown_pair(&pair);
}

/* ────────────────────────────────────────
 * Test: rebinding a busy device (#129)
 *
 * dev0 keeps sending while its listen port is changed 20 times, the way
 * a UAPI "listen_port=" does it. Each rebind closes the old sockets; the
 * sequential sender must never be in sendmmsg on one of them (TSan
 * reports the race if it is), and traffic must flow afterwards.
 * ──────────────────────────────────────── */
typedef struct {
    test_pair_t *pair;
    atomic_bool stop;
} rebind_traffic_t;

static void *rebind_traffic(void *arg)
{
    rebind_traffic_t *t = arg;
    uint16_t seq = 1000;
    while (!atomic_load(&t->stop)) {
        uint8_t pkt[128];
        size_t len = build_icmpv4_ping(pkt, sizeof(pkt), t->pair->peer[1].ip,
                                       t->pair->peer[0].ip, seq++);
        (void)wg_channel_tun_send(t->pair->peer[0].tun, pkt, len);
        usleep(200);
    }
    return NULL;
}

static void drain_tun(wg_channel_tun_t *tun)
{
    uint8_t *data = NULL;
    size_t len = 0;
    while (wg_channel_tun_recv_timeout(tun, &data, &len, 50) == WG_OK)
        free(data);
}

static void test_rebind_under_traffic(void)
{
    test_pair_t pair;
    setup_pair(&pair);
    send_and_verify(&pair, 0, 1, 1); /* handshake */

    rebind_traffic_t t = {.pair = &pair};
    atomic_store(&t.stop, false);
    pthread_t th;
    assert(pthread_create(&th, NULL, rebind_traffic, &t) == 0);

    wg_device_t *dev = pair.peer[0].dev;
    for (int i = 0; i < 20; i++) {
        /* Same locking as the UAPI listen_port handler. */
        pthread_mutex_lock(&dev->state_lock);
        pthread_rwlock_wrlock(&dev->net.lock);
        dev->net.port = find_free_port();
        assert(wg_device_bind_update(dev) == WG_OK);
        pthread_rwlock_unlock(&dev->net.lock);
        pthread_mutex_unlock(&dev->state_lock);
        usleep(10000);
    }

    atomic_store(&t.stop, true);
    pthread_join(th, NULL);

    /* dev1 learns dev0's new port from the packets it receives. */
    drain_tun(pair.peer[1].tun);
    send_and_verify(&pair, 0, 1, 2);
    PASS("rebind_under_traffic (20 port changes while sending)");

    teardown_pair(&pair);
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_device_handshake_stdbind ===\n");
    printf("  (Tests handshake + data over real UDP sockets)\n\n");

    test_handshake_and_data_over_udp();
    test_rebind_under_traffic();

    printf("\nAll StdBind handshake tests passed.\n");
    return 0;
}

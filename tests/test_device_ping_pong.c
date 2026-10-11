/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * DEV-14: Two Device Ping-Pong integration test.
 *
 * Creates two WireGuard devices (A and B) connected via ChannelBind
 * and ChannelTUN. Verifies:
 *   1. Handshake completes automatically
 *   2. Data transits correctly in both directions
 *   3. Multiple packets (bulk transfer)
 *   4. Packets reach the TUN at their IP length, without WireGuard's
 *      padding, and a packet claiming more than it carries is dropped
 *
 * Reference: wireguard-go/device/device_test.go
 */

#include "../src/bind/wg_bind.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_channel.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PASS(name) printf("  PASS: %s\n", name)
#define TIMEOUT_MS 10000 /* 10 seconds for handshake + transit */

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static void gen_keypair(wg_key_t *priv, wg_key_t *pub)
{
    /* crypto_box_keypair generates a clamped Curve25519 private key
     * and the corresponding public key. No additional clamping needed. */
    crypto_box_keypair(pub->key, priv->key);
}

/* ────────────────────────────────────────
 * Build an IPv4 ICMP echo request packet
 *
 * Matches wireguard-go/tun/tuntest/tuntest.go Ping()
 * ──────────────────────────────────────── */

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
    const size_t payload_len = 4; /* port(2) + seq(2) */
    const size_t total = IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + payload_len;
    assert(cap >= total);

    memset(out, 0, total);

    /* Payload */
    uint8_t payload[4];
    payload[0] = 0x05;
    payload[1] = 0x39; /* port 1337 */
    payload[2] = (uint8_t)(seq >> 8);
    payload[3] = (uint8_t)seq;

    /* ICMP header */
    uint8_t *icmp = out + IPV4_HEADER_SIZE;
    icmp[0] = 8; /* echo request */
    icmp[1] = 0; /* code */
    /* checksum placeholder */
    icmp[2] = 0;
    icmp[3] = 0;

    /* ICMP checksum over header + payload */
    uint16_t icmp_cksum =
        inet_checksum(icmp, ICMP_HEADER_SIZE, inet_checksum(payload, payload_len, 0));
    icmp[2] = (uint8_t)(icmp_cksum >> 8);
    icmp[3] = (uint8_t)(icmp_cksum & 0xFF);

    /* Copy payload */
    memcpy(out + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE, payload, payload_len);

    /* IPv4 header */
    uint8_t *ip = out;
    ip[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4); /* version + IHL */
    uint16_t total_len = htons((uint16_t)total);
    memcpy(ip + 2, &total_len, 2);
    ip[8] = 65; /* TTL */
    ip[9] = 1;  /* protocol: ICMP */
    /* src address */
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    /* IP checksum */
    uint16_t ip_cksum = inet_checksum(ip, IPV4_HEADER_SIZE, 0);
    ip[10] = (uint8_t)(ip_cksum >> 8);
    ip[11] = (uint8_t)(ip_cksum & 0xFF);

    return total;
}

/* ────────────────────────────────────────
 * Build an IPv4 or IPv6 packet of exactly `total` bytes
 *
 * Nothing above IP is parsed on the way through, so the payload is just
 * a byte pattern.
 * ──────────────────────────────────────── */

#define IPV6_HEADER_SIZE 40

static void fill_payload(uint8_t *p, size_t len, uint16_t id)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t)(id + i);
}

static void build_ipv4_packet(uint8_t *out, size_t total, uint32_t dst_ip,
                              uint32_t src_ip, uint16_t id)
{
    assert(total >= IPV4_HEADER_SIZE && total <= 0xFFFF);
    memset(out, 0, IPV4_HEADER_SIZE);
    out[0] = (4 << 4) | (IPV4_HEADER_SIZE / 4); /* version + IHL */
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[4] = (uint8_t)(id >> 8);
    out[5] = (uint8_t)id;
    out[8] = 64; /* TTL */
    out[9] = 17; /* protocol: UDP */
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(out + 12, &src_be, 4);
    memcpy(out + 16, &dst_be, 4);
    uint16_t cksum = inet_checksum(out, IPV4_HEADER_SIZE, 0);
    out[10] = (uint8_t)(cksum >> 8);
    out[11] = (uint8_t)cksum;
    fill_payload(out + IPV4_HEADER_SIZE, total - IPV4_HEADER_SIZE, id);
}

/* fd00::1 for peer 0, fd00::2 for peer 1 */
static void ipv6_addr(uint8_t *out, int peer_index)
{
    memset(out, 0, 16);
    out[0] = 0xfd;
    out[15] = (uint8_t)(peer_index + 1);
}

static void build_ipv6_packet(uint8_t *out, size_t total, int dst_peer, int src_peer,
                              uint16_t id)
{
    assert(total >= IPV6_HEADER_SIZE && total - IPV6_HEADER_SIZE <= 0xFFFF);
    size_t payload_len = total - IPV6_HEADER_SIZE;
    memset(out, 0, IPV6_HEADER_SIZE);
    out[0] = 6 << 4;
    out[4] = (uint8_t)(payload_len >> 8);
    out[5] = (uint8_t)payload_len;
    out[6] = 17; /* next header: UDP */
    out[7] = 64; /* hop limit */
    ipv6_addr(out + 8, src_peer);
    ipv6_addr(out + 24, dst_peer);
    fill_payload(out + IPV6_HEADER_SIZE, payload_len, id);
}

/* ────────────────────────────────────────
 * Test logger
 * ──────────────────────────────────────── */

static void test_log(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    const char *prefix = (const char *)ctx;
    if (level > WG_LOG_VERBOSE)
        return;
    va_list ap;
    va_start(ap, fmt);
    printf("  [%s] ", prefix);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

/* ────────────────────────────────────────
 * Test pair: two connected devices
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_channel_tun_t *tun;
    wg_channel_bind_t *bind;
    uint32_t ip; /* host byte order */
} test_peer_t;

typedef struct {
    test_peer_t peer[2];
} test_pair_t;

/* When set, dev0's TUN ops are wrapped so that returning from read or
 * write after close has run fails the test: close is where a real TUN
 * frees what a blocked read is still using (#127). */
static bool g_watch_close;
static wg_tun_ops_t g_orig_tun;
static atomic_bool g_tun_closed;
static atomic_int g_use_after_close;

static int watched_read(void *ctx, uint8_t **bufs, int *sizes, int count, int offset)
{
    int n = g_orig_tun.read(ctx, bufs, sizes, count, offset);
    if (atomic_load(&g_tun_closed))
        atomic_fetch_add(&g_use_after_close, 1);
    return n;
}

static int watched_write(void *ctx, uint8_t **bufs, const int *sizes, int count,
                         int offset)
{
    if (atomic_load(&g_tun_closed))
        atomic_fetch_add(&g_use_after_close, 1);
    return g_orig_tun.write(ctx, bufs, sizes, count, offset);
}

static void watched_close(void *ctx)
{
    atomic_store(&g_tun_closed, true);
    g_orig_tun.close(ctx);
}

static void setup_pair(test_pair_t *pair)
{
    /* Generate keys for both devices. */
    wg_key_t priv[2], pub[2];
    gen_keypair(&priv[0], &pub[0]);
    gen_keypair(&priv[1], &pub[1]);

    /* IPs: 1.0.0.1 and 1.0.0.2 */
    pair->peer[0].ip = 0x01000001; /* 1.0.0.1 */
    pair->peer[1].ip = 0x01000002; /* 1.0.0.2 */

    /* Create ChannelBind pair. */
    wg_error_t err = wg_channel_bind_pair(&pair->peer[0].bind, &pair->peer[1].bind);
    assert(err == WG_OK);

    /* Create ChannelTUN for each device. */
    for (int i = 0; i < 2; i++) {
        err = wg_channel_tun_create(&pair->peer[i].tun, WG_DEFAULT_MTU);
        assert(err == WG_OK);
    }

    /* Create devices. */
    for (int i = 0; i < 2; i++) {
        wg_tun_ops_t tun_ops = wg_channel_tun_ops(pair->peer[i].tun);
        if (i == 0 && g_watch_close) {
            g_orig_tun = tun_ops;
            tun_ops.read = watched_read;
            tun_ops.write = watched_write;
            tun_ops.close = watched_close;
        }
        wg_bind_ops_t bind_ops = wg_channel_bind_ops(pair->peer[i].bind);

        char *name = (i == 0) ? "dev0" : "dev1";
        wg_logger_t logger = {
            .log = test_log,
            .ctx = name,
        };

        err = wg_device_new(&pair->peer[i].dev, &tun_ops, &bind_ops, &logger);
        assert(err == WG_OK);

        /* Set private key. */
        err = wg_device_set_private_key(pair->peer[i].dev, &priv[i]);
        assert(err == WG_OK);
    }

    /* Add peers: dev0 knows pub1, dev1 knows pub0. */
    for (int i = 0; i < 2; i++) {
        int other = i ^ 1;
        wg_peer_t *peer = NULL;
        err = wg_peer_new(pair->peer[i].dev, pub[other].key, NULL, &peer);
        assert(err == WG_OK);

        /* Set endpoint: point at the other side's bind endpoint. */
        wg_endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr.sa4.sin_family = AF_INET;
        ep.addr.sa4.sin_port = htons((uint16_t)(other + 1));
        ep.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);
        err = wg_peer_set_endpoint(peer, &ep);
        assert(err == WG_OK);

        /* Add allowed IP: the other device's IP /32 */
        uint32_t allowed_ip = htonl(pair->peer[other].ip);
        err = wg_peer_add_allowed_ip(peer, &allowed_ip, 32, AF_INET);
        assert(err == WG_OK);

        /* ...and its IPv6 address /128 */
        uint8_t allowed_ip6[16];
        ipv6_addr(allowed_ip6, other);
        err = wg_peer_add_allowed_ip(peer, allowed_ip6, 128, AF_INET6);
        assert(err == WG_OK);
    }

    /* Bring both devices up. */
    for (int i = 0; i < 2; i++) {
        err = wg_device_up(pair->peer[i].dev);
        assert(err == WG_OK);
    }
}

static void teardown_pair(test_pair_t *pair)
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
 * Send a ping from peer[from] to peer[to] and verify receipt.
 * ──────────────────────────────────────── */

static void send_and_verify(test_pair_t *pair, int from, int to, uint16_t seq)
{
    uint8_t pkt[128];
    size_t pkt_len =
        build_icmpv4_ping(pkt, sizeof(pkt), pair->peer[to].ip, pair->peer[from].ip, seq);

    /* Inject into sender's TUN (simulates app sending a packet). */
    wg_error_t err = wg_channel_tun_send(pair->peer[from].tun, pkt, pkt_len);
    assert(err == WG_OK);

    /* Read from receiver's TUN (packet should arrive after handshake + encrypt +
     * decrypt). */
    uint8_t *recv_data = NULL;
    size_t recv_len = 0;
    err = wg_channel_tun_recv_timeout(pair->peer[to].tun, &recv_data, &recv_len,
                                      TIMEOUT_MS);
    if (err != WG_OK) {
        fprintf(stderr,
                "  FAIL: send_and_verify(%d->%d, seq=%d): "
                "recv timed out or failed: %s\n",
                from, to, seq, wg_error_str(err));
        assert(0 && "packet did not transit");
    }

    /* Verify data matches. */
    assert(recv_len == pkt_len);
    assert(memcmp(recv_data, pkt, pkt_len) == 0);

    free(recv_data);
}

/* ────────────────────────────────────────
 * Test: basic ping (A -> B)
 * ──────────────────────────────────────── */
static void test_ping(void)
{
    test_pair_t pair;
    setup_pair(&pair);

    send_and_verify(&pair, 1, 0, 0);

    teardown_pair(&pair);
    PASS("ping (1->0)");
}

/* ────────────────────────────────────────
 * Test: pong (B -> A)
 * ──────────────────────────────────────── */
static void test_pong(void)
{
    test_pair_t pair;
    setup_pair(&pair);

    /* First establish session with a ping. */
    send_and_verify(&pair, 1, 0, 0);
    /* Now pong in reverse. */
    send_and_verify(&pair, 0, 1, 1);

    teardown_pair(&pair);
    PASS("pong (0->1)");
}

/* ────────────────────────────────────────
 * Test: ping-pong (both directions)
 * ──────────────────────────────────────── */
static void test_ping_pong(void)
{
    test_pair_t pair;
    setup_pair(&pair);

    send_and_verify(&pair, 1, 0, 0);
    send_and_verify(&pair, 0, 1, 1);
    send_and_verify(&pair, 1, 0, 2);
    send_and_verify(&pair, 0, 1, 3);

    teardown_pair(&pair);
    PASS("ping_pong");
}

/* ────────────────────────────────────────
 * Test: bulk data transfer (many packets)
 * ──────────────────────────────────────── */
static void test_bulk_transfer(void)
{
    test_pair_t pair;
    setup_pair(&pair);

    /* Establish session first. */
    send_and_verify(&pair, 1, 0, 0);

    /* Send many packets in one direction. */
    const int N = 50;
    for (int i = 1; i <= N; i++) {
        send_and_verify(&pair, 1, 0, (uint16_t)i);
    }

    teardown_pair(&pair);
    PASS("bulk_transfer");
}

/* ────────────────────────────────────────
 * Send a raw packet from peer[from]; return what peer[to]'s TUN receives
 * within timeout_ms (caller frees), or NULL if nothing arrives.
 * ──────────────────────────────────────── */

static uint8_t *transit(test_pair_t *pair, int from, int to, const uint8_t *pkt,
                        size_t len, int timeout_ms, size_t *recv_len)
{
    wg_error_t err = wg_channel_tun_send(pair->peer[from].tun, pkt, len);
    assert(err == WG_OK);

    uint8_t *recv_data = NULL;
    *recv_len = 0;
    err =
        wg_channel_tun_recv_timeout(pair->peer[to].tun, &recv_data, recv_len, timeout_ms);
    return err == WG_OK ? recv_data : NULL;
}

static void expect_exact_transit(test_pair_t *pair, int from, int to, const uint8_t *pkt,
                                 size_t len)
{
    size_t recv_len = 0;
    uint8_t *got = transit(pair, from, to, pkt, len, TIMEOUT_MS, &recv_len);
    if (!got || recv_len != len) {
        fprintf(stderr, "  FAIL: %zu-byte IPv%d packet %d->%d arrived as %s%zu bytes\n",
                len, pkt[0] >> 4, from, to, got ? "" : "nothing, ", recv_len);
        assert(0 && "packet did not reach the TUN at its IP length");
    }
    assert(memcmp(got, pkt, len) == 0);
    free(got);
}

/* ────────────────────────────────────────
 * Test: packets reach the TUN at their IP length
 *
 * WireGuard pads plaintext to a multiple of 16 bytes. Every size from a
 * bare header to two blocks past it must arrive without that padding.
 * ──────────────────────────────────────── */
static void test_ip_length(void)
{
    test_pair_t pair;
    setup_pair(&pair);
    send_and_verify(&pair, 1, 0, 0);

    uint8_t pkt[128];
    for (size_t len = IPV4_HEADER_SIZE; len <= IPV4_HEADER_SIZE + 33; len++) {
        build_ipv4_packet(pkt, len, pair.peer[0].ip, pair.peer[1].ip, (uint16_t)len);
        expect_exact_transit(&pair, 1, 0, pkt, len);
    }
    for (size_t len = IPV6_HEADER_SIZE; len <= IPV6_HEADER_SIZE + 33; len++) {
        build_ipv6_packet(pkt, len, 0, 1, (uint16_t)len);
        expect_exact_transit(&pair, 1, 0, pkt, len);
    }

    teardown_pair(&pair);
    PASS("ip_length");
}

/* ────────────────────────────────────────
 * Test: a packet whose IP header claims more than it carries is dropped
 * ──────────────────────────────────────── */
static void test_ip_length_overrun_dropped(void)
{
    test_pair_t pair;
    setup_pair(&pair);
    send_and_verify(&pair, 1, 0, 0);

    /* 32 bytes needs no padding, so the plaintext is exactly this packet;
     * its total length field then points one byte past the end. The
     * checksum goes stale, but nothing on the way checks it. */
    uint8_t pkt[32];
    build_ipv4_packet(pkt, sizeof(pkt), pair.peer[0].ip, pair.peer[1].ip, 1);
    pkt[3] = (uint8_t)(sizeof(pkt) + 1);

    size_t recv_len = 0;
    uint8_t *got = transit(&pair, 1, 0, pkt, sizeof(pkt), 500, &recv_len);
    if (got) {
        fprintf(stderr, "  FAIL: overrunning packet arrived as %zu bytes\n", recv_len);
        free(got);
        assert(0 && "packet claiming more than it carries reached the TUN");
    }

    /* The tunnel keeps working. */
    send_and_verify(&pair, 1, 0, 2);

    teardown_pair(&pair);
    PASS("ip_length_overrun_dropped");
}

/*
 * TODO: test_up_down_cycle — bring devices up, exchange packets, down, up, exchange
 * again. Currently skipped because device_down() cannot unblock the TUN reader thread
 * when using ChannelTUN (the blocking queue_pop in tun.read has no cancel mechanism).
 * This will be addressed when TUN lifecycle management is added (TUN-3 or similar).
 */

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

/* ────────────────────────────────────────
 * Test: closing a device never releases the TUN under a live reader
 *
 * dev0's TUN reader is blocked in read when the device closes. The TUN
 * must be woken (cancel), the reader joined, and only then closed, so
 * nothing returns from read or write after close.
 * ──────────────────────────────────────── */
static void test_close_joins_tun_reader_first(void)
{
    printf("  %-50s", "device close joins TUN reader before close");
    fflush(stdout);

    test_pair_t pair;
    g_watch_close = true;
    atomic_store(&g_tun_closed, false);
    atomic_store(&g_use_after_close, 0);
    setup_pair(&pair);

    send_and_verify(&pair, 0, 1, 1);
    send_and_verify(&pair, 1, 0, 2);

    teardown_pair(&pair);
    g_watch_close = false;

    assert(atomic_load(&g_tun_closed));
    assert(atomic_load(&g_use_after_close) == 0);
    printf("PASS\n");
}

/* ────────────────────────────────────────
 * Test: removing a peer and adding it back on a running device
 *
 * The sequential threads cache peer pointers. The removed peer must not
 * be freed while one of them may still hold it (ASan/TSan report it if
 * it is), and the re-added peer must be served at once rather than after
 * a periodic cache refresh, which with a long FUTEX_WAIT timeout could
 * take seconds. Traffic is stopped around the removal: freeing a peer
 * while a handshake for it is in flight is a separate problem.
 * ──────────────────────────────────────── */
static void sleep_us(long us)
{
    struct timespec ts = {us / 1000000, (us % 1000000) * 1000};
    nanosleep(&ts, NULL);
}

static void drain_channel_tun(wg_channel_tun_t *tun)
{
    uint8_t *data = NULL;
    size_t len = 0;
    while (wg_channel_tun_recv_timeout(tun, &data, &len, 50) == WG_OK)
        free(data);
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void test_remove_and_readd_peer(void)
{
    printf("  %-50s", "remove and re-add a peer on a running device");
    fflush(stdout);

    test_pair_t pair;
    setup_pair(&pair);
    send_and_verify(&pair, 0, 1, 1);
    send_and_verify(&pair, 1, 0, 2);

    wg_device_t *dev1 = pair.peer[1].dev;
    wg_key_t pub0;
    bool found = false;
    for (size_t i = 0; i < dev1->peers.capacity; i++) {
        if (dev1->peers.entries[i].occupied) {
            memcpy(pub0.key, dev1->peers.entries[i].public_key, WG_KEY_LEN);
            found = true;
            break;
        }
    }
    assert(found);

    for (int round = 0; round < 3; round++) {
        sleep_us(100000); /* let in-flight packets and handshakes settle */
        assert(wg_device_remove_peer(dev1, &pub0) == WG_OK);

        wg_peer_t *peer = NULL;
        assert(wg_peer_new(dev1, pub0.key, NULL, &peer) == WG_OK);
        wg_endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr.sa4.sin_family = AF_INET;
        ep.addr.sa4.sin_port = htons(1);
        ep.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);
        assert(wg_peer_set_endpoint(peer, &ep) == WG_OK);
        uint32_t allowed_ip = htonl(pair.peer[0].ip);
        assert(wg_peer_add_allowed_ip(peer, &allowed_ip, 32, AF_INET) == WG_OK);
        wg_peer_start(peer); /* the device is up, as the UAPI does */

        /* dev0 still has its old session, so dev1 starts the handshake.
         * The new peer must be picked up at once. */
        drain_channel_tun(pair.peer[0].tun);
        double t0 = now_ms();
        send_and_verify(&pair, 1, 0, (uint16_t)(10 + round));
        double took = now_ms() - t0;
        assert(took < 500.0);
        send_and_verify(&pair, 0, 1, (uint16_t)(20 + round));
    }

    teardown_pair(&pair);
    printf("PASS\n");
}

/* Remove and re-add a peer while packets flow both ways and the other
 * side keeps starting handshakes, so the removal lands while the TUN
 * reader, the UDP receiver, the handshake worker and the sequential
 * threads hold the peer (#135). Meant for ASan/TSan builds, which catch
 * a peer freed while in use (on main before the fix, ASan reports a
 * heap-use-after-free in about 3 of 8 runs). */
typedef struct {
    test_pair_t *pair;
    atomic_bool stop;
} churn_ctx_t;

static void *churn_send(void *arg, int from, int to)
{
    churn_ctx_t *c = arg;
    uint16_t seq = 0;
    while (!atomic_load(&c->stop)) {
        uint8_t pkt[128];
        size_t len = build_icmpv4_ping(pkt, sizeof(pkt), c->pair->peer[to].ip,
                                       c->pair->peer[from].ip, seq++);
        (void)wg_channel_tun_send(c->pair->peer[from].tun, pkt, len);
        uint8_t *data = NULL;
        size_t dlen = 0;
        while (wg_channel_tun_try_recv(c->pair->peer[to].tun, &data, &dlen) == WG_OK)
            free(data);
        sleep_us(200);
    }
    return NULL;
}

static void *churn_send_01(void *arg)
{
    return churn_send(arg, 0, 1);
}

static void *churn_send_10(void *arg)
{
    return churn_send(arg, 1, 0);
}

/* Make dev0 start a new handshake with its next packet, so dev1's
 * handshake worker answers (and uses the peer) while it is removed. */
static void *churn_rekey(void *arg)
{
    churn_ctx_t *c = arg;
    wg_device_t *dev0 = c->pair->peer[0].dev;
    while (!atomic_load(&c->stop)) {
        pthread_rwlock_rdlock(&dev0->peers.lock);
        for (size_t i = 0; i < dev0->peers.capacity; i++) {
            if (dev0->peers.entries[i].occupied) {
                struct wg_peer *p = dev0->peers.entries[i].peer;
                wg_peer_expire_current_keypairs(p);
                /* Skip the REKEY_TIMEOUT rate limit on initiations. */
                pthread_rwlock_wrlock(&p->handshake.lock);
                p->handshake.last_sent_handshake_ns = 0;
                pthread_rwlock_unlock(&p->handshake.lock);
            }
        }
        pthread_rwlock_unlock(&dev0->peers.lock);
        sleep_us(3000);
    }
    return NULL;
}

static void readd_peer(test_pair_t *pair, const wg_key_t *pub0)
{
    wg_device_t *dev1 = pair->peer[1].dev;
    wg_peer_t *peer = NULL;
    assert(wg_peer_new(dev1, pub0->key, NULL, &peer) == WG_OK);
    wg_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.addr.sa4.sin_family = AF_INET;
    ep.addr.sa4.sin_port = htons(1);
    ep.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);
    assert(wg_peer_set_endpoint(peer, &ep) == WG_OK);
    uint32_t allowed_ip = htonl(pair->peer[0].ip);
    assert(wg_peer_add_allowed_ip(peer, &allowed_ip, 32, AF_INET) == WG_OK);
    wg_peer_start(peer);
}

static void test_remove_peer_under_traffic(void)
{
    printf("  %-50s", "remove a peer under traffic and handshakes");
    fflush(stdout);

    test_pair_t pair;
    setup_pair(&pair);
    send_and_verify(&pair, 0, 1, 1);
    send_and_verify(&pair, 1, 0, 2);

    wg_device_t *dev1 = pair.peer[1].dev;
    wg_key_t pub0;
    bool found = false;
    for (size_t i = 0; i < dev1->peers.capacity; i++) {
        if (dev1->peers.entries[i].occupied) {
            memcpy(pub0.key, dev1->peers.entries[i].public_key, WG_KEY_LEN);
            found = true;
            break;
        }
    }
    assert(found);

    churn_ctx_t c = {.pair = &pair};
    atomic_init(&c.stop, false);
    pthread_t t01, t10, trk;
    assert(pthread_create(&t01, NULL, churn_send_01, &c) == 0);
    assert(pthread_create(&t10, NULL, churn_send_10, &c) == 0);
    assert(pthread_create(&trk, NULL, churn_rekey, &c) == 0);

    for (int round = 0; round < 20; round++) {
        sleep_us(2000 + (round % 5) * 3000);
        assert(wg_device_remove_peer(dev1, &pub0) == WG_OK);
        readd_peer(&pair, &pub0);
    }

    atomic_store(&c.stop, true);
    pthread_join(t01, NULL);
    pthread_join(t10, NULL);
    pthread_join(trk, NULL);

    /* No check that traffic flows again here: after the churn both sides
     * may take several REKEY_TIMEOUT retries to agree on a session, and
     * test_remove_and_readd_peer covers re-adding. This test is for
     * ASan/TSan: no peer used after it is freed, no deadlock. */
    teardown_pair(&pair);
    printf("PASS\n");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_device_ping_pong ===\n");

    test_ping();
    test_pong();
    test_ping_pong();
    test_bulk_transfer();
    test_ip_length();
    test_ip_length_overrun_dropped();
    test_remove_and_readd_peer();
    test_remove_peer_under_traffic();
    test_close_joins_tun_reader_first();

    printf("All device ping-pong tests passed.\n");
    return 0;
}

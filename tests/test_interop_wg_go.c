/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TEST-2: wireguard-go interoperability test.
 *
 * Linux only. Creates two network namespaces connected by a veth pair:
 *   NS_WGC:  wg-c device (in-process, real TUN + StdBind)
 *   NS_WGGO: wireguard-go process, configured via `wg` command
 *
 * Verifies:
 *   1. wg-c (initiator) -> wireguard-go (responder): ping
 *   2. wireguard-go (initiator) -> wg-c (responder): ping
 *   3. Bidirectional data transfer
 *   4. PSK-enabled handshake
 *   5. Traffic counters
 *
 * Requires: root, wireguard-go binary, wg tool (wireguard-tools).
 *
 * Reference: issue #60
 */

#ifdef __linux__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../src/bind/wg_bind_std.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_linux.h"
#include "../src/workers/wg_workers.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ────────────────────────────────────────
 * Constants
 * ──────────────────────────────────────── */

#define NS_WGC    "interop_wgc"
#define NS_WGGO   "interop_wggo"
#define VETH_WGC  "veth_wgc"
#define VETH_WGGO "veth_wggo"

#define VETH_IP_WGC  "192.168.251.1/24"
#define VETH_IP_WGGO "192.168.251.2/24"

#define WG_IP_WGC    "10.100.0.1"
#define WG_IP_WGGO   "10.100.0.2"
#define WG_CIDR_WGC  "10.100.0.1/24"
#define WG_CIDR_WGGO "10.100.0.2/24"

#define PORT_WGC  51820
#define PORT_WGGO 51821

#define PASS(name) printf("  PASS: %s\n", (name))
#define FAIL(name)                      \
    do {                                \
        printf("  FAIL: %s\n", (name)); \
        failures++;                     \
    } while (0)

static int failures = 0;
static pid_t wggo_pid = 0;

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static void skip(const char *reason)
{
    printf("SKIP: %s\n", reason);
    exit(0);
}

static int run(const char *cmd)
{
    int rc = system(cmd);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static int run_quiet(const char *cmd)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%s >/dev/null 2>&1", cmd);
    return run(buf);
}

static void check_prerequisites(void)
{
    if (getuid() != 0)
        skip("not root (need CAP_NET_ADMIN for netns + TUN)");
    if (run_quiet("which wireguard-go") != 0)
        skip("wireguard-go not found in PATH");
    if (run_quiet("which wg") != 0)
        skip("wg (wireguard-tools) not found in PATH");
}

/* ────────────────────────────────────────
 * Key encoding helpers
 * ──────────────────────────────────────── */

static void key_to_base64(const uint8_t key[32], char out[45])
{
    /* WireGuard uses standard base64 (not URL-safe) */
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    for (i = 0; i < 30; i += 3) {
        uint32_t v =
            ((uint32_t)key[i] << 16) | ((uint32_t)key[i + 1] << 8) | (uint32_t)key[i + 2];
        out[j++] = b64[(v >> 18) & 0x3F];
        out[j++] = b64[(v >> 12) & 0x3F];
        out[j++] = b64[(v >> 6) & 0x3F];
        out[j++] = b64[v & 0x3F];
    }
    /* Last 2 bytes */
    uint32_t v = ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 8);
    out[j++] = b64[(v >> 18) & 0x3F];
    out[j++] = b64[(v >> 12) & 0x3F];
    out[j++] = b64[(v >> 6) & 0x3F];
    out[j++] = '=';
    out[j] = '\0';
}

/* ────────────────────────────────────────
 * Network namespace helpers
 * ──────────────────────────────────────── */

static void cleanup_ns(void)
{
    /* Kill wireguard-go if still running */
    if (wggo_pid > 0) {
        kill(wggo_pid, SIGTERM);
        waitpid(wggo_pid, NULL, 0);
        wggo_pid = 0;
    }
    run_quiet("ip netns exec " NS_WGGO " killall wireguard-go");
    run("ip netns del " NS_WGC " 2>/dev/null");
    run("ip netns del " NS_WGGO " 2>/dev/null");
}

static int enter_netns(const char *name)
{
    int orig = open("/proc/self/ns/net", O_RDONLY);
    assert(orig >= 0);

    char path[256];
    snprintf(path, sizeof(path), "/var/run/netns/%s", name);
    int ns_fd = open(path, O_RDONLY);
    assert(ns_fd >= 0);
    assert(setns(ns_fd, CLONE_NEWNET) == 0);
    close(ns_fd);

    return orig;
}

static void restore_netns(int orig_fd)
{
    assert(setns(orig_fd, CLONE_NEWNET) == 0);
    close(orig_fd);
}

static void setup_netns(void)
{
    cleanup_ns();

    assert(run("ip netns add " NS_WGC) == 0);
    assert(run("ip netns add " NS_WGGO) == 0);

    assert(run("ip link add " VETH_WGC " type veth peer name " VETH_WGGO) == 0);
    assert(run("ip link set " VETH_WGC " netns " NS_WGC) == 0);
    assert(run("ip link set " VETH_WGGO " netns " NS_WGGO) == 0);

    assert(run("ip netns exec " NS_WGC " ip addr add " VETH_IP_WGC " dev " VETH_WGC) ==
           0);
    assert(run("ip netns exec " NS_WGC " ip link set " VETH_WGC " up") == 0);
    assert(run("ip netns exec " NS_WGC " ip link set lo up") == 0);

    assert(run("ip netns exec " NS_WGGO " ip addr add " VETH_IP_WGGO " dev " VETH_WGGO) ==
           0);
    assert(run("ip netns exec " NS_WGGO " ip link set " VETH_WGGO " up") == 0);
    assert(run("ip netns exec " NS_WGGO " ip link set lo up") == 0);
}

/* ────────────────────────────────────────
 * Start wireguard-go in NS_WGGO
 * ──────────────────────────────────────── */

static void start_wireguard_go(void)
{
    /* wireguard-go creates its own TUN device */
    assert(run("ip netns exec " NS_WGGO " wireguard-go wggo0") == 0);

    /* Give it a moment to create the UAPI socket */
    usleep(500000);
}

static void configure_wireguard_go(const uint8_t priv_wggo[32], const uint8_t pub_wgc[32],
                                   const uint8_t *psk)
{
    char priv_b64[45], pub_b64[45];
    key_to_base64(priv_wggo, priv_b64);
    key_to_base64(pub_wgc, pub_b64);

    char cmd[1024];

    /* Set private key and listen port */
    snprintf(cmd, sizeof(cmd),
             "ip netns exec " NS_WGGO
             " wg set wggo0 private-key <(echo '%s') listen-port %d",
             priv_b64, PORT_WGGO);
    /* wg set doesn't support process substitution, use a temp file */
    snprintf(cmd, sizeof(cmd),
             "ip netns exec " NS_WGGO
             " bash -c 'echo %s | wg set wggo0 private-key /dev/stdin listen-port %d'",
             priv_b64, PORT_WGGO);
    assert(run(cmd) == 0);

    /* Add peer (wg-c) */
    if (psk) {
        char psk_b64[45];
        key_to_base64(psk, psk_b64);
        snprintf(cmd, sizeof(cmd),
                 "ip netns exec " NS_WGGO " bash -c 'echo %s | wg set wggo0"
                 " peer %s"
                 " preshared-key /dev/stdin"
                 " endpoint 192.168.251.1:%d"
                 " allowed-ips %s'",
                 psk_b64, pub_b64, PORT_WGC, WG_CIDR_WGC);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "ip netns exec " NS_WGGO " wg set wggo0"
                 " peer %s"
                 " endpoint 192.168.251.1:%d"
                 " allowed-ips %s",
                 pub_b64, PORT_WGC, WG_CIDR_WGC);
    }
    assert(run(cmd) == 0);

    /* Assign IP and bring interface up */
    assert(run("ip netns exec " NS_WGGO " ip addr add " WG_CIDR_WGGO " dev wggo0") == 0);
    assert(run("ip netns exec " NS_WGGO " ip link set wggo0 up") == 0);
}

/* ────────────────────────────────────────
 * wg-c device context (in-process)
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_tun_linux_t *tun;
    wg_std_bind_t *bind;
    wg_peer_t *peer;
} wgc_ctx_t;

static void wgc_create(wgc_ctx_t *ctx, const uint8_t priv_wgc[32],
                       const uint8_t pub_wggo[32], const uint8_t *psk)
{
    int orig = enter_netns(NS_WGC);
    wg_error_t err;

    err = wg_tun_linux_create(&ctx->tun, "wgc0", WG_DEFAULT_MTU);
    if (err != WG_OK) {
        fprintf(stderr, "TUN create failed: %s\n", wg_error_str(err));
        restore_netns(orig);
        assert(0);
    }

    err = wg_std_bind_new(&ctx->bind);
    assert(err == WG_OK);

    wg_tun_ops_t tun_ops = wg_tun_linux_ops(ctx->tun);
    wg_bind_ops_t bind_ops = wg_std_bind_ops(ctx->bind);

    err = wg_device_new(&ctx->dev, &tun_ops, &bind_ops, NULL);
    assert(err == WG_OK);

    /* Set private key */
    wg_key_t priv_key;
    memcpy(priv_key.key, priv_wgc, 32);
    err = wg_device_set_private_key(ctx->dev, &priv_key);
    assert(err == WG_OK);

    /* Set port and bring up */
    ctx->dev->net.port = PORT_WGC;
    err = wg_device_up(ctx->dev);
    assert(err == WG_OK);

    /* Add peer (wireguard-go) */
    ctx->peer = NULL;
    err = wg_peer_new(ctx->dev, pub_wggo, psk, &ctx->peer);
    assert(err == WG_OK);

    /* Endpoint: wireguard-go's veth IP + listen port */
    wg_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.addr.sa4.sin_family = AF_INET;
    ep.addr.sa4.sin_port = htons(PORT_WGGO);
    inet_pton(AF_INET, "192.168.251.2", &ep.addr.sa4.sin_addr);
    err = wg_peer_set_endpoint(ctx->peer, &ep);
    assert(err == WG_OK);

    /* Allowed IP: wireguard-go's overlay IP */
    uint32_t allowed;
    inet_pton(AF_INET, WG_IP_WGGO, &allowed);
    err = wg_peer_add_allowed_ip(ctx->peer, &allowed, 32, AF_INET);
    assert(err == WG_OK);

    wg_peer_start(ctx->peer);

    restore_netns(orig);

    /* Assign overlay IP and bring TUN up */
    assert(run("ip netns exec " NS_WGC " ip addr add " WG_CIDR_WGC " dev wgc0") == 0);
    assert(run("ip netns exec " NS_WGC " ip link set wgc0 up") == 0);
}

static void wgc_destroy(wgc_ctx_t *ctx)
{
    if (ctx->dev)
        wg_device_close(ctx->dev);
    if (ctx->bind)
        wg_std_bind_destroy(ctx->bind);
}

/* ────────────────────────────────────────
 * Test 1: wg-c initiator -> wireguard-go responder
 *
 * wg-c sends ping to wireguard-go's overlay IP.
 * ──────────────────────────────────────── */

static void test_wgc_initiator(void)
{
    printf("\n--- Test: wg-c (initiator) -> wireguard-go (responder) ---\n");

    /* Generate keys */
    uint8_t priv_wgc[32], pub_wgc[32];
    uint8_t priv_wggo[32], pub_wggo[32];
    crypto_box_keypair(pub_wgc, priv_wgc);
    crypto_box_keypair(pub_wggo, priv_wggo);

    setup_netns();
    start_wireguard_go();
    configure_wireguard_go(priv_wggo, pub_wgc, NULL);

    wgc_ctx_t wgc;
    wgc_create(&wgc, priv_wgc, pub_wggo, NULL);

    /* Ping from wg-c -> wireguard-go */
    if (run("ip netns exec " NS_WGC " ping -c 3 -W 5 " WG_IP_WGGO " >/dev/null 2>&1") ==
        0)
        PASS("wg-c -> wireguard-go ping");
    else
        FAIL("wg-c -> wireguard-go ping");

    /* Verify handshake completed on wg-c side */
    int64_t hs = atomic_load(&wgc.peer->last_handshake_ns);
    if (hs > 0)
        PASS("handshake timestamp set (wg-c)");
    else
        FAIL("handshake timestamp set (wg-c)");

    /* Verify traffic counters */
    uint64_t tx = atomic_load(&wgc.peer->tx_bytes);
    uint64_t rx = atomic_load(&wgc.peer->rx_bytes);
    if (tx > 0 && rx > 0)
        printf("  PASS: traffic counters (tx=%llu rx=%llu)\n", (unsigned long long)tx,
               (unsigned long long)rx);
    else
        FAIL("traffic counters");

    /* Verify wireguard-go sees the peer via `wg show` */
    if (run("ip netns exec " NS_WGGO " wg show wggo0 | grep -q 'latest handshake'") == 0)
        PASS("wireguard-go handshake verified via wg show");
    else
        FAIL("wireguard-go handshake verified via wg show");

    wgc_destroy(&wgc);
    cleanup_ns();
}

/* ────────────────────────────────────────
 * Test 2: wireguard-go initiator -> wg-c responder
 *
 * wireguard-go pings wg-c's overlay IP, triggering
 * wireguard-go to initiate the handshake.
 * ──────────────────────────────────────── */

static void test_wggo_initiator(void)
{
    printf("\n--- Test: wireguard-go (initiator) -> wg-c (responder) ---\n");

    uint8_t priv_wgc[32], pub_wgc[32];
    uint8_t priv_wggo[32], pub_wggo[32];
    crypto_box_keypair(pub_wgc, priv_wgc);
    crypto_box_keypair(pub_wggo, priv_wggo);

    setup_netns();
    start_wireguard_go();
    configure_wireguard_go(priv_wggo, pub_wgc, NULL);

    wgc_ctx_t wgc;
    wgc_create(&wgc, priv_wgc, pub_wggo, NULL);

    /* Ping from wireguard-go -> wg-c (wireguard-go initiates) */
    if (run("ip netns exec " NS_WGGO " ping -c 3 -W 5 " WG_IP_WGC " >/dev/null 2>&1") ==
        0)
        PASS("wireguard-go -> wg-c ping");
    else
        FAIL("wireguard-go -> wg-c ping");

    /* Verify handshake on wg-c side */
    int64_t hs = atomic_load(&wgc.peer->last_handshake_ns);
    if (hs > 0)
        PASS("handshake timestamp set (wg-c responder)");
    else
        FAIL("handshake timestamp set (wg-c responder)");

    wgc_destroy(&wgc);
    cleanup_ns();
}

/* ────────────────────────────────────────
 * Test 3: Bidirectional data transfer
 * ──────────────────────────────────────── */

static void test_bidirectional(void)
{
    printf("\n--- Test: Bidirectional data transfer ---\n");

    uint8_t priv_wgc[32], pub_wgc[32];
    uint8_t priv_wggo[32], pub_wggo[32];
    crypto_box_keypair(pub_wgc, priv_wgc);
    crypto_box_keypair(pub_wggo, priv_wggo);

    setup_netns();
    start_wireguard_go();
    configure_wireguard_go(priv_wggo, pub_wgc, NULL);

    wgc_ctx_t wgc;
    wgc_create(&wgc, priv_wgc, pub_wggo, NULL);

    /* wg-c -> wireguard-go */
    if (run("ip netns exec " NS_WGC " ping -c 5 -W 5 " WG_IP_WGGO " >/dev/null 2>&1") ==
        0)
        PASS("wg-c -> wireguard-go (5 pings)");
    else
        FAIL("wg-c -> wireguard-go (5 pings)");

    /* wireguard-go -> wg-c */
    if (run("ip netns exec " NS_WGGO " ping -c 5 -W 5 " WG_IP_WGC " >/dev/null 2>&1") ==
        0)
        PASS("wireguard-go -> wg-c (5 pings)");
    else
        FAIL("wireguard-go -> wg-c (5 pings)");

    /* Check traffic counters show bidirectional traffic */
    uint64_t tx = atomic_load(&wgc.peer->tx_bytes);
    uint64_t rx = atomic_load(&wgc.peer->rx_bytes);
    if (tx > 200 && rx > 200)
        printf("  PASS: bidirectional traffic counters (tx=%llu rx=%llu)\n",
               (unsigned long long)tx, (unsigned long long)rx);
    else
        FAIL("bidirectional traffic counters");

    wgc_destroy(&wgc);
    cleanup_ns();
}

/* ────────────────────────────────────────
 * Test 4: PSK-enabled handshake
 * ──────────────────────────────────────── */

static void test_psk_handshake(void)
{
    printf("\n--- Test: PSK-enabled handshake ---\n");

    uint8_t priv_wgc[32], pub_wgc[32];
    uint8_t priv_wggo[32], pub_wggo[32];
    uint8_t psk[32];
    crypto_box_keypair(pub_wgc, priv_wgc);
    crypto_box_keypair(pub_wggo, priv_wggo);
    randombytes_buf(psk, 32);

    setup_netns();
    start_wireguard_go();
    configure_wireguard_go(priv_wggo, pub_wgc, psk);

    wgc_ctx_t wgc;
    wgc_create(&wgc, priv_wgc, pub_wggo, psk);

    /* Ping with PSK */
    if (run("ip netns exec " NS_WGC " ping -c 3 -W 5 " WG_IP_WGGO " >/dev/null 2>&1") ==
        0)
        PASS("PSK handshake + ping (wg-c -> wireguard-go)");
    else
        FAIL("PSK handshake + ping (wg-c -> wireguard-go)");

    /* Reverse direction */
    if (run("ip netns exec " NS_WGGO " ping -c 3 -W 5 " WG_IP_WGC " >/dev/null 2>&1") ==
        0)
        PASS("PSK handshake + ping (wireguard-go -> wg-c)");
    else
        FAIL("PSK handshake + ping (wireguard-go -> wg-c)");

    /* Verify handshake */
    int64_t hs = atomic_load(&wgc.peer->last_handshake_ns);
    if (hs > 0)
        PASS("PSK handshake timestamp set");
    else
        FAIL("PSK handshake timestamp set");

    wgc_destroy(&wgc);
    cleanup_ns();
}

/* ────────────────────────────────────────
 * Test 5: Keepalive
 * ──────────────────────────────────────── */

static void test_keepalive(void)
{
    printf("\n--- Test: Persistent keepalive ---\n");

    uint8_t priv_wgc[32], pub_wgc[32];
    uint8_t priv_wggo[32], pub_wggo[32];
    crypto_box_keypair(pub_wgc, priv_wgc);
    crypto_box_keypair(pub_wggo, priv_wggo);

    setup_netns();
    start_wireguard_go();
    configure_wireguard_go(priv_wggo, pub_wgc, NULL);

    wgc_ctx_t wgc;
    wgc_create(&wgc, priv_wgc, pub_wggo, NULL);

    /* Set persistent keepalive on wg-c side */
    wg_error_t err = wg_peer_set_persistent_keepalive(wgc.peer, 1);
    assert(err == WG_OK);

    /* Wait for keepalive to trigger handshake (2 seconds should be enough) */
    sleep(3);

    /* Verify handshake happened via keepalive */
    int64_t hs = atomic_load(&wgc.peer->last_handshake_ns);
    if (hs > 0)
        PASS("keepalive triggered handshake");
    else
        FAIL("keepalive triggered handshake");

    /* Verify wireguard-go sees the keepalive */
    if (run("ip netns exec " NS_WGGO " wg show wggo0 | grep -q 'latest handshake'") == 0)
        PASS("wireguard-go received keepalive");
    else
        FAIL("wireguard-go received keepalive");

    /* Now ping should work without additional handshake */
    if (run("ip netns exec " NS_WGC " ping -c 1 -W 3 " WG_IP_WGGO " >/dev/null 2>&1") ==
        0)
        PASS("ping after keepalive handshake");
    else
        FAIL("ping after keepalive handshake");

    wgc_destroy(&wgc);
    cleanup_ns();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    check_prerequisites();

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_interop_wg_go (Linux: wg-c <-> wireguard-go) ===\n");

    test_wgc_initiator();
    test_wggo_initiator();
    test_bidirectional();
    test_psk_handshake();
    test_keepalive();

    printf("\n");
    if (failures > 0) {
        printf("FAILED: %d test(s)\n", failures);
        return 1;
    }
    printf("All interop tests passed.\n");
    return 0;
}

#else /* !__linux__ */

#include <stdio.h>

int main(void)
{
    printf("SKIP: test_interop_wg_go requires Linux\n");
    return 0;
}

#endif

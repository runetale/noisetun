/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Real-environment handshake test using real TUN + StdNetBind (UDP).
 *
 * Linux:  Two network namespaces connected by a veth pair, each with a
 *         real TUN device and real UDP sockets.
 * macOS:  Two utun devices on the same host, StdNetBind on loopback.
 *
 * Verifies that the Noise IKpsk2 handshake completes and data transits.
 *
 * Requires: root (CAP_NET_ADMIN on Linux, utun on macOS).
 */

#ifdef __linux__
/* ════════════════════════════════════════
 * Linux implementation
 * ════════════════════════════════════════ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../src/bind/wg_bind_std.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_linux.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define NS_A   "hs_test_a"
#define NS_B   "hs_test_b"
#define VETH_A "veth_hsa"
#define VETH_B "veth_hsb"

#define VETH_IP_A "192.168.250.1/24"
#define VETH_IP_B "192.168.250.2/24"

#define WG_IP_A   "10.99.0.1/24"
#define WG_IP_B   "10.99.0.2/24"
#define WG_ADDR_A "10.99.0.1"
#define WG_ADDR_B "10.99.0.2"

#define PORT_A 54120
#define PORT_B 54121

#define PASS(name) printf("  PASS: %s\n", (name))
#define FAIL(name)                      \
    do {                                \
        printf("  FAIL: %s\n", (name)); \
        failures++;                     \
    } while (0)

static int failures = 0;

static void skip(const char *reason)
{
    printf("SKIP: %s\n", reason);
    exit(0);
}

static void check_root(void)
{
    if (getuid() != 0)
        skip("not root (need CAP_NET_ADMIN for netns + TUN)");
}

static int run(const char *cmd)
{
    int rc = system(cmd);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static void cleanup_ns(void)
{
    run("ip netns del " NS_A " 2>/dev/null");
    run("ip netns del " NS_B " 2>/dev/null");
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

    assert(run("ip netns add " NS_A) == 0);
    assert(run("ip netns add " NS_B) == 0);

    assert(run("ip link add " VETH_A " type veth peer name " VETH_B) == 0);
    assert(run("ip link set " VETH_A " netns " NS_A) == 0);
    assert(run("ip link set " VETH_B " netns " NS_B) == 0);

    assert(run("ip netns exec " NS_A " ip addr add " VETH_IP_A " dev " VETH_A) == 0);
    assert(run("ip netns exec " NS_A " ip link set " VETH_A " up") == 0);
    assert(run("ip netns exec " NS_A " ip link set lo up") == 0);

    assert(run("ip netns exec " NS_B " ip addr add " VETH_IP_B " dev " VETH_B) == 0);
    assert(run("ip netns exec " NS_B " ip link set " VETH_B " up") == 0);
    assert(run("ip netns exec " NS_B " ip link set lo up") == 0);
}

typedef struct {
    wg_device_t *dev;
    wg_tun_linux_t *tun;
    wg_std_bind_t *bind;
    const char *ns_name;
    const char *iface_name;
} dev_ctx_t;

static void dev_ctx_create(dev_ctx_t *ctx, const char *ns, const char *iface)
{
    ctx->ns_name = ns;
    ctx->iface_name = iface;

    int orig = enter_netns(ns);
    wg_error_t err;

    err = wg_tun_linux_create(&ctx->tun, iface, WG_DEFAULT_MTU);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create TUN '%s' in %s: %s\n", iface, ns,
                wg_error_str(err));
        restore_netns(orig);
        assert(0);
    }

    err = wg_std_bind_new(&ctx->bind);
    assert(err == WG_OK);

    wg_tun_ops_t tun_ops = wg_tun_linux_ops(ctx->tun);
    wg_bind_ops_t bind_ops = wg_std_bind_ops(ctx->bind);

    err = wg_device_new(&ctx->dev, &tun_ops, &bind_ops, NULL);
    assert(err == WG_OK);

    restore_netns(orig);
}

static void dev_ctx_up(dev_ctx_t *ctx)
{
    int orig = enter_netns(ctx->ns_name);
    wg_error_t err = wg_device_up(ctx->dev);
    assert(err == WG_OK);
    restore_netns(orig);
}

static void dev_ctx_set_port(dev_ctx_t *ctx, uint16_t port)
{
    int orig = enter_netns(ctx->ns_name);
    pthread_rwlock_wrlock(&ctx->dev->net.lock);
    ctx->dev->net.port = port;
    if (wg_device_is_up(ctx->dev))
        wg_device_bind_update(ctx->dev);
    pthread_rwlock_unlock(&ctx->dev->net.lock);
    restore_netns(orig);
}

static void dev_ctx_destroy(dev_ctx_t *ctx)
{
    if (ctx->dev)
        wg_device_close(ctx->dev);
    if (ctx->bind)
        wg_std_bind_destroy(ctx->bind);
}

static void test_handshake_and_ping(void)
{
    dev_ctx_t a, b;

    dev_ctx_create(&a, NS_A, "wg0");
    dev_ctx_create(&b, NS_B, "wg1");

    wg_key_t priv_a, pub_a, priv_b, pub_b;
    crypto_box_keypair(pub_a.key, priv_a.key);
    crypto_box_keypair(pub_b.key, priv_b.key);

    assert(wg_device_set_private_key(a.dev, &priv_a) == WG_OK);
    assert(wg_device_set_private_key(b.dev, &priv_b) == WG_OK);

    dev_ctx_up(&a);
    dev_ctx_up(&b);
    dev_ctx_set_port(&a, PORT_A);
    dev_ctx_set_port(&b, PORT_B);

    /* Peer A->B */
    wg_peer_t *peer_a_to_b = NULL;
    assert(wg_peer_new(a.dev, pub_b.key, NULL, &peer_a_to_b) == WG_OK);

    wg_endpoint_t ep_b;
    memset(&ep_b, 0, sizeof(ep_b));
    ep_b.addr.sa4.sin_family = AF_INET;
    ep_b.addr.sa4.sin_port = htons(PORT_B);
    inet_pton(AF_INET, "192.168.250.2", &ep_b.addr.sa4.sin_addr);
    assert(wg_peer_set_endpoint(peer_a_to_b, &ep_b) == WG_OK);

    uint32_t allowed_b;
    inet_pton(AF_INET, WG_ADDR_B, &allowed_b);
    assert(wg_peer_add_allowed_ip(peer_a_to_b, &allowed_b, 32, AF_INET) == WG_OK);
    wg_peer_start(peer_a_to_b);

    /* Peer B->A */
    wg_peer_t *peer_b_to_a = NULL;
    assert(wg_peer_new(b.dev, pub_a.key, NULL, &peer_b_to_a) == WG_OK);

    wg_endpoint_t ep_a;
    memset(&ep_a, 0, sizeof(ep_a));
    ep_a.addr.sa4.sin_family = AF_INET;
    ep_a.addr.sa4.sin_port = htons(PORT_A);
    inet_pton(AF_INET, "192.168.250.1", &ep_a.addr.sa4.sin_addr);
    assert(wg_peer_set_endpoint(peer_b_to_a, &ep_a) == WG_OK);

    uint32_t allowed_a;
    inet_pton(AF_INET, WG_ADDR_A, &allowed_a);
    assert(wg_peer_add_allowed_ip(peer_b_to_a, &allowed_a, 32, AF_INET) == WG_OK);
    wg_peer_start(peer_b_to_a);

    /* Overlay IPs */
    assert(run("ip netns exec " NS_A " ip addr add " WG_IP_A " dev wg0") == 0);
    assert(run("ip netns exec " NS_A " ip link set wg0 up") == 0);
    assert(run("ip netns exec " NS_B " ip addr add " WG_IP_B " dev wg1") == 0);
    assert(run("ip netns exec " NS_B " ip link set wg1 up") == 0);

    /* Test 1: A -> B ping */
    if (run("ip netns exec " NS_A " ping -c 3 -W 5 " WG_ADDR_B " >/dev/null 2>&1") == 0)
        PASS("A -> B ping (handshake + data)");
    else
        FAIL("A -> B ping");

    /* Test 2: B -> A ping */
    if (run("ip netns exec " NS_B " ping -c 3 -W 5 " WG_ADDR_A " >/dev/null 2>&1") == 0)
        PASS("B -> A ping");
    else
        FAIL("B -> A ping");

    /* Test 3: handshake timestamp A */
    int64_t hs_ns = atomic_load(&peer_a_to_b->last_handshake_ns);
    if (hs_ns > 0)
        PASS("handshake timestamp set (A)");
    else
        FAIL("handshake timestamp set (A)");

    /* Test 4: traffic counters */
    uint64_t tx = atomic_load(&peer_a_to_b->tx_bytes);
    uint64_t rx = atomic_load(&peer_a_to_b->rx_bytes);
    if (tx > 0 && rx > 0) {
        printf("  PASS: traffic counters (A: tx=%llu rx=%llu)\n", (unsigned long long)tx,
               (unsigned long long)rx);
    } else
        FAIL("traffic counters (A)");

    /* Test 5: handshake timestamp B */
    hs_ns = atomic_load(&peer_b_to_a->last_handshake_ns);
    if (hs_ns > 0)
        PASS("handshake timestamp set (B)");
    else
        FAIL("handshake timestamp set (B)");

    dev_ctx_destroy(&a);
    dev_ctx_destroy(&b);
}

int main(void)
{
    check_root();

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_handshake_real (Linux: TUN + UDP + netns) ===\n");

    setup_netns();
    test_handshake_and_ping();
    cleanup_ns();

    printf("\n");
    if (failures > 0) {
        printf("FAILED: %d test(s)\n", failures);
        return 1;
    }
    printf("All real handshake tests passed.\n");
    return 0;
}

#elif defined(__APPLE__)
/* ════════════════════════════════════════
 * macOS implementation
 * ════════════════════════════════════════ */

#include "../src/bind/wg_bind_std.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_peer.h"
#include "../src/tun/wg_tun_darwin.h"
#include "../src/workers/wg_workers.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WG_ADDR_A "10.99.0.1"
#define WG_ADDR_B "10.99.0.2"

#define PORT_A 54120
#define PORT_B 54121

#define PASS(name) printf("  PASS: %s\n", (name))
#define FAIL(name)                      \
    do {                                \
        printf("  FAIL: %s\n", (name)); \
        failures++;                     \
    } while (0)

static int failures = 0;

static void skip(const char *reason)
{
    printf("SKIP: %s\n", reason);
    exit(0);
}

static void check_root(void)
{
    if (getuid() != 0)
        skip("not root (need privileges for utun)");
}

static int run(const char *cmd)
{
    int rc = system(cmd);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* ────────────────────────────────────────
 * Device context
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_tun_darwin_t *tun;
    wg_std_bind_t *bind;
    const char *tun_name;
} dev_ctx_t;

static void dev_ctx_create(dev_ctx_t *ctx)
{
    wg_error_t err;

    err = wg_tun_darwin_create(&ctx->tun, "utun", WG_DEFAULT_MTU);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create utun: %s\n", wg_error_str(err));
        skip("utun creation failed (check root/entitlements)");
    }

    wg_tun_ops_t tun_ops = wg_tun_darwin_ops(ctx->tun);
    ctx->tun_name = tun_ops.name(tun_ops.ctx);

    err = wg_std_bind_new(&ctx->bind);
    assert(err == WG_OK);

    wg_bind_ops_t bind_ops = wg_std_bind_ops(ctx->bind);

    err = wg_device_new(&ctx->dev, &tun_ops, &bind_ops, NULL);
    assert(err == WG_OK);
}

static void dev_ctx_set_port_and_up(dev_ctx_t *ctx, uint16_t port)
{
    /* Set port BEFORE device_up so the bind opens on the right port
     * immediately, avoiding bind_update (which joins the recv thread
     * and can deadlock on macOS). */
    ctx->dev->net.port = port;
    wg_error_t err = wg_device_up(ctx->dev);
    assert(err == WG_OK);
}

static void dev_ctx_destroy(dev_ctx_t *ctx)
{
    if (ctx->dev)
        wg_device_close(ctx->dev);
    if (ctx->bind)
        wg_std_bind_destroy(ctx->bind);
}

/* ────────────────────────────────────────
 * Test
 *
 * macOS has no network namespaces, so two utun on the same host
 * cannot be connected via ping (the kernel delivers locally without
 * entering the tunnel). Instead we:
 *   1. Set persistent_keepalive on peer A→B (triggers handshake + keepalive)
 *   2. Poll until the handshake completes on both sides
 *   3. Verify timestamps and traffic counters (handshake packets)
 *
 * This validates: real utun creation, real UDP sockets on loopback,
 * full Noise IKpsk2 handshake, and bidirectional encrypted traffic.
 * ──────────────────────────────────────── */

static void test_handshake(void)
{
    dev_ctx_t a, b;

    dev_ctx_create(&a);
    dev_ctx_create(&b);

    printf("  Device A: %s\n", a.tun_name);
    printf("  Device B: %s\n", b.tun_name);
    fflush(stdout);

    wg_key_t priv_a, pub_a, priv_b, pub_b;
    crypto_box_keypair(pub_a.key, priv_a.key);
    crypto_box_keypair(pub_b.key, priv_b.key);

    assert(wg_device_set_private_key(a.dev, &priv_a) == WG_OK);
    assert(wg_device_set_private_key(b.dev, &priv_b) == WG_OK);
    /* Set port and bring up in one step (avoids bind_update which
     * deadlocks on macOS when joining the recv thread). */
    dev_ctx_set_port_and_up(&a, PORT_A);
    dev_ctx_set_port_and_up(&b, PORT_B);

    /* Peer A->B: endpoint = 127.0.0.1:PORT_B */
    wg_peer_t *peer_a_to_b = NULL;
    assert(wg_peer_new(a.dev, pub_b.key, NULL, &peer_a_to_b) == WG_OK);

    wg_endpoint_t ep_b;
    memset(&ep_b, 0, sizeof(ep_b));
    ep_b.addr.sa4.sin_family = AF_INET;
    ep_b.addr.sa4.sin_port = htons(PORT_B);
    ep_b.addr.sa4.sin_len = sizeof(struct sockaddr_in);
    inet_pton(AF_INET, "127.0.0.1", &ep_b.addr.sa4.sin_addr);
    assert(wg_peer_set_endpoint(peer_a_to_b, &ep_b) == WG_OK);

    uint32_t allowed_b;
    inet_pton(AF_INET, WG_ADDR_B, &allowed_b);
    assert(wg_peer_add_allowed_ip(peer_a_to_b, &allowed_b, 32, AF_INET) == WG_OK);

    wg_peer_start(peer_a_to_b);

    /* Peer B->A: endpoint = 127.0.0.1:PORT_A */
    wg_peer_t *peer_b_to_a = NULL;
    assert(wg_peer_new(b.dev, pub_a.key, NULL, &peer_b_to_a) == WG_OK);

    wg_endpoint_t ep_a;
    memset(&ep_a, 0, sizeof(ep_a));
    ep_a.addr.sa4.sin_family = AF_INET;
    ep_a.addr.sa4.sin_port = htons(PORT_A);
    ep_a.addr.sa4.sin_len = sizeof(struct sockaddr_in);
    inet_pton(AF_INET, "127.0.0.1", &ep_a.addr.sa4.sin_addr);
    assert(wg_peer_set_endpoint(peer_b_to_a, &ep_a) == WG_OK);

    uint32_t allowed_a;
    inet_pton(AF_INET, WG_ADDR_A, &allowed_a);
    assert(wg_peer_add_allowed_ip(peer_b_to_a, &allowed_a, 32, AF_INET) == WG_OK);
    wg_peer_start(peer_b_to_a);

    /* Explicitly trigger handshake from A→B.
     * This sends a Handshake Initiation via real UDP on loopback. */
    wg_send_handshake_initiation(peer_a_to_b, false);

    /* Wait for handshake to complete (poll with timeout) */
    printf("  Waiting for handshake...\n");
    int64_t hs_a = 0, hs_b = 0;
    for (int i = 0; i < 100; i++) { /* up to 10 seconds */
        usleep(100000);             /* 100ms */
        hs_a = atomic_load(&peer_a_to_b->last_handshake_ns);
        hs_b = atomic_load(&peer_b_to_a->last_handshake_ns);
        if (hs_a > 0 && hs_b > 0)
            break;
    }

    /* Test 1: handshake completed on A */
    if (hs_a > 0)
        PASS("handshake completed (A)");
    else
        FAIL("handshake completed (A)");

    /* Test 2: handshake completed on B */
    if (hs_b > 0)
        PASS("handshake completed (B)");
    else
        FAIL("handshake completed (B)");

    /* Test 3: traffic counters on A (handshake packets) */
    uint64_t tx_a = atomic_load(&peer_a_to_b->tx_bytes);
    uint64_t rx_a = atomic_load(&peer_a_to_b->rx_bytes);
    if (tx_a > 0) {
        printf("  PASS: traffic counters (A: tx=%llu rx=%llu)\n",
               (unsigned long long)tx_a, (unsigned long long)rx_a);
    } else
        FAIL("traffic counters (A)");

    /* Test 4: traffic counters on B */
    uint64_t tx_b = atomic_load(&peer_b_to_a->tx_bytes);
    uint64_t rx_b = atomic_load(&peer_b_to_a->rx_bytes);
    if (rx_b > 0) {
        printf("  PASS: traffic counters (B: tx=%llu rx=%llu)\n",
               (unsigned long long)tx_b, (unsigned long long)rx_b);
    } else
        FAIL("traffic counters (B)");

    dev_ctx_destroy(&a);
    dev_ctx_destroy(&b);
}

int main(void)
{
    check_root();

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_handshake_real (macOS: utun + UDP + loopback) ===\n");

    test_handshake();

    printf("\n");
    if (failures > 0) {
        printf("FAILED: %d test(s)\n", failures);
        return 1;
    }
    printf("All real handshake tests passed.\n");
    return 0;
}

#else
/* ════════════════════════════════════════
 * Unsupported platforms
 * ════════════════════════════════════════ */

#include <stdio.h>

int main(void)
{
    printf("SKIP: test_handshake_real requires Linux or macOS\n");
    return 0;
}

#endif

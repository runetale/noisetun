/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TUNN-1: wireguard-tools `wg` command UAPI compatibility test.
 *
 * Creates a wg-c device with a UAPI socket server, then verifies that
 * the `wg` command can:
 *   1. Read device state via `wg show`
 *   2. Configure peers via `wg set`
 *   3. See traffic counters after data transfer
 *
 * Linux only. Requires root + wireguard-tools (`wg` command).
 *
 * Reference: issue #69
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
#include "../src/uapi/wg_uapi_server.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ────────────────────────────────────────
 * Constants
 * ──────────────────────────────────────── */

#define NS_A "uapi_test_a"
#define NS_B "uapi_test_b"

#define VETH_A "veth_uapi_a"
#define VETH_B "veth_uapi_b"

#define VETH_IP_A "192.168.252.1/24"
#define VETH_IP_B "192.168.252.2/24"

#define WG_IP_A   "10.101.0.1"
#define WG_IP_B   "10.101.0.2"
#define WG_CIDR_A "10.101.0.1/24"
#define WG_CIDR_B "10.101.0.2/24"

#define PORT_A 52820
#define PORT_B 52821

#define PASS(name) printf("  PASS: %s\n", (name))
#define FAIL(name)                      \
    do {                                \
        printf("  FAIL: %s\n", (name)); \
        failures++;                     \
    } while (0)

static int failures = 0;

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

/* Run a command and capture stdout into buf. Returns 0 on success. */
static int run_capture(const char *cmd, char *buf, size_t cap)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;
    size_t total = 0;
    while (total < cap - 1) {
        size_t n = fread(buf + total, 1, cap - 1 - total, fp);
        if (n == 0)
            break;
        total += n;
    }
    buf[total] = '\0';
    int rc = pclose(fp);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static void check_prerequisites(void)
{
    if (getuid() != 0)
        skip("not root (need CAP_NET_ADMIN for netns + TUN)");
    if (run_quiet("which wg") != 0)
        skip("wg (wireguard-tools) not found in PATH");
}

/* ────────────────────────────────────────
 * Key encoding
 * ──────────────────────────────────────── */

static void key_to_base64(const uint8_t key[32], char out[45])
{
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

/* ────────────────────────────────────────
 * Device context with UAPI server
 * ──────────────────────────────────────── */

typedef struct {
    wg_device_t *dev;
    wg_tun_linux_t *tun;
    wg_std_bind_t *bind;
    wg_uapi_server_t *uapi;
    pthread_t uapi_thread;
    const char *iface;
} dev_ctx_t;

static void *uapi_thread_fn(void *arg)
{
    wg_uapi_server_t *srv = arg;
    wg_uapi_server_run(srv);
    return NULL;
}

static void dev_ctx_create(dev_ctx_t *ctx, const char *ns, const char *iface,
                           uint16_t port, const uint8_t priv[32])
{
    ctx->iface = iface;

    int orig = enter_netns(ns);
    wg_error_t err;

    err = wg_tun_linux_create(&ctx->tun, iface, WG_DEFAULT_MTU);
    assert(err == WG_OK);

    err = wg_std_bind_new(&ctx->bind);
    assert(err == WG_OK);

    wg_tun_ops_t tun_ops = wg_tun_linux_ops(ctx->tun);
    wg_bind_ops_t bind_ops = wg_std_bind_ops(ctx->bind);

    err = wg_device_new(&ctx->dev, &tun_ops, &bind_ops, NULL);
    assert(err == WG_OK);

    wg_key_t priv_key;
    memcpy(priv_key.key, priv, 32);
    err = wg_device_set_private_key(ctx->dev, &priv_key);
    assert(err == WG_OK);

    ctx->dev->net.port = port;
    err = wg_device_up(ctx->dev);
    assert(err == WG_OK);

    /* Start UAPI server */
    err = wg_uapi_server_create(&ctx->uapi, ctx->dev, iface);
    assert(err == WG_OK);

    int rc = pthread_create(&ctx->uapi_thread, NULL, uapi_thread_fn, ctx->uapi);
    assert(rc == 0);

    restore_netns(orig);
}

static void dev_ctx_destroy(dev_ctx_t *ctx)
{
    if (ctx->uapi) {
        wg_uapi_server_stop(ctx->uapi);
        pthread_join(ctx->uapi_thread, NULL);
        wg_uapi_server_destroy(ctx->uapi);
    }
    if (ctx->dev)
        wg_device_close(ctx->dev);
    if (ctx->bind)
        wg_std_bind_destroy(ctx->bind);
}

/* ────────────────────────────────────────
 * Test 1: `wg show` reads device state
 *
 * Verify that `wg show <iface>` can read
 * the private key and listen port from our
 * UAPI socket.
 * ──────────────────────────────────────── */

static void test_wg_show(dev_ctx_t *ctx_a, const uint8_t pub_a[32],
                         const uint8_t pub_b[32])
{
    printf("\n--- Test: wg show reads device state ---\n");

    char cmd[512];
    char output[4096];

    /* wg show should see our interface */
    snprintf(cmd, sizeof(cmd), "ip netns exec " NS_A " wg show %s", ctx_a->iface);
    int rc = run_capture(cmd, output, sizeof(output));

    if (rc != 0) {
        FAIL("wg show exit code");
        printf("    wg show failed with rc=%d\n", rc);
        return;
    }
    PASS("wg show exit code");

    /* Check that public key is present */
    char pub_b64[45];
    key_to_base64(pub_a, pub_b64);
    if (strstr(output, pub_b64))
        PASS("wg show: public key present");
    else
        FAIL("wg show: public key present");

    /* Check listen port */
    char port_str[32];
    snprintf(port_str, sizeof(port_str), "%d", PORT_A);
    if (strstr(output, port_str))
        PASS("wg show: listen port present");
    else
        FAIL("wg show: listen port present");

    /* Check peer public key */
    char peer_b64[45];
    key_to_base64(pub_b, peer_b64);
    if (strstr(output, peer_b64))
        PASS("wg show: peer public key present");
    else
        FAIL("wg show: peer public key present");
}

/* ────────────────────────────────────────
 * Test 2: `wg set` adds a new peer
 *
 * Use `wg set` to add a peer to device B,
 * then verify it appears in `wg show`.
 * ──────────────────────────────────────── */

static void test_wg_set_peer(dev_ctx_t *ctx_b, const uint8_t pub_a[32])
{
    printf("\n--- Test: wg set adds peer ---\n");

    char pub_b64[45];
    key_to_base64(pub_a, pub_b64);

    char cmd[1024];

    /* Add peer A to device B via wg set (use /32 for host route) */
    snprintf(cmd, sizeof(cmd),
             "ip netns exec " NS_B " wg set %s"
             " peer %s"
             " endpoint 192.168.252.1:%d"
             " allowed-ips %s/32",
             ctx_b->iface, pub_b64, PORT_A, WG_IP_A);

    int rc = run(cmd);
    if (rc == 0)
        PASS("wg set peer exit code");
    else {
        FAIL("wg set peer exit code");
        return;
    }

    /* Verify peer appears in wg show */
    char output[4096];
    snprintf(cmd, sizeof(cmd), "ip netns exec " NS_B " wg show %s", ctx_b->iface);
    rc = run_capture(cmd, output, sizeof(output));

    if (rc == 0 && strstr(output, pub_b64))
        PASS("wg show: new peer visible");
    else
        FAIL("wg show: new peer visible");

    /* Verify allowed-ips (wg show displays "10.101.0.1/32") */
    if (strstr(output, "10.101.0.1/32"))
        PASS("wg show: allowed-ips correct");
    else
        FAIL("wg show: allowed-ips correct");
}

/* ────────────────────────────────────────
 * Test 3: `wg show` displays traffic
 *         counters after data transfer
 * ──────────────────────────────────────── */

static void test_wg_show_transfer(dev_ctx_t *ctx_a)
{
    printf("\n--- Test: wg show transfer counters ---\n");

    /* Ping from A to B to generate traffic */
    int rc = run("ip netns exec " NS_A " ping -c 3 -W 5 " WG_IP_B " >/dev/null 2>&1");
    if (rc == 0)
        PASS("ping through tunnel");
    else {
        FAIL("ping through tunnel");
        return;
    }

    /* Check that wg show reports transfer stats */
    char cmd[512];
    char output[4096];
    snprintf(cmd, sizeof(cmd), "ip netns exec " NS_A " wg show %s transfer",
             ctx_a->iface);
    rc = run_capture(cmd, output, sizeof(output));

    if (rc != 0) {
        FAIL("wg show transfer exit code");
        return;
    }

    /* Output format: <peer_pubkey>\t<rx_bytes>\t<tx_bytes>\n */
    /* Both rx and tx should be non-zero after ping */
    long rx = 0, tx = 0;
    char *tab1 = strchr(output, '\t');
    if (tab1) {
        rx = strtol(tab1 + 1, NULL, 10);
        char *tab2 = strchr(tab1 + 1, '\t');
        if (tab2)
            tx = strtol(tab2 + 1, NULL, 10);
    }

    if (rx > 0 && tx > 0)
        printf("  PASS: transfer counters (rx=%ld tx=%ld)\n", rx, tx);
    else
        FAIL("transfer counters non-zero");
}

/* ────────────────────────────────────────
 * Test 4: `wg showconf` produces valid
 *         configuration output
 * ──────────────────────────────────────── */

static void test_wg_showconf(dev_ctx_t *ctx_a)
{
    printf("\n--- Test: wg showconf ---\n");

    char cmd[512];
    char output[4096];
    snprintf(cmd, sizeof(cmd), "ip netns exec " NS_A " wg showconf %s", ctx_a->iface);
    int rc = run_capture(cmd, output, sizeof(output));

    if (rc != 0) {
        FAIL("wg showconf exit code");
        return;
    }
    PASS("wg showconf exit code");

    if (strstr(output, "[Interface]"))
        PASS("wg showconf: [Interface] section");
    else
        FAIL("wg showconf: [Interface] section");

    if (strstr(output, "[Peer]"))
        PASS("wg showconf: [Peer] section");
    else
        FAIL("wg showconf: [Peer] section");

    if (strstr(output, "PrivateKey"))
        PASS("wg showconf: PrivateKey present");
    else
        FAIL("wg showconf: PrivateKey present");

    char port_str[32];
    snprintf(port_str, sizeof(port_str), "ListenPort = %d", PORT_A);
    if (strstr(output, port_str))
        PASS("wg showconf: ListenPort correct");
    else
        FAIL("wg showconf: ListenPort correct");
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

    printf("=== test_uapi_wg_compat (Linux: wg tool + UAPI socket) ===\n");

    /* Generate keys */
    uint8_t priv_a[32], pub_a[32];
    uint8_t priv_b[32], pub_b[32];
    crypto_box_keypair(pub_a, priv_a);
    crypto_box_keypair(pub_b, priv_b);

    setup_netns();

    /* Create device A with UAPI server */
    dev_ctx_t ctx_a;
    dev_ctx_create(&ctx_a, NS_A, "wgua0", PORT_A, priv_a);

    /* Add peer B to device A (programmatically) */
    {
        int orig = enter_netns(NS_A);
        wg_peer_t *peer = NULL;
        wg_error_t err = wg_peer_new(ctx_a.dev, pub_b, NULL, &peer);
        assert(err == WG_OK);

        wg_endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr.sa4.sin_family = AF_INET;
        ep.addr.sa4.sin_port = htons(PORT_B);
        inet_pton(AF_INET, "192.168.252.2", &ep.addr.sa4.sin_addr);
        err = wg_peer_set_endpoint(peer, &ep);
        assert(err == WG_OK);

        uint32_t allowed;
        inet_pton(AF_INET, WG_IP_B, &allowed);
        err = wg_peer_add_allowed_ip(peer, &allowed, 32, AF_INET);
        assert(err == WG_OK);

        wg_peer_start(peer);
        restore_netns(orig);
    }

    /* Assign overlay IPs on device A */
    assert(run("ip netns exec " NS_A " ip addr add " WG_CIDR_A " dev wgua0") == 0);
    assert(run("ip netns exec " NS_A " ip link set wgua0 up") == 0);

    /* Create device B with UAPI server */
    dev_ctx_t ctx_b;
    dev_ctx_create(&ctx_b, NS_B, "wgub0", PORT_B, priv_b);

    /* Give UAPI servers a moment to start accepting */
    usleep(100000);

    /* Test 1: wg show reads device A state */
    test_wg_show(&ctx_a, pub_a, pub_b);

    /* Test 2: wg set adds peer A to device B */
    test_wg_set_peer(&ctx_b, pub_a);

    /* Now assign overlay IP on device B and bring up */
    assert(run("ip netns exec " NS_B " ip addr add " WG_CIDR_B " dev wgub0") == 0);
    assert(run("ip netns exec " NS_B " ip link set wgub0 up") == 0);

    /* Wait a moment for peer setup to propagate */
    usleep(200000);

    /* Test 3: transfer counters after ping */
    test_wg_show_transfer(&ctx_a);

    /* Test 4: wg showconf */
    test_wg_showconf(&ctx_a);

    /* Cleanup */
    dev_ctx_destroy(&ctx_a);
    dev_ctx_destroy(&ctx_b);
    cleanup_ns();

    printf("\n");
    if (failures > 0) {
        printf("FAILED: %d test(s)\n", failures);
        return 1;
    }
    printf("All UAPI wg-compat tests passed.\n");
    return 0;
}

#else /* !__linux__ */

#include <stdio.h>

int main(void)
{
    printf("SKIP: test_uapi_wg_compat requires Linux\n");
    return 0;
}

#endif

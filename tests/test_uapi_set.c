/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * wg_uapi_set() against wireguard-go's semantics (device/uapi.go):
 * "allowed_ip=-<prefix>" removes a prefix, and a malformed value, a line
 * without '=' or an unknown key is an error instead of being skipped.
 * Needs no TUN or socket, so it runs on every platform.
 */

#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/peer/wg_allowedips.h"
#include "../src/peer/wg_peer.h"

#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define PASS(name) printf("  PASS: %s\n", name)

static char hex_a[65], hex_b[65];
static uint8_t pub_a[32], pub_b[32];

/* A real Curve25519 public key, hex-encoded (peers are validated). */
static void make_pub(uint8_t pub[32], char hex[65])
{
    uint8_t priv[32];
    randombytes_buf(priv, sizeof(priv));
    crypto_scalarmult_base(pub, priv);
    sodium_bin2hex(hex, 65, pub, 32);
    sodium_memzero(priv, sizeof(priv));
}

static wg_error_t set(wg_device_t *dev, const char *cfg)
{
    return wg_uapi_set(dev, cfg, strlen(cfg));
}

static struct wg_peer *route(wg_device_t *dev, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t ip[4] = {a, b, c, d};
    return wg_allowedips_lookup(&dev->allowedips, ip, AF_INET);
}

static void test_remove_allowed_ip(wg_device_t *dev)
{
    char cfg[512];
    snprintf(cfg, sizeof(cfg),
             "public_key=%s\nallowed_ip=10.0.0.2/32\nallowed_ip=10.0.0.3/32\n"
             "public_key=%s\nallowed_ip=10.0.0.4/32\n\n",
             hex_a, hex_b);
    assert(set(dev, cfg) == WG_OK);
    struct wg_peer *a = wg_device_lookup_peer(dev, pub_a);
    struct wg_peer *b = wg_device_lookup_peer(dev, pub_b);
    assert(a && b);
    assert(route(dev, 10, 0, 0, 2) == a);
    assert(route(dev, 10, 0, 0, 3) == a);

    /* Remove one prefix of peer A; the other stays. */
    snprintf(cfg, sizeof(cfg), "public_key=%s\nallowed_ip=-10.0.0.2/32\n\n", hex_a);
    assert(set(dev, cfg) == WG_OK);
    assert(route(dev, 10, 0, 0, 2) == NULL);
    assert(route(dev, 10, 0, 0, 3) == a);

    /* A prefix that belongs to another peer is left alone. */
    snprintf(cfg, sizeof(cfg), "public_key=%s\nallowed_ip=-10.0.0.4/32\n\n", hex_a);
    assert(set(dev, cfg) == WG_OK);
    assert(route(dev, 10, 0, 0, 4) == b);

    /* Removing a prefix that is not there is not an error. */
    snprintf(cfg, sizeof(cfg), "public_key=%s\nallowed_ip=-10.9.9.9/32\n\n", hex_a);
    assert(set(dev, cfg) == WG_OK);
    PASS("allowed_ip=-<prefix> removes exactly that prefix of that peer");
}

static void test_rejects_bad_input(wg_device_t *dev)
{
    static const char *const device_bad[] = {
        "no_such_key=1\n\n",
        "listen_port=abc\n\n",
        "listen_port=70000\n\n",
        "listen_port=-1\n\n",
        "fwmark=x\n\n",
        "fwmark=4294967296\n\n",
        "private_key=zz\n\n",
        "replace_peers=false\n\n",
        "this line has no equals\n\n",
    };
    for (size_t i = 0; i < sizeof(device_bad) / sizeof(device_bad[0]); i++)
        assert(set(dev, device_bad[i]) == WG_ERR_INVALID_ARGUMENT);

    static const char *const peer_bad[] = {
        "allowed_ip=10.0.0.9\n",
        "allowed_ip=10.0.0.9/33\n",
        "allowed_ip=-bogus/8\n",
        "endpoint=nowhere\n",
        "persistent_keepalive_interval=abc\n",
        "persistent_keepalive_interval=70000\n",
        "preshared_key=00\n",
        "protocol_version=2\n",
        "remove=yes\n",
        "update_only=1\n",
        "replace_allowed_ips=false\n",
        "no_such_peer_key=1\n",
    };
    char cfg[256];
    for (size_t i = 0; i < sizeof(peer_bad) / sizeof(peer_bad[0]); i++) {
        snprintf(cfg, sizeof(cfg), "public_key=%s\n%s\n", hex_a, peer_bad[i]);
        assert(set(dev, cfg) == WG_ERR_INVALID_ARGUMENT);
    }

    /* A value longer than any legal one is rejected, not truncated. */
    char big[700];
    memset(big, '1', sizeof(big));
    memcpy(big, "fwmark=", 7);
    big[sizeof(big) - 2] = '\n';
    big[sizeof(big) - 1] = '\0';
    assert(set(dev, big) == WG_ERR_INVALID_ARGUMENT);
    PASS("malformed values, lines without '=' and unknown keys are errors");
}

static void test_accepts_what_wg_sends(wg_device_t *dev)
{
    assert(set(dev, "fwmark=\n\n") == WG_OK); /* empty = 0 */
    assert(set(dev, "fwmark=0\n\n") == WG_OK);
    char cfg[256];
    snprintf(
        cfg, sizeof(cfg),
        "public_key=%s\nprotocol_version=1\npersistent_keepalive_interval=25\n"
        "endpoint=127.0.0.1:51820\nreplace_allowed_ips=true\nallowed_ip=10.0.1.0/24\n\n",
        hex_a);
    assert(set(dev, cfg) == WG_OK);
    assert(route(dev, 10, 0, 1, 7) == wg_device_lookup_peer(dev, pub_a));
    PASS("keys and values wg(8) sends are accepted");
}

static void test_update_only_unknown_peer(wg_device_t *dev)
{
    uint8_t pub_c[32];
    char hex_c[65];
    make_pub(pub_c, hex_c);

    /* update_only on an unknown key creates nothing, but its values are
     * still checked, as wireguard-go checks its dummy peer. */
    char cfg[256];
    snprintf(cfg, sizeof(cfg),
             "public_key=%s\nupdate_only=true\nallowed_ip=10.0.2.0/24\n\n", hex_c);
    assert(set(dev, cfg) == WG_OK);
    assert(wg_device_lookup_peer(dev, pub_c) == NULL);
    assert(route(dev, 10, 0, 2, 1) == NULL);

    snprintf(cfg, sizeof(cfg), "public_key=%s\nupdate_only=true\nallowed_ip=nonsense\n\n",
             hex_c);
    assert(set(dev, cfg) == WG_ERR_INVALID_ARGUMENT);
    assert(wg_device_lookup_peer(dev, pub_c) == NULL);
    PASS("update_only=true on an unknown peer: nothing created, values still checked");
}

/* The endpoint a peer has now, as the port number (the tests use one
 * address and tell endpoints apart by port). 0 = none. */
static unsigned endpoint_port(struct wg_peer *peer)
{
    wg_endpoint_t ep;
    if (!wg_peer_get_endpoint(peer, &ep))
        return 0;
    return ntohs(ep.addr.sa4.sin_port);
}

/* A packet from 192.0.2.1:port, as the receive path reports it. */
static void packet_from(struct wg_peer *peer, unsigned port)
{
    wg_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.addr.sa4.sin_family = AF_INET;
    ep.addr.sa4.sin_port = htons((uint16_t)port);
    ep.addr.sa4.sin_addr.s_addr = htonl(0xC0000201); /* 192.0.2.1 */
    wg_peer_set_endpoint_from_packet(peer, &ep);
}

/* wg_device_disable_roaming (wireguard-go's
 * DisableSomeRoamingForBrokenMobileSemantics): a peer with a configured
 * endpoint keeps it, before or after the call; one without learns it. */
static void test_disable_roaming(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    char hex[4][65], cfg[1024];
    uint8_t pub[4][32], priv[32];
    char priv_hex[65];
    for (int i = 0; i < 4; i++)
        make_pub(pub[i], hex[i]);
    randombytes_buf(priv, sizeof(priv));
    sodium_bin2hex(priv_hex, sizeof(priv_hex), priv, sizeof(priv));
    sodium_memzero(priv, sizeof(priv));

    /* Peer 0 with an endpoint, peer 1 without. */
    snprintf(cfg, sizeof(cfg),
             "private_key=%s\npublic_key=%s\nendpoint=192.0.2.1:1000\n"
             "public_key=%s\n\n",
             priv_hex, hex[0], hex[1]);
    assert(set(dev, cfg) == WG_OK);
    struct wg_peer *p0 = wg_device_lookup_peer(dev, pub[0]);
    struct wg_peer *p1 = wg_device_lookup_peer(dev, pub[1]);

    /* Roaming is on by default. */
    packet_from(p0, 1001);
    assert(endpoint_port(p0) == 1001);

    wg_device_disable_roaming(dev);
    packet_from(p0, 1002);
    assert(endpoint_port(p0) == 1001);
    packet_from(p1, 2000);
    assert(endpoint_port(p1) == 2000);

    /* Peers added afterwards: with an endpoint it sticks, without one the
     * first packet sets it. */
    snprintf(cfg, sizeof(cfg),
             "public_key=%s\nendpoint=192.0.2.1:3000\npublic_key=%s\n\n", hex[2], hex[3]);
    assert(set(dev, cfg) == WG_OK);
    struct wg_peer *p2 = wg_device_lookup_peer(dev, pub[2]);
    struct wg_peer *p3 = wg_device_lookup_peer(dev, pub[3]);
    packet_from(p2, 3001);
    assert(endpoint_port(p2) == 3000);
    packet_from(p3, 4000);
    assert(endpoint_port(p3) == 4000);

    wg_device_close(dev);
    PASS("disable_roaming keeps configured endpoints, before and after");
}

static void test_peer_before_private_key(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);
    uint8_t pub[32];
    char hex[65], cfg[256];
    make_pub(pub, hex);

    snprintf(cfg, sizeof(cfg), "public_key=%s\nallowed_ip=10.0.3.0/24\n\n", hex);
    assert(set(dev, cfg) == WG_OK);
    struct wg_peer *peer = wg_device_lookup_peer(dev, pub);
    assert(peer);
    assert(sodium_is_zero(peer->handshake.precomputed_static_static, 32));

    uint8_t priv[32];
    char priv_hex[65];
    randombytes_buf(priv, sizeof(priv));
    sodium_bin2hex(priv_hex, sizeof(priv_hex), priv, sizeof(priv));
    snprintf(cfg, sizeof(cfg), "private_key=%s\n\n", priv_hex);
    assert(set(dev, cfg) == WG_OK);
    assert(!sodium_is_zero(peer->handshake.precomputed_static_static, 32));
    sodium_memzero(priv, sizeof(priv));

    wg_device_close(dev);
    PASS("a peer may be added before the private key; DH is computed when it is set");
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();
    printf("=== test_uapi_set ===\n");

    make_pub(pub_a, hex_a);
    make_pub(pub_b, hex_b);

    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    /* wg(8) sets the private key first; peers need it for the
     * static-static DH. */
    uint8_t priv[32];
    char cfg[128], priv_hex[65];
    randombytes_buf(priv, sizeof(priv));
    sodium_bin2hex(priv_hex, sizeof(priv_hex), priv, sizeof(priv));
    snprintf(cfg, sizeof(cfg), "private_key=%s\n\n", priv_hex);
    assert(set(dev, cfg) == WG_OK);
    sodium_memzero(priv, sizeof(priv));

    test_remove_allowed_ip(dev);
    test_rejects_bad_input(dev);
    test_accepts_what_wg_sends(dev);
    test_update_only_unknown_peer(dev);
    test_peer_before_private_key();
    test_disable_roaming();

    wg_device_close(dev);
    printf("All UAPI set tests passed.\n");
    return 0;
}

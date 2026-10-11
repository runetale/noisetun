/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Runetale Inc.
 *
 * Capped packet-buffer pools (WG_POOL_MAX_ELEMENTS: iOS, Android, or
 * -DWG_MEMORY_CONSTRAINED=ON) with every outbound buffer in use: packets
 * staged for peers whose handshake never completes hold them all, and the
 * TUN reader waits in Get.
 *
 *   1. A handshake with another peer still completes and its staged packet
 *      is delivered: the keepalive after the response must not wait for a
 *      buffer when staged packets can serve as the keepalive.
 *   2. The device still shuts down: the waiting reader must be woken, since
 *      the buffers only come back after it is joined.
 *
 * Builds without a cap skip it.
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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> /* _exit */

#define PASS(name) printf("  PASS: %s\n", name)

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sleep_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void gen_keypair(wg_key_t *priv, wg_key_t *pub)
{
    randombytes_buf(priv->key, WG_KEY_LEN);
    priv->key[0] &= 248;
    priv->key[31] &= 127;
    priv->key[31] |= 64;
    crypto_scalarmult_base(pub->key, priv->key);
}

/* A minimal IPv4 packet from src to dst (no valid transport header needed:
 * wg-c routes on the destination address). */
static size_t ipv4_packet(uint8_t *out, uint32_t src, uint32_t dst)
{
    const size_t len = 60;
    memset(out, 0, len);
    out[0] = 0x45;
    out[2] = 0;
    out[3] = (uint8_t)len;
    out[8] = 64;
    out[9] = 17; /* UDP */
    uint32_t s = htonl(src), d = htonl(dst);
    memcpy(out + 12, &s, 4);
    memcpy(out + 16, &d, 4);
    return len;
}

static wg_peer_t *add_peer(wg_device_t *dev, const wg_key_t *pub, uint32_t allowed,
                           uint8_t cidr, uint16_t port)
{
    wg_peer_t *peer = NULL;
    assert(wg_peer_new(dev, pub->key, NULL, &peer) == WG_OK);
    wg_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.addr.sa4.sin_family = AF_INET;
    ep.addr.sa4.sin_port = htons(port);
    ep.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);
    assert(wg_peer_set_endpoint(peer, &ep) == WG_OK);
    uint32_t ip = htonl(allowed);
    assert(wg_peer_add_allowed_ip(peer, &ip, cidr, AF_INET) == WG_OK);
    return peer;
}

static uint32_t outbound_in_use(wg_device_t *dev)
{
    pthread_mutex_lock(&dev->pool.outbound->lock);
    uint32_t out = dev->pool.outbound->out;
    pthread_mutex_unlock(&dev->pool.outbound->lock);
    return out;
}

static atomic_bool g_closed;

static void *close_device(void *arg)
{
    wg_device_close(arg);
    atomic_store(&g_closed, true);
    return NULL;
}

int main(void)
{
    printf("=== test_pool_exhaustion ===\n");
    if (WG_POOL_MAX_ELEMENTS == 0) {
        printf("SKIP: packet-buffer pools are not capped in this build\n");
        return 0;
    }
    assert(wg_init() == WG_OK);

    /* dev0 and dev1 over a channel bind; dev1 starts down. */
    wg_key_t priv[2], pub[2];
    gen_keypair(&priv[0], &pub[0]);
    gen_keypair(&priv[1], &pub[1]);
    const uint32_t ip0 = 0x0a000001, ip1 = 0x0a000002; /* 10.0.0.1, 10.0.0.2 */

    wg_channel_bind_t *bind[2];
    wg_channel_tun_t *tun[2];
    wg_device_t *dev[2];
    assert(wg_channel_bind_pair(&bind[0], &bind[1]) == WG_OK);
    for (int i = 0; i < 2; i++) {
        assert(wg_channel_tun_create(&tun[i], WG_DEFAULT_MTU) == WG_OK);
        wg_tun_ops_t tun_ops = wg_channel_tun_ops(tun[i]);
        wg_bind_ops_t bind_ops = wg_channel_bind_ops(bind[i]);
        assert(wg_device_new(&dev[i], &tun_ops, &bind_ops, NULL) == WG_OK);
        assert(wg_device_set_private_key(dev[i], &priv[i]) == WG_OK);
    }
    add_peer(dev[0], &pub[1], ip1, 32, 2);
    add_peer(dev[1], &pub[0], ip0, 32, 1);

    /* Peers nobody answers for: their handshakes never complete, so their
     * packets stay staged (up to WG_QUEUE_STAGED_SIZE each). */
    const int dead = (int)(WG_POOL_MAX_ELEMENTS / WG_QUEUE_STAGED_SIZE) + 1;
    for (int i = 0; i < dead; i++) {
        wg_key_t p, q;
        gen_keypair(&p, &q);
        add_peer(dev[0], &q, 0x0b000000u | ((uint32_t)i << 8), 24, 2);
    }
    assert(wg_device_up(dev[0]) == WG_OK);

    /* One packet for dev1, staged behind a handshake dev1 cannot answer yet. */
    uint8_t pkt[64];
    size_t len = ipv4_packet(pkt, ip0, ip1);
    assert(wg_channel_tun_send(tun[0], pkt, len) == WG_OK);

    /* Fill every other staged queue until the pool is at its cap. */
    for (int i = 0; i < dead; i++)
        for (int k = 0; k < WG_QUEUE_STAGED_SIZE; k++) {
            size_t n = ipv4_packet(pkt, ip0, 0x0b000001u | ((uint32_t)i << 8));
            assert(wg_channel_tun_send(tun[0], pkt, n) == WG_OK);
        }
    double t0 = now_s();
    while (outbound_in_use(dev[0]) < WG_POOL_MAX_ELEMENTS && now_s() - t0 < 10)
        sleep_ms(10);
    printf("  outbound buffers in use: %u of %u\n", outbound_in_use(dev[0]),
           (unsigned)WG_POOL_MAX_ELEMENTS);
    assert(outbound_in_use(dev[0]) >= WG_POOL_MAX_ELEMENTS);

    /* 1. dev1 comes up; dev0's retried handshake completes (REKEY_TIMEOUT
     * is 5 s) and its staged packet must arrive. */
    assert(wg_device_up(dev[1]) == WG_OK);
    uint8_t *got = NULL;
    size_t got_len = 0;
    wg_error_t err = wg_channel_tun_recv_timeout(tun[1], &got, &got_len, 20000);
    if (err != WG_OK) {
        fprintf(stderr, "  FAIL: the staged packet never arrived (%s)\n",
                wg_error_str(err));
        return 1;
    }
    assert(got_len == len);
    free(got);
    PASS("a handshake completes and delivers staged data with the pool exhausted");

    /* 2. Close dev0 while its pool is still exhausted; it must return. */
    pthread_t closer;
    assert(pthread_create(&closer, NULL, close_device, dev[0]) == 0);
    t0 = now_s();
    while (!atomic_load(&g_closed) && now_s() - t0 < 10)
        sleep_ms(10);
    if (!atomic_load(&g_closed)) {
        fprintf(stderr, "  FAIL: wg_device_close did not return within 10 s\n");
        _exit(1); /* the closer is stuck; nothing else to clean up */
    }
    pthread_join(closer, NULL);
    PASS("the device closes with the pool exhausted");

    wg_device_close(dev[1]);
    for (int i = 0; i < 2; i++) {
        wg_channel_tun_destroy(tun[i]);
        wg_channel_bind_destroy(bind[i]);
    }
    printf("All pool exhaustion tests passed.\n");
    return 0;
}

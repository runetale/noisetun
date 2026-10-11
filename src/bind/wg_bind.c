/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * ChannelBind: in-memory bind implementation for testing.
 *
 * Reference: wireguard-go/conn/bindtest/bindtest.go
 */

#include "wg_bind.h"

#include "../device/wg_queue.h"

#include "platform/wg_platform.h"
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Internal packet type
 * ──────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t len;
    wg_endpoint_t src; /* source endpoint */
} wg_channel_packet_t;

static void channel_packet_free(void *p)
{
    wg_channel_packet_t *pkt = p;
    if (pkt) {
        free(pkt->data);
        free(pkt);
    }
}

/* ────────────────────────────────────────
 * ChannelBind structure
 * ──────────────────────────────────────── */
#define WG_CHANNEL_QUEUE_SIZE 8192

struct wg_channel_bind {
    wg_queue_t *rx_queue;         /* packets received by this side */
    wg_channel_bind_t *peer_bind; /* the other side of the pair */
    bool is_open;
    pthread_mutex_t lock;
    wg_endpoint_t local_endpoint; /* our fake endpoint */
};

/* ────────────────────────────────────────
 * Bind ops callbacks
 * ──────────────────────────────────────── */

static int channel_open(void *ctx, uint16_t port)
{
    wg_channel_bind_t *cb = ctx;
    (void)port;
    pthread_mutex_lock(&cb->lock);
    cb->is_open = true;
    pthread_mutex_unlock(&cb->lock);
    return 0;
}

static void channel_close(void *ctx)
{
    wg_channel_bind_t *cb = ctx;
    pthread_mutex_lock(&cb->lock);
    cb->is_open = false;
    pthread_mutex_unlock(&cb->lock);
    wg_queue_close(cb->rx_queue);
}

static int channel_send(void *ctx, uint8_t **bufs, int *sizes, int count,
                        const wg_endpoint_t *ep)
{
    wg_channel_bind_t *cb = ctx;
    (void)ep;

    pthread_mutex_lock(&cb->lock);
    if (!cb->is_open || !cb->peer_bind) {
        pthread_mutex_unlock(&cb->lock);
        return -1;
    }
    wg_channel_bind_t *peer = cb->peer_bind;
    wg_endpoint_t our_ep = cb->local_endpoint;
    pthread_mutex_unlock(&cb->lock);

    for (int i = 0; i < count; i++) {
        if (!bufs[i] || sizes[i] <= 0)
            continue;

        wg_channel_packet_t *pkt = malloc(sizeof(*pkt));
        if (!pkt)
            return -1;
        pkt->data = malloc((size_t)sizes[i]);
        if (!pkt->data) {
            free(pkt);
            return -1;
        }
        memcpy(pkt->data, bufs[i], (size_t)sizes[i]);
        pkt->len = (size_t)sizes[i];
        pkt->src = our_ep;

        wg_error_t err = wg_queue_try_push(peer->rx_queue, pkt);
        if (err != WG_OK) {
            channel_packet_free(pkt);
            /* Queue full — drop packet (matches Go behavior) */
        }
    }

    return count;
}

static int channel_recv(void *ctx, uint8_t **bufs, int *sizes, int count,
                        wg_endpoint_t *eps)
{
    wg_channel_bind_t *cb = ctx;

    if (count < 1)
        return 0;

    void *raw = NULL;
    wg_error_t err = wg_queue_pop(cb->rx_queue, &raw);
    if (err != WG_OK)
        return -1; /* queue closed */

    wg_channel_packet_t *pkt = raw;

    /* Guard against buffer overflow: truncate if packet exceeds
     * the caller's buffer capacity (sizes[0] on input). */
    size_t copy_len = pkt->len;
    if (sizes[0] > 0 && copy_len > (size_t)sizes[0])
        copy_len = (size_t)sizes[0];

    memcpy(bufs[0], pkt->data, copy_len);
    sizes[0] = (int)copy_len;

    if (eps)
        eps[0] = pkt->src;

    channel_packet_free(pkt);
    return 1;
}

static int channel_set_mark(void *ctx, uint32_t mark)
{
    (void)ctx;
    (void)mark;
    return 0;
}

static int channel_batch_size(void *ctx)
{
    (void)ctx;
    return 1;
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_channel_bind_pair(wg_channel_bind_t **a, wg_channel_bind_t **b)
{
    wg_channel_bind_t *ba = calloc(1, sizeof(*ba));
    wg_channel_bind_t *bb = calloc(1, sizeof(*bb));
    if (!ba || !bb)
        goto fail;

    ba->rx_queue = calloc(1, sizeof(wg_queue_t));
    bb->rx_queue = calloc(1, sizeof(wg_queue_t));
    if (!ba->rx_queue || !bb->rx_queue)
        goto fail;

    if (wg_queue_init(ba->rx_queue, WG_CHANNEL_QUEUE_SIZE) != WG_OK)
        goto fail;
    if (wg_queue_init(bb->rx_queue, WG_CHANNEL_QUEUE_SIZE) != WG_OK)
        goto fail;

    pthread_mutex_init(&ba->lock, NULL);
    pthread_mutex_init(&bb->lock, NULL);

    ba->peer_bind = bb;
    bb->peer_bind = ba;
    ba->is_open = false;
    bb->is_open = false;

    /* Set up fake endpoints: 127.0.0.1:1 and 127.0.0.1:2 */
    memset(&ba->local_endpoint, 0, sizeof(ba->local_endpoint));
    ba->local_endpoint.addr.sa4.sin_family = AF_INET;
    ba->local_endpoint.addr.sa4.sin_port = htons(1);
    ba->local_endpoint.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);

    memset(&bb->local_endpoint, 0, sizeof(bb->local_endpoint));
    bb->local_endpoint.addr.sa4.sin_family = AF_INET;
    bb->local_endpoint.addr.sa4.sin_port = htons(2);
    bb->local_endpoint.addr.sa4.sin_addr.s_addr = htonl(0x7f000001);

    *a = ba;
    *b = bb;
    return WG_OK;

fail:
    if (ba) {
        if (ba->rx_queue) {
            wg_queue_destroy(ba->rx_queue);
            free(ba->rx_queue);
        }
        free(ba);
    }
    if (bb) {
        if (bb->rx_queue) {
            wg_queue_destroy(bb->rx_queue);
            free(bb->rx_queue);
        }
        free(bb);
    }
    return WG_ERR_NO_MEMORY;
}

wg_bind_ops_t wg_channel_bind_ops(wg_channel_bind_t *cb)
{
    return (wg_bind_ops_t){
        .open = channel_open,
        .close = channel_close,
        .send = channel_send,
        .recv = channel_recv,
        .set_mark = channel_set_mark,
        .batch_size = channel_batch_size,
        .ctx = cb,
    };
}

void wg_channel_bind_destroy(wg_channel_bind_t *cb)
{
    if (!cb)
        return;

    /* Disconnect from peer */
    pthread_mutex_lock(&cb->lock);
    if (cb->peer_bind) {
        pthread_mutex_lock(&cb->peer_bind->lock);
        cb->peer_bind->peer_bind = NULL;
        pthread_mutex_unlock(&cb->peer_bind->lock);
    }
    cb->peer_bind = NULL;
    pthread_mutex_unlock(&cb->lock);

    /* Close and flush receive queue */
    wg_queue_close(cb->rx_queue);
    wg_queue_flush(cb->rx_queue, channel_packet_free);
    wg_queue_destroy(cb->rx_queue);
    free(cb->rx_queue);

    pthread_mutex_destroy(&cb->lock);
    free(cb);
}

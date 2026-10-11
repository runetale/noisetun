/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * ChannelTUN: in-memory TUN implementation for testing.
 *
 * Reference: wireguard-go/tun/tuntest/tuntest.go
 */

#include "wg_tun_channel.h"

#include "../device/wg_queue.h"
#include "wg_tun.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Internal packet type
 * ──────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t len;
} wg_channel_tun_packet_t;

static void tun_packet_free(void *p)
{
    wg_channel_tun_packet_t *pkt = p;
    if (pkt) {
        free(pkt->data);
        free(pkt);
    }
}

/* ────────────────────────────────────────
 * ChannelTUN structure
 * ──────────────────────────────────────── */
#define WG_CHANNEL_TUN_QUEUE_SIZE 1024

struct wg_channel_tun {
    wg_queue_t *outbound; /* test -> TUN read() */
    wg_queue_t *inbound;  /* TUN write() -> test */
    int mtu;
    _Atomic bool closed;
};

/* ────────────────────────────────────────
 * TUN ops callbacks
 * ──────────────────────────────────────── */

static int channel_tun_read(void *ctx, uint8_t **bufs, int *sizes, int count, int offset)
{
    wg_channel_tun_t *ct = ctx;
    if (count < 1)
        return 0;

    void *raw = NULL;
    wg_error_t err = wg_queue_pop(ct->outbound, &raw);
    if (err != WG_OK)
        return -1; /* closed */

    wg_channel_tun_packet_t *pkt = raw;

    /* Drop oversized packets rather than silently truncating
     * (truncation would corrupt checksums and hide bugs). */
    if (pkt->len > (size_t)ct->mtu) {
        tun_packet_free(pkt);
        return 0;
    }

    memcpy(bufs[0] + offset, pkt->data, pkt->len);
    sizes[0] = (int)pkt->len;

    tun_packet_free(pkt);
    return 1;
}

static int channel_tun_write(void *ctx, uint8_t **bufs, const int *sizes, int count,
                             int offset)
{
    wg_channel_tun_t *ct = ctx;

    for (int i = 0; i < count; i++) {
        if (!bufs[i] || sizes[i] <= offset)
            continue;

        size_t pkt_len = (size_t)(sizes[i] - offset);
        wg_channel_tun_packet_t *pkt = malloc(sizeof(*pkt));
        if (!pkt)
            return -1;
        pkt->data = malloc(pkt_len);
        if (!pkt->data) {
            free(pkt);
            return -1;
        }
        memcpy(pkt->data, bufs[i] + offset, pkt_len);
        pkt->len = pkt_len;

        wg_error_t err = wg_queue_try_push(ct->inbound, pkt);
        if (err != WG_OK) {
            tun_packet_free(pkt);
            /* Queue full — drop (matches Go behavior) */
        }
    }

    return count;
}

static int channel_tun_mtu(void *ctx)
{
    wg_channel_tun_t *ct = ctx;
    return ct->mtu;
}

static const char *channel_tun_name(void *ctx)
{
    (void)ctx;
    return "channelTUN";
}

static int channel_tun_batch_size(void *ctx)
{
    (void)ctx;
    return 1;
}

static int channel_tun_events(void *ctx)
{
    (void)ctx;
    return WG_TUN_EVENT_UP;
}

static void channel_tun_close(void *ctx)
{
    wg_channel_tun_t *ct = ctx;
    atomic_store(&ct->closed, true);
    wg_queue_close(ct->outbound);
    wg_queue_close(ct->inbound);
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_channel_tun_create(wg_channel_tun_t **out, int mtu)
{
    wg_channel_tun_t *ct = calloc(1, sizeof(*ct));
    if (!ct)
        return WG_ERR_NO_MEMORY;

    ct->outbound = calloc(1, sizeof(wg_queue_t));
    ct->inbound = calloc(1, sizeof(wg_queue_t));
    if (!ct->outbound || !ct->inbound)
        goto fail;

    if (wg_queue_init(ct->outbound, WG_CHANNEL_TUN_QUEUE_SIZE) != WG_OK)
        goto fail;
    if (wg_queue_init(ct->inbound, WG_CHANNEL_TUN_QUEUE_SIZE) != WG_OK) {
        wg_queue_destroy(ct->outbound);
        goto fail;
    }

    ct->mtu = mtu;
    atomic_init(&ct->closed, false);

    *out = ct;
    return WG_OK;

fail:
    if (ct->outbound) {
        wg_queue_destroy(ct->outbound);
        free(ct->outbound);
    }
    if (ct->inbound) {
        wg_queue_destroy(ct->inbound);
        free(ct->inbound);
    }
    free(ct);
    return WG_ERR_NO_MEMORY;
}

wg_tun_ops_t wg_channel_tun_ops(wg_channel_tun_t *ct)
{
    return (wg_tun_ops_t){
        .read = channel_tun_read,
        .write = channel_tun_write,
        .mtu = channel_tun_mtu,
        .name = channel_tun_name,
        .batch_size = channel_tun_batch_size,
        .events = channel_tun_events,
        .close = channel_tun_close,
        .cancel = channel_tun_close, /* close frees nothing either */
        .ctx = ct,
    };
}

wg_error_t wg_channel_tun_send(wg_channel_tun_t *ct, const uint8_t *data, size_t len)
{
    wg_channel_tun_packet_t *pkt = malloc(sizeof(*pkt));
    if (!pkt)
        return WG_ERR_NO_MEMORY;
    pkt->data = malloc(len);
    if (!pkt->data) {
        free(pkt);
        return WG_ERR_NO_MEMORY;
    }
    memcpy(pkt->data, data, len);
    pkt->len = len;

    wg_error_t err = wg_queue_push(ct->outbound, pkt);
    if (err != WG_OK) {
        tun_packet_free(pkt);
        return err;
    }
    return WG_OK;
}

wg_error_t wg_channel_tun_recv(wg_channel_tun_t *ct, uint8_t **out_data, size_t *out_len)
{
    void *raw = NULL;
    wg_error_t err = wg_queue_pop(ct->inbound, &raw);
    if (err != WG_OK)
        return err;

    wg_channel_tun_packet_t *pkt = raw;
    *out_data = pkt->data;
    *out_len = pkt->len;
    free(pkt); /* free wrapper, caller owns data */
    return WG_OK;
}

wg_error_t wg_channel_tun_try_recv(wg_channel_tun_t *ct, uint8_t **out_data,
                                   size_t *out_len)
{
    void *raw = NULL;
    wg_error_t err = wg_queue_try_pop(ct->inbound, &raw);
    if (err != WG_OK)
        return err;

    wg_channel_tun_packet_t *pkt = raw;
    *out_data = pkt->data;
    *out_len = pkt->len;
    free(pkt);
    return WG_OK;
}

wg_error_t wg_channel_tun_recv_timeout(wg_channel_tun_t *ct, uint8_t **out_data,
                                       size_t *out_len, int timeout_ms)
{
    void *raw = NULL;
    wg_error_t err = wg_queue_pop_timeout(ct->inbound, &raw, timeout_ms);
    if (err != WG_OK)
        return err;

    wg_channel_tun_packet_t *pkt = raw;
    *out_data = pkt->data;
    *out_len = pkt->len;
    free(pkt);
    return WG_OK;
}

void wg_channel_tun_destroy(wg_channel_tun_t *ct)
{
    if (!ct)
        return;

    if (!atomic_load(&ct->closed)) {
        wg_queue_close(ct->outbound);
        wg_queue_close(ct->inbound);
    }

    wg_queue_flush(ct->outbound, tun_packet_free);
    wg_queue_destroy(ct->outbound);
    free(ct->outbound);

    wg_queue_flush(ct->inbound, tun_packet_free);
    wg_queue_destroy(ct->inbound);
    free(ct->inbound);

    free(ct);
}

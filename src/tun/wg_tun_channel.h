/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * ChannelTUN: in-memory TUN implementation for testing.
 *
 * Provides a pair of channels (queues) that simulate a TUN device:
 *   - Outbound: test code pushes packets here -> TUN read() delivers them
 *   - Inbound:  TUN write() pushes packets here -> test code reads them
 *
 * Reference: wireguard-go/tun/tuntest/tuntest.go
 */

#ifndef WG_TUN_CHANNEL_H
#define WG_TUN_CHANNEL_H

#include "wg_error.h"
#include "wireguard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque handle */
typedef struct wg_channel_tun wg_channel_tun_t;

/*
 * Create a ChannelTUN instance.
 *
 * mtu: simulated MTU (typically 1420).
 */
wg_error_t wg_channel_tun_create(wg_channel_tun_t **out, int mtu);

/*
 * Get a wg_tun_ops_t populated with the ChannelTUN callbacks.
 * The returned ops struct has ctx set to the channel_tun instance.
 */
wg_tun_ops_t wg_channel_tun_ops(wg_channel_tun_t *ct);

/*
 * Inject a packet into the TUN device (simulates application-layer send).
 * The packet will be returned by the next TUN read() call.
 * Blocks if the outbound queue is full.
 */
wg_error_t wg_channel_tun_send(wg_channel_tun_t *ct, const uint8_t *data, size_t len);

/*
 * Read a packet that the WireGuard device wrote to the TUN.
 * Blocks until a packet is available or the TUN is closed.
 *
 * On success: *out_data is malloc'd (caller frees), *out_len is set.
 * Returns WG_ERR_DEVICE_CLOSED if TUN was closed.
 */
wg_error_t wg_channel_tun_recv(wg_channel_tun_t *ct, uint8_t **out_data, size_t *out_len);

/*
 * Non-blocking receive. Returns WG_ERR_QUEUE_EMPTY if nothing available.
 */
wg_error_t wg_channel_tun_try_recv(wg_channel_tun_t *ct, uint8_t **out_data,
                                   size_t *out_len);

/*
 * Receive with timeout (milliseconds).
 * Returns WG_ERR_TIMEOUT if no packet within the timeout.
 */
wg_error_t wg_channel_tun_recv_timeout(wg_channel_tun_t *ct, uint8_t **out_data,
                                       size_t *out_len, int timeout_ms);

/*
 * Destroy a ChannelTUN instance and free resources.
 */
void wg_channel_tun_destroy(wg_channel_tun_t *ct);

#endif /* WG_TUN_CHANNEL_H */

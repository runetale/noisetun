/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * ChannelBind: in-memory bind implementation for testing.
 *
 * Creates a pair of connected bind instances that simulate UDP sockets.
 * send() on one side pushes packets into the other side's receive queue.
 *
 * Reference: wireguard-go/conn/bindtest/bindtest.go
 */

#ifndef WG_BIND_H
#define WG_BIND_H

#include "wg_error.h"
#include "wireguard.h"

#include <stdbool.h>

/* Opaque handle */
typedef struct wg_channel_bind wg_channel_bind_t;

/*
 * Create a pair of connected ChannelBind instances.
 * Packets sent on *a arrive at *b's recv, and vice versa.
 *
 * Both instances must be destroyed with wg_channel_bind_destroy().
 */
wg_error_t wg_channel_bind_pair(wg_channel_bind_t **a, wg_channel_bind_t **b);

/*
 * Get a wg_bind_ops_t populated with the ChannelBind callbacks.
 * The returned ops struct has ctx set to the channel_bind instance.
 */
wg_bind_ops_t wg_channel_bind_ops(wg_channel_bind_t *cb);

/*
 * Destroy a ChannelBind instance and free resources.
 * Must be called on both sides of the pair independently, and only once
 * the devices using BOTH sides are closed: a send on the other side
 * pushes into this side's receive queue without holding its lock.
 */
void wg_channel_bind_destroy(wg_channel_bind_t *cb);

#endif /* WG_BIND_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * macOS utun device implementation.
 *
 * Creates a utun device via PF_SYSTEM control socket, provides non-blocking
 * read/write via rwcancel, and monitors interface events via AF_ROUTE socket.
 *
 * Reference: wireguard-go/tun/tun_darwin.go
 */

#ifndef WG_TUN_DARWIN_H
#define WG_TUN_DARWIN_H

#include "wg_tun.h"
#include "wg_error.h"

typedef struct wg_tun_darwin wg_tun_darwin_t;

/*
 * Create a utun device by name and MTU.
 * name: "utun" for auto-assignment, or "utunN" for a specific index.
 * Creates utun control socket, sets non-blocking, starts route listener.
 * Requires root or appropriate entitlements.
 */
wg_error_t wg_tun_darwin_create(wg_tun_darwin_t **out, const char *name, int mtu);

/*
 * Create a utun device from an existing file descriptor.
 * No route monitoring — suitable for inherited FDs (e.g. from Network Extension).
 * The caller must have already configured the utun device.
 */
wg_error_t wg_tun_darwin_create_from_fd(wg_tun_darwin_t **out, int fd);

/*
 * Return a wg_tun_ops_t populated with macOS utun callbacks.
 * The returned struct's ctx points to the wg_tun_darwin_t.
 */
wg_tun_ops_t wg_tun_darwin_ops(wg_tun_darwin_t *tun);

/*
 * The device's file descriptor, for handing it to a daemonised child
 * (WG_TUN_FD).
 */
int wg_tun_darwin_fd(wg_tun_darwin_t *tun);

/*
 * Destroy the macOS utun device.
 * Cancels I/O, joins the route listener thread, closes all file descriptors.
 * This is also called by the ops->close() callback.
 */
void wg_tun_darwin_destroy(wg_tun_darwin_t *tun);

#endif /* WG_TUN_DARWIN_H */

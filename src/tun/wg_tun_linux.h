/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Linux TUN device implementation.
 *
 * Opens /dev/net/tun with IFF_TUN | IFF_NO_PI, provides non-blocking
 * read/write via rwcancel, and monitors interface events via netlink.
 *
 * Reference: wireguard-go/tun/tun_linux.go
 */

#ifndef WG_TUN_LINUX_H
#define WG_TUN_LINUX_H

#include "wg_tun.h"
#include "wg_error.h"

typedef struct wg_tun_linux wg_tun_linux_t;

/*
 * Create a TUN device by name and MTU.
 * Opens /dev/net/tun, configures IFF_TUN|IFF_NO_PI, sets non-blocking,
 * starts netlink listener thread for interface events.
 * Requires CAP_NET_ADMIN.
 */
wg_error_t wg_tun_linux_create(wg_tun_linux_t **out, const char *name, int mtu);

/*
 * Create a TUN device from an existing file descriptor.
 * No netlink monitoring — suitable for inherited FDs (e.g. from Android).
 * The caller must have already configured the TUN device.
 */
wg_error_t wg_tun_linux_create_from_fd(wg_tun_linux_t **out, int fd);

/*
 * Return a wg_tun_ops_t populated with Linux TUN callbacks.
 * The returned struct's ctx points to the wg_tun_linux_t.
 */
wg_tun_ops_t wg_tun_linux_ops(wg_tun_linux_t *tun);

/*
 * The device's file descriptor, for handing it to a daemonised child
 * (WG_TUN_FD).
 */
int wg_tun_linux_fd(wg_tun_linux_t *tun);

/*
 * Destroy the Linux TUN device.
 * Cancels I/O, joins the netlink thread, closes all file descriptors.
 * This is also called by the ops->close() callback.
 */
void wg_tun_linux_destroy(wg_tun_linux_t *tun);

/*
 * Set an optional stats pointer for GRO diagnostic counters.
 * Must be called before starting workers.  stats should point
 * to a wg_stats_t (passed as void* to avoid header dependency).
 */
void wg_tun_linux_set_gro_stats(wg_tun_linux_t *tun, void *stats);

#endif /* WG_TUN_LINUX_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * StdNetBind: standard UDP socket bind implementation.
 *
 * Opens dual IPv4/IPv6 UDP sockets on the same port.
 * Implements wg_bind_ops_t for real network I/O.
 *
 * Reference: wireguard-go/conn/bind_std.go
 */

#ifndef WG_BIND_STD_H
#define WG_BIND_STD_H

#include "wireguard.h"

typedef struct wg_std_bind wg_std_bind_t;

/*
 * Allocate a new StdNetBind (sockets not yet open).
 * Call wg_std_bind_ops() to get the bind ops, then open() to bind.
 */
wg_error_t wg_std_bind_new(wg_std_bind_t **out);

/*
 * Return a wg_bind_ops_t struct pointing to this StdNetBind.
 */
wg_bind_ops_t wg_std_bind_ops(wg_std_bind_t *bind);

/*
 * The UDP socket for AF_INET or AF_INET6, or -1 while it is closed. For
 * callers that must act on the socket itself, such as Android's
 * VpnService.protect(), which keeps it out of the VPN. The fd is closed
 * and replaced whenever the bind reopens (a port change, a network
 * change), so ask again after one.
 */
int wg_std_bind_socket_fd(wg_std_bind_t *bind, int family);

/*
 * Destroy the StdNetBind, closing any open sockets.
 */
void wg_std_bind_destroy(wg_std_bind_t *bind);

#endif /* WG_BIND_STD_H */

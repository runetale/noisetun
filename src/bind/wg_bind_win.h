/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * WinRingBind: Windows Registered I/O (RIO) UDP bind implementation.
 *
 * Uses the Winsock Registered I/O extensions for high-performance
 * zero-copy UDP packet I/O. Falls back to standard WSASendTo/WSARecvFrom
 * if RIO is not available (Windows 7 or older).
 *
 * Reference: wireguard-go/conn/bind_windows.go
 *            wireguard-go/conn/winrio/rio_windows.go
 */

#ifndef WG_BIND_WIN_H
#define WG_BIND_WIN_H

#ifdef _WIN32

#include "wg_error.h"
#include "wireguard.h"
#include <windows.h>

typedef struct wg_win_bind wg_win_bind_t;

/*
 * Create a Windows UDP bind (RIO-based if available, fallback otherwise).
 * Does not bind to a port yet — call open() via the ops.
 */
wg_error_t wg_win_bind_create(wg_win_bind_t **out);

/*
 * Get the wg_bind_ops_t for this bind instance.
 */
wg_bind_ops_t wg_win_bind_ops(wg_win_bind_t *bind);

/*
 * Destroy the Windows bind and free all resources.
 */
void wg_win_bind_destroy(wg_win_bind_t *bind);

/*
 * Bind IPv4 socket to a specific interface (routing loop prevention).
 * Sets IP_UNICAST_IF. If blackhole is TRUE, all IPv4 sends are silently dropped.
 */
int wg_win_bind_socket_to_interface4(wg_win_bind_t *bind, uint32_t iface_index,
                                     BOOL blackhole);

/*
 * Bind IPv6 socket to a specific interface.
 * Sets IPV6_UNICAST_IF. If blackhole is TRUE, all IPv6 sends are silently dropped.
 */
int wg_win_bind_socket_to_interface6(wg_win_bind_t *bind, uint32_t iface_index,
                                     BOOL blackhole);

#endif /* _WIN32 */
#endif /* WG_BIND_WIN_H */

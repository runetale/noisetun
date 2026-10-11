/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Windows TUN device implementation using Wintun.
 *
 * Wintun provides a lightweight, kernel-mode TUN adapter for Windows.
 * We load wintun.dll dynamically and use its ring-buffer based packet I/O.
 *
 * Reference: https://www.wintun.net/
 *            wireguard-go/tun/tun_windows.go
 */

#ifndef WG_TUN_WINDOWS_H
#define WG_TUN_WINDOWS_H

#ifdef _WIN32

#include "wg_tun.h"
#include "wg_error.h"

typedef struct wg_tun_windows wg_tun_windows_t;

/*
 * Create a Wintun TUN device.
 * name: adapter name (e.g., "WireGuard")
 * tunnel_type: tunnel type string shown in Windows (e.g., "WireGuard")
 * guid: optional GUID string for the adapter (NULL for auto-generated)
 * mtu: desired MTU
 *
 * Loads wintun.dll, creates adapter and starts a session.
 * Requires Administrator privileges.
 */
wg_error_t wg_tun_windows_create(wg_tun_windows_t **out, const char *name,
                                 const char *tunnel_type, const char *guid, int mtu);

/*
 * Return a wg_tun_ops_t populated with Windows Wintun callbacks.
 * The returned struct's ctx points to the wg_tun_windows_t.
 */
wg_tun_ops_t wg_tun_windows_ops(wg_tun_windows_t *tun);

/*
 * Destroy the Windows TUN device.
 * Ends the Wintun session, closes the adapter, and frees the DLL.
 */
void wg_tun_windows_destroy(wg_tun_windows_t *tun);

/*
 * Get the adapter's LUID (Locally Unique Identifier).
 * Used for configuring routes, firewall rules, and DNS via Windows APIs.
 * Returns 0 on success, -1 if LUID retrieval is not supported.
 */
int wg_tun_windows_get_luid(wg_tun_windows_t *tun, void *luid, size_t luid_size);

#endif /* _WIN32 */
#endif /* WG_TUN_WINDOWS_H */

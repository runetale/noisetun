/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * UAPI socket server: accepts IPC connections on a UNIX domain socket
 * at /var/run/wireguard/<name>.sock and delegates get/set operations
 * to wg_uapi_get() / wg_uapi_set().
 *
 * Protocol-compatible with wireguard-go / wireguard-tools `wg` command.
 *
 * Reference: wireguard-go/ipc/uapi_unix.go
 *            wireguard-go/device/uapi.go  IpcHandle()
 */

#ifndef WG_UAPI_SERVER_H
#define WG_UAPI_SERVER_H

#include "wireguard.h"

typedef struct wg_uapi_server wg_uapi_server_t;

/*
 * Create a UAPI server for the given device and interface name.
 * Creates /var/run/wireguard/<iface_name>.sock.
 * Does NOT start accepting connections yet — call wg_uapi_server_run().
 */
wg_error_t wg_uapi_server_create(wg_uapi_server_t **out, wg_device_t *dev,
                                 const char *iface_name);

/*
 * Create a UAPI server from an existing listening socket fd.
 * Used when WG_UAPI_FD is set (daemonization).
 */
/*
 * Create /var/run/wireguard/<iface_name>.sock and return its listening fd
 * (or -1), without a server around it. The daemonising parent opens it
 * and hands it to the child as WG_UAPI_FD, as wireguard-go's UAPIOpen.
 */
int wg_uapi_listen(const char *iface_name);

wg_error_t wg_uapi_server_create_from_fd(wg_uapi_server_t **out, wg_device_t *dev, int fd,
                                         const char *iface_name);

/*
 * Run the accept loop (blocking).
 * Each connection is handled inline: read operation, process, respond.
 * Returns when wg_uapi_server_stop() is called or on fatal error.
 */
wg_error_t wg_uapi_server_run(wg_uapi_server_t *srv);

/*
 * Signal the server to stop accepting connections.
 * Safe to call from a signal handler or another thread.
 */
void wg_uapi_server_stop(wg_uapi_server_t *srv);

/*
 * Destroy the server, close the socket, and unlink the socket file.
 */
void wg_uapi_server_destroy(wg_uapi_server_t *srv);

#endif /* WG_UAPI_SERVER_H */

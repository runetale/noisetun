/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * wireguard.h -- Public API for libwireguard.
 *
 * This is the single header that consumers include.
 * Internal headers (wg_noise.h, wg_session.h, etc.) are not part of the
 * public API and may change without notice.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include "wg_constants.h"
#include "wg_error.h"
#include "wg_messages.h"
#include "wg_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────
 * Opaque handles
 * ──────────────────────────────────────── */
typedef struct wg_device wg_device_t;
typedef struct wg_peer wg_peer_t;

/* ────────────────────────────────────────
 * TUN device abstraction
 *
 * Callers populate this struct with function pointers for their
 * platform-specific TUN implementation.  All callbacks receive the
 * opaque `ctx` pointer.
 *
 * Reference: wireguard-go/tun/tun.go  Device interface
 * ──────────────────────────────────────── */
typedef struct {
    int (*read)(void *ctx, uint8_t **bufs, int *sizes, int count, int offset);
    int (*write)(void *ctx, uint8_t **bufs, const int *sizes, int count, int offset);
    int (*mtu)(void *ctx);
    const char *(*name)(void *ctx);
    int (*batch_size)(void *ctx);
    int (*events)(void *ctx); /* returns bitmask: WG_TUN_EVENT_* */
    /* Release the device. Called only once no thread is inside read or
     * write any more, so it may free everything. */
    void (*close)(void *ctx);
    /* Optional. Wake any thread blocked in read or write and make later
     * calls fail, without freeing anything; may be called more than once
     * and concurrently with read and write. wg_device_close() calls it
     * first, joins its threads, and only then calls close. An
     * implementation whose close frees memory must provide it. */
    void (*cancel)(void *ctx);
    void *ctx;
} wg_tun_ops_t;

/* ────────────────────────────────────────
 * UDP bind abstraction
 * ──────────────────────────────────────── */

/* UDP GSO send statistics (queried from bind implementation). */
typedef struct {
    uint64_t ok;      /* GSO sendmsg succeeded */
    uint64_t fail;    /* GSO sendmsg failed → sendmmsg fallback */
    uint64_t skip;    /* GSO skipped (size mismatch or single pkt) */
    uint64_t packets; /* total packets sent via GSO */
} wg_bind_gso_stats_t;

typedef struct {
    /* Open on `port` (0 = any). Returns the port bound, 0 if the bind has
     * no port of its own (a test bind), or a negative value on error. */
    int (*open)(void *ctx, uint16_t port);
    void (*close)(void *ctx);
    int (*send)(void *ctx, uint8_t **bufs, int *sizes, int count,
                const wg_endpoint_t *ep);
    int (*recv)(void *ctx, uint8_t **bufs, int *sizes, int count, wg_endpoint_t *eps);
    int (*set_mark)(void *ctx, uint32_t mark);
    int (*batch_size)(void *ctx);
    void (*get_gso_stats)(void *ctx, wg_bind_gso_stats_t *out);
    /* Optional. Wake a thread blocked in recv and make later recv calls
     * fail, without closing the sockets; may be called concurrently with
     * recv and send. The device calls it, joins its receive thread, and
     * only then calls close under net.lock for writing, so no thread is
     * using a socket when it is closed and its fd number reused. A bind
     * whose close releases fds that recv may still hold should provide it. */
    void (*cancel)(void *ctx);
    void *ctx;
} wg_bind_ops_t;

/* ────────────────────────────────────────
 * Logger
 * ──────────────────────────────────────── */
typedef enum {
    WG_LOG_VERBOSE,
    WG_LOG_ERROR,
    WG_LOG_SILENT,
} wg_log_level_t;

typedef struct {
    void (*log)(void *ctx, wg_log_level_t level, const char *fmt, ...);
    void *ctx;
} wg_logger_t;

/* A logger that writes to stderr, dropping messages below min_level. */
wg_logger_t wg_logger_default(wg_log_level_t min_level);

/* ────────────────────────────────────────
 * Device lifecycle
 * ──────────────────────────────────────── */
wg_error_t wg_device_new(wg_device_t **out, const wg_tun_ops_t *tun,
                         const wg_bind_ops_t *bind, const wg_logger_t *logger);

wg_error_t wg_device_up(wg_device_t *dev);
wg_error_t wg_device_down(wg_device_t *dev);
void wg_device_close(wg_device_t *dev);

/* ────────────────────────────────────────
 * Identity
 * ──────────────────────────────────────── */
wg_error_t wg_device_set_private_key(wg_device_t *dev, const wg_key_t *private_key);

/* ────────────────────────────────────────
 * Peer management
 * ──────────────────────────────────────── */
wg_error_t wg_device_add_peer(wg_device_t *dev, const wg_key_t *public_key,
                              const wg_key_t *preshared_key, wg_peer_t **out);

wg_error_t wg_peer_set_endpoint(wg_peer_t *peer, const wg_endpoint_t *ep);

wg_error_t wg_peer_add_allowed_ip(wg_peer_t *peer, const void *ip, uint8_t cidr,
                                  int family);

wg_error_t wg_peer_set_persistent_keepalive(wg_peer_t *peer, uint16_t interval_sec);

wg_error_t wg_device_remove_peer(wg_device_t *dev, const wg_key_t *public_key);

/* ────────────────────────────────────────
 * Peer stats (read-only snapshot)
 * ──────────────────────────────────────── */
typedef struct {
    wg_key_t public_key;
    wg_endpoint_t endpoint;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    int64_t last_handshake_sec;
    int32_t last_handshake_nsec;
    uint16_t persistent_keepalive;
} wg_peer_stats_t;

wg_error_t wg_device_get_peer_stats(wg_device_t *dev, wg_peer_stats_t *out,
                                    size_t *count);

/* ────────────────────────────────────────
 * UAPI (IPC text protocol)
 * ──────────────────────────────────────── */
wg_error_t wg_uapi_get(wg_device_t *dev, char *buf, size_t *len);
wg_error_t wg_uapi_set(wg_device_t *dev, const char *input, size_t len);

/*
 * Keep peers' configured endpoints: a packet from another address no
 * longer moves a peer that was given an endpoint. For mobile networks,
 * where the address a reply comes from is not one the peer can be reached
 * at (wireguard-go's DisableSomeRoamingForBrokenMobileSemantics). Applies
 * to existing peers and to peers added later through UAPI.
 */
void wg_device_disable_roaming(wg_device_t *dev);

/* ────────────────────────────────────────
 * Embedding: a tunnel on a TUN fd from the platform
 *
 * For apps on platforms that create the TUN device themselves and hand
 * over its fd: Android (VpnService.Builder.establish()) and the iOS and
 * macOS Network Extension (the utun fd of the packet tunnel provider).
 * Linux and Apple platforms only. The functions correspond to the ones
 * wireguard-go exposes to the WireGuard apps (wgTurnOn, wgTurnOff,
 * wgSetConfig, wgGetConfig, wgBumpSockets, wgGetSocketV4/V6).
 * ──────────────────────────────────────── */
#ifndef _WIN32
typedef struct wg_tunnel wg_tunnel_t;

/*
 * Start a tunnel on tun_fd, configured by `settings`: the body of a UAPI
 * "set" (private_key=..., listen_port=..., public_key=... and so on, one
 * key=value per line), as wg(8) would send it. NULL or "" starts it
 * unconfigured. The tunnel owns tun_fd from this call on, and closes it in
 * wg_tunnel_stop(), or here if starting fails. logger may be NULL.
 */
wg_error_t wg_tunnel_start(wg_tunnel_t **out, int tun_fd, const char *settings,
                           const wg_logger_t *logger);

/* Stop the tunnel and free it, closing the TUN fd and the sockets. */
void wg_tunnel_stop(wg_tunnel_t *tunnel);

/* Apply a UAPI "set" body to a running tunnel. */
wg_error_t wg_tunnel_set(wg_tunnel_t *tunnel, const char *settings);

/*
 * The tunnel's configuration and state as a UAPI "get" body, in *out,
 * which the caller frees with free(). It includes the private key.
 */
wg_error_t wg_tunnel_get(wg_tunnel_t *tunnel, char **out);

/*
 * Close and reopen the UDP sockets, for the platform's network-change
 * callback (a Wi-Fi to cellular switch, say). The socket fds change.
 */
wg_error_t wg_tunnel_bump_sockets(wg_tunnel_t *tunnel);

/* wg_device_disable_roaming() for the tunnel's device. */
void wg_tunnel_disable_roaming(wg_tunnel_t *tunnel);

/*
 * The tunnel's UDP socket for AF_INET or AF_INET6, or -1 if it is not
 * open, for Android's VpnService.protect(). Call again after a
 * listen_port change or wg_tunnel_bump_sockets().
 */
int wg_tunnel_socket_fd(wg_tunnel_t *tunnel, int family);

/* The device underneath, for the rest of this API. */
wg_device_t *wg_tunnel_device(wg_tunnel_t *tunnel);
#endif /* !_WIN32 */

/* The library version, "MAJOR.MINOR.PATCH". The one place it is set:
 * CMake reads it from here, and a build without CMake needs no define. */
#define WG_VERSION "0.1.0"
const char *wg_version(void);

/* ────────────────────────────────────────
 * Secure memory
 * ──────────────────────────────────────── */

/*
 * Securely zero a wg_key_t using sodium_memzero().
 * Guaranteed not to be optimized away by the compiler.
 */
void wg_key_zero(wg_key_t *k);

/* ────────────────────────────────────────
 * Module init / cleanup
 * ──────────────────────────────────────── */
wg_error_t wg_init(void);
void wg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_H */

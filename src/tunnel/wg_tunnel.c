/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Embedding API: a tunnel on a TUN fd that the platform created
 * (wg_tunnel_* in wireguard.h).
 *
 * The same assembly as tools/wg-c (TUN from fd, StdNetBind, device), with
 * the host app configuring it through these calls instead of a UAPI socket.
 */

#include "wireguard.h"

#include "../bind/wg_bind_std.h"
#include "../crypto/wg_crypto.h"
#include "../device/wg_device.h"
#if defined(__linux__)
#include "../tun/wg_tun_linux.h"
#elif defined(__APPLE__)
#include "../tun/wg_tun_darwin.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct wg_tunnel {
    wg_device_t *dev;
    wg_std_bind_t *bind;
};

/* Wrap tun_fd; on failure the fd is still the caller's. */
static wg_error_t tun_from_fd(int tun_fd, wg_tun_ops_t *ops)
{
#if defined(__linux__)
    wg_tun_linux_t *tun;
    wg_error_t err = wg_tun_linux_create_from_fd(&tun, tun_fd);
    if (err == WG_OK)
        *ops = wg_tun_linux_ops(tun);
    return err;
#elif defined(__APPLE__)
    wg_tun_darwin_t *tun;
    wg_error_t err = wg_tun_darwin_create_from_fd(&tun, tun_fd);
    if (err == WG_OK)
        *ops = wg_tun_darwin_ops(tun);
    return err;
#else
    (void)tun_fd;
    (void)ops;
    return WG_ERR_TUN;
#endif
}

wg_error_t wg_tunnel_start(wg_tunnel_t **out, int tun_fd, const char *settings,
                           const wg_logger_t *logger)
{
    wg_error_t err;

    if (!out || tun_fd < 0) {
        if (tun_fd >= 0)
            close(tun_fd);
        return WG_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    err = wg_init();
    if (err != WG_OK) {
        close(tun_fd);
        return err;
    }

    wg_tunnel_t *t = calloc(1, sizeof(*t));
    if (!t) {
        close(tun_fd);
        return WG_ERR_NO_MEMORY;
    }

    wg_tun_ops_t tun_ops;
    memset(&tun_ops, 0, sizeof(tun_ops));
    err = tun_from_fd(tun_fd, &tun_ops);
    if (err != WG_OK) {
        close(tun_fd);
        free(t);
        return err;
    }

    err = wg_std_bind_new(&t->bind);
    if (err != WG_OK) {
        tun_ops.close(tun_ops.ctx);
        free(t);
        return err;
    }

    wg_bind_ops_t bind_ops = wg_std_bind_ops(t->bind);
    err = wg_device_new(&t->dev, &tun_ops, &bind_ops, logger);
    if (err != WG_OK) {
        tun_ops.close(tun_ops.ctx);
        wg_std_bind_destroy(t->bind);
        free(t);
        return err;
    }

    /* Configure, then bring up, as wireguard-go's wgTurnOn does: the
     * sockets open once, on the configured port. */
    if (settings && settings[0]) {
        err = wg_uapi_set(t->dev, settings, strlen(settings));
        if (err != WG_OK)
            goto fail;
    }
    err = wg_device_up(t->dev);
    if (err != WG_OK)
        goto fail;

    *out = t;
    return WG_OK;

fail:
    wg_tunnel_stop(t);
    return err;
}

void wg_tunnel_stop(wg_tunnel_t *t)
{
    if (!t)
        return;
    /* The device closes the TUN; the bind is ours. */
    wg_device_close(t->dev);
    wg_std_bind_destroy(t->bind);
    free(t);
}

wg_error_t wg_tunnel_set(wg_tunnel_t *t, const char *settings)
{
    if (!t || !settings)
        return WG_ERR_INVALID_ARGUMENT;
    return wg_uapi_set(t->dev, settings, strlen(settings));
}

wg_error_t wg_tunnel_get(wg_tunnel_t *t, char **out)
{
    if (!t || !out)
        return WG_ERR_INVALID_ARGUMENT;
    *out = NULL;

    /* wg_uapi_get reports a short buffer, not the size it needs: grow
     * until the dump fits (a few hundred bytes per peer). */
    for (size_t cap = 4096; cap <= ((size_t)64 << 20); cap *= 2) {
        char *buf = malloc(cap + 1);
        if (!buf)
            return WG_ERR_NO_MEMORY;
        size_t len = cap;
        wg_error_t err = wg_uapi_get(t->dev, buf, &len);
        if (err == WG_OK) {
            buf[len] = '\0';
            *out = buf;
            return WG_OK;
        }
        /* The dump holds the private key: wipe what was written. */
        wg_secure_zero(buf, cap);
        free(buf);
        if (err != WG_ERR_BUFFER_TOO_SMALL)
            return err;
    }
    return WG_ERR_BUFFER_TOO_SMALL;
}

wg_error_t wg_tunnel_bump_sockets(wg_tunnel_t *t)
{
    if (!t)
        return WG_ERR_INVALID_ARGUMENT;

    /* Lock order as for a listen_port change in UAPI (#129). */
    wg_device_t *dev = t->dev;
    wg_error_t err = WG_OK;
    pthread_mutex_lock(&dev->state_lock);
    pthread_rwlock_wrlock(&dev->net.lock);
    if (wg_device_is_up(dev))
        err = wg_device_bind_update(dev);
    pthread_rwlock_unlock(&dev->net.lock);
    pthread_mutex_unlock(&dev->state_lock);
    return err;
}

void wg_tunnel_disable_roaming(wg_tunnel_t *t)
{
    if (t)
        wg_device_disable_roaming(t->dev);
}

int wg_tunnel_socket_fd(wg_tunnel_t *t, int family)
{
    return t ? wg_std_bind_socket_fd(t->bind, family) : -1;
}

wg_device_t *wg_tunnel_device(wg_tunnel_t *t)
{
    return t ? t->dev : NULL;
}

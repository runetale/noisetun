/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * UAPI: IPC text protocol for device configuration (IpcGet / IpcSet).
 *
 * Reference: wireguard-go/device/uapi.go
 */

#include "../device/wg_device.h"
#include "../peer/wg_allowedips.h"
#include "../peer/wg_peer.h"
#include "../timers/wg_timers.h"
#include "../workers/wg_workers.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Hex encode / decode
 * ──────────────────────────────────────── */

static void hex_encode(const uint8_t *data, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static bool hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len)
{
    if (hex_len != out_len * 2)
        return false;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        char tmp[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        if (sscanf(tmp, "%02x", &byte) != 1)
            return false;
        out[i] = (uint8_t)byte;
    }
    return true;
}

/* ────────────────────────────────────────
 * Endpoint parse / format
 * ──────────────────────────────────────── */

static bool parse_endpoint(const char *str, wg_endpoint_t *ep)
{
    memset(ep, 0, sizeof(*ep));

    /* IPv6: [addr]:port */
    if (str[0] == '[') {
        const char *end = strchr(str, ']');
        if (!end)
            return false;

        size_t addr_len = (size_t)(end - str - 1);
        char addr_buf[INET6_ADDRSTRLEN];
        if (addr_len >= sizeof(addr_buf))
            return false;
        memcpy(addr_buf, str + 1, addr_len);
        addr_buf[addr_len] = '\0';

        if (end[1] != ':')
            return false;

        char *endp;
        unsigned long port = strtoul(end + 2, &endp, 10);
        if (endp == end + 2 || *endp != '\0' || port > 65535)
            return false;

        ep->addr.sa6.sin6_family = AF_INET6;
        ep->addr.sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, addr_buf, &ep->addr.sa6.sin6_addr) != 1)
            return false;
        return true;
    }

    /* IPv4: addr:port — find last ':' to handle the port */
    const char *colon = strrchr(str, ':');
    if (!colon)
        return false;

    size_t addr_len = (size_t)(colon - str);
    char addr_buf[INET_ADDRSTRLEN];
    if (addr_len >= sizeof(addr_buf))
        return false;
    memcpy(addr_buf, str, addr_len);
    addr_buf[addr_len] = '\0';

    char *endp;
    unsigned long port = strtoul(colon + 1, &endp, 10);
    if (endp == colon + 1 || *endp != '\0' || port > 65535)
        return false;

    ep->addr.sa4.sin_family = AF_INET;
    ep->addr.sa4.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr_buf, &ep->addr.sa4.sin_addr) != 1)
        return false;
    return true;
}

static int format_endpoint(const wg_endpoint_t *ep, char *buf, size_t cap)
{
    if (ep->addr.sa.sa_family == AF_INET6) {
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ep->addr.sa6.sin6_addr, addr, sizeof(addr));
        return snprintf(buf, cap, "[%s]:%u", addr, ntohs(ep->addr.sa6.sin6_port));
    }
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ep->addr.sa4.sin_addr, addr, sizeof(addr));
    return snprintf(buf, cap, "%s:%u", addr, ntohs(ep->addr.sa4.sin_port));
}

/* ────────────────────────────────────────
 * CIDR parse
 * ──────────────────────────────────────── */

static bool parse_cidr(const char *str, uint8_t *ip_out, uint8_t *cidr_out,
                       int *family_out)
{
    const char *slash = strchr(str, '/');
    if (!slash)
        return false;

    size_t addr_len = (size_t)(slash - str);
    char addr_buf[INET6_ADDRSTRLEN];
    if (addr_len >= sizeof(addr_buf))
        return false;
    memcpy(addr_buf, str, addr_len);
    addr_buf[addr_len] = '\0';

    char *cidr_endp;
    unsigned long cidr = strtoul(slash + 1, &cidr_endp, 10);
    if (cidr_endp == slash + 1 || *cidr_endp != '\0')
        return false;

    /* Try IPv4 first. */
    struct in_addr in4;
    if (inet_pton(AF_INET, addr_buf, &in4) == 1) {
        if (cidr > 32)
            return false;
        memcpy(ip_out, &in4, 4);
        *cidr_out = (uint8_t)cidr;
        *family_out = AF_INET;
        return true;
    }

    /* Try IPv6. */
    struct in6_addr in6;
    if (inet_pton(AF_INET6, addr_buf, &in6) == 1) {
        if (cidr > 128)
            return false;
        memcpy(ip_out, &in6, 16);
        *cidr_out = (uint8_t)cidr;
        *family_out = AF_INET6;
        return true;
    }

    return false;
}

/* ────────────────────────────────────────
 * Buffer append helper
 * ──────────────────────────────────────── */

static bool buf_append(char **pos, size_t *remaining, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*pos, *remaining, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= *remaining)
        return false;

    *pos += n;
    *remaining -= (size_t)n;
    return true;
}

/* ────────────────────────────────────────
 * AllowedIPs visitor for GET
 * ──────────────────────────────────────── */

typedef struct {
    char **pos;
    size_t *remaining;
    bool ok;
} get_aip_ctx_t;

static bool get_aip_visitor(const uint8_t *ip, uint8_t cidr, int family, void *ctx)
{
    get_aip_ctx_t *gc = ctx;
    char addr[INET6_ADDRSTRLEN];

    if (family == AF_INET)
        inet_ntop(AF_INET, ip, addr, sizeof(addr));
    else
        inet_ntop(AF_INET6, ip, addr, sizeof(addr));

    if (!buf_append(gc->pos, gc->remaining, "allowed_ip=%s/%u\n", addr, (unsigned)cidr)) {
        gc->ok = false;
        return false;
    }
    return true;
}

/* ────────────────────────────────────────
 * wg_uapi_get — serialize device state
 * ──────────────────────────────────────── */

wg_error_t wg_uapi_get(wg_device_t *dev, char *buf, size_t *len)
{
    if (!dev || !len)
        return WG_ERR_INVALID_ARGUMENT;

    char *pos = buf;
    size_t remaining = buf ? *len : 0;
    bool truncated = false;

    /* Device keys. */
    pthread_rwlock_rdlock(&dev->static_identity.lock);
    if (dev->static_identity.has_identity) {
        char hex[WG_KEY_LEN * 2 + 1];
        hex_encode(dev->static_identity.static_private, WG_KEY_LEN, hex);
        buf_append(&pos, &remaining, "private_key=%s\n", hex);
    }
    pthread_rwlock_unlock(&dev->static_identity.lock);

    pthread_rwlock_rdlock(&dev->net.lock);
    if (dev->net.port != 0)
        buf_append(&pos, &remaining, "listen_port=%u\n", dev->net.port);
    if (dev->net.fwmark != 0)
        buf_append(&pos, &remaining, "fwmark=%u\n", dev->net.fwmark);
    pthread_rwlock_unlock(&dev->net.lock);

    /* Peers. */
    pthread_rwlock_rdlock(&dev->peers.lock);
    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;

        struct wg_peer *p = dev->peers.entries[i].peer;

        /* public_key */
        char hex[WG_KEY_LEN * 2 + 1];
        hex_encode(dev->peers.entries[i].public_key, WG_KEY_LEN, hex);
        buf_append(&pos, &remaining, "public_key=%s\n", hex);

        /* preshared_key */
        pthread_rwlock_rdlock(&p->handshake.lock);
        hex_encode(p->handshake.preshared_key, WG_KEY_LEN, hex);
        pthread_rwlock_unlock(&p->handshake.lock);
        buf_append(&pos, &remaining, "preshared_key=%s\n", hex);

        /* protocol_version */
        buf_append(&pos, &remaining, "protocol_version=1\n");

        /* endpoint */
        wg_endpoint_t ep;
        if (wg_peer_get_endpoint(p, &ep)) {
            char ep_buf[128];
            format_endpoint(&ep, ep_buf, sizeof(ep_buf));
            buf_append(&pos, &remaining, "endpoint=%s\n", ep_buf);
        }

        /* last_handshake_time */
        int64_t hs_ns = atomic_load(&p->last_handshake_ns);
        buf_append(&pos, &remaining, "last_handshake_time_sec=%lld\n",
                   (long long)(hs_ns / 1000000000LL));
        buf_append(&pos, &remaining, "last_handshake_time_nsec=%lld\n",
                   (long long)(hs_ns % 1000000000LL));

        /* traffic */
        buf_append(&pos, &remaining, "tx_bytes=%llu\n",
                   (unsigned long long)atomic_load(&p->tx_bytes));
        buf_append(&pos, &remaining, "rx_bytes=%llu\n",
                   (unsigned long long)atomic_load(&p->rx_bytes));

        /* persistent_keepalive_interval */
        uint32_t ka = atomic_load(&p->persistent_keepalive_interval);
        buf_append(&pos, &remaining, "persistent_keepalive_interval=%u\n", ka);

        /* allowed_ips */
        get_aip_ctx_t aip_ctx = {&pos, &remaining, true};
        wg_allowedips_walk_by_peer(&dev->allowedips, p, get_aip_visitor, &aip_ctx);
        if (!aip_ctx.ok)
            truncated = true;
    }
    pthread_rwlock_unlock(&dev->peers.lock);

    /* Terminate. */
    if (!buf_append(&pos, &remaining, "\n"))
        truncated = true;

    *len = (size_t)(pos - buf);
    return truncated ? WG_ERR_BUFFER_TOO_SMALL : WG_OK;
}

/* ────────────────────────────────────────
 * wg_uapi_set — apply configuration
 * ──────────────────────────────────────── */

/*
 * The end of a peer's section. A peer this call created gets the
 * device's roaming policy (wireguard-go's handlePostConfig) and, on a
 * running device, is started.
 */
static void finish_peer(wg_device_t *dev, struct wg_peer *peer, bool created)
{
    if (!peer || !created)
        return;

    pthread_rwlock_rdlock(&dev->net.lock);
    bool broken_roaming = dev->net.broken_roaming;
    pthread_rwlock_unlock(&dev->net.lock);
    if (broken_roaming) {
        pthread_mutex_lock(&peer->endpoint.lock);
        peer->endpoint.disable_roaming = peer->endpoint.has_value;
        pthread_mutex_unlock(&peer->endpoint.lock);
    }

    if (wg_device_is_up(dev))
        wg_peer_start(peer);
}

wg_error_t wg_uapi_set(wg_device_t *dev, const char *input, size_t len)
{
    if (!dev || !input)
        return WG_ERR_INVALID_ARGUMENT;

    wg_error_t result = WG_OK;
    struct wg_peer *cur_peer = NULL;
    bool device_mode = true; /* start in device config mode */
    bool peer_created = false;

    const char *p = input;
    const char *end = input + len;

    while (p < end) {
        /* Find end of line. */
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol)
            eol = end;

        size_t line_len = (size_t)(eol - p);

        /* Empty line = end of config. */
        if (line_len == 0)
            break;

        /* Find '=' separator. A line without one is an error, as in
         * wireguard-go: silently skipping it would report success for a
         * configuration that was not applied. */
        const char *eq = memchr(p, '=', line_len);
        if (!eq) {
            result = WG_ERR_INVALID_ARGUMENT;
            break;
        }

        size_t key_len = (size_t)(eq - p);
        const char *val = eq + 1;
        size_t val_len = (size_t)(eol - val);

        /* Null-terminate the value for parsing. No legal value comes near
         * this size; a longer one is rejected, not truncated. */
        char val_buf[512];
        if (val_len >= sizeof(val_buf)) {
            result = WG_ERR_INVALID_ARGUMENT;
            break;
        }
        memcpy(val_buf, val, val_len);
        val_buf[val_len] = '\0';

#define KEY_IS(s) (key_len == sizeof(s) - 1 && memcmp(p, s, key_len) == 0)

        /* ── public_key switches to peer mode ── */

        if (KEY_IS("public_key")) {
            /* Finish previous peer. */
            finish_peer(dev, cur_peer, peer_created);

            device_mode = false;
            peer_created = false;
            cur_peer = NULL;

            wg_key_t pk;
            if (!hex_decode(val_buf, val_len, pk.key, WG_KEY_LEN)) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }

            /* Look up or create peer. */
            cur_peer = wg_device_lookup_peer(dev, pk.key);
            if (!cur_peer) {
                wg_error_t err = wg_device_add_peer(dev, &pk, NULL, &cur_peer);
                if (err != WG_OK) {
                    result = err;
                    break;
                }
                peer_created = true;
            }

            p = eol + 1;
            continue;
        }

        /* ── Device-mode keys ── */

        if (device_mode) {
            if (KEY_IS("private_key")) {
                wg_key_t sk;
                bool ok = hex_decode(val_buf, val_len, sk.key, WG_KEY_LEN);
                if (ok)
                    wg_device_set_private_key(dev, &sk);
                wg_key_zero(&sk);
                if (!ok) {
                    result = WG_ERR_INVALID_ARGUMENT;
                    break;
                }

            } else if (KEY_IS("listen_port")) {
                char *endp;
                unsigned long port_val = strtoul(val_buf, &endp, 10);
                if (endp == val_buf || *endp != '\0' || val_buf[0] == '-' ||
                    port_val > 65535) {
                    result = WG_ERR_INVALID_ARGUMENT;
                    break;
                }
                /* state_lock first, as up/down take it: the rebind drops
                 * net.lock while it joins the receive thread, and must not
                 * let the device go down and up in that window (#129). */
                pthread_mutex_lock(&dev->state_lock);
                pthread_rwlock_wrlock(&dev->net.lock);
                uint16_t old_port = dev->net.port;
                dev->net.port = (uint16_t)port_val;
                /* Re-bind if port changed and device is UP. */
                if (dev->net.port != old_port && wg_device_is_up(dev)) {
                    wg_device_bind_update(dev);
                }
                pthread_rwlock_unlock(&dev->net.lock);
                pthread_mutex_unlock(&dev->state_lock);

            } else if (KEY_IS("fwmark")) {
                /* Empty means 0, as in wireguard-go. */
                unsigned long mark = 0;
                if (val_len > 0) {
                    char *endp;
                    errno = 0;
                    mark = strtoul(val_buf, &endp, 10);
                    if (*endp != '\0' || errno || mark > UINT32_MAX ||
                        val_buf[0] == '-') {
                        result = WG_ERR_INVALID_ARGUMENT;
                        break;
                    }
                }
                pthread_rwlock_wrlock(&dev->net.lock);
                dev->net.fwmark = (uint32_t)mark;
                if (dev->net.bind.set_mark)
                    dev->net.bind.set_mark(dev->net.bind.ctx, dev->net.fwmark);
                pthread_rwlock_unlock(&dev->net.lock);

            } else if (KEY_IS("replace_peers")) {
                if (strcmp(val_buf, "true") != 0) {
                    result = WG_ERR_INVALID_ARGUMENT;
                    break;
                }
                wg_device_remove_all_peers(dev);

            } else {
                /* Unknown device key: wireguard-go rejects it too. */
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }

            p = eol + 1;
            continue;
        }

        /* ── Peer-mode keys ──
         *
         * Every value is checked even when there is no live peer (after
         * remove=true or update_only=true on an unknown key), as
         * wireguard-go checks its dummy peer: a bad value is an error
         * either way. Only the applying needs cur_peer. */

        if (KEY_IS("remove")) {
            if (strcmp(val_buf, "true") != 0) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            if (cur_peer) {
                /* Get public key for removal. */
                pthread_rwlock_rdlock(&cur_peer->handshake.lock);
                wg_key_t pk;
                memcpy(pk.key, cur_peer->handshake.remote_static, WG_KEY_LEN);
                pthread_rwlock_unlock(&cur_peer->handshake.lock);
                cur_peer = NULL;
                peer_created = false;
                wg_device_remove_peer(dev, &pk);
            }

        } else if (KEY_IS("preshared_key")) {
            uint8_t psk[WG_KEY_LEN];
            bool ok = hex_decode(val_buf, val_len, psk, WG_KEY_LEN);
            if (ok && cur_peer) {
                pthread_rwlock_wrlock(&cur_peer->handshake.lock);
                memcpy(cur_peer->handshake.preshared_key, psk, WG_KEY_LEN);
                pthread_rwlock_unlock(&cur_peer->handshake.lock);
            }
            sodium_memzero(psk, sizeof(psk));
            if (!ok) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }

        } else if (KEY_IS("endpoint")) {
            wg_endpoint_t ep;
            if (!parse_endpoint(val_buf, &ep)) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            if (cur_peer)
                wg_peer_set_endpoint(cur_peer, &ep);

        } else if (KEY_IS("persistent_keepalive_interval")) {
            char *ka_endp;
            unsigned long interval = strtoul(val_buf, &ka_endp, 10);
            if (ka_endp == val_buf || *ka_endp != '\0' || val_buf[0] == '-' ||
                interval > 65535) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            if (cur_peer)
                wg_peer_set_persistent_keepalive(cur_peer, (uint16_t)interval);

        } else if (KEY_IS("replace_allowed_ips")) {
            if (strcmp(val_buf, "true") != 0) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            if (cur_peer)
                wg_allowedips_remove_by_peer(&dev->allowedips, cur_peer);

        } else if (KEY_IS("allowed_ip")) {
            /* "-<prefix>" removes that prefix from this peer (wireguard-go,
             * and wg(8) "allowed-ips -<prefix>"). Ignoring it would leave a
             * route in place that the operator believes is gone. */
            bool remove = val_buf[0] == '-';
            uint8_t ip[16];
            uint8_t cidr;
            int family;
            if (!parse_cidr(val_buf + (remove ? 1 : 0), ip, &cidr, &family)) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            if (cur_peer) {
                if (remove)
                    wg_allowedips_remove(&dev->allowedips, ip, cidr, family, cur_peer);
                else
                    wg_peer_add_allowed_ip(cur_peer, ip, cidr, family);
            }

        } else if (KEY_IS("protocol_version")) {
            if (strcmp(val_buf, "1") != 0) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }

        } else if (KEY_IS("update_only")) {
            if (strcmp(val_buf, "true") != 0) {
                result = WG_ERR_INVALID_ARGUMENT;
                break;
            }
            /* If peer wasn't found (only created), remove it. */
            if (cur_peer && peer_created) {
                pthread_rwlock_rdlock(&cur_peer->handshake.lock);
                wg_key_t pk;
                memcpy(pk.key, cur_peer->handshake.remote_static, WG_KEY_LEN);
                pthread_rwlock_unlock(&cur_peer->handshake.lock);
                cur_peer = NULL;
                peer_created = false;
                wg_device_remove_peer(dev, &pk);
            }

        } else {
            /* Unknown peer key: wireguard-go rejects it too. */
            result = WG_ERR_INVALID_ARGUMENT;
            break;
        }

#undef KEY_IS

        p = eol + 1;
    }

    /* Finish last peer. */
    finish_peer(dev, cur_peer, peer_created);

    return result;
}

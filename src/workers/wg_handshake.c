/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * DEV-11: Handshake worker — processes handshake messages from the
 * handshake queue (initiation, response, cookie reply).
 *
 * Also provides send functions for handshake initiation, response,
 * cookie reply, and keepalive.
 *
 * Reference: wireguard-go/device/receive.go (RoutineHandshake)
 *            wireguard-go/device/send.go (SendHandshakeInitiation,
 *            SendHandshakeResponse, SendHandshakeCookie, SendKeepalive)
 */

#include "wg_workers.h"

#include "../cookie/wg_cookie.h"
#include "../device/wg_pools.h"
#include "../ratelimiter/wg_ratelimiter.h"
#include "../session/wg_session.h"
#include "../timers/wg_timers.h"
#include "../device/wg_logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

/* ────────────────────────────────────────
 * Handshake element allocation
 * ──────────────────────────────────────── */

wg_handshake_elem_t *wg_handshake_elem_new(void)
{
    wg_handshake_elem_t *e = calloc(1, sizeof(*e));
    return e;
}

void wg_handshake_elem_free(void *elem)
{
    free(elem);
}

/* Helper: send a raw buffer to an endpoint (no peer context) */
static wg_error_t device_send_to_endpoint(wg_device_t *dev, uint8_t *buf, size_t len,
                                          const wg_endpoint_t *ep)
{
    pthread_rwlock_rdlock(&dev->net.lock);
    if (!dev->net.bind.send) {
        pthread_rwlock_unlock(&dev->net.lock);
        return WG_ERR_BIND;
    }

    uint8_t *bufs[1] = {buf};
    int sizes[1] = {(int)len};
    int ret = dev->net.bind.send(dev->net.bind.ctx, bufs, sizes, 1, ep);
    pthread_rwlock_unlock(&dev->net.lock);

    return (ret > 0) ? WG_OK : WG_ERR_SEND;
}

/* ────────────────────────────────────────
 * Handshake logging (verbose)
 *
 * The worker used to discard handshake messages silently, which left a
 * peer whose handshakes never complete undiagnosable. Log each discard
 * with its reason and sender, and each handshake step that succeeds.
 * ──────────────────────────────────────── */

static void format_sender(const wg_endpoint_t *ep, char *buf, size_t cap)
{
    if (ep->addr.sa.sa_family == AF_INET6) {
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ep->addr.sa6.sin6_addr, addr, sizeof(addr));
        snprintf(buf, cap, "[%s]:%u", addr, ntohs(ep->addr.sa6.sin6_port));
        return;
    }
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ep->addr.sa4.sin_addr, addr, sizeof(addr));
    snprintf(buf, cap, "%s:%u", addr, ntohs(ep->addr.sa4.sin_port));
}

static const char *message_name(uint8_t msg_type)
{
    switch (msg_type) {
    case WG_MESSAGE_INITIATION:
        return "initiation";
    case WG_MESSAGE_RESPONSE:
        return "response";
    case WG_MESSAGE_COOKIE_REPLY:
        return "cookie reply";
    default:
        return "message";
    }
}

/* Logs "handshake: <event> <message> from <sender> [(peer <key prefix>)]: <detail>".
 * The key prefix is the first 6 bytes in hex, as runetaled prints keys. */
static void log_handshake(wg_device_t *dev, const wg_handshake_elem_t *elem,
                          const char *event, const uint8_t *peer_key, const char *detail)
{
    if (!dev->logger.log)
        return;

    char sender[64];
    format_sender(&elem->endpoint, sender, sizeof(sender));

    char peer[24] = "";
    if (peer_key)
        snprintf(peer, sizeof(peer), " (peer %02x%02x%02x%02x%02x%02x)", peer_key[0],
                 peer_key[1], peer_key[2], peer_key[3], peer_key[4], peer_key[5]);

    wg_log_verbose(dev, "handshake: %s %s from %s%s: %s", event,
                   message_name(elem->msg_type), sender, peer, detail);
}

/* ────────────────────────────────────────
 * Consume initiation: 1-pass approach
 *
 * Phase 1: decrypt initiator's static public key using device identity
 *          (es DH only — no ss DH yet).
 * Phase 2: look up peer, then commit using peer's precomputed ss.
 *
 * This avoids redundant DH calculations. Matches wireguard-go
 * ConsumeMessageInitiation() which uses precomputedStaticStatic.
 * ──────────────────────────────────────── */

static struct wg_peer *device_consume_initiation(wg_device_t *dev,
                                                 const wg_handshake_elem_t *elem,
                                                 const wg_message_initiation_t *msg)
{
    /* Phase 1: decrypt static key (device-level, es DH only) */
    wg_initiation_half_t half;
    wg_error_t err =
        wg_noise_consume_initiation_decrypt_static(&dev->static_identity, msg, &half);
    if (err != WG_OK) {
        log_handshake(dev, elem, "dropped", NULL, wg_error_str(err));
        return NULL;
    }

    /* Look up peer by decrypted static key */
    struct wg_peer *peer = wg_device_lookup_peer(dev, half.decrypted_static);
    if (!peer || !atomic_load(&peer->is_running)) {
        log_handshake(dev, elem, "dropped", half.decrypted_static,
                      peer ? "peer not running" : "unknown peer");
        wg_secure_zero(&half, sizeof(half));
        return NULL;
    }

    /* Phase 2: commit to peer's handshake (ss DH + timestamp) */
    err = wg_noise_consume_initiation_commit(&peer->handshake, msg, &half);
    if (err != WG_OK)
        log_handshake(dev, elem, "dropped", half.decrypted_static, wg_error_str(err));
    wg_secure_zero(&half, sizeof(half));
    if (err != WG_OK)
        return NULL;

    return peer;
}

/* ────────────────────────────────────────
 * Consume response: look up peer via index table,
 * then consume on the peer's handshake.
 * ──────────────────────────────────────── */

static struct wg_peer *device_consume_response(wg_device_t *dev,
                                               const wg_handshake_elem_t *elem,
                                               const wg_message_response_t *msg)
{
    uint32_t receiver = wg_le32toh(msg->receiver_index);

    wg_index_entry_t entry;
    if (!wg_index_table_lookup_copy(&dev->index_table, receiver, &entry)) {
        log_handshake(dev, elem, "dropped", NULL, "unknown receiver index");
        return NULL;
    }

    if (entry.type != WG_INDEX_ENTRY_HANDSHAKE || !entry.peer) {
        log_handshake(dev, elem, "dropped", NULL,
                      "receiver index is not a pending handshake");
        return NULL;
    }

    struct wg_peer *peer = entry.peer;

    wg_error_t err = wg_noise_handshake_consume_response(&peer->handshake, msg);
    if (err != WG_OK) {
        log_handshake(dev, elem, "dropped", NULL, wg_error_str(err));
        return NULL;
    }

    return peer;
}

/* ────────────────────────────────────────
 * DEV-11: Handshake Worker
 *
 * Processes handshake messages from device.queue.handshake.
 * Single thread per device.
 *
 * Reference: wireguard-go/device/receive.go RoutineHandshake
 * ──────────────────────────────────────── */

void *wg_worker_handshake(void *arg)
{
    wg_device_t *dev = arg;

    for (;;) {
        void *raw = NULL;
        wg_error_t err = wg_queue_pop(dev->queue.handshake, &raw);
        if (err != WG_OK)
            break; /* queue closed */

        wg_handshake_elem_t *elem = raw;

        /* Peers found below stay in use until skip: */
        wg_peer_reader_enter(dev, &dev->hs_peer_gen);

        /* ── Handle cookie reply (no MAC checks needed) ── */

        if (elem->msg_type == WG_MESSAGE_COOKIE_REPLY) {
            if (elem->packet_len != WG_MESSAGE_COOKIE_REPLY_SIZE)
                goto skip;

            const wg_message_cookie_reply_t *reply =
                (const wg_message_cookie_reply_t *)elem->buffer;
            uint32_t receiver = wg_le32toh(reply->receiver_index);

            wg_index_entry_t entry;
            if (!wg_index_table_lookup_copy(&dev->index_table, receiver, &entry))
                goto skip;
            if (!entry.peer)
                goto skip;

            struct wg_peer *peer = entry.peer;
            if (atomic_load(&peer->is_running))
                wg_cookie_generator_consume_reply(&peer->cookie_generator, reply);
            goto skip;
        }

        /* ── Initiation or Response: validate MACs ── */

        if (elem->msg_type != WG_MESSAGE_INITIATION &&
            elem->msg_type != WG_MESSAGE_RESPONSE)
            goto skip;

        /* Check MAC1 */
        if (!wg_cookie_checker_check_mac1(&dev->cookie_checker, elem->buffer,
                                          elem->packet_len)) {
            log_handshake(dev, elem, "dropped", NULL, "invalid mac1");
            goto skip;
        }

        /* Under load: verify MAC2 + rate limit */
        if (wg_device_is_under_load(dev)) {
            /* Extract source address bytes for MAC2 check.
             * Use sockaddr directly for rate-limiter and cookie. */
            const uint8_t *src_bytes = (const uint8_t *)&elem->endpoint.addr;
            size_t src_len;
            if (elem->endpoint.addr.sa.sa_family == AF_INET6)
                src_len = sizeof(struct sockaddr_in6);
            else
                src_len = sizeof(struct sockaddr_in);

            if (!wg_cookie_checker_check_mac2(&dev->cookie_checker, elem->buffer,
                                              elem->packet_len, src_bytes, src_len)) {
                log_handshake(dev, elem, "dropped", NULL,
                              "under load, sent cookie reply");
                wg_send_handshake_cookie(dev, elem);
                goto skip;
            }

            /* Extract IP address for rate limiter. */
            const uint8_t *rate_ip;
            uint8_t rate_len;
            if (elem->endpoint.addr.sa.sa_family == AF_INET6) {
                rate_ip = (const uint8_t *)&elem->endpoint.addr.sa6.sin6_addr;
                rate_len = 16;
            } else {
                rate_ip = (const uint8_t *)&elem->endpoint.addr.sa4.sin_addr;
                rate_len = 4;
            }
            if (!wg_ratelimiter_allow(&dev->rate.limiter, rate_ip, rate_len)) {
                log_handshake(dev, elem, "dropped", NULL, "under load, rate limited");
                goto skip;
            }
        }

        /* ── Process initiation ── */

        if (elem->msg_type == WG_MESSAGE_INITIATION) {
            if (elem->packet_len != WG_MESSAGE_INITIATION_SIZE) {
                log_handshake(dev, elem, "dropped", NULL, "bad size");
                goto skip;
            }

            const wg_message_initiation_t *msg =
                (const wg_message_initiation_t *)elem->buffer;

            struct wg_peer *peer = device_consume_initiation(dev, elem, msg);
            if (!peer)
                goto skip;

            log_handshake(dev, elem, "accepted", peer->handshake.remote_static,
                          "sending response");

            /* Update timers */
            wg_timers_any_authenticated_packet_traversal(peer);
            wg_timers_any_authenticated_packet_received(peer);

            /* Update endpoint */
            wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);

            /* Update rx counter */
            atomic_fetch_add(&peer->rx_bytes, (uint64_t)elem->packet_len);

            /* Send response */
            wg_send_handshake_response(peer);
        }

        /* ── Process response ── */

        else if (elem->msg_type == WG_MESSAGE_RESPONSE) {
            if (elem->packet_len != WG_MESSAGE_RESPONSE_SIZE) {
                log_handshake(dev, elem, "dropped", NULL, "bad size");
                goto skip;
            }

            const wg_message_response_t *msg =
                (const wg_message_response_t *)elem->buffer;

            struct wg_peer *peer = device_consume_response(dev, elem, msg);
            if (!peer)
                goto skip;

            /* Update endpoint */
            wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);

            /* Update rx counter */
            atomic_fetch_add(&peer->rx_bytes, (uint64_t)elem->packet_len);

            /* Update timers */
            wg_timers_any_authenticated_packet_traversal(peer);
            wg_timers_any_authenticated_packet_received(peer);

            /* Derive session keys */
            err = wg_begin_symmetric_session(&peer->handshake, &peer->keypairs,
                                             &dev->index_table);
            if (err != WG_OK) {
                log_handshake(dev, elem, "dropped", peer->handshake.remote_static,
                              wg_error_str(err));
                goto skip;
            }

            log_handshake(dev, elem, "accepted", peer->handshake.remote_static,
                          "session established");

            wg_timers_session_derived(peer);
            wg_timers_handshake_complete(peer);
            wg_send_keepalive(peer);
        }

    skip:
        wg_peer_reader_exit(&dev->hs_peer_gen);
        wg_handshake_elem_free(elem);
    }

    return NULL;
}

/* ────────────────────────────────────────
 * SendHandshakeInitiation
 *
 * Create and send a handshake initiation message.
 * Rate-limited: skip if last sent < REKEY_TIMEOUT ago.
 *
 * Reference: wireguard-go/device/send.go SendHandshakeInitiation
 * ──────────────────────────────────────── */

/* Allocate an index for the peer's handshake and record it, under
 * handshake.lock and only while the peer is not being removed: the
 * remover sets is_dead, then deletes the peer's indices under the same
 * lock, so every index added here is either refused or deleted. */
static wg_error_t handshake_new_index(wg_device_t *dev, struct wg_peer *peer)
{
    pthread_rwlock_wrlock(&peer->handshake.lock);
    if (atomic_load(&peer->is_dead)) {
        pthread_rwlock_unlock(&peer->handshake.lock);
        return WG_ERR_PEER_NOT_FOUND;
    }
    uint32_t local_index;
    wg_error_t err =
        wg_index_table_new_index(&dev->index_table, peer, &peer->handshake, &local_index);
    if (err == WG_OK)
        peer->handshake.local_index = local_index;
    pthread_rwlock_unlock(&peer->handshake.lock);
    return err;
}

wg_error_t wg_send_handshake_initiation(struct wg_peer *peer, bool is_retry)
{
    wg_device_t *dev = peer->device;
    if (!dev || wg_device_is_closed(dev))
        return WG_ERR_DEVICE_CLOSED;

    if (!is_retry)
        atomic_store(&peer->timers.handshake_attempts, 0);

    /* Rate limit: skip if sent recently.
     * Take wrlock directly to avoid TOCTOU between rdlock and wrlock. */
    pthread_rwlock_wrlock(&peer->handshake.lock);
    uint64_t now = wg_mono_ns();
    uint64_t last = peer->handshake.last_sent_handshake_ns;
    if (last != 0 && (now - last) < (uint64_t)WG_REKEY_TIMEOUT * 1000000000ULL) {
        pthread_rwlock_unlock(&peer->handshake.lock);
        return WG_OK;
    }
    peer->handshake.last_sent_handshake_ns = now;
    pthread_rwlock_unlock(&peer->handshake.lock);

    wg_error_t err = handshake_new_index(dev, peer);
    if (err != WG_OK)
        return err;

    /* Create initiation message */
    wg_message_initiation_t msg;
    err = wg_noise_handshake_create_initiation(&msg, &peer->handshake);
    if (err != WG_OK)
        return err;

    /* Add MACs (mac1 always, mac2 if we have a valid cookie) */
    wg_cookie_generator_add_macs(&peer->cookie_generator, (uint8_t *)&msg, sizeof(msg));

    /* Timer events */
    wg_timers_any_authenticated_packet_traversal(peer);
    wg_timers_any_authenticated_packet_sent(peer);

    /* Send via bind */
    wg_peer_send_buffer(peer, (uint8_t *)&msg, sizeof(msg));

    wg_timers_handshake_initiated(peer);

    return WG_OK;
}

/* ────────────────────────────────────────
 * SendHandshakeResponse
 *
 * Create and send a handshake response, then derive session keys.
 *
 * Reference: wireguard-go/device/send.go SendHandshakeResponse
 * ──────────────────────────────────────── */

wg_error_t wg_send_handshake_response(struct wg_peer *peer)
{
    wg_device_t *dev = peer->device;
    if (!dev || wg_device_is_closed(dev))
        return WG_ERR_DEVICE_CLOSED;

    /* Update last sent handshake time */
    pthread_rwlock_wrlock(&peer->handshake.lock);
    peer->handshake.last_sent_handshake_ns = wg_mono_ns();
    pthread_rwlock_unlock(&peer->handshake.lock);

    wg_error_t err = handshake_new_index(dev, peer);
    if (err != WG_OK)
        return err;

    /* Create response message */
    wg_message_response_t msg;
    err = wg_noise_handshake_create_response(&msg, &peer->handshake);
    if (err != WG_OK)
        return err;

    /* Add MACs */
    wg_cookie_generator_add_macs(&peer->cookie_generator, (uint8_t *)&msg, sizeof(msg));

    /* Derive session keys */
    err =
        wg_begin_symmetric_session(&peer->handshake, &peer->keypairs, &dev->index_table);
    if (err != WG_OK)
        return err;

    wg_timers_session_derived(peer);
    wg_timers_any_authenticated_packet_traversal(peer);
    wg_timers_any_authenticated_packet_sent(peer);

    /* Send via bind */
    err = wg_peer_send_buffer(peer, (uint8_t *)&msg, sizeof(msg));

    return err;
}

/* ────────────────────────────────────────
 * SendHandshakeCookie
 *
 * Send a cookie reply message to a handshake that failed MAC2
 * validation while the device is under load.
 *
 * Reference: wireguard-go/device/send.go SendHandshakeCookie
 * ──────────────────────────────────────── */

wg_error_t wg_send_handshake_cookie(wg_device_t *dev, wg_handshake_elem_t *elem)
{
    /* Extract sender_index from the incoming message (at offset 4) */
    uint32_t sender = 0;
    if (elem->packet_len >= 8)
        memcpy(&sender, elem->buffer + 4, sizeof(sender));
    sender = wg_le32toh(sender);

    const uint8_t *src_bytes = (const uint8_t *)&elem->endpoint.addr;
    size_t src_len;
    if (elem->endpoint.addr.sa.sa_family == AF_INET6)
        src_len = sizeof(struct sockaddr_in6);
    else
        src_len = sizeof(struct sockaddr_in);

    wg_message_cookie_reply_t reply;
    wg_error_t err =
        wg_cookie_checker_create_reply(&dev->cookie_checker, &reply, elem->buffer,
                                       elem->packet_len, sender, src_bytes, src_len);
    if (err != WG_OK)
        return err;

    return device_send_to_endpoint(dev, (uint8_t *)&reply, sizeof(reply),
                                   &elem->endpoint);
}

/* ────────────────────────────────────────
 * SendKeepalive
 *
 * Queue an empty (keepalive) packet for the peer.
 *
 * Reference: wireguard-go/device/send.go SendKeepalive
 * ──────────────────────────────────────── */

void wg_send_keepalive(struct wg_peer *peer)
{
    if (!atomic_load(&peer->is_running))
        return;

    /* Staged packets serve as the keepalive, as in wireguard-go: send
     * them without taking a buffer. Taking one first could wait forever
     * with capped pools, when the staged packets are what holds them. */
    if (wg_queue_count(peer->queue.staged) > 0) {
        wg_send_staged_packets(peer);
        return;
    }

    /* Get an empty outbound element from pool (packet_len=0 = keepalive).
     * With one thread for every timer, waiting here for a buffer would
     * hold up the timers of every peer, including the ones whose staged
     * packets hold the buffers; skip the keepalive instead. */
    wg_device_t *dev = peer->device;
    wg_outbound_elem_t *elem;
    if (dev->pool.outbound) {
        elem = WG_TIMERS_SHARED_THREAD ? wg_wait_pool_try_get(dev->pool.outbound)
                                       : wg_wait_pool_get(dev->pool.outbound);
        if (elem)
            elem->pool = dev->pool.outbound;
    } else {
        elem = wg_outbound_elem_new();
    }
    if (!elem)
        return;

    elem->packet_len = 0;
    elem->peer = peer;
    atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    /* Push individual elem to staged queue. */
    wg_error_t err = wg_queue_try_push(peer->queue.staged, elem);
    if (err != WG_OK) {
        wg_outbound_elem_free(elem);
        return;
    }

    wg_send_staged_packets(peer);
}

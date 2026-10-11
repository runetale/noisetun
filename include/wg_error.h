/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

#ifndef WG_ERROR_H
#define WG_ERROR_H

typedef enum {
    WG_OK = 0,

    /* Key / crypto errors */
    WG_ERR_INVALID_KEY,
    WG_ERR_INVALID_PUBKEY,
    WG_ERR_DH_FAILED,

    /* Handshake errors */
    WG_ERR_HANDSHAKE_DECRYPT,
    WG_ERR_HANDSHAKE_STATE,
    WG_ERR_REPLAY,
    WG_ERR_FLOOD,
    WG_ERR_TIMESTAMP,

    /* Transport errors */
    WG_ERR_ENCRYPT,
    WG_ERR_TRANSPORT_DECRYPT,
    WG_ERR_COUNTER_OVERFLOW,
    WG_ERR_KEYPAIR_EXPIRED,

    /* Session / index */
    WG_ERR_INDEX_COLLISION,
    WG_ERR_INDEX_NOT_FOUND,
    WG_ERR_PEER_NOT_FOUND,

    /* Peer / allowed IPs */
    WG_ERR_ALLOWEDIPS_FULL,
    WG_ERR_MAX_PEERS,
    WG_ERR_DUPLICATE_PEER,

    /* Queue / resource */
    WG_ERR_QUEUE_FULL,
    WG_ERR_QUEUE_EMPTY,
    WG_ERR_NO_MEMORY,

    /* I/O */
    WG_ERR_TUN,
    WG_ERR_BIND,
    WG_ERR_SEND,
    WG_ERR_RECV,

    /* Cookie */
    WG_ERR_COOKIE_REQUIRED,
    WG_ERR_COOKIE_INVALID,

    /* Validation */
    WG_ERR_INVALID_ARGUMENT,

    /* Device lifecycle */
    WG_ERR_DEVICE_CLOSED,

    /* Buffer */
    WG_ERR_BUFFER_TOO_SMALL,

    /* Timeout */
    WG_ERR_TIMEOUT,

    WG_ERR__COUNT
} wg_error_t;

static inline const char *wg_error_str(wg_error_t err)
{
    static const char *const table[] = {
        [WG_OK] = "success",
        [WG_ERR_INVALID_KEY] = "invalid key",
        [WG_ERR_INVALID_PUBKEY] = "invalid public key",
        [WG_ERR_DH_FAILED] = "DH computation failed",
        [WG_ERR_HANDSHAKE_DECRYPT] = "handshake decryption failed",
        [WG_ERR_HANDSHAKE_STATE] = "unexpected handshake state",
        [WG_ERR_REPLAY] = "replay attack detected",
        [WG_ERR_FLOOD] = "initiation flood detected",
        [WG_ERR_TIMESTAMP] = "invalid timestamp",
        [WG_ERR_ENCRYPT] = "encryption failed",
        [WG_ERR_TRANSPORT_DECRYPT] = "transport decryption failed",
        [WG_ERR_COUNTER_OVERFLOW] = "nonce counter overflow",
        [WG_ERR_KEYPAIR_EXPIRED] = "keypair expired",
        [WG_ERR_INDEX_COLLISION] = "sender index collision",
        [WG_ERR_INDEX_NOT_FOUND] = "sender index not found",
        [WG_ERR_PEER_NOT_FOUND] = "peer not found",
        [WG_ERR_ALLOWEDIPS_FULL] = "allowed IPs table full",
        [WG_ERR_MAX_PEERS] = "maximum peers reached",
        [WG_ERR_DUPLICATE_PEER] = "duplicate peer",
        [WG_ERR_QUEUE_FULL] = "queue full",
        [WG_ERR_QUEUE_EMPTY] = "queue empty",
        [WG_ERR_NO_MEMORY] = "out of memory",
        [WG_ERR_TUN] = "TUN device error",
        [WG_ERR_BIND] = "bind error",
        [WG_ERR_SEND] = "send error",
        [WG_ERR_RECV] = "receive error",
        [WG_ERR_COOKIE_REQUIRED] = "cookie required",
        [WG_ERR_COOKIE_INVALID] = "cookie invalid",
        [WG_ERR_INVALID_ARGUMENT] = "invalid argument",
        [WG_ERR_DEVICE_CLOSED] = "device closed",
        [WG_ERR_BUFFER_TOO_SMALL] = "buffer too small",
        [WG_ERR_TIMEOUT] = "operation timed out",
    };
    if (err >= WG_ERR__COUNT)
        return "unknown error";
    return table[err];
}

#endif /* WG_ERROR_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

#ifndef WG_TYPES_H
#define WG_TYPES_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

/*
 * Cryptographic key types.
 * All keys are 32 bytes (Curve25519 / ChaCha20-Poly1305 / BLAKE2s).
 */
#define WG_KEY_LEN 32

typedef struct {
    uint8_t key[WG_KEY_LEN];
} wg_key_t;

typedef struct {
    wg_key_t private_key;
    wg_key_t public_key;
} wg_keypair_t;

/*
 * Sender index: random uint32 identifying a session. The index table
 * (src/peer/wg_indextable.c) draws again on a collision.
 */
typedef uint32_t wg_index_t;

/*
 * Endpoint: network address of a peer (IPv4 or IPv6), with the local
 * address it was last reached from (sticky source address).
 */
/*
 * Sticky socket control buffer size.
 * Must be large enough for CMSG_SPACE(sizeof(struct in6_pktinfo)) ≈ 40 bytes.
 * 48 bytes gives comfortable headroom for all platforms.
 */
#define WG_STICKY_CONTROL_SIZE 48

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
    } addr;
    uint32_t ifindex;
    /* Sticky socket: stores IP_PKTINFO / IPV6_PKTINFO control message
     * received on incoming packets so that replies are sent from the
     * same source address and interface. */
    uint8_t src_control[WG_STICKY_CONTROL_SIZE];
    uint32_t src_control_len; /* 0 = no sticky source */
} wg_endpoint_t;

/*
 * TAI64N timestamp (12 bytes): used in handshake initiation.
 * See https://cr.yp.to/libtai/tai64.html
 */
#define WG_TIMESTAMP_LEN 12

typedef struct {
    uint8_t bytes[WG_TIMESTAMP_LEN];
} wg_timestamp_t;

/* Nonce: 64-bit counter for transport data messages. */
typedef uint64_t wg_nonce_t;

/*
 * Buffer: pointer + length + capacity.
 * Used for packet data throughout the stack.
 */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} wg_buf_t;

static inline wg_buf_t wg_buf_from(uint8_t *data, size_t len, size_t cap)
{
    return (wg_buf_t){.data = data, .len = len, .cap = cap};
}

static inline void wg_key_zero(wg_key_t *k)
{
    volatile uint8_t *p = k->key;
    for (size_t i = 0; i < WG_KEY_LEN; i++)
        p[i] = 0;
}

/* Compile-time size checks */
static_assert(sizeof(wg_key_t) == 32, "wg_key_t must be 32 bytes");
static_assert(sizeof(wg_timestamp_t) == 12, "wg_timestamp_t must be 12 bytes");

#endif /* WG_TYPES_H */

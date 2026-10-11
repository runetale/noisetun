/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * On-wire message layouts, as the WireGuard whitepaper defines them
 * (section 5.4: handshake initiation, response, cookie reply and
 * transport data).
 */

#ifndef WG_MESSAGES_H
#define WG_MESSAGES_H

#include "wg_constants.h"
#include "wg_types.h"

#include <assert.h>

/* Portable packed struct support for GCC/Clang and MSVC.
 * Usage: WG_PACKED_BEGIN struct foo { ... } WG_PACKED_END; */
#ifdef _MSC_VER
#define WG_PACKED_BEGIN __pragma(pack(push, 1))
#define WG_PACKED_END   __pragma(pack(pop))
#define WG_PACKED
#else
#define WG_PACKED_BEGIN
#define WG_PACKED_END
#define WG_PACKED __attribute__((packed))
#endif

/* Common header: type (le32) */
WG_PACKED_BEGIN
typedef struct {
    uint32_t type;
} WG_PACKED wg_message_header_t;
WG_PACKED_END

/* MACs appended to handshake messages (32 bytes total) */
WG_PACKED_BEGIN
typedef struct {
    uint8_t mac1[WG_COOKIE_LEN]; /* 16 bytes */
    uint8_t mac2[WG_COOKIE_LEN]; /* 16 bytes */
} WG_PACKED wg_message_macs_t;
WG_PACKED_END

/*
 * Handshake Initiation (148 bytes)
 * -> e, es, s, ss, {t}
 *
 * Layout: 4 + 4 + 32 + 48 + 28 + 16 + 16 = 148
 */
WG_PACKED_BEGIN
typedef struct {
    wg_message_header_t header;                                           /*   4 bytes */
    uint32_t sender_index;                                                /*   4 bytes */
    uint8_t unencrypted_ephemeral[WG_NOISE_PUBLIC_KEY_LEN];               /* 32 bytes */
    uint8_t encrypted_static[WG_NOISE_PUBLIC_KEY_LEN + WG_AEAD_TAG_SIZE]; /* 48 bytes */
    uint8_t encrypted_timestamp[WG_NOISE_TIMESTAMP_LEN + WG_AEAD_TAG_SIZE]; /* 28 bytes */
    wg_message_macs_t macs;                                                 /* 32 bytes */
} WG_PACKED wg_message_initiation_t;
WG_PACKED_END

/*
 * Handshake Response (92 bytes)
 * <- e, ee, se, psk, {}
 *
 * Layout: 4 + 4 + 4 + 32 + 16 + 16 + 16 = 92
 */
WG_PACKED_BEGIN
typedef struct {
    wg_message_header_t header;                             /*   4 bytes */
    uint32_t sender_index;                                  /*   4 bytes */
    uint32_t receiver_index;                                /*   4 bytes */
    uint8_t unencrypted_ephemeral[WG_NOISE_PUBLIC_KEY_LEN]; /* 32 bytes */
    uint8_t encrypted_nothing[0 + WG_AEAD_TAG_SIZE];        /* 16 bytes */
    wg_message_macs_t macs;                                 /* 32 bytes */
} WG_PACKED wg_message_response_t;
WG_PACKED_END

/*
 * Cookie Reply (64 bytes)
 *
 * Layout: 4 + 4 + 24 + 32 = 64
 *   encrypted_cookie = noise_encrypted_len(COOKIE_LEN) = 16 + 16 = 32
 */
WG_PACKED_BEGIN
typedef struct {
    wg_message_header_t header;                                 /*   4 bytes */
    uint32_t receiver_index;                                    /*   4 bytes */
    uint8_t nonce[WG_COOKIE_NONCE_LEN];                         /* 24 bytes */
    uint8_t encrypted_cookie[WG_COOKIE_LEN + WG_AEAD_TAG_SIZE]; /* 32 bytes */
} WG_PACKED wg_message_cookie_reply_t;
WG_PACKED_END

/*
 * Transport Data header (16 bytes) + encrypted payload
 */
WG_PACKED_BEGIN
typedef struct {
    wg_message_header_t header; /*   4 bytes */
    uint32_t receiver_index;    /*   4 bytes */
    uint64_t counter;           /*   8 bytes (nonce, little-endian) */
    uint8_t encrypted_data[];   /* variable: payload + 16-byte Poly1305 tag */
} WG_PACKED wg_message_transport_t;
WG_PACKED_END

/* Size validations matching the WireGuard spec */
static_assert(sizeof(wg_message_macs_t) == 32,
              "message_macs must be 32 bytes (2 x COOKIE_LEN)");
static_assert(sizeof(wg_message_initiation_t) == WG_MESSAGE_INITIATION_SIZE,
              "initiation message must be 148 bytes");
static_assert(sizeof(wg_message_response_t) == WG_MESSAGE_RESPONSE_SIZE,
              "response message must be 92 bytes");
static_assert(sizeof(wg_message_cookie_reply_t) == WG_MESSAGE_COOKIE_REPLY_SIZE,
              "cookie reply message must be 64 bytes");
static_assert(sizeof(wg_message_transport_t) == WG_MESSAGE_TRANSPORT_HEADER,
              "transport header must be 16 bytes");

/* Portable LE32→host conversion for message type field.
 * On-wire format is always little-endian (WireGuard spec). */
static inline uint32_t wg_le32toh(uint32_t v)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap32(v);
#elif defined(_MSC_VER)
    /* MSVC on x86/x64/ARM64 is always LE */
    return v;
#else
    return v;
#endif
}

static inline uint32_t wg_htole32(uint32_t v)
{
    return wg_le32toh(v); /* same swap operation */
}

/* Portable LE64↔host conversion for transport counter field. */
static inline uint64_t wg_le64toh(uint64_t v)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static inline uint64_t wg_htole64(uint64_t v)
{
    return wg_le64toh(v);
}

/* Helper to determine message type from the first 4 bytes */
static inline uint32_t wg_message_type(const uint8_t *data, size_t len)
{
    if (len < sizeof(wg_message_header_t))
        return 0;
    uint32_t type;
    memcpy(&type, data, sizeof(type));
    return wg_le32toh(type);
}

/* Encrypted length helper: plaintext_len + AEAD tag */
static inline size_t wg_noise_encrypted_len(size_t plaintext_len)
{
    return plaintext_len + WG_AEAD_TAG_SIZE;
}

#endif /* WG_MESSAGES_H */

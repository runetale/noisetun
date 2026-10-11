/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

#ifndef WG_CONSTANTS_H
#define WG_CONSTANTS_H

#include <stdint.h>

/*
 * WireGuard protocol constants.
 * References:
 *   - https://www.wireguard.com/papers/wireguard.pdf (sections 5 and 6)
 *   - wireguard-go/device/constants.go
 */

/* --- Noise protocol identifiers --- */
#define WG_NOISE_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_NOISE_IDENTIFIER   "WireGuard v1 zx2c4 Jason@zx2c4.com"

#define WG_NOISE_HASH_LEN          32
#define WG_NOISE_SYMMETRIC_KEY_LEN 32
#define WG_NOISE_PUBLIC_KEY_LEN    32
#define WG_NOISE_TIMESTAMP_LEN     12

/* --- Message types (first 4 bytes, little-endian) --- */
#define WG_MESSAGE_INITIATION   1
#define WG_MESSAGE_RESPONSE     2
#define WG_MESSAGE_COOKIE_REPLY 3
#define WG_MESSAGE_TRANSPORT    4

/* --- Message sizes (bytes) --- */
#define WG_MESSAGE_INITIATION_SIZE   148
#define WG_MESSAGE_RESPONSE_SIZE     92
#define WG_MESSAGE_COOKIE_REPLY_SIZE 64
#define WG_MESSAGE_TRANSPORT_HEADER  16

/* AEAD overhead: Poly1305 tag */
#define WG_AEAD_TAG_SIZE 16

/* --- Timers (seconds) --- */
#define WG_REKEY_AFTER_TIME         120
#define WG_REJECT_AFTER_TIME        180
#define WG_REKEY_TIMEOUT            5
#define WG_KEEPALIVE_TIMEOUT        10
#define WG_REKEY_TIMEOUT_JITTER_MAX 0 /* 333ms, set at runtime in jiffies */

/* --- Timer limits (nanoseconds, compile-time constants) --- */
#define WG_REKEY_AFTER_TIME_NS  ((uint64_t)WG_REKEY_AFTER_TIME * 1000000000ULL)
#define WG_REJECT_AFTER_TIME_NS ((uint64_t)WG_REJECT_AFTER_TIME * 1000000000ULL)

/* --- Counter limits --- */
#define WG_REKEY_AFTER_MESSAGES  ((uint64_t)1 << 60)
#define WG_REJECT_AFTER_MESSAGES (UINT64_MAX - (1ULL << 13) - 1)

/* Max handshake attempts before giving up */
#define WG_MAX_TIMER_HANDSHAKES 90 /* ~7.5 minutes at 5s interval */

/* Initiations per second (rate limit) */
#define WG_INITIATIONS_PER_SECOND 50

/* --- Anti-replay window --- */
/* Names aligned with wireguard-go: counterBitsTotal, counterRedundantBitsTotal,
 * counterWindowSize */
#define WG_COUNTER_BITS_TOTAL           8192
#define WG_COUNTER_REDUNDANT_BITS_TOTAL 64 /* was WG_COUNTER_REDUNDANT_BITS */
#define WG_COUNTER_WINDOW_SIZE          (WG_COUNTER_BITS_TOTAL - WG_COUNTER_REDUNDANT_BITS_TOTAL)

/* --- Memory profile ---
 * An iOS Network Extension is stopped by the system at about 50 MB, so
 * iOS builds bound what the data path can hold, as wireguard-go's
 * queueconstants_ios.go does: smaller queues, at most WG_POOL_MAX_ELEMENTS
 * packet buffers per direction (a thread that needs one more waits for one
 * to come back), and buffers sized for one packet, since utun hands over
 * one packet per read and there is no UDP coalescing. Android gets
 * wireguard-go's Android queue and pool sizes. Other builds can opt in to
 * the bounds with -DWG_MEMORY_CONSTRAINED=1 (the buffer size stays). */
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#ifndef WG_MEMORY_CONSTRAINED
#if defined(__APPLE__) && TARGET_OS_IPHONE
#define WG_MEMORY_CONSTRAINED 1
#else
#define WG_MEMORY_CONSTRAINED 0
#endif
#endif

/* --- Queue sizes ---
 * MPMC encryption/decryption queues carry individual elements.
 * SPSC per-peer queues carry containers (1024, ~34 elems each). */
#if WG_MEMORY_CONSTRAINED || defined(__ANDROID__)
#define WG_QUEUE_OUTBOUND_SIZE 1024
#define WG_QUEUE_INBOUND_SIZE  1024
#else
#define WG_QUEUE_OUTBOUND_SIZE 4096
#define WG_QUEUE_INBOUND_SIZE  4096
#endif

/* Packet buffers per direction; 0 = allocated as needed, never capped. */
#if WG_MEMORY_CONSTRAINED
#define WG_POOL_MAX_ELEMENTS 1024
#elif defined(__ANDROID__)
#define WG_POOL_MAX_ELEMENTS 4096
#else
#define WG_POOL_MAX_ELEMENTS 0
#endif
#define WG_QUEUE_CONTAINER_SIZE 1024 /* SPSC per-peer container queues */
#define WG_QUEUE_HANDSHAKE_SIZE 128
#define WG_MAX_QUEUED_PACKETS   128
#define WG_QUEUE_STAGED_SIZE    128

/* --- Peer limits --- */
#define WG_MAX_PEERS_PER_DEVICE (1U << 20)

/* --- Cookie --- */
#define WG_COOKIE_LEN       16
#define WG_COOKIE_NONCE_LEN 24 /* XChaCha20-Poly1305 nonce */

/* --- Packet sizes --- */
#define WG_MIN_MESSAGE_SIZE 4
#if defined(__APPLE__) && TARGET_OS_IPHONE
#define WG_MAX_SEGMENT_SIZE 1700 /* one packet: no GSO/GRO on iOS */
#else
#define WG_MAX_SEGMENT_SIZE 65535
#endif
#define WG_DEFAULT_MTU 1420

#endif /* WG_CONSTANTS_H */

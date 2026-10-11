/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Anti-replay filter (RFC 6479 sliding window).
 *
 * Reference: wireguard-go/replay/replay.go
 */

#ifndef WG_REPLAY_H
#define WG_REPLAY_H

#include "wg_constants.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * Constants (derived from wg_constants.h)
 *
 * ring is 128 x uint64_t = 8192 bits.
 * windowSize = (128 - 1) * 64 = 8128.
 * ──────────────────────────────────────── */
#define WG_REPLAY_BLOCK_BIT_LOG 6
#define WG_REPLAY_BLOCK_BITS    (1 << WG_REPLAY_BLOCK_BIT_LOG) /* 64 */
#define WG_REPLAY_RING_BLOCKS   (WG_COUNTER_BITS_TOTAL / 64)   /* 128 */
#define WG_REPLAY_WINDOW_SIZE \
    ((WG_REPLAY_RING_BLOCKS - 1) * WG_REPLAY_BLOCK_BITS) /* 8128 */
#define WG_REPLAY_BLOCK_MASK (WG_REPLAY_RING_BLOCKS - 1) /* 127 */
#define WG_REPLAY_BIT_MASK   (WG_REPLAY_BLOCK_BITS - 1)  /* 63 */

/* The receive window of one keypair: the highest counter accepted so
 * far, and a bitmap of the counters seen below it. */
typedef struct {
    uint64_t last;
    pthread_mutex_t lock;
    uint64_t ring[WG_REPLAY_RING_BLOCKS];
} wg_replay_counter_t;

/* ────────────────────────────────────────
 * API
 * ──────────────────────────────────────── */

/*
 * Initialise a replay counter to the zero state.
 */
void wg_replay_counter_init(wg_replay_counter_t *rc);

/*
 * Destroy a replay counter (releases the mutex).
 */
void wg_replay_counter_destroy(wg_replay_counter_t *rc);

/*
 * Validate a received counter value.
 *
 * Thread-safe: acquires rc->lock internally.
 *
 * Returns true if the counter is accepted (not a replay and within limit).
 * Returns false if:
 *   - counter >= limit  (overlimit / nonce exhaustion)
 *   - counter is behind the window  (too old)
 *   - counter was already seen  (duplicate)
 */
bool wg_replay_counter_validate(wg_replay_counter_t *rc, uint64_t counter,
                                uint64_t limit);

#endif /* WG_REPLAY_H */

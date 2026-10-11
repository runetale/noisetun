/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Anti-replay filter (RFC 6479 sliding window).
 *
 * Direct port of wireguard-go/replay/replay.go (Copyright (C) 2017-2025
 * WireGuard LLC, MIT License; see NOTICE) with C idioms:
 *   - pthread_mutex_t for thread safety (Go version is not concurrent-safe)
 *   - uint64_t ring[] instead of Go []block
 *   - goto out for a single unlock
 *   - likely/unlikely hints on hot paths
 *
 * Reference: wireguard-go/replay/replay.go
 */

#include "wg_replay.h"

#include "wg_compiler.h"

#include <string.h>

void wg_replay_counter_init(wg_replay_counter_t *rc)
{
    memset(rc, 0, sizeof(*rc));
    pthread_mutex_init(&rc->lock, NULL);
}

void wg_replay_counter_destroy(wg_replay_counter_t *rc)
{
    pthread_mutex_destroy(&rc->lock);
    memset(rc, 0, sizeof(*rc));
}

bool wg_replay_counter_validate(wg_replay_counter_t *rc, uint64_t counter, uint64_t limit)
{
    bool ret = false;

    if (wg_unlikely(counter >= limit))
        return false;

    pthread_mutex_lock(&rc->lock);

    uint64_t index_block = counter >> WG_REPLAY_BLOCK_BIT_LOG;

    if (wg_likely(counter > rc->last)) {
        /* Advance the window: clear newly exposed blocks. */
        uint64_t current = rc->last >> WG_REPLAY_BLOCK_BIT_LOG;
        uint64_t diff = index_block - current;
        if (diff > WG_REPLAY_RING_BLOCKS)
            diff = WG_REPLAY_RING_BLOCKS;
        for (uint64_t i = current + 1; i <= current + diff; i++)
            rc->ring[i & WG_REPLAY_BLOCK_MASK] = 0;
        rc->last = counter;
    } else if (wg_unlikely(rc->last - counter > WG_REPLAY_WINDOW_SIZE)) {
        goto out;
    }

    /* Check and set the bit. */
    index_block &= WG_REPLAY_BLOCK_MASK;
    uint64_t index_bit = counter & WG_REPLAY_BIT_MASK;
    uint64_t old = rc->ring[index_block];
    uint64_t updated = old | ((uint64_t)1 << index_bit);
    rc->ring[index_block] = updated;
    ret = (old != updated);

out:
    pthread_mutex_unlock(&rc->lock);
    return ret;
}

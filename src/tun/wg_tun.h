/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TUN device common abstraction.
 *
 * Defines event constants and helpers shared by all platform-specific
 * TUN implementations.
 *
 * Reference: wireguard-go/tun/tun.go
 */

#ifndef WG_TUN_H
#define WG_TUN_H

#include "wireguard.h"

#include <stdbool.h>

/* ────────────────────────────────────────
 * TUN event bitmask
 *
 * Returned by wg_tun_ops_t::events().
 * Multiple events can be OR'd together.
 * ──────────────────────────────────────── */
#define WG_TUN_EVENT_UP         (1 << 0)
#define WG_TUN_EVENT_DOWN       (1 << 1)
#define WG_TUN_EVENT_MTU_UPDATE (1 << 2)

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

/* Default batch size for implementations without batching. */
static inline int wg_tun_default_batch_size(void)
{
    return 1;
}

/* Validate that required ops are populated. */
static inline bool wg_tun_ops_valid(const wg_tun_ops_t *ops)
{
    return ops && ops->read && ops->write && ops->mtu && ops->batch_size && ops->close &&
           ops->ctx;
}

#endif /* WG_TUN_H */

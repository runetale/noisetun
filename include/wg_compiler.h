/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Compiler hints and portable low-level primitives.
 */

#ifndef WG_COMPILER_H
#define WG_COMPILER_H

/* ────────────────────────────────────────
 * Branch-prediction hints (same semantics as Linux kernel likely/unlikely)
 * ──────────────────────────────────────── */
#if defined(__GNUC__) || defined(__clang__)
#define wg_likely(x)   __builtin_expect(!!(x), 1)
#define wg_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define wg_likely(x)   (!!(x))
#define wg_unlikely(x) (!!(x))
#endif

#endif /* WG_COMPILER_H */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Logger helpers for device-level logging.
 *
 * Reference: wireguard-go/device/logger.go
 */

#ifndef WG_LOGGER_H
#define WG_LOGGER_H

#include "wireguard.h"

/* Forward declaration (avoids circular include with wg_device.h) */
struct wg_device;

/* ────────────────────────────────────────
 * Log macros — null-check the function pointer before calling.
 * ──────────────────────────────────────── */

#define wg_log_verbose(dev, fmt, ...)                                                 \
    do {                                                                              \
        if ((dev)->logger.log)                                                        \
            (dev)->logger.log((dev)->logger.ctx, WG_LOG_VERBOSE, fmt, ##__VA_ARGS__); \
    } while (0)

#define wg_log_error(dev, fmt, ...)                                                 \
    do {                                                                            \
        if ((dev)->logger.log)                                                      \
            (dev)->logger.log((dev)->logger.ctx, WG_LOG_ERROR, fmt, ##__VA_ARGS__); \
    } while (0)

/* ────────────────────────────────────────
 * Default stderr logger
 *
 * Returns a wg_logger_t that prints to stderr.
 * Messages below min_level are suppressed.
 * ──────────────────────────────────────── */

wg_logger_t wg_logger_default(wg_log_level_t min_level);

#endif /* WG_LOGGER_H */

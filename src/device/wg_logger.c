/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Default stderr logger implementation.
 *
 * Reference: wireguard-go/device/logger.go
 */

#include "wg_logger.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

static void stderr_log(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    wg_log_level_t min_level = (wg_log_level_t)(uintptr_t)ctx;

    if (level < min_level)
        return;

    const char *prefix;
    switch (level) {
    case WG_LOG_VERBOSE:
        prefix = "[VERBOSE] ";
        break;
    case WG_LOG_ERROR:
        prefix = "[ERROR] ";
        break;
    default:
        prefix = "";
        break;
    }

    va_list ap;
    va_start(ap, fmt);

#ifdef _WIN32
    _lock_file(stderr);
#else
    flockfile(stderr);
#endif
    fputs(prefix, stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
#ifdef _WIN32
    _unlock_file(stderr);
#else
    funlockfile(stderr);
#endif

    va_end(ap);
}

wg_logger_t wg_logger_default(wg_log_level_t min_level)
{
    return (wg_logger_t){
        .log = stderr_log,
        .ctx = (void *)(uintptr_t)min_level,
    };
}

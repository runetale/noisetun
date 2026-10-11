/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TUN device common helpers.
 *
 * Platform-specific implementations live in wg_tun_linux.c, etc.
 * This file provides shared utility used by multiple platforms.
 */

#include "wg_tun.h"

/* Intentionally empty — all helpers are inline in wg_tun.h.
 * This compilation unit exists so CMakeLists.txt always has a
 * platform-independent TUN source file to compile. */

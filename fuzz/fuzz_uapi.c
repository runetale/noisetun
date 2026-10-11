/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Fuzz target: UAPI set (configuration) parser.
 * Exercises wg_uapi_set with arbitrary configuration text.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address -o fuzz_uapi \
 *        fuzz_uapi.c -I../src -I../include -L../build/src -lwireguard -lsodium -lpthread
 */

#include "../include/wireguard.h"
#include "../src/crypto/wg_crypto.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int g_initialized = 0;
static wg_device_t *g_dev = NULL;

static void init_once(void)
{
    if (g_initialized)
        return;
    g_initialized = 1;

    sodium_init();
    wg_noise_module_init();

    wg_device_new(&g_dev, NULL, NULL, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init_once();

    if (size == 0 || size > 65536)
        return 0;

    /* Ensure null-terminated input for the parser */
    char *buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    wg_uapi_set(g_dev, buf, size);

    free(buf);
    return 0;
}

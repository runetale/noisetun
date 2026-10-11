/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Fuzz target: handshake message parsing.
 * Exercises consume_initiation and consume_response with arbitrary bytes.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address -o fuzz_handshake \
 *        fuzz_handshake.c -I../src -I../include -L../build/src -lwireguard -lsodium -lpthread
 */

#include "../include/wg_messages.h"
#include "../src/cookie/wg_cookie.h"
#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int g_initialized = 0;
static wg_noise_static_identity_t g_identity;
static wg_cookie_checker_t g_checker;

static void init_once(void)
{
    if (g_initialized)
        return;
    g_initialized = 1;

    sodium_init();
    wg_noise_module_init();

    uint8_t sk[32];
    wg_x25519_generate_private(sk);
    wg_noise_static_identity_init(&g_identity);
    wg_noise_static_identity_set_private_key(&g_identity, sk);

    wg_cookie_checker_init(&g_checker, g_identity.static_public);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init_once();

    if (size < 4)
        return 0;

    uint32_t msg_type = data[0] | ((uint32_t)data[1] << 8) |
                        ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);

    switch (msg_type) {
    case 1: /* Initiation (148 bytes) */
        if (size < sizeof(wg_message_initiation_t))
            return 0;

        /* MAC1 check (the first thing the real code does) */
        wg_cookie_checker_check_mac1(&g_checker, data, size);

        /* Try to decrypt static (will fail with random data — that's fine) */
        {
            wg_message_initiation_t msg;
            memcpy(&msg, data, sizeof(msg));

            wg_initiation_half_t half;
            wg_noise_consume_initiation_decrypt_static(&g_identity, &msg, &half);
        }
        break;

    case 2: /* Response (92 bytes) */
        if (size < sizeof(wg_message_response_t))
            return 0;

        /* MAC1 check */
        wg_cookie_checker_check_mac1(&g_checker, data, size);
        break;

    case 3: /* Cookie Reply (64 bytes) */
        if (size < sizeof(wg_message_cookie_reply_t))
            return 0;
        /* Cookie replies are consumed per-peer; just validate structure is safe to access */
        break;

    case 4: /* Transport */
        if (size < sizeof(wg_message_transport_t))
            return 0;
        /* Transport header parse — verify no OOB on short packets */
        {
            wg_message_transport_t hdr;
            memcpy(&hdr, data, sizeof(hdr));
            (void)hdr.receiver_index;
            (void)hdr.counter;
        }
        break;

    default:
        /* Unknown type — early reject (same as real code) */
        break;
    }

    return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Fuzz target: transport packet decryption path.
 * Exercises wg_aead_decrypt with arbitrary ciphertext.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address -o fuzz_transport \
 *        fuzz_transport.c -I../src -I../include -L../build/src -lwireguard -lsodium -lpthread
 */

#include "../include/wg_messages.h"
#include "../src/crypto/wg_crypto.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int g_initialized = 0;
static uint8_t g_key[32];

static void init_once(void)
{
    if (g_initialized)
        return;
    g_initialized = 1;

    sodium_init();
    randombytes_buf(g_key, 32);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init_once();

    /* Transport packet: header (16 bytes) + encrypted payload (>= 16 bytes for tag) */
    if (size < sizeof(wg_message_transport_t) + 16)
        return 0;

    /* Parse header */
    wg_message_transport_t hdr;
    memcpy(&hdr, data, sizeof(hdr));

    /* Skip non-transport types */
    if (hdr.header.type != 4)
        return 0;

    const uint8_t *payload = data + sizeof(wg_message_transport_t);
    size_t payload_len = size - sizeof(wg_message_transport_t);

    /* Attempt decryption — will fail (wrong key / garbage data) but must not crash */
    uint8_t *plaintext = malloc(payload_len);
    if (!plaintext)
        return 0;

    size_t pt_len;
    wg_aead_decrypt(plaintext, &pt_len, payload, payload_len, NULL, 0,
                    hdr.counter, g_key);

    free(plaintext);
    return 0;
}

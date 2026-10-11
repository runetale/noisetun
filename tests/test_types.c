/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * FOUND-1 verification: type sizes and constants.
 */

#include "wireguard.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_key_sizes(void)
{
    assert(sizeof(wg_key_t) == 32);
    assert(sizeof(wg_keypair_t) == 64);
    assert(WG_KEY_LEN == 32);
}

static void test_timestamp_size(void)
{
    assert(sizeof(wg_timestamp_t) == 12);
    assert(WG_NOISE_TIMESTAMP_LEN == 12);
}

static void test_message_sizes(void)
{
    assert(sizeof(wg_message_initiation_t) == 148);
    assert(sizeof(wg_message_cookie_reply_t) == 64);
    assert(sizeof(wg_message_transport_t) == 16);
}

static void test_message_types(void)
{
    assert(WG_MESSAGE_INITIATION == 1);
    assert(WG_MESSAGE_RESPONSE == 2);
    assert(WG_MESSAGE_COOKIE_REPLY == 3);
    assert(WG_MESSAGE_TRANSPORT == 4);
}

static void test_protocol_constants(void)
{
    assert(WG_REKEY_AFTER_TIME == 120);
    assert(WG_REJECT_AFTER_TIME == 180);
    assert(WG_REKEY_TIMEOUT == 5);
    assert(WG_KEEPALIVE_TIMEOUT == 10);
    assert(WG_REKEY_AFTER_MESSAGES == ((uint64_t)1 << 60));
    assert(WG_MAX_PEERS_PER_DEVICE == (1U << 20));
    assert(WG_DEFAULT_MTU == 1420);
}

static void test_key_zero(void)
{
    wg_key_t k;
    memset(k.key, 0xff, WG_KEY_LEN);
    wg_key_zero(&k);
    for (int i = 0; i < WG_KEY_LEN; i++)
        assert(k.key[i] == 0);
}

static void test_buf(void)
{
    uint8_t data[128];
    wg_buf_t buf = wg_buf_from(data, 64, 128);
    assert(buf.data == data);
    assert(buf.len == 64);
    assert(buf.cap == 128);
}

static void test_error_strings(void)
{
    assert(strcmp(wg_error_str(WG_OK), "success") == 0);
    assert(strcmp(wg_error_str(WG_ERR_NO_MEMORY), "out of memory") == 0);
    assert(strcmp(wg_error_str(WG_ERR_REPLAY), "replay attack detected") == 0);
    assert(strcmp(wg_error_str(WG_ERR__COUNT), "unknown error") == 0);
    assert(strcmp(wg_error_str((wg_error_t)999), "unknown error") == 0);
}

static void test_message_type_helper(void)
{
    wg_message_initiation_t init = {0};
    init.header.type = WG_MESSAGE_INITIATION;
    assert(wg_message_type((const uint8_t *)&init, sizeof(init)) ==
           WG_MESSAGE_INITIATION);

    uint8_t tiny[2] = {0};
    assert(wg_message_type(tiny, sizeof(tiny)) == 0);
}

static void test_encrypted_len(void)
{
    assert(wg_noise_encrypted_len(0) == 16);
    assert(wg_noise_encrypted_len(32) == 48);
    assert(wg_noise_encrypted_len(WG_NOISE_PUBLIC_KEY_LEN) ==
           WG_NOISE_PUBLIC_KEY_LEN + WG_AEAD_TAG_SIZE);
}

int main(void)
{
    test_key_sizes();
    test_timestamp_size();
    test_message_sizes();
    test_message_types();
    test_protocol_constants();
    test_key_zero();
    test_buf();
    test_error_strings();
    test_message_type_helper();
    test_encrypted_len();

    printf("All FOUND-1 tests passed.\n");
    return 0;
}

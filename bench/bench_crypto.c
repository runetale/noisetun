/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Microbenchmark: ChaCha20-Poly1305 AEAD throughput.
 * Measures wg_aead_encrypt/decrypt speed for the active backend.
 */

#include "../src/crypto/wg_crypto.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(void)
{
    if (sodium_init() < 0) return 1;

    const size_t pkt_size = 1420;
    const int duration = 5;

    uint8_t key[32], plain[1420], ct[1420 + 16], dec[1420];
    randombytes_buf(key, 32);
    randombytes_buf(plain, pkt_size);

    uint8_t ad[16] = {0};

    /* Warmup */
    for (int i = 0; i < 1000; i++) {
        size_t ct_len, pt_len;
        wg_aead_encrypt(ct, &ct_len, plain, pkt_size, ad, 16, (uint64_t)i, key);
        wg_aead_decrypt(dec, &pt_len, ct, ct_len, ad, 16, (uint64_t)i, key);
    }

    /* Benchmark encrypt */
    uint64_t enc_count = 0;
    double start = now_sec();
    double deadline = start + duration;
    while (now_sec() < deadline) {
        for (int i = 0; i < 100; i++) {
            size_t ct_len;
            wg_aead_encrypt(ct, &ct_len, plain, pkt_size, ad, 16, enc_count, key);
            enc_count++;
        }
    }
    double enc_elapsed = now_sec() - start;
    double enc_mbps = ((double)enc_count * pkt_size * 8.0) / (enc_elapsed * 1e6);
    double enc_mBps = ((double)enc_count * pkt_size) / (enc_elapsed * 1e6);

    /* Prepare ciphertext for decrypt bench */
    size_t ct_len;
    wg_aead_encrypt(ct, &ct_len, plain, pkt_size, ad, 16, 0, key);

    /* Benchmark decrypt */
    uint64_t dec_count = 0;
    start = now_sec();
    deadline = start + duration;
    while (now_sec() < deadline) {
        for (int i = 0; i < 100; i++) {
            size_t pt_len;
            wg_aead_decrypt(dec, &pt_len, ct, ct_len, ad, 16, 0, key);
            dec_count++;
        }
    }
    double dec_elapsed = now_sec() - start;
    double dec_mbps = ((double)dec_count * pkt_size * 8.0) / (dec_elapsed * 1e6);
    double dec_mBps = ((double)dec_count * pkt_size) / (dec_elapsed * 1e6);

#if defined(__aarch64__) && !defined(WG_NO_ARM64_NEON)
    const char *backend = "ARM64 NEON intrinsics";
#elif defined(WG_USE_OPENSSL)
    const char *backend = "OpenSSL EVP";
#else
    const char *backend = "libsodium";
#endif

    printf("ChaCha20-Poly1305 AEAD (%s)\n", backend);
    printf("  Packet size: %zu bytes\n\n", pkt_size);
    printf("  Encrypt: %8.0f Mbps  (%6.0f MB/s)  %llu ops\n",
           enc_mbps, enc_mBps, (unsigned long long)enc_count);
    printf("  Decrypt: %8.0f Mbps  (%6.0f MB/s)  %llu ops\n",
           dec_mbps, dec_mBps, (unsigned long long)dec_count);

    return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Microbenchmark: Noise IKpsk2 handshake throughput.
 * Measures handshakes/sec (create_initiation + consume_initiation +
 * create_response + consume_response = 1 full handshake).
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/noise/wg_noise.h"

#include <assert.h>
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

int main(int argc, char **argv)
{
    int duration = 5;
    if (argc > 1)
        duration = atoi(argv[1]);
    if (duration <= 0)
        duration = 5;

    if (sodium_init() < 0)
        return 1;
    wg_noise_module_init();

    /* Setup two static identities */
    uint8_t sk_i[32], sk_r[32];
    wg_x25519_generate_private(sk_i);
    wg_x25519_generate_private(sk_r);

    wg_noise_static_identity_t si_i, si_r;
    wg_noise_static_identity_init(&si_i);
    wg_noise_static_identity_init(&si_r);
    wg_noise_static_identity_set_private_key(&si_i, sk_i);
    wg_noise_static_identity_set_private_key(&si_r, sk_r);

    printf("Noise IKpsk2 Handshake Benchmark (%d seconds)\n\n", duration);

    /* Benchmark: create_initiation only */
    uint64_t init_count = 0;
    double start = now_sec();
    double deadline = start + duration;

    while (now_sec() < deadline) {
        for (int i = 0; i < 10; i++) {
            wg_noise_handshake_t hs;
            memset(&hs, 0, sizeof(hs));
            hs.static_identity = &si_i;
            memcpy(hs.remote_static, si_r.static_public, 32);
            pthread_rwlock_init(&hs.lock, NULL);
            wg_noise_precompute_static_static(&hs);

            wg_message_initiation_t msg;
            wg_error_t err = wg_noise_handshake_create_initiation(&msg, &hs);
            assert(err == WG_OK);
            (void)err;

            pthread_rwlock_destroy(&hs.lock);
            init_count++;
        }
    }
    double elapsed = now_sec() - start;
    printf("  create_initiation: %8.0f handshakes/sec  (%llu in %.1fs)\n",
           init_count / elapsed, (unsigned long long)init_count, elapsed);

    /* Benchmark: X25519 DH (the dominant cost in handshake) */
    uint64_t dh_count = 0;
    start = now_sec();
    deadline = start + duration;

    while (now_sec() < deadline) {
        for (int i = 0; i < 10; i++) {
            uint8_t out[32];
            wg_x25519(out, sk_i, si_r.static_public);
            dh_count++;
        }
    }
    elapsed = now_sec() - start;
    printf("  X25519 DH:         %8.0f ops/sec        (%llu in %.1fs)\n",
           dh_count / elapsed, (unsigned long long)dh_count, elapsed);

    /* Benchmark: BLAKE2s-256 (hash throughput) */
    uint64_t hash_count = 0;
    uint8_t hash_in[64], hash_out[32];
    randombytes_buf(hash_in, 64);
    start = now_sec();
    deadline = start + duration;

    while (now_sec() < deadline) {
        for (int i = 0; i < 100; i++) {
            wg_blake2s(hash_out, 32, hash_in, 64, NULL, 0);
            hash_count++;
        }
    }
    elapsed = now_sec() - start;
    double hash_mbps = ((double)hash_count * 64 * 8) / (elapsed * 1e6);
    printf("  BLAKE2s-256:       %8.0f ops/sec        (%.0f Mbps, 64B input)\n",
           hash_count / elapsed, hash_mbps);

    pthread_rwlock_destroy(&si_i.lock);
    pthread_rwlock_destroy(&si_r.lock);

    return 0;
}

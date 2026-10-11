/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 */

/* Fast UDP flood of WireGuard initiation packets with valid MAC1.
 * Used by test_cookie_reply.sh to trigger under_load on the server.
 *
 * Usage: flood_initiation <target_ip> <target_port> <duration_sec> <server_pubkey_base64>
 *
 * Sends using sendmmsg() for maximum throughput.
 * Build: cc -O2 -o flood_initiation flood_initiation.c -lsodium
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define WG_INITIATION_SIZE 148
#define MAC1_OFFSET 116
#define MAC2_OFFSET 132
#define BATCH_SIZE 64

/* ═══════════════════════════════════════════════════════════════════
 * Minimal BLAKE2s implementation (RFC 7693)
 * WireGuard mandates BLAKE2s; libsodium only has BLAKE2b.
 * ═══════════════════════════════════════════════════════════════════ */

#define BLAKE2S_OUTLEN 32
#define BLAKE2S_KEYLEN 32
#define BLAKE2S_BLOCKLEN 64

static const uint32_t blake2s_iv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint8_t buf[BLAKE2S_BLOCKLEN];
    size_t buflen;
    size_t outlen;
} blake2s_state;

static void blake2s_compress(blake2s_state *s, const uint8_t *block, int last)
{
    uint32_t v[16], m[16];
    for (int i = 0; i < 8; i++)
        v[i] = s->h[i];
    v[8] = blake2s_iv[0];
    v[9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ s->t[0];
    v[13] = blake2s_iv[5] ^ s->t[1];
    v[14] = last ? ~blake2s_iv[6] : blake2s_iv[6];
    v[15] = blake2s_iv[7];
    for (int i = 0; i < 16; i++)
        m[i] = load32_le(block + 4 * i);

#define G(r, i, a, b, c, d)                                                                       \
    do {                                                                                           \
        a += b + m[blake2s_sigma[r][2 * i]];                                                      \
        d = rotr32(d ^ a, 16);                                                                    \
        c += d;                                                                                    \
        b = rotr32(b ^ c, 12);                                                                    \
        a += b + m[blake2s_sigma[r][2 * i + 1]];                                                  \
        d = rotr32(d ^ a, 8);                                                                     \
        c += d;                                                                                    \
        b = rotr32(b ^ c, 7);                                                                     \
    } while (0)

    for (int r = 0; r < 10; r++) {
        G(r, 0, v[0], v[4], v[8], v[12]);
        G(r, 1, v[1], v[5], v[9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8], v[13]);
        G(r, 7, v[3], v[4], v[9], v[14]);
    }
#undef G

    for (int i = 0; i < 8; i++)
        s->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2s_init(blake2s_state *s, size_t outlen)
{
    memset(s, 0, sizeof(*s));
    s->outlen = outlen;
    for (int i = 0; i < 8; i++)
        s->h[i] = blake2s_iv[i];
    s->h[0] ^= 0x01010000 ^ (uint32_t)outlen;
}

static void blake2s_init_key(blake2s_state *s, size_t outlen, const uint8_t *key, size_t keylen)
{
    memset(s, 0, sizeof(*s));
    s->outlen = outlen;
    for (int i = 0; i < 8; i++)
        s->h[i] = blake2s_iv[i];
    s->h[0] ^= 0x01010000 ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;

    uint8_t block[BLAKE2S_BLOCKLEN];
    memset(block, 0, BLAKE2S_BLOCKLEN);
    memcpy(block, key, keylen);
    s->t[0] += BLAKE2S_BLOCKLEN;
    blake2s_compress(s, block, 0);
}

static void blake2s_update(blake2s_state *s, const uint8_t *in, size_t inlen)
{
    while (inlen > 0) {
        if (s->buflen == BLAKE2S_BLOCKLEN) {
            s->t[0] += BLAKE2S_BLOCKLEN;
            if (s->t[0] == 0)
                s->t[1]++;
            blake2s_compress(s, s->buf, 0);
            s->buflen = 0;
        }
        size_t n = BLAKE2S_BLOCKLEN - s->buflen;
        if (n > inlen)
            n = inlen;
        memcpy(s->buf + s->buflen, in, n);
        s->buflen += n;
        in += n;
        inlen -= n;
    }
}

static void blake2s_final(blake2s_state *s, uint8_t *out)
{
    s->t[0] += (uint32_t)s->buflen;
    if (s->t[0] < (uint32_t)s->buflen)
        s->t[1]++;
    memset(s->buf + s->buflen, 0, BLAKE2S_BLOCKLEN - s->buflen);
    blake2s_compress(s, s->buf, 1);
    for (size_t i = 0; i < s->outlen; i++)
        out[i] = (uint8_t)(s->h[i / 4] >> (8 * (i % 4)));
}

/* Compute keyed BLAKE2s MAC (same as wg_mac in wg-c) */
static void blake2s_mac(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                        const uint8_t *key, size_t keylen)
{
    blake2s_state s;
    if (key && keylen > 0)
        blake2s_init_key(&s, outlen, key, keylen);
    else
        blake2s_init(&s, outlen);
    blake2s_update(&s, in, inlen);
    blake2s_final(&s, out);
}

/* ═══════════════════════════════════════════════════════════════════ */

static void compute_mac1_key(const uint8_t server_pubkey[32], uint8_t mac1_key[32])
{
    /* mac1_key = BLAKE2s-256("mac1----" || server_public_key) — unkeyed */
    blake2s_state s;
    blake2s_init(&s, 32);
    blake2s_update(&s, (const uint8_t *)"mac1----", 8);
    blake2s_update(&s, server_pubkey, 32);
    blake2s_final(&s, mac1_key);
}

static void build_packet(uint8_t pkt[WG_INITIATION_SIZE], const uint8_t mac1_key[32])
{
    /* type = 1 (LE uint32) */
    pkt[0] = 1;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;

    /* random sender_index + noise fields (bytes 4..115) */
    randombytes_buf(pkt + 4, 112);

    /* MAC1 = keyed BLAKE2s-128(mac1_key, message[0:116]) */
    blake2s_mac(pkt + MAC1_OFFSET, 16, pkt, MAC1_OFFSET, mac1_key, 32);

    /* MAC2 = zeros (no cookie) */
    memset(pkt + MAC2_OFFSET, 0, 16);
}

static int base64_decode(const char *b64, uint8_t *out, size_t out_len)
{
    size_t decoded_len;
    if (sodium_base642bin(out, out_len, b64, strlen(b64), NULL, &decoded_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return -1;
    return (decoded_len == out_len) ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr,
                "Usage: %s <ip> <port> <duration_sec> <server_pubkey_b64> [burst_pause_us]\n"
                "  burst_pause_us: microseconds to sleep between batches (0 = no pause)\n",
                argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    double duration = atof(argv[3]);
    const char *pubkey_b64 = argv[4];
    int burst_pause_us = (argc == 6) ? atoi(argv[5]) : 0;

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    uint8_t server_pubkey[32];
    if (base64_decode(pubkey_b64, server_pubkey, 32) != 0) {
        fprintf(stderr, "Invalid base64 public key\n");
        return 1;
    }

    uint8_t mac1_key[32];
    compute_mac1_key(server_pubkey, mac1_key);

    /* Setup target address */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", target_ip);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    /* Pre-build packet batch */
    uint8_t packets[BATCH_SIZE][WG_INITIATION_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];

    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH_SIZE; i++) {
        build_packet(packets[i], mac1_key);
        iovecs[i].iov_base = packets[i];
        iovecs[i].iov_len = WG_INITIATION_SIZE;
        msgs[i].msg_hdr.msg_name = &addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(addr);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    uint64_t count = 0;

    for (;;) {
        /* Regenerate random content for each batch */
        for (int i = 0; i < BATCH_SIZE; i++)
            build_packet(packets[i], mac1_key);

        int sent = sendmmsg(sock, msgs, BATCH_SIZE, 0);
        if (sent > 0)
            count += sent;

        if (burst_pause_us > 0)
            usleep(burst_pause_us);

        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= duration)
            break;
    }

    close(sock);
    printf("Sent %lu valid-MAC1 initiations in %.1fs (%.0f pkt/s)\n", (unsigned long)count,
           duration, count / duration);
    return 0;
}

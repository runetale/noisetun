/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * TX-2 verification: Anti-replay filter (RFC 6479).
 *
 * Test vectors ported from wireguard-go/replay/replay_test.go.
 */

#include "../src/replay/wg_replay.h"
#include <assert.h>
#include <stdio.h>

#define REJECT_AFTER_MESSAGES WG_REJECT_AFTER_MESSAGES
#define T_LIM                 (WG_REPLAY_WINDOW_SIZE + 1)

static int test_num;

static void T(wg_replay_counter_t *rc, uint64_t n, bool expected)
{
    test_num++;
    bool got = wg_replay_counter_validate(rc, n, REJECT_AFTER_MESSAGES);
    if (got != expected) {
        fprintf(stderr, "  FAIL: test %d: counter=%llu expected=%s got=%s\n", test_num,
                (unsigned long long)n, expected ? "true" : "false",
                got ? "true" : "false");
        assert(0);
    }
}

/* ────────────────────────────────────────
 * Main test: sequential test vectors from wireguard-go
 * ──────────────────────────────────────── */
static void test_sequential_vectors(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    T(&f, 0, true);                          /*  1 */
    T(&f, 1, true);                          /*  2 */
    T(&f, 1, false);                         /*  3 */
    T(&f, 9, true);                          /*  4 */
    T(&f, 8, true);                          /*  5 */
    T(&f, 7, true);                          /*  6 */
    T(&f, 7, false);                         /*  7 */
    T(&f, T_LIM, true);                      /*  8 */
    T(&f, T_LIM - 1, true);                  /*  9 */
    T(&f, T_LIM - 1, false);                 /* 10 */
    T(&f, T_LIM - 2, true);                  /* 11 */
    T(&f, 2, true);                          /* 12 */
    T(&f, 2, false);                         /* 13 */
    T(&f, T_LIM + 16, true);                 /* 14 */
    T(&f, 3, false);                         /* 15 */
    T(&f, T_LIM + 16, false);                /* 16 */
    T(&f, T_LIM * 4, true);                  /* 17 */
    T(&f, T_LIM * 4 - (T_LIM - 1), true);    /* 18 */
    T(&f, 10, false);                        /* 19 */
    T(&f, T_LIM * 4 - T_LIM, false);         /* 20 */
    T(&f, T_LIM * 4 - (T_LIM + 1), false);   /* 21 */
    T(&f, T_LIM * 4 - (T_LIM - 2), true);    /* 22 */
    T(&f, T_LIM * 4 + 1 - T_LIM, false);     /* 23 */
    T(&f, 0, false);                         /* 24 */
    T(&f, REJECT_AFTER_MESSAGES, false);     /* 25 */
    T(&f, REJECT_AFTER_MESSAGES - 1, true);  /* 26 */
    T(&f, REJECT_AFTER_MESSAGES, false);     /* 27 */
    T(&f, REJECT_AFTER_MESSAGES - 1, false); /* 28 */
    T(&f, REJECT_AFTER_MESSAGES - 2, true);  /* 29 */
    T(&f, REJECT_AFTER_MESSAGES + 1, false); /* 30 */
    T(&f, REJECT_AFTER_MESSAGES + 2, false); /* 31 */
    T(&f, REJECT_AFTER_MESSAGES - 2, false); /* 32 */
    T(&f, REJECT_AFTER_MESSAGES - 3, true);  /* 33 */
    T(&f, 0, false);                         /* 34 */

    wg_replay_counter_destroy(&f);
    printf("  PASS: sequential_vectors (34 cases)\n");
}

/* ────────────────────────────────────────
 * Bulk test 1: forward fill 1..windowSize, then 0
 * ──────────────────────────────────────── */
static void test_bulk_1(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = 1; i <= WG_REPLAY_WINDOW_SIZE; i++)
        T(&f, i, true);
    T(&f, 0, true);
    T(&f, 0, false);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_1 (forward fill)\n");
}

/* ────────────────────────────────────────
 * Bulk test 2: forward fill 2..windowSize+1, then 1 and 0
 * ──────────────────────────────────────── */
static void test_bulk_2(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = 2; i <= WG_REPLAY_WINDOW_SIZE + 1; i++)
        T(&f, i, true);
    T(&f, 1, true);
    T(&f, 0, false);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_2 (forward fill offset)\n");
}

/* ────────────────────────────────────────
 * Bulk test 3: reverse fill windowSize+1..1
 * ──────────────────────────────────────── */
static void test_bulk_3(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = WG_REPLAY_WINDOW_SIZE + 1; i > 0; i--)
        T(&f, i, true);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_3 (reverse fill)\n");
}

/* ────────────────────────────────────────
 * Bulk test 4: reverse fill windowSize+2..2, then 0 fails
 * ──────────────────────────────────────── */
static void test_bulk_4(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = WG_REPLAY_WINDOW_SIZE + 2; i > 1; i--)
        T(&f, i, true);
    T(&f, 0, false);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_4 (reverse fill offset)\n");
}

/* ────────────────────────────────────────
 * Bulk test 5: reverse fill windowSize..1, then windowSize+1, then 0 fails
 * ──────────────────────────────────────── */
static void test_bulk_5(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = WG_REPLAY_WINDOW_SIZE; i > 0; i--)
        T(&f, i, true);
    T(&f, WG_REPLAY_WINDOW_SIZE + 1, true);
    T(&f, 0, false);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_5 (reverse then advance)\n");
}

/* ────────────────────────────────────────
 * Bulk test 6: reverse fill windowSize..1, then 0, then windowSize+1
 * ──────────────────────────────────────── */
static void test_bulk_6(void)
{
    wg_replay_counter_t f;
    wg_replay_counter_init(&f);
    test_num = 0;

    for (uint64_t i = WG_REPLAY_WINDOW_SIZE; i > 0; i--)
        T(&f, i, true);
    T(&f, 0, true);
    T(&f, WG_REPLAY_WINDOW_SIZE + 1, true);

    wg_replay_counter_destroy(&f);
    printf("  PASS: bulk_6 (reverse, zero, advance)\n");
}

int main(void)
{
    printf("TX-2 Anti-Replay filter tests:\n");

    test_sequential_vectors();
    test_bulk_1();
    test_bulk_2();
    test_bulk_3();
    test_bulk_4();
    test_bulk_5();
    test_bulk_6();

    printf("All TX-2 tests passed.\n");
    return 0;
}

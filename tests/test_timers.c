/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for timer state machine (wg_timers).
 */

#include "timers/wg_timers.h"
#include "noise/wg_noise.h"
#include "peer/wg_peer.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

#define TEST(name)               \
    do {                         \
        printf("  %-50s", name); \
        fflush(stdout);          \
    } while (0)
#define PASS()            \
    do {                  \
        printf("PASS\n"); \
    } while (0)

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ────────────────────────────────────────
 * Test: timer create/destroy
 * ──────────────────────────────────────── */

static _Atomic int callback_count;

static void test_callback(struct wg_peer *peer)
{
    (void)peer;
    atomic_fetch_add(&callback_count, 1);
}

static void test_timer_lifecycle(void)
{
    TEST("timer create/destroy");

    wg_timer_t *timer = wg_timer_new(NULL, test_callback);
    assert(timer != NULL);
    assert(!wg_timer_is_pending(timer));

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Test: timer fires after duration
 * ──────────────────────────────────────── */

static void test_timer_fires(void)
{
    TEST("timer fires after duration");

    atomic_store(&callback_count, 0);

    wg_timer_t *timer = wg_timer_new(NULL, test_callback);
    assert(timer != NULL);

    /* Arm for 50ms */
    wg_timer_mod(timer, 50 * 1000000ULL);
    assert(wg_timer_is_pending(timer));

    /* Wait 150ms — should have fired */
    sleep_ms(150);
    assert(atomic_load(&callback_count) == 1);
    assert(!wg_timer_is_pending(timer));

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Test: timer cancel (Del)
 * ──────────────────────────────────────── */

static void test_timer_cancel(void)
{
    TEST("timer cancel (Del)");

    atomic_store(&callback_count, 0);

    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    /* Arm for 200ms */
    wg_timer_mod(timer, 200 * 1000000ULL);
    assert(wg_timer_is_pending(timer));

    /* Cancel after 50ms */
    sleep_ms(50);
    wg_timer_del(timer);
    assert(!wg_timer_is_pending(timer));

    /* Wait past original deadline */
    sleep_ms(200);
    assert(atomic_load(&callback_count) == 0);

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Test: timer re-arm (Mod while pending)
 * ──────────────────────────────────────── */

static void test_timer_rearm(void)
{
    TEST("timer re-arm (Mod while pending)");

    atomic_store(&callback_count, 0);

    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    /* Arm for 300ms */
    wg_timer_mod(timer, 300 * 1000000ULL);

    /* Re-arm for 500ms after 50ms (well before the 300ms deadline) */
    sleep_ms(50);
    wg_timer_mod(timer, 500 * 1000000ULL);

    /* At ~400ms: past original 300ms deadline, but re-armed so shouldn't fire */
    sleep_ms(350);
    assert(atomic_load(&callback_count) == 0);

    /* At ~700ms: re-armed timer (deadline ~550ms) should have fired */
    sleep_ms(300);
    assert(atomic_load(&callback_count) == 1);

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Tests: Mod and Del do not always wake the timer thread
 *
 * The thread sleeps to the deadline it last saw; Mod wakes it only for
 * an earlier deadline, and Del not at all.
 * ──────────────────────────────────────── */

static void test_timer_mod_earlier(void)
{
    TEST("Mod to an earlier deadline wakes the thread");

    atomic_store(&callback_count, 0);
    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    wg_timer_mod(timer, 2000 * 1000000ULL);
    sleep_ms(20); /* let the thread sleep to the 2 s deadline */
    wg_timer_mod(timer, 50 * 1000000ULL);

    sleep_ms(300);
    assert(atomic_load(&callback_count) == 1);

    wg_timer_destroy(timer);
    PASS();
}

static void test_timer_del_then_mod(void)
{
    TEST("Del then Mod fires at the new deadline, not the old");

    atomic_store(&callback_count, 0);
    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    /* Thread sleeps to ~100 ms; the timer is re-armed to ~350 ms. */
    wg_timer_mod(timer, 100 * 1000000ULL);
    sleep_ms(20);
    wg_timer_del(timer);
    sleep_ms(30);
    wg_timer_mod(timer, 300 * 1000000ULL);

    /* ~200 ms: the thread woke at 100 ms and must have gone back to sleep */
    sleep_ms(150);
    assert(atomic_load(&callback_count) == 0);
    assert(wg_timer_is_pending(timer));

    /* ~550 ms */
    sleep_ms(350);
    assert(atomic_load(&callback_count) == 1);

    wg_timer_destroy(timer);
    PASS();
}

static void test_timer_mod_after_idle(void)
{
    TEST("Mod after Del and the old deadline passed fires");

    atomic_store(&callback_count, 0);
    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    /* The thread wakes at 50 ms, finds nothing pending, waits untimed. */
    wg_timer_mod(timer, 50 * 1000000ULL);
    wg_timer_del(timer);
    sleep_ms(150);
    assert(atomic_load(&callback_count) == 0);

    wg_timer_mod(timer, 50 * 1000000ULL);
    sleep_ms(250);
    assert(atomic_load(&callback_count) == 1);

    wg_timer_destroy(timer);
    PASS();
}

static void test_timer_mod_del_churn(void)
{
    TEST("Mod/Del churn then Mod fires once");

    atomic_store(&callback_count, 0);
    wg_timer_t *timer = wg_timer_new(NULL, test_callback);

    /* The data path's pattern: re-armed and cancelled every batch. */
    for (int i = 0; i < 100000; i++) {
        wg_timer_mod(timer, 50 * 1000000ULL);
        wg_timer_del(timer);
    }
    assert(atomic_load(&callback_count) == 0);

    wg_timer_mod(timer, 50 * 1000000ULL);
    sleep_ms(300);
    assert(atomic_load(&callback_count) == 1);

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Test: DelSync waits for running callback
 * ──────────────────────────────────────── */

static _Atomic bool callback_started;
static _Atomic bool callback_finished;

static void slow_callback(struct wg_peer *peer)
{
    (void)peer;
    atomic_store(&callback_started, true);
    sleep_ms(100);
    atomic_store(&callback_finished, true);
}

static void test_del_sync(void)
{
    TEST("DelSync waits for running callback");

    atomic_store(&callback_started, false);
    atomic_store(&callback_finished, false);

    wg_timer_t *timer = wg_timer_new(NULL, slow_callback);

    /* Arm immediately (1ms) */
    wg_timer_mod(timer, 1 * 1000000ULL);

    /* Wait for callback to start */
    sleep_ms(50);

    /* DelSync should wait for callback to finish */
    wg_timer_del_sync(timer);
    assert(atomic_load(&callback_finished));

    wg_timer_destroy(timer);
    PASS();
}

/* ────────────────────────────────────────
 * Test: timer event callbacks (data_sent, etc.)
 * ──────────────────────────────────────── */

static void test_timer_events(void)
{
    TEST("timer event callbacks on mock peer");

    /* We can't easily test the full timer event integration without
     * a proper device, but we can test that the functions don't crash
     * on a peer that is_running=false (timers_active returns false). */

    wg_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    atomic_store(&peer.is_running, false);
    peer.device = NULL;

    /* These should all be no-ops when timers_active() is false */
    wg_timers_data_sent(&peer);
    wg_timers_data_received(&peer);
    wg_timers_any_authenticated_packet_sent(&peer);
    wg_timers_any_authenticated_packet_received(&peer);
    wg_timers_handshake_initiated(&peer);
    wg_timers_handshake_complete(&peer);
    wg_timers_session_derived(&peer);
    wg_timers_any_authenticated_packet_traversal(&peer);

    PASS();
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    printf("=== test_timers ===\n");

    test_timer_lifecycle();
    test_timer_fires();
    test_timer_cancel();
    test_timer_rearm();
    test_timer_mod_earlier();
    test_timer_del_then_mod();
    test_timer_mod_after_idle();
    test_timer_mod_del_churn();
    test_del_sync();
    test_timer_events();

    printf("All timer tests passed.\n");
    return 0;
}

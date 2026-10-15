/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Timer state machine for per-peer WireGuard timers.
 *
 * Reference: wireguard-go/device/timers.go
 */

#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pthread_setname_np */
#endif
#endif
#include "wg_timers.h"

/* macOS (#64) and Windows (#65: 184 -> 274 Mbps on a 4 vCPU ARM64 VM):
 * their TUN paths hand over one packet at a time, so the wake was per
 * packet. */
#if defined(__APPLE__) || defined(_WIN32)
#define WG_TIMER_LAZY_WAKE 1
#else
#define WG_TIMER_LAZY_WAKE 0
#endif

#include "../noise/wg_noise.h"
#include "../peer/wg_peer.h"
#include "../workers/wg_workers.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ────────────────────────────────────────
 * Platform-specific timed wait
 *
 * Linux:  pthread_condattr_setclock(CLOCK_MONOTONIC) lets
 *         pthread_cond_timedwait accept a CLOCK_MONOTONIC abstime.
 * macOS:  No pthread_condattr_setclock. Use the non-portable
 *         pthread_cond_timedwait_relative_np with a relative timespec.
 * ──────────────────────────────────────── */

static uint64_t mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Timed wait on a condvar until deadline_ns (monotonic) or signal.
 * Returns ETIMEDOUT if the deadline elapsed, 0 otherwise.
 */
static int cond_timedwait_mono(pthread_cond_t *cond, pthread_mutex_t *lock,
                               int cond_clock, uint64_t deadline_ns)
{
#ifdef __APPLE__
    /* macOS: compute relative timeout from monotonic clock */
    (void)cond_clock;
    uint64_t now = mono_now_ns();
    if (now >= deadline_ns) {
        /* Already past deadline — poll once and return timeout */
        struct timespec zero = {0, 0};
        int rc = pthread_cond_timedwait_relative_np(cond, lock, &zero);
        return (rc == ETIMEDOUT) ? ETIMEDOUT : rc;
    }
    uint64_t remain = deadline_ns - now;
    struct timespec rel;
    rel.tv_sec = (time_t)(remain / 1000000000ULL);
    rel.tv_nsec = (long)(remain % 1000000000ULL);
    return pthread_cond_timedwait_relative_np(cond, lock, &rel);
#else
    /* Linux / POSIX: condvar is configured for CLOCK_MONOTONIC */
    struct timespec ts;
    if (cond_clock == CLOCK_MONOTONIC) {
        ts.tv_sec = (time_t)(deadline_ns / 1000000000ULL);
        ts.tv_nsec = (long)(deadline_ns % 1000000000ULL);
        return pthread_cond_timedwait(cond, lock, &ts);
    }
    /* The condvar kept the default clock (setclock refused, or ignored
     * as on ESP-IDF: WG_CONDATTR_SETCLOCK_WORKS).
     * A monotonic deadline read as a realtime one lies decades in the
     * past once the wall clock is set, and the thread would spin. Turn
     * what remains into a deadline on the condvar's own clock. */
    uint64_t now = mono_now_ns();
    uint64_t remain = deadline_ns > now ? deadline_ns - now : 0;
    clock_gettime(cond_clock, &ts);
    uint64_t abs_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec + remain;
    ts.tv_sec = (time_t)(abs_ns / 1000000000ULL);
    ts.tv_nsec = (long)(abs_ns % 1000000000ULL);
    return pthread_cond_timedwait(cond, lock, &ts);
#endif
}

#if WG_TIMERS_SHARED_THREAD

/* ────────────────────────────────────────
 * Shared timer thread
 *
 * One thread runs every timer in the process: it sleeps until the
 * earliest armed deadline, then runs that timer's callback with no lock
 * held. svc.lock guards the timer list and each timer's deadline_ns and
 * is_pending, and is never held while taking another lock, so mod and
 * del can be called with any lock held, as with per-timer threads.
 *
 * DelSync and destroy wait while the timer's callback is running
 * (svc.firing), the job run_lock does for a per-timer thread. Callbacks
 * run one after another, so a callback must not wait on anything another
 * timer's callback would have to do first.
 *
 * The thread starts with the first timer and is joined after the last,
 * under svc_life, so a new timer never races the old thread's exit.
 * ──────────────────────────────────────── */

static pthread_mutex_t svc_life = PTHREAD_MUTEX_INITIALIZER;

static struct {
    pthread_mutex_t lock;
    pthread_cond_t cond; /* wakes the thread: earlier deadline, stop */
    pthread_cond_t idle; /* a callback returned */
    int cond_clock;      /* clock cond's timed waits count on */
    wg_timer_t *timers;  /* every live timer */
    size_t count;
    wg_timer_t *firing;        /* timer whose callback is running */
    uint64_t wait_deadline_ns; /* what the thread sleeps until: UINT64_MAX
                                  untimed, 0 not sleeping */
    bool stopping;
    uintptr_t gen; /* bumped per thread, so a detached old one bows out */
    pthread_t thread;
} svc = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .idle = PTHREAD_COND_INITIALIZER,
};

static void *svc_thread_fn(void *arg)
{
    uintptr_t gen = (uintptr_t)arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "wg-timers");
#endif

    pthread_mutex_lock(&svc.lock);
    while (!svc.stopping && svc.gen == gen) {
        uint64_t now = mono_now_ns();
        uint64_t next = UINT64_MAX;
        wg_timer_t *due = NULL;
        for (wg_timer_t *t = svc.timers; t; t = t->next) {
            if (!t->is_pending)
                continue;
            if (t->deadline_ns <= now) {
                due = t;
                break;
            }
            if (t->deadline_ns < next)
                next = t->deadline_ns;
        }

        if (!due) {
            svc.wait_deadline_ns = next;
            if (next == UINT64_MAX)
                pthread_cond_wait(&svc.cond, &svc.lock);
            else
                cond_timedwait_mono(&svc.cond, &svc.lock, svc.cond_clock, next);
            svc.wait_deadline_ns = 0;
            continue;
        }

        due->is_pending = false;
        svc.firing = due;
        pthread_mutex_unlock(&svc.lock);

        if (due->callback)
            due->callback(due->peer);

        pthread_mutex_lock(&svc.lock);
        if (svc.firing == due)
            svc.firing = NULL;
        pthread_cond_broadcast(&svc.idle);
    }
    pthread_mutex_unlock(&svc.lock);

    return NULL;
}

/* Called under svc_life with no timers. */
static bool svc_start(void)
{
#ifdef __APPLE__
    /* cond_timedwait_mono waits relative to the monotonic clock. */
    pthread_cond_init(&svc.cond, NULL);
    svc.cond_clock = CLOCK_REALTIME;
#else
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    if (!WG_CONDATTR_SETCLOCK_WORKS ||
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
        pthread_cond_init(&svc.cond, NULL);
        svc.cond_clock = CLOCK_REALTIME;
    } else {
        pthread_cond_init(&svc.cond, &attr);
        svc.cond_clock = CLOCK_MONOTONIC;
    }
    pthread_condattr_destroy(&attr);
#endif

    pthread_mutex_lock(&svc.lock);
    svc.stopping = false;
    uintptr_t gen = ++svc.gen;
    pthread_mutex_unlock(&svc.lock);
    if (pthread_create(&svc.thread, NULL, svc_thread_fn, (void *)gen) != 0) {
        pthread_cond_destroy(&svc.cond);
        return false;
    }
    return true;
}

/* Called under svc_life once the last timer is gone. */
static void svc_stop(void)
{
    pthread_mutex_lock(&svc.lock);
    svc.stopping = true;
    pthread_cond_signal(&svc.cond);
    pthread_mutex_unlock(&svc.lock);

    if (pthread_equal(pthread_self(), svc.thread))
        pthread_detach(svc.thread); /* the last timer went from a callback */
    else
        pthread_join(svc.thread, NULL);
    pthread_cond_destroy(&svc.cond);
}

/* Waits, under svc.lock, until timer's callback is not running. A
 * callback stopping its own timer does not wait for itself. */
static void svc_wait_not_firing(wg_timer_t *timer)
{
    while (svc.firing == timer && !pthread_equal(pthread_self(), svc.thread))
        pthread_cond_wait(&svc.idle, &svc.lock);
}

wg_timer_t *wg_timer_new(struct wg_peer *peer, wg_timer_fn callback)
{
    wg_timer_t *timer = calloc(1, sizeof(*timer));
    if (!timer)
        return NULL;

    timer->peer = peer;
    timer->callback = callback;

    pthread_mutex_lock(&svc_life);
    if (svc.count == 0 && !svc_start()) {
        pthread_mutex_unlock(&svc_life);
        free(timer);
        return NULL;
    }
    pthread_mutex_lock(&svc.lock);
    timer->next = svc.timers;
    svc.timers = timer;
    svc.count++;
    pthread_mutex_unlock(&svc.lock);
    pthread_mutex_unlock(&svc_life);

    return timer;
}

void wg_timer_mod(wg_timer_t *timer, uint64_t duration_ns)
{
    if (!timer)
        return;

    uint64_t now = mono_now_ns();

    pthread_mutex_lock(&svc.lock);
    timer->is_pending = true;
    timer->deadline_ns = now + duration_ns;
    /* A later deadline is picked up when the thread wakes for the one it
     * sleeps to, and a thread that is not sleeping rescans anyway. */
    if (timer->deadline_ns < svc.wait_deadline_ns)
        pthread_cond_signal(&svc.cond);
    pthread_mutex_unlock(&svc.lock);
}

void wg_timer_del(wg_timer_t *timer)
{
    if (!timer)
        return;

    /* No wake: the thread finds nothing due at its old deadline. */
    pthread_mutex_lock(&svc.lock);
    timer->is_pending = false;
    pthread_mutex_unlock(&svc.lock);
}

void wg_timer_del_sync(wg_timer_t *timer)
{
    if (!timer)
        return;

    pthread_mutex_lock(&svc.lock);
    timer->is_pending = false;
    svc_wait_not_firing(timer);
    /* The callback may have re-armed it. */
    timer->is_pending = false;
    pthread_mutex_unlock(&svc.lock);
}

bool wg_timer_is_pending(wg_timer_t *timer)
{
    if (!timer)
        return false;

    pthread_mutex_lock(&svc.lock);
    bool pending = timer->is_pending;
    pthread_mutex_unlock(&svc.lock);
    return pending;
}

void wg_timer_destroy(wg_timer_t *timer)
{
    if (!timer)
        return;

    pthread_mutex_lock(&svc_life);
    pthread_mutex_lock(&svc.lock);
    for (wg_timer_t **pp = &svc.timers; *pp; pp = &(*pp)->next) {
        if (*pp == timer) {
            *pp = timer->next;
            break;
        }
    }
    svc.count--;
    svc_wait_not_firing(timer);
    size_t left = svc.count;
    pthread_mutex_unlock(&svc.lock);
    if (left == 0)
        svc_stop();
    pthread_mutex_unlock(&svc_life);

    free(timer);
}

#else /* !WG_TIMERS_SHARED_THREAD */

/* ────────────────────────────────────────
 * Timer thread
 * ──────────────────────────────────────── */

static void *timer_thread_fn(void *arg)
{
    wg_timer_t *timer = (wg_timer_t *)arg;
#ifdef __linux__
    pthread_setname_np(pthread_self(), "wg-timer");
#endif

    pthread_mutex_lock(&timer->lock);
    while (!timer->should_stop) {
        if (!timer->is_pending) {
            timer->wait_deadline_ns = UINT64_MAX;
            pthread_cond_wait(&timer->cond, &timer->lock);
            continue;
        }

        /* Mod and Del do not wake us unless the deadline moved earlier
         * (see wg_timer_mod), so the deadline we slept to may be stale:
         * check the clock against the current one. */
        if (mono_now_ns() < timer->deadline_ns) {
            timer->wait_deadline_ns = timer->deadline_ns;
            cond_timedwait_mono(&timer->cond, &timer->lock, timer->cond_clock,
                                timer->deadline_ns);
            continue;
        }

        /* Deadline reached — fire the callback */
        timer->is_pending = false;
        timer->wait_deadline_ns = 0;
        pthread_mutex_unlock(&timer->lock);

        /* Acquire run_lock so DelSync can wait for us */
        pthread_mutex_lock(&timer->run_lock);

        /* Re-check stop (might have been set between unlock and run_lock) */
        pthread_mutex_lock(&timer->lock);
        bool should_fire = !timer->should_stop;
        pthread_mutex_unlock(&timer->lock);

        if (should_fire && timer->callback)
            timer->callback(timer->peer);

        pthread_mutex_unlock(&timer->run_lock);
        pthread_mutex_lock(&timer->lock);
    }
    pthread_mutex_unlock(&timer->lock);

    return NULL;
}

/* ────────────────────────────────────────
 * Timer lifecycle
 * ──────────────────────────────────────── */

wg_timer_t *wg_timer_new(struct wg_peer *peer, wg_timer_fn callback)
{
    wg_timer_t *timer = calloc(1, sizeof(*timer));
    if (!timer)
        return NULL;

    timer->peer = peer;
    timer->callback = callback;
    timer->deadline_ns = 0;
    timer->is_pending = false;
    timer->wait_deadline_ns = 0;
    timer->should_stop = false;
    timer->thread_started = false;

    pthread_mutex_init(&timer->lock, NULL);

#ifdef __APPLE__
    /* macOS: no pthread_condattr_setclock; use default (REALTIME).
     * cond_timedwait_mono() uses pthread_cond_timedwait_relative_np. */
    pthread_cond_init(&timer->cond, NULL);
    timer->cond_clock = CLOCK_REALTIME;
#else
    /* Linux / POSIX: set CLOCK_MONOTONIC so pthread_cond_timedwait
     * accepts monotonic absolute times directly. */
    {
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);
        if (!WG_CONDATTR_SETCLOCK_WORKS ||
            pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
            pthread_cond_init(&timer->cond, NULL);
            timer->cond_clock = CLOCK_REALTIME;
        } else {
            pthread_cond_init(&timer->cond, &attr);
            timer->cond_clock = CLOCK_MONOTONIC;
        }
        pthread_condattr_destroy(&attr);
    }
#endif

    pthread_mutex_init(&timer->run_lock, NULL);

    /* Start the timer thread */
    if (pthread_create(&timer->thread, NULL, timer_thread_fn, timer) != 0) {
        pthread_mutex_destroy(&timer->lock);
        pthread_cond_destroy(&timer->cond);
        pthread_mutex_destroy(&timer->run_lock);
        free(timer);
        return NULL;
    }
    timer->thread_started = true;

    return timer;
}

void wg_timer_mod(wg_timer_t *timer, uint64_t duration_ns)
{
    if (!timer)
        return;

    uint64_t now = mono_now_ns();

    pthread_mutex_lock(&timer->lock);
    timer->is_pending = true;
    timer->deadline_ns = now + duration_ns;
    /* The data path re-arms these timers for every batch, and waking the
     * thread each time costs two context switches. On macOS, where utun
     * makes a batch one packet, the signal was 16% of the send thread
     * (performance-analysis.md #64), so only wake the thread when it
     * would otherwise sleep past the new deadline; a later deadline is
     * picked up when it wakes for the old one. On Linux the lazy wake
     * cost 2-3% of x86 peak throughput through scheduler placement
     * (#61), so it keeps waking every time. */
    if (!WG_TIMER_LAZY_WAKE || timer->deadline_ns < timer->wait_deadline_ns)
        pthread_cond_signal(&timer->cond);
    pthread_mutex_unlock(&timer->lock);
}

void wg_timer_del(wg_timer_t *timer)
{
    if (!timer)
        return;

    /* With the lazy wake (macOS), no wake: the thread finds nothing
     * pending at its old deadline and goes back to an untimed wait.
     * Linux keeps waking, as in wg_timer_mod. */
    pthread_mutex_lock(&timer->lock);
    timer->is_pending = false;
    if (!WG_TIMER_LAZY_WAKE)
        pthread_cond_signal(&timer->cond);
    pthread_mutex_unlock(&timer->lock);
}

void wg_timer_del_sync(wg_timer_t *timer)
{
    if (!timer)
        return;

    wg_timer_del(timer);

    /* Wait for any running callback to finish */
    pthread_mutex_lock(&timer->run_lock);
    wg_timer_del(timer);
    pthread_mutex_unlock(&timer->run_lock);
}

bool wg_timer_is_pending(wg_timer_t *timer)
{
    if (!timer)
        return false;

    pthread_mutex_lock(&timer->lock);
    bool pending = timer->is_pending;
    pthread_mutex_unlock(&timer->lock);
    return pending;
}

void wg_timer_destroy(wg_timer_t *timer)
{
    if (!timer)
        return;

    /* Signal thread to stop */
    pthread_mutex_lock(&timer->lock);
    timer->should_stop = true;
    timer->is_pending = false;
    pthread_cond_signal(&timer->cond);
    pthread_mutex_unlock(&timer->lock);

    /* Wait for thread to exit */
    if (timer->thread_started)
        pthread_join(timer->thread, NULL);

    pthread_mutex_destroy(&timer->lock);
    pthread_cond_destroy(&timer->cond);
    pthread_mutex_destroy(&timer->run_lock);

    free(timer);
}

#endif /* WG_TIMERS_SHARED_THREAD */

/* ────────────────────────────────────────
 * Helper: check if peer timers should fire
 * ──────────────────────────────────────── */

static bool timers_active(struct wg_peer *peer)
{
    return atomic_load(&peer->is_running) && peer->device != NULL;
}

/* ────────────────────────────────────────
 * Timer expiration callbacks
 * ──────────────────────────────────────── */

static void expired_retransmit_handshake(struct wg_peer *peer)
{
    if (atomic_load(&peer->timers.handshake_attempts) > WG_MAX_TIMER_HANDSHAKES) {
        /* Give up: too many attempts */
        if (timers_active(peer))
            wg_timer_del(peer->timers.send_keepalive);

        /* Set zero-key-material timer if not already pending */
        if (timers_active(peer) && !wg_timer_is_pending(peer->timers.zero_key_material)) {
            wg_timer_mod(peer->timers.zero_key_material, WG_REJECT_AFTER_TIME_NS * 3);
        }
    } else {
        atomic_fetch_add(&peer->timers.handshake_attempts, 1);

        /* Mark endpoint src for clearing */
        pthread_mutex_lock(&peer->endpoint.lock);
        if (peer->endpoint.has_value)
            peer->endpoint.clear_src_on_tx = true;
        pthread_mutex_unlock(&peer->endpoint.lock);

        /* Send handshake initiation (retry). */
        wg_send_handshake_initiation(peer, true);
    }
}

static void expired_send_keepalive(struct wg_peer *peer)
{
    wg_send_keepalive(peer);
    if (atomic_exchange(&peer->timers.need_another_keepalive, false)) {
        if (timers_active(peer))
            wg_timer_mod(peer->timers.send_keepalive,
                         (uint64_t)WG_KEEPALIVE_TIMEOUT * 1000000000ULL);
    }
}

static void expired_new_handshake(struct wg_peer *peer)
{
    /* Mark endpoint src for clearing */
    pthread_mutex_lock(&peer->endpoint.lock);
    if (peer->endpoint.has_value)
        peer->endpoint.clear_src_on_tx = true;
    pthread_mutex_unlock(&peer->endpoint.lock);

    wg_send_handshake_initiation(peer, false);
}

static void expired_zero_key_material(struct wg_peer *peer)
{
    wg_peer_zero_and_flush(peer);
}

static void expired_persistent_keepalive(struct wg_peer *peer)
{
    if (atomic_load(&peer->persistent_keepalive_interval) > 0)
        wg_send_keepalive(peer);
}

/* ────────────────────────────────────────
 * Per-peer timer management
 * ──────────────────────────────────────── */

/*
 * P1-14: propagate allocation failure from wg_timer_new.
 * Returns false if any timer allocation fails.
 */
bool wg_timers_init(struct wg_peer *peer)
{
    peer->timers.retransmit_handshake = wg_timer_new(peer, expired_retransmit_handshake);
    peer->timers.send_keepalive = wg_timer_new(peer, expired_send_keepalive);
    peer->timers.new_handshake = wg_timer_new(peer, expired_new_handshake);
    peer->timers.zero_key_material = wg_timer_new(peer, expired_zero_key_material);
    peer->timers.persistent_keepalive = wg_timer_new(peer, expired_persistent_keepalive);

    if (!peer->timers.retransmit_handshake || !peer->timers.send_keepalive ||
        !peer->timers.new_handshake || !peer->timers.zero_key_material ||
        !peer->timers.persistent_keepalive) {
        wg_timers_destroy(peer);
        return false;
    }
    return true;
}

void wg_timers_start(struct wg_peer *peer)
{
    atomic_store(&peer->timers.handshake_attempts, 0);
    atomic_store(&peer->timers.sent_last_minute_handshake, false);
    atomic_store(&peer->timers.need_another_keepalive, false);

    /* Arm persistent keepalive timer if configured (matches wireguard-go
     * peer.Start() behavior — send initial keepalive/handshake). */
    uint32_t keepalive = atomic_load(&peer->persistent_keepalive_interval);
    if (keepalive > 0 && peer->timers.persistent_keepalive) {
        wg_timer_mod(peer->timers.persistent_keepalive,
                     (uint64_t)keepalive * 1000000000ULL);
    }
}

void wg_timers_stop(struct wg_peer *peer)
{
    wg_timer_del_sync(peer->timers.retransmit_handshake);
    wg_timer_del_sync(peer->timers.send_keepalive);
    wg_timer_del_sync(peer->timers.new_handshake);
    wg_timer_del_sync(peer->timers.zero_key_material);
    wg_timer_del_sync(peer->timers.persistent_keepalive);
}

void wg_timers_destroy(struct wg_peer *peer)
{
    wg_timer_destroy(peer->timers.retransmit_handshake);
    wg_timer_destroy(peer->timers.send_keepalive);
    wg_timer_destroy(peer->timers.new_handshake);
    wg_timer_destroy(peer->timers.zero_key_material);
    wg_timer_destroy(peer->timers.persistent_keepalive);

    peer->timers.retransmit_handshake = NULL;
    peer->timers.send_keepalive = NULL;
    peer->timers.new_handshake = NULL;
    peer->timers.zero_key_material = NULL;
    peer->timers.persistent_keepalive = NULL;
}

/* ────────────────────────────────────────
 * Timer event callbacks
 * ──────────────────────────────────────── */

void wg_timers_data_sent(struct wg_peer *peer)
{
    if (timers_active(peer) && !wg_timer_is_pending(peer->timers.new_handshake)) {
        wg_timer_mod(peer->timers.new_handshake,
                     (uint64_t)(WG_KEEPALIVE_TIMEOUT + WG_REKEY_TIMEOUT) * 1000000000ULL);
    }
}

void wg_timers_data_received(struct wg_peer *peer)
{
    if (timers_active(peer)) {
        if (!wg_timer_is_pending(peer->timers.send_keepalive)) {
            wg_timer_mod(peer->timers.send_keepalive,
                         (uint64_t)WG_KEEPALIVE_TIMEOUT * 1000000000ULL);
        } else {
            atomic_store(&peer->timers.need_another_keepalive, true);
        }
    }
}

void wg_timers_any_authenticated_packet_sent(struct wg_peer *peer)
{
    if (timers_active(peer))
        wg_timer_del(peer->timers.send_keepalive);
}

void wg_timers_any_authenticated_packet_received(struct wg_peer *peer)
{
    if (timers_active(peer))
        wg_timer_del(peer->timers.new_handshake);
}

void wg_timers_handshake_initiated(struct wg_peer *peer)
{
    if (timers_active(peer)) {
        wg_timer_mod(peer->timers.retransmit_handshake,
                     (uint64_t)WG_REKEY_TIMEOUT * 1000000000ULL);
    }
}

void wg_timers_handshake_complete(struct wg_peer *peer)
{
    if (timers_active(peer))
        wg_timer_del(peer->timers.retransmit_handshake);

    atomic_store(&peer->timers.handshake_attempts, 0);
    atomic_store(&peer->timers.sent_last_minute_handshake, false);
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int64_t wall_ns = (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
        atomic_store(&peer->last_handshake_ns, wall_ns);
    }
}

void wg_timers_session_derived(struct wg_peer *peer)
{
    if (timers_active(peer)) {
        wg_timer_mod(peer->timers.zero_key_material, WG_REJECT_AFTER_TIME_NS * 3);
    }
}

void wg_timers_any_authenticated_packet_traversal(struct wg_peer *peer)
{
    uint32_t keepalive = atomic_load(&peer->persistent_keepalive_interval);
    if (keepalive > 0 && timers_active(peer)) {
        wg_timer_mod(peer->timers.persistent_keepalive,
                     (uint64_t)keepalive * 1000000000ULL);
    }
}

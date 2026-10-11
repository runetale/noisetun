/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Device lifecycle implementation.
 *
 * Reference: wireguard-go/device/device.go
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "wg_device.h"
#include "wg_logger.h"

#include "../peer/wg_peer.h"
#include "../workers/wg_workers.h"
#include "../workers/wg_seq_wake.h"

#include <sodium.h>
#include "platform/wg_platform.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#endif

/* ────────────────────────────────────────
 * Monotonic clock helper
 * ──────────────────────────────────────── */

static int64_t mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* ────────────────────────────────────────
 * Element pool callbacks
 *
 * Each elem's pthread_mutex/cond is initialised once at creation
 * and reused across pool get/put cycles. The reset callback clears
 * per-packet state (keypair, flags) without touching the sync primitives.
 * ──────────────────────────────────────── */

static void *outbound_pool_alloc(void *ctx)
{
    (void)ctx;
    return wg_outbound_elem_new(); /* calloc + mutex_init + cond_init */
}

static void outbound_pool_free(void *obj, void *ctx)
{
    (void)ctx;
    wg_outbound_elem_t *e = obj;
    if (!e)
        return;
    if (e->keypair)
        wg_noise_keypair_put(e->keypair);
    e->pool = NULL; /* prevent recursive pool put */
    free(e);
}

static void outbound_pool_reset(void *obj, void *ctx)
{
    (void)ctx;
    wg_outbound_elem_t *e = obj;
    if (e->keypair) {
        wg_noise_keypair_put(e->keypair);
        e->keypair = NULL;
    }
    e->peer = NULL;
    e->packet_len = 0;
    e->nonce = 0;
    atomic_store_explicit(&e->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);
    atomic_store_explicit(&e->refs, 1, memory_order_relaxed);
    /* Note: pool backptr is preserved — no per-element sync primitives to reset. */
}

static void *inbound_pool_alloc(void *ctx)
{
    (void)ctx;
    return wg_inbound_elem_new();
}

static void inbound_pool_free(void *obj, void *ctx)
{
    (void)ctx;
    wg_inbound_elem_t *e = obj;
    if (!e)
        return;
    if (e->keypair)
        wg_noise_keypair_put(e->keypair);
    e->pool = NULL;
    free(e);
}

static void inbound_pool_reset(void *obj, void *ctx)
{
    (void)ctx;
    wg_inbound_elem_t *e = obj;
    if (e->keypair) {
        wg_noise_keypair_put(e->keypair);
        e->keypair = NULL;
    }
    e->peer = NULL;
    e->packet_len = 0;
    e->plaintext_len = 0;
    e->counter = 0;
    e->ok = false;
    atomic_store_explicit(&e->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);
    atomic_store_explicit(&e->refs, 1, memory_order_relaxed);
    memset(&e->endpoint, 0, sizeof(e->endpoint));
}

/* ────────────────────────────────────────
 * Internal: remove a peer (caller holds peers write lock)
 * ──────────────────────────────────────── */

/* Removing a peer while the device runs (#135):
 *
 *   1. unlink_peer_locked + map removal, under peers.lock: the peer map
 *      and AllowedIPs no longer lead to it, and is_dead stops new
 *      handshake indices;
 *   2. retire_peers, with no lock held: stop it, and drop every index
 *      still pointing at it, so no table leads to it any more; bump the
 *      generation and wait until every thread that might have found it
 *      before (wg_device_wait_peer_readers) has let go;
 *   3. wg_peer_destroy: only its timer threads and queued elements can
 *      still refer to it, and it joins the former and drains the latter.
 *
 * Stopping outside peers.lock and the identity lock matters: stopping
 * takes the drain locks and the timers' run_lock, and threads holding
 * those take the identity lock to start a handshake. */
static void unlink_peer_locked(wg_device_t *dev, struct wg_peer *peer)
{
    /* Refuse new handshake indices from here on (see
     * handshake_new_index in wg_handshake.c). */
    atomic_store(&peer->is_dead, true);

    /* Remove from allowed IPs routing table. */
    wg_allowedips_remove_by_peer(&dev->allowedips, peer);
}

static void retire_peers(wg_device_t *dev, struct wg_peer **peers, size_t count)
{
    if (count == 0)
        return;

    /* Held throughout, so down_locked (which runs under it) never stops a
     * peer that is being freed here. Nothing waited on below takes it:
     * the reader threads and timer callbacks never do. */
    pthread_mutex_lock(&dev->state_lock);

    for (size_t i = 0; i < count; i++) {
        struct wg_peer *peer = peers[i];

        /* Stop peer timers and flush queues. */
        wg_peer_stop(peer);

        /* Drop every index still pointing at the peer, including ones a
         * handshake in progress added after wg_peer_stop() cleared the
         * current ones. Under the handshake lock, so an index added by a
         * thread that saw is_dead still false is in the table by now. */
        pthread_rwlock_wrlock(&peer->handshake.lock);
        wg_index_table_delete_peer(&dev->index_table, peer);
        pthread_rwlock_unlock(&peer->handshake.lock);
    }

    /* Nothing leads to these peers now. */
    uint64_t gen =
        atomic_fetch_add_explicit(&dev->peers.generation, 1, memory_order_seq_cst) + 1;
    wg_device_wait_peer_readers(dev, gen);

    for (size_t i = 0; i < count; i++)
        wg_peer_destroy(peers[i]);

    pthread_mutex_unlock(&dev->state_lock);
}

static void remove_peer_locked(wg_device_t *dev, struct wg_peer *peer,
                               const uint8_t public_key[WG_KEY_LEN])
{
    unlink_peer_locked(dev, peer);

    /* Remove from peer map. */
    wg_peer_map_remove(&dev->peers, public_key);
}

/* ────────────────────────────────────────
 * Internal: bring device up (caller holds state_lock)
 * ──────────────────────────────────────── */

/* ────────────────────────────────────────
 * CPU topology detection and affinity pinning (Linux only)
 *
 * Detect physical core count and HT via sysfs, then:
 *   - Split physical cores evenly: first half → send path, second half → recv path
 *   - Include HT siblings automatically
 *   - Scale crypto workers to phys_cores_per_path (minimum 1, maximum 4)
 *
 * Examples:
 *   2 vCPU (1 core, no HT):  no pinning, 1 worker per direction
 *   4 vCPU (4 cores, no HT): send→C0-1, recv→C2-3, 2 workers
 *   4 vCPU (2 cores × 2 HT): send→C0,2, recv→C1,3, 1 worker
 *   8 vCPU (4 cores × 2 HT): send→C0,1,4,5, recv→C2,3,6,7, 2 workers
 *   16 vCPU (8 cores × 2 HT): send→C0-3,8-11, recv→C4-7,12-15, 4 workers
 * ──────────────────────────────────────── */
#ifdef __linux__
#include <stdio.h>

/* Detect number of physical cores and HT siblings per core.
 * Returns physical core count. Sets *threads_per_core (1 = no HT, 2 = HT). */
static int detect_topology(int ncpu, int *threads_per_core)
{
    *threads_per_core = 1;

    /* Read thread siblings from sysfs for CPU 0. */
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", "r");
    if (f) {
        /* Format: "0,4" (HT) or "0" (no HT) or "0-1" (range). */
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            int sibling_count = 1;
            for (char *p = buf; *p; p++) {
                if (*p == ',' || *p == '-')
                    sibling_count++;
            }
            if (sibling_count > 1)
                *threads_per_core = sibling_count;
        }
        fclose(f);
    }

    int phys_cores = ncpu / *threads_per_core;
    if (phys_cores < 1)
        phys_cores = 1;
    return phys_cores;
}

/* Build a CPU mask for a range of physical cores.
 * phys_start..phys_end (inclusive), including HT siblings. */
static void build_core_mask(cpu_set_t *mask, int phys_start, int phys_end,
                            int threads_per_core, int ncpu)
{
    CPU_ZERO(mask);
    for (int pc = phys_start; pc <= phys_end && pc < ncpu; pc++) {
        CPU_SET(pc, mask);
        /* HT sibling: on most Linux systems, CPU N and CPU N+phys_cores share a core. */
        for (int t = 1; t < threads_per_core; t++) {
            int sibling = pc + (ncpu / threads_per_core) * t;
            if (sibling < ncpu)
                CPU_SET(sibling, mask);
        }
    }
}

static void pin_thread_mask(pthread_t thread, cpu_set_t *mask, const char *name,
                            wg_device_t *dev)
{
#ifdef __ANDROID__
    int ret = sched_setaffinity(pthread_gettid_np(thread), sizeof(*mask), mask) == 0
                  ? 0
                  : errno;
#else
    int ret = pthread_setaffinity_np(thread, sizeof(*mask), mask);
#endif
    if (ret != 0)
        wg_log_error(dev, "pin_thread: failed to pin %s: %d", name, ret);
}

static void pin_workers(wg_device_t *dev)
{
#ifdef __ANDROID__
    /* Phones mix big and little cores; the scheduler places threads
     * better than a split by core number (and bionic has no
     * pthread_setaffinity_np). */
    (void)dev;
    return;
#endif
    int ncpu = dev->ncpu;
    int phys_cores = dev->phys_cores;
    if (phys_cores < 4)
        return; /* < 4 physical cores: let OS decide */

    /* Split physical cores evenly: first half → send, second half → recv. */
    int half = phys_cores / 2;
    cpu_set_t send_mask, recv_mask;
    build_core_mask(&send_mask, 0, half - 1, dev->threads_per_core, ncpu);
    build_core_mask(&recv_mask, half, phys_cores - 1, dev->threads_per_core, ncpu);

    /* Store masks for re-pin in bind_update. */
    dev->send_mask = send_mask;
    dev->recv_mask = recv_mask;

    /* Send path */
    if (dev->workers.tun_reader_started)
        pin_thread_mask(dev->workers.tun_reader, &send_mask, "tun_reader", dev);
    for (int i = 0; i < dev->rtc.num_send; i++)
        if (dev->rtc.send[i].started)
            pin_thread_mask(dev->rtc.send[i].thread, &send_mask, "rtc_send", dev);
    if (dev->workers.sequential_send_started)
        pin_thread_mask(dev->workers.sequential_send, &send_mask, "seq_send", dev);

    /* Recv path */
    if (dev->workers.udp_recv_started)
        pin_thread_mask(dev->workers.udp_recv, &recv_mask, "udp_recv", dev);
    for (int i = 0; i < dev->rtc.num_recv; i++)
        if (dev->rtc.recv[i].started)
            pin_thread_mask(dev->rtc.recv[i].thread, &recv_mask, "rtc_recv", dev);
    if (dev->workers.sequential_recv_started)
        pin_thread_mask(dev->workers.sequential_recv, &recv_mask, "seq_recv", dev);
}

/* Thread names for ps -L, top -H and perf. At most 15 characters. */
static void name_workers(wg_device_t *dev)
{
    char name[16];
    if (dev->workers.tun_reader_started)
        pthread_setname_np(dev->workers.tun_reader, "wg-tun-read");
    if (dev->workers.udp_recv_started)
        pthread_setname_np(dev->workers.udp_recv, "wg-udp-recv");
    if (dev->workers.handshake_started)
        pthread_setname_np(dev->workers.handshake, "wg-handshake");
    if (dev->workers.sequential_send_started)
        pthread_setname_np(dev->workers.sequential_send, "wg-seq-send");
    if (dev->workers.sequential_recv_started)
        pthread_setname_np(dev->workers.sequential_recv, "wg-seq-recv");
    for (int i = 0; i < dev->rtc.num_send; i++) {
        if (dev->rtc.send[i].started) {
            snprintf(name, sizeof(name), "wg-rtc-send%d", i);
            pthread_setname_np(dev->rtc.send[i].thread, name);
        }
    }
    for (int i = 0; i < dev->rtc.num_recv; i++) {
        if (dev->rtc.recv[i].started) {
            snprintf(name, sizeof(name), "wg-rtc-recv%d", i);
            pthread_setname_np(dev->rtc.recv[i].thread, name);
        }
    }
}
#endif /* __linux__ */

/* The RTC worker types embed wg_spsc_t, whose head and tail are _Alignas(64)
 * to keep them on separate cache lines. calloc only guarantees 16-byte
 * alignment, so the arrays come from posix_memalign. */
static void *alloc_aligned_array(size_t count, size_t size, size_t align)
{
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, count * size) != 0)
        return NULL;
    memset(ptr, 0, count * size);
    return ptr;
}

static wg_error_t up_locked(wg_device_t *dev)
{
    wg_wait_pool_reopen(dev->pool.outbound);
    wg_wait_pool_reopen(dev->pool.inbound);

    /* Open bind (UDP sockets). With listen_port 0 the kernel picks a
     * port; keep it, so that UAPI reports it and a rebind reuses it, as
     * wireguard-go does. */
    pthread_rwlock_wrlock(&dev->net.lock);
    if (dev->net.bind.open) {
        int bound = dev->net.bind.open(dev->net.bind.ctx, dev->net.port);
        if (bound > 0)
            dev->net.port = (uint16_t)bound;
    }
    pthread_rwlock_unlock(&dev->net.lock);

    /* Detect CPU topology. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1)
        ncpu = 1;
    if (ncpu > 64)
        ncpu = 64;
    dev->ncpu = (int)ncpu;
#ifdef __linux__
    dev->phys_cores = detect_topology((int)ncpu, &dev->threads_per_core);
#else
    dev->threads_per_core = 1;
    dev->phys_cores = (int)ncpu;
#endif
#if defined(__APPLE__)
    /* utun hands over one packet per read, so the pipeline's hand-offs
     * cost more than parallel crypto gains: one thread each way was 30%
     * faster than eight workers plus sequential threads at half the CPU
     * (performance-analysis.md #64). */
    dev->inline_crypto = true;
#else
    dev->inline_crypto = (dev->ncpu <= 4);
#endif
    /* Experiment knob: WG_INLINE_CRYPTO=1 forces the single-thread
     * data path (no crypto workers, no sequential threads), 0 forces
     * the pipeline. */
    const char *inline_env = getenv("WG_INLINE_CRYPTO");
    if (inline_env && *inline_env)
        dev->inline_crypto = atoi(inline_env) != 0;

    wg_log_verbose(dev, "CPU topology: %d vCPU, %d physical cores, %d threads/core",
                   dev->ncpu, dev->phys_cores, dev->threads_per_core);

    /* Allocate and start RTC workers (skip on single-core). */
    if (!dev->inline_crypto) {
        /* Scale crypto workers based on vCPUs per direction.
         * Each direction gets ncpu/2 vCPUs. Subtract 2 for the producer
         * (tun_reader/udp_recv) and sequential thread; remainder → crypto.
         * HT siblings boost crypto throughput, so count vCPUs not phys cores.
         *
         * ncpu=2:  1 send + 1 recv (minimum)
         * ncpu=4:  1 send + 1 recv
         * ncpu=8:  2 send + 2 recv (4 vCPUs/dir - 2 = 2)
         * ncpu=16: 4 send + 4 recv (capped)
         * ncpu=32: 4 send + 4 recv (capped) */
        int vcpus_per_path = dev->ncpu / 2;
        int num_send = vcpus_per_path > 2 ? vcpus_per_path - 2 : 1;
        int num_recv = vcpus_per_path > 2 ? vcpus_per_path - 2 : 1;
        if (num_send > 4)
            num_send = 4;
        if (num_recv > 4)
            num_recv = 4;

        wg_log_verbose(dev, "Workers: %d send + %d recv crypto, 1+1 sequential", num_send,
                       num_recv);

        dev->rtc.send =
            alloc_aligned_array((size_t)num_send, sizeof(wg_rtc_send_worker_t),
                                _Alignof(wg_rtc_send_worker_t));
        dev->rtc.recv =
            alloc_aligned_array((size_t)num_recv, sizeof(wg_rtc_recv_worker_t),
                                _Alignof(wg_rtc_recv_worker_t));
        dev->rtc.num_send = 0;
        dev->rtc.num_recv = 0;
        atomic_store(&dev->rtc.send_rr, 0);
        atomic_store(&dev->rtc.recv_rr, 0);
        /* No worker has started yet; change_state brings the device back
         * down, which frees whichever array was allocated. */
        if (!dev->rtc.send || !dev->rtc.recv)
            return WG_ERR_NO_MEMORY;

        /* Start send workers. */
        if (dev->rtc.send) {
            for (int i = 0; i < num_send; i++) {
                if (wg_spsc_init(&dev->rtc.send[i].queue, 16384) != WG_OK)
                    break;
                dev->rtc.send[i].dev = dev;
                dev->rtc.send[i].id = i;
                dev->rtc.send[i].started = false;
                if (pthread_create(&dev->rtc.send[i].thread, NULL, wg_worker_rtc_send,
                                   &dev->rtc.send[i]) != 0)
                    break;
                dev->rtc.send[i].started = true;
                dev->rtc.num_send = i + 1;
            }
        }

        /* Start recv workers. */
        if (dev->rtc.recv) {
            for (int i = 0; i < num_recv; i++) {
                if (wg_spsc_init(&dev->rtc.recv[i].queue, 16384) != WG_OK)
                    break;
                dev->rtc.recv[i].dev = dev;
                dev->rtc.recv[i].id = i;
                dev->rtc.recv[i].started = false;
                if (pthread_create(&dev->rtc.recv[i].thread, NULL, wg_worker_rtc_recv,
                                   &dev->rtc.recv[i]) != 0)
                    break;
                dev->rtc.recv[i].started = true;
                dev->rtc.num_recv = i + 1;
            }
        }
    }

    /* Start sequential sender/receiver (ordered delivery from prev_queue). */
    if (!dev->inline_crypto) {
        if (pthread_create(&dev->workers.sequential_send, NULL, wg_worker_sequential_send,
                           dev) == 0)
            dev->workers.sequential_send_started = true;
        if (pthread_create(&dev->workers.sequential_recv, NULL, wg_worker_sequential_recv,
                           dev) == 0)
            dev->workers.sequential_recv_started = true;
    }

    /* Start handshake worker. */
    {
        int ret = pthread_create(&dev->workers.handshake, NULL, wg_worker_handshake, dev);
        if (ret == 0)
            dev->workers.handshake_started = true;
    }

    /* Start TUN reader. */
    {
        int ret = pthread_create(&dev->workers.tun_reader, NULL, wg_worker_tun_read, dev);
        if (ret == 0)
            dev->workers.tun_reader_started = true;
    }

    /* Start UDP receive worker. */
    {
        int ret = pthread_create(&dev->workers.udp_recv, NULL, wg_worker_udp_recv, dev);
        if (ret == 0)
            dev->workers.udp_recv_started = true;
    }

    /* Pin worker threads to specific CPU cores (Linux only). */
#ifdef __linux__
    name_workers(dev);
    pin_workers(dev);
#endif

    /* Start all peers. */
    pthread_rwlock_rdlock(&dev->peers.lock);
    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        struct wg_peer *peer = dev->peers.entries[i].peer;
        wg_peer_start(peer);
    }
    pthread_rwlock_unlock(&dev->peers.lock);

    return WG_OK;
}

/* ────────────────────────────────────────
 * Internal: bring device down (caller holds state_lock)
 * ──────────────────────────────────────── */

static wg_error_t down_locked(wg_device_t *dev)
{
    /* Wake the UDP recv worker. With a cancel op the sockets stay open
     * until every worker is joined (below), so none of them is using an fd
     * when it is closed and its number reused (#129). Without one, close
     * is the only way to unblock recv, so it keeps its old place. */
    bool bind_cancelled = false;
    pthread_rwlock_rdlock(&dev->net.lock);
    if (dev->net.bind.cancel) {
        dev->net.bind.cancel(dev->net.bind.ctx);
        bind_cancelled = true;
    } else if (dev->net.bind.close) {
        dev->net.bind.close(dev->net.bind.ctx);
    }
    pthread_rwlock_unlock(&dev->net.lock);

    /* Close device queues to unblock handshake workers. */
    wg_queue_close(dev->queue.handshake);
    wg_queue_close(dev->queue.encryption);
    wg_queue_close(dev->queue.decryption);

    /* With capped pools a worker may be waiting in Get for a buffer that
     * only comes back after it is joined (queued elements are freed
     * below, staged ones when the peers go): wake it with NULL. */
    wg_wait_pool_close(dev->pool.outbound);
    wg_wait_pool_close(dev->pool.inbound);

    /* Close RTC SPSC queues to unblock RTC workers. */
    for (int i = 0; i < dev->rtc.num_send; i++)
        wg_spsc_close(&dev->rtc.send[i].queue);
    for (int i = 0; i < dev->rtc.num_recv; i++)
        wg_spsc_close(&dev->rtc.recv[i].queue);

    /* Join device worker threads. */
    if (dev->workers.udp_recv_started) {
        pthread_join(dev->workers.udp_recv, NULL);
        dev->workers.udp_recv_started = false;
    }
    if (dev->workers.tun_reader_started) {
        pthread_join(dev->workers.tun_reader, NULL);
        dev->workers.tun_reader_started = false;
    }
    if (dev->workers.handshake_started) {
        pthread_join(dev->workers.handshake, NULL);
        dev->workers.handshake_started = false;
    }

    /* Join RTC crypto workers (they exit when SPSC is closed). */
    for (int i = 0; i < dev->rtc.num_send; i++) {
        if (dev->rtc.send[i].started) {
            pthread_join(dev->rtc.send[i].thread, NULL);
            dev->rtc.send[i].started = false;
        }
    }
    for (int i = 0; i < dev->rtc.num_recv; i++) {
        if (dev->rtc.recv[i].started) {
            pthread_join(dev->rtc.recv[i].thread, NULL);
            dev->rtc.recv[i].started = false;
        }
    }

    /* Mark any remaining SPSC elements as DEAD so sequential workers can
     * drain prev_queues without spinning forever, and drop the SPSC's
     * reference as the worker would have. Not one a sequential thread
     * took: that one finishes on its own. The order queue's reference
     * keeps the element alive until the sequential thread frees it. */
    for (int i = 0; i < dev->rtc.num_send; i++) {
        void *elem;
        while (wg_spsc_try_pop(&dev->rtc.send[i].queue, &elem) == WG_OK) {
            wg_outbound_elem_t *e = elem;
#if WG_SEQ_INLINE
            (void)wg_elem_kill(&e->state);
            wg_outbound_elem_free(e);
#else
            atomic_store_explicit(&e->state, WG_ELEM_DEAD, memory_order_release);
#endif
        }
        wg_spsc_destroy(&dev->rtc.send[i].queue);
    }
    for (int i = 0; i < dev->rtc.num_recv; i++) {
        void *elem;
        while (wg_spsc_try_pop(&dev->rtc.recv[i].queue, &elem) == WG_OK) {
            wg_inbound_elem_t *e = elem;
#if WG_SEQ_INLINE
            (void)wg_elem_kill(&e->state);
            wg_inbound_elem_free(e);
#else
            atomic_store_explicit(&e->state, WG_ELEM_DEAD, memory_order_release);
#endif
        }
        wg_spsc_destroy(&dev->rtc.recv[i].queue);
    }

    /* Join sequential sender/receiver — they drain prev_queues and exit
     * when device state changes to !UP. */
    if (dev->workers.sequential_send_started) {
        pthread_join(dev->workers.sequential_send, NULL);
        dev->workers.sequential_send_started = false;
    }
    if (dev->workers.sequential_recv_started) {
        pthread_join(dev->workers.sequential_recv, NULL);
        dev->workers.sequential_recv_started = false;
    }

    /* Every device worker is joined. Other senders (timers, handshakes)
     * send under net.lock for reading, so closing under it for writing
     * waits for any send in flight; later sends find the sockets closed. */
    if (bind_cancelled && dev->net.bind.close) {
        pthread_rwlock_wrlock(&dev->net.lock);
        dev->net.bind.close(dev->net.bind.ctx);
        pthread_rwlock_unlock(&dev->net.lock);
    }

    wg_aligned_free(dev->rtc.send);
    wg_aligned_free(dev->rtc.recv);
    dev->rtc.send = NULL;
    dev->rtc.recv = NULL;
    dev->rtc.num_send = 0;
    dev->rtc.num_recv = 0;

    /* Now safe to stop peers — all crypto workers and sequential workers
     * have exited, so no thread holds references to elements.
     *
     * Not under peers.lock: stopping waits for a running timer callback
     * (wg_timer_del_sync), a callback may take the identity lock to start
     * a handshake, and wg_device_set_private_key takes peers.lock under
     * the identity lock (#132). Copy the list instead. The peers stay
     * allocated: only retire_peers frees them, and it holds state_lock,
     * as the caller does here. */
    struct wg_peer **stop = NULL;
    size_t nstop = 0;
    pthread_rwlock_rdlock(&dev->peers.lock);
    if (dev->peers.count > 0)
        stop = calloc(dev->peers.count, sizeof(*stop));
    for (size_t i = 0; stop && i < dev->peers.capacity; i++) {
        if (dev->peers.entries[i].occupied)
            stop[nstop++] = dev->peers.entries[i].peer;
    }
    if (dev->peers.count > 0 && !stop) {
        /* Out of memory: stop them under the lock, as before. */
        for (size_t i = 0; i < dev->peers.capacity; i++) {
            if (dev->peers.entries[i].occupied)
                wg_peer_stop(dev->peers.entries[i].peer);
        }
    }
    pthread_rwlock_unlock(&dev->peers.lock);
    for (size_t i = 0; i < nstop; i++)
        wg_peer_stop(stop[i]);
    free(stop);

    /* Flush and re-initialize device queues for potential restart.
     *
     * encryption/decryption queues hold non-owning references — the
     * same element is owned by the peer's prev_queue
     * (already flushed above in wg_peer_stop).  Pass NULL to avoid
     * double-free. */
    wg_queue_flush(dev->queue.handshake, wg_handshake_elem_free);
    wg_queue_flush(dev->queue.encryption, NULL);
    wg_queue_flush(dev->queue.decryption, NULL);
    wg_queue_destroy(dev->queue.handshake);
    wg_queue_destroy(dev->queue.encryption);
    wg_queue_destroy(dev->queue.decryption);
    wg_queue_init(dev->queue.handshake, WG_QUEUE_HANDSHAKE_SIZE);
    wg_queue_init(dev->queue.encryption, WG_QUEUE_OUTBOUND_SIZE);
    wg_queue_init(dev->queue.decryption, WG_QUEUE_INBOUND_SIZE);

    return WG_OK;
}

/* ────────────────────────────────────────
 * Internal: state transition
 * ──────────────────────────────────────── */

static wg_error_t change_state(wg_device_t *dev, wg_device_state_t want)
{
    pthread_mutex_lock(&dev->state_lock);

    wg_device_state_t old = wg_device_get_state(dev);

    /* Once closed, always closed. */
    if (old == WG_DEVICE_STATE_CLOSED) {
        pthread_mutex_unlock(&dev->state_lock);
        return WG_OK;
    }

    /* No-op if already in desired state. */
    if (old == want) {
        pthread_mutex_unlock(&dev->state_lock);
        return WG_OK;
    }

    wg_error_t err = WG_OK;
    switch (want) {
    case WG_DEVICE_STATE_UP:
        atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_UP);
        err = up_locked(dev);
        if (err != WG_OK) {
            /* Up failed; fall through to bring down. */
            atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_DOWN);
            down_locked(dev);
        }
        break;

    case WG_DEVICE_STATE_DOWN:
        atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_DOWN);
        down_locked(dev);
        break;

    case WG_DEVICE_STATE_CLOSED:
        /* Handled separately in wg_device_close. */
        break;
    }

    pthread_mutex_unlock(&dev->state_lock);
    return err;
}

/* ────────────────────────────────────────
 * Public API: Device lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_device_new(wg_device_t **out, const wg_tun_ops_t *tun,
                         const wg_bind_ops_t *bind, const wg_logger_t *logger)
{
    /* Allocate with 64-byte alignment: -march=native on AVX2/AVX-512 CPUs
     * generates vmovdqa for struct copies, which faults on < 32-byte alignment.
     * calloc only guarantees 16-byte alignment on x86_64 glibc. */
    wg_device_t *dev = NULL;
    if (posix_memalign((void **)&dev, 64, sizeof(*dev)) != 0 || !dev)
        return WG_ERR_NO_MEMORY;
    memset(dev, 0, sizeof(*dev));

    atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_DOWN);
    pthread_mutex_init(&dev->state_lock, NULL);

    /* Static identity */
    wg_noise_static_identity_init(&dev->static_identity);

    /* Peer map */
    wg_error_t err = wg_peer_map_init(&dev->peers);
    if (err != WG_OK)
        goto fail_peers;

    /* Allowed IPs */
    wg_allowedips_init(&dev->allowedips);

    /* Index table */
    err = wg_index_table_init(&dev->index_table);
    if (err != WG_OK)
        goto fail_index;

    /* Cookie checker (initialised without key; set when private key is set).
     * dev was zeroed after posix_memalign, so cookie_checker is already zeroed;
     * just init the lock. */
    pthread_rwlock_init(&dev->cookie_checker.lock, NULL);

    /* Rate limiter */
    atomic_store(&dev->rate.under_load_until_ns, 0);
    err = wg_ratelimiter_init(&dev->rate.limiter);
    if (err != WG_OK)
        goto fail_rate;

    /* Network / bind */
    pthread_rwlock_init(&dev->net.lock, NULL);
    if (bind)
        dev->net.bind = *bind;
    dev->net.port = 0;
    dev->net.fwmark = 0;

    /* TUN */
    if (tun) {
        dev->tun.tun = *tun;
        if (tun->mtu && tun->ctx) {
            int mtu = tun->mtu(tun->ctx);
            atomic_store(&dev->tun.mtu, (int32_t)(mtu > 0 ? mtu : WG_DEFAULT_MTU));
        } else {
            atomic_store(&dev->tun.mtu, (int32_t)WG_DEFAULT_MTU);
        }
    } else {
        atomic_store(&dev->tun.mtu, (int32_t)WG_DEFAULT_MTU);
    }

    /* Device queues */
    dev->queue.handshake = calloc(1, sizeof(wg_queue_t));
    dev->queue.encryption = calloc(1, sizeof(wg_queue_t));
    dev->queue.decryption = calloc(1, sizeof(wg_queue_t));
    if (!dev->queue.handshake || !dev->queue.encryption || !dev->queue.decryption) {
        err = WG_ERR_NO_MEMORY;
        goto fail_queues;
    }

    err = wg_queue_init(dev->queue.handshake, WG_QUEUE_HANDSHAKE_SIZE);
    if (err != WG_OK)
        goto fail_queues;
    err = wg_queue_init(dev->queue.encryption, WG_QUEUE_OUTBOUND_SIZE);
    if (err != WG_OK)
        goto fail_queues;
    err = wg_queue_init(dev->queue.decryption, WG_QUEUE_INBOUND_SIZE);
    if (err != WG_OK)
        goto fail_queues;

    /* Element pools (outbound / inbound) */
    dev->pool.outbound = calloc(1, sizeof(wg_wait_pool_t));
    dev->pool.inbound = calloc(1, sizeof(wg_wait_pool_t));
    if (!dev->pool.outbound || !dev->pool.inbound) {
        err = WG_ERR_NO_MEMORY;
        goto fail_pools;
    }

    /* The lock-free pool has no cap; a capped one (WG_POOL_MAX_ELEMENTS)
     * takes the locked path, which makes Get wait at the cap. */
    err = wg_wait_pool_init(dev->pool.outbound, WG_POOL_MAX_ELEMENTS, outbound_pool_alloc,
                            outbound_pool_free, outbound_pool_reset, NULL);
    if (err != WG_OK)
        goto fail_pools;
    if (WG_POOL_MAX_ELEMENTS == 0)
        wg_wait_pool_enable_lockfree(dev->pool.outbound,
                                     offsetof(wg_outbound_elem_t, _pool_next));

    err = wg_wait_pool_init(dev->pool.inbound, WG_POOL_MAX_ELEMENTS, inbound_pool_alloc,
                            inbound_pool_free, inbound_pool_reset, NULL);
    if (err != WG_OK)
        goto fail_pools;
    if (WG_POOL_MAX_ELEMENTS == 0)
        wg_wait_pool_enable_lockfree(dev->pool.inbound,
                                     offsetof(wg_inbound_elem_t, _pool_next));

    /* Logger */
    if (logger)
        dev->logger = *logger;

    /* Pipeline stats */
    wg_stats_init(&dev->stats);

    *out = dev;
    return WG_OK;

fail_pools:
    if (dev->pool.outbound) {
        wg_wait_pool_destroy(dev->pool.outbound);
        free(dev->pool.outbound);
    }
    if (dev->pool.inbound) {
        wg_wait_pool_destroy(dev->pool.inbound);
        free(dev->pool.inbound);
    }
fail_queues:
    if (dev->queue.handshake) {
        wg_queue_destroy(dev->queue.handshake);
        free(dev->queue.handshake);
    }
    if (dev->queue.encryption) {
        wg_queue_destroy(dev->queue.encryption);
        free(dev->queue.encryption);
    }
    if (dev->queue.decryption) {
        wg_queue_destroy(dev->queue.decryption);
        free(dev->queue.decryption);
    }
    wg_ratelimiter_close(&dev->rate.limiter);
fail_rate:
    pthread_rwlock_destroy(&dev->cookie_checker.lock); /* P1-10 */
    wg_index_table_destroy(&dev->index_table);
fail_index:
    wg_allowedips_destroy(&dev->allowedips);
    wg_peer_map_destroy(&dev->peers);
fail_peers:
    pthread_mutex_destroy(&dev->state_lock);
    wg_aligned_free(dev);
    return err;
}

/* ────────────────────────────────────────
 * Bind update: close old sockets, join old recv thread,
 * open new sockets, start new recv thread.
 *
 * Must be called with dev->net.lock held for WRITE.
 * Note: temporarily releases and re-acquires net.lock internally
 * to allow the recv thread to exit (it takes net.lock for read
 * between iterations). The lock is held again on return.
 *
 * Reference: wireguard-go/device/device.go BindUpdate
 * ──────────────────────────────────────── */

wg_error_t wg_device_bind_update(wg_device_t *dev)
{
    /* Wake the recv thread, join it, and only then close the sockets, so
     * it is never inside recv on an fd that is being closed (#129). Without
     * a cancel op, close is what unblocks recv and must come first.
     *
     * The join happens with net.lock released: with inline crypto (4 vCPUs
     * or fewer) the recv thread runs the receive path itself, which can
     * send (staged packets after a handshake, a handshake when the key is
     * old) and so take net.lock for reading. Holding it for writing across
     * the join would deadlock. The caller holds state_lock, so the device
     * cannot go down and up (and start a new receive thread on sockets we
     * are about to close) while net.lock is released; the receive thread
     * never takes state_lock, so the join cannot deadlock on it. */
    if (dev->net.bind.cancel)
        dev->net.bind.cancel(dev->net.bind.ctx);
    else if (dev->net.bind.close)
        dev->net.bind.close(dev->net.bind.ctx);

    if (dev->workers.udp_recv_started) {
        pthread_t recv_thread = dev->workers.udp_recv;
        dev->workers.udp_recv_started = false;
        pthread_rwlock_unlock(&dev->net.lock);
        pthread_join(recv_thread, NULL);
        pthread_rwlock_wrlock(&dev->net.lock);
    }

    /* Senders send under net.lock for reading, and we hold it for writing
     * again, so no send is in flight on the sockets being closed. */
    if (dev->net.bind.cancel && dev->net.bind.close)
        dev->net.bind.close(dev->net.bind.ctx);

    /* Only re-open if device is up. */
    if (!wg_device_is_up(dev))
        return WG_OK;

    /* Open new sockets: bind.open returns the port bound, 0 for a bind
     * without one, negative on error. */
    if (dev->net.bind.open) {
        int rc = dev->net.bind.open(dev->net.bind.ctx, dev->net.port);
        if (rc < 0)
            return WG_ERR_BIND;
        if (rc > 0)
            dev->net.port = (uint16_t)rc;
    }

    /* Set fwmark on new sockets. */
    if (dev->net.fwmark != 0 && dev->net.bind.set_mark)
        dev->net.bind.set_mark(dev->net.bind.ctx, dev->net.fwmark);

    /* Start new recv thread. */
    if (pthread_create(&dev->workers.udp_recv, NULL, wg_worker_udp_recv, dev) == 0) {
        dev->workers.udp_recv_started = true;
#ifdef __linux__
        pthread_setname_np(dev->workers.udp_recv, "wg-udp-recv");
#ifndef __ANDROID__ /* no pinning there (pin_workers) */
        /* Re-pin udp_recv after bind_update recreation. */
        if (dev->phys_cores >= 4)
            pin_thread_mask(dev->workers.udp_recv, &dev->recv_mask, "udp_recv", dev);
#endif
#endif
    }

    return WG_OK;
}

wg_error_t wg_device_up(wg_device_t *dev)
{
    return change_state(dev, WG_DEVICE_STATE_UP);
}

wg_error_t wg_device_down(wg_device_t *dev)
{
    return change_state(dev, WG_DEVICE_STATE_DOWN);
}

void wg_device_close(wg_device_t *dev)
{
    if (!dev)
        return;

    pthread_mutex_lock(&dev->state_lock);

    if (wg_device_is_closed(dev)) {
        pthread_mutex_unlock(&dev->state_lock);
        return;
    }

    atomic_store(&dev->state, (uint32_t)WG_DEVICE_STATE_CLOSED);

    /* Wake the TUN reader, bring the device down (which joins every
     * thread that uses the TUN), and only then release the TUN: close may
     * free what a blocked read is still using (#127). Without a cancel
     * op, close is the only way to unblock the reader, so it keeps its
     * old place before the join. */
    bool tun_cancelled = false;
    if (dev->tun.tun.cancel && dev->tun.tun.ctx) {
        dev->tun.tun.cancel(dev->tun.tun.ctx);
        tun_cancelled = true;
    } else if (dev->tun.tun.close && dev->tun.tun.ctx) {
        dev->tun.tun.close(dev->tun.tun.ctx);
    }

    /* Bring down (close bind, stop peers). */
    down_locked(dev);

    if (tun_cancelled && dev->tun.tun.close)
        dev->tun.tun.close(dev->tun.tun.ctx);

    pthread_mutex_unlock(&dev->state_lock);

    /* Remove all peers (they assume queues are still active). */
    wg_device_remove_all_peers(dev);

    /* Flush and close queues.  Handshake elements are owned by the
     * handshake queue, so use their free function.  Encryption/decryption
     * queues hold non-owning references (ownership is in peer outbound/
     * inbound queues, already flushed by wg_device_remove_all_peers above),
     * so pass NULL to avoid double-free. */
    if (dev->queue.handshake) {
        wg_queue_close(dev->queue.handshake);
        wg_queue_flush(dev->queue.handshake, wg_handshake_elem_free);
        wg_queue_destroy(dev->queue.handshake);
        free(dev->queue.handshake);
    }
    if (dev->queue.encryption) {
        wg_queue_close(dev->queue.encryption);
        wg_queue_flush(dev->queue.encryption, NULL);
        wg_queue_destroy(dev->queue.encryption);
        free(dev->queue.encryption);
    }
    if (dev->queue.decryption) {
        wg_queue_close(dev->queue.decryption);
        wg_queue_flush(dev->queue.decryption, NULL);
        wg_queue_destroy(dev->queue.decryption);
        free(dev->queue.decryption);
    }

    /* Destroy element pools (frees all cached objects). */
    if (dev->pool.outbound) {
        wg_wait_pool_destroy(dev->pool.outbound);
        free(dev->pool.outbound);
    }
    if (dev->pool.inbound) {
        wg_wait_pool_destroy(dev->pool.inbound);
        free(dev->pool.inbound);
    }

    /* Close rate limiter. */
    wg_ratelimiter_close(&dev->rate.limiter);

    /* Destroy subsystems. */
    wg_cookie_checker_destroy(&dev->cookie_checker);
    wg_index_table_destroy(&dev->index_table);
    wg_allowedips_destroy(&dev->allowedips);
    wg_peer_map_destroy(&dev->peers);
    pthread_rwlock_destroy(&dev->static_identity.lock);
    pthread_rwlock_destroy(&dev->net.lock);
    pthread_mutex_destroy(&dev->state_lock);

    wg_aligned_free(dev);
}

/* ────────────────────────────────────────
 * Identity
 * ──────────────────────────────────────── */

wg_error_t wg_device_set_private_key(wg_device_t *dev, const wg_key_t *private_key)
{
    /* Lock ordering: see "Lock Acquisition Order" in wg_device.h */
    pthread_rwlock_wrlock(&dev->static_identity.lock);

    /* No change? */
    if (dev->static_identity.has_identity &&
        sodium_memcmp(dev->static_identity.static_private, private_key->key,
                      WG_KEY_LEN) == 0) {
        pthread_rwlock_unlock(&dev->static_identity.lock);
        return WG_OK;
    }

    /* Lock peers for modification. */
    pthread_rwlock_wrlock(&dev->peers.lock);

    /* Read-lock all peer handshakes to get a consistent snapshot.
     * We must hold handshake locks while reading remote_static below. */
    struct wg_peer **locked_peers = NULL;
    size_t locked_count = 0;

    if (dev->peers.count > 0) {
        locked_peers = calloc(dev->peers.count, sizeof(struct wg_peer *));
        if (!locked_peers) {
            pthread_rwlock_unlock(&dev->peers.lock);
            pthread_rwlock_unlock(&dev->static_identity.lock);
            return WG_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < dev->peers.capacity; i++) {
            if (!dev->peers.entries[i].occupied)
                continue;
            struct wg_peer *p = dev->peers.entries[i].peer;
            pthread_rwlock_rdlock(&p->handshake.lock);
            locked_peers[locked_count++] = p;
        }
    }

    /* Compute new public key. */
    uint8_t new_public[WG_KEY_LEN];
    crypto_scalarmult_base(new_public, private_key->key);

    /*
     * P0-2 fix: collect peers to remove FIRST, then remove them.
     * remove_peer_locked uses backward-shift deletion which shifts
     * entries during iteration, causing skips or double processing.
     */
    struct wg_peer **removed_peers = NULL;
    size_t removed_count = 0;
    /* Also store the public keys for removal (they may shift in the map). */
    uint8_t (*removed_keys)[WG_KEY_LEN] = NULL;

    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        struct wg_peer *p = dev->peers.entries[i].peer;
        if (sodium_memcmp(p->handshake.remote_static, new_public, WG_KEY_LEN) == 0) {
            if (!removed_peers) {
                removed_peers = calloc(dev->peers.capacity, sizeof(struct wg_peer *));
                removed_keys = calloc(dev->peers.capacity, WG_KEY_LEN);
                if (!removed_peers || !removed_keys) {
                    free(removed_peers);
                    free(removed_keys);
                    removed_peers = NULL;
                    removed_keys = NULL;
                }
            }
            if (removed_peers && removed_keys) {
                removed_peers[removed_count] = p;
                memcpy(removed_keys[removed_count], dev->peers.entries[i].public_key,
                       WG_KEY_LEN);
                removed_count++;
            }
        }
    }

    /* Now perform the removals (safe — not iterating the map). */
    for (size_t i = 0; i < removed_count; i++) {
        pthread_rwlock_unlock(&removed_peers[i]->handshake.lock);
        remove_peer_locked(dev, removed_peers[i], removed_keys[i]);
    }
    free(removed_keys);

    /* Update key material. */
    memcpy(dev->static_identity.static_private, private_key->key, WG_KEY_LEN);
    memcpy(dev->static_identity.static_public, new_public, WG_KEY_LEN);
    dev->static_identity.has_identity = true;

    /* Re-init cookie checker with new public key. */
    wg_cookie_checker_init(&dev->cookie_checker, new_public);

    /* Unlock all handshakes (skip removed peers — already unlocked) before
     * the precomputation below: wg_noise_precompute_static_static takes
     * handshake.lock for writing, and waiting for it while still holding it
     * for reading never returns. peers.lock stays held, so the set of peers
     * does not change, and static_identity.lock keeps every handshake that
     * reads the key waiting until this function returns. */
    for (size_t i = 0; i < locked_count; i++) {
        bool was_removed = false;
        for (size_t j = 0; j < removed_count; j++) {
            if (locked_peers[i] == removed_peers[j]) {
                was_removed = true;
                break;
            }
        }
        if (!was_removed)
            pthread_rwlock_unlock(&locked_peers[i]->handshake.lock);
    }
    free(locked_peers);

    /* Recompute static-static DH precomputation for all remaining peers. */
    struct wg_peer **expired_peers = NULL;
    size_t expired_count = 0;
    bool expire_fallback = false;
    if (dev->peers.count > 0) {
        expired_peers = calloc(dev->peers.count, sizeof(struct wg_peer *));
        if (!expired_peers)
            expire_fallback = true;
    }

    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        struct wg_peer *p = dev->peers.entries[i].peer;
        wg_noise_precompute_static_static(&p->handshake);
        if (expired_peers)
            expired_peers[expired_count++] = p;
    }

    pthread_rwlock_unlock(&dev->peers.lock);
    pthread_rwlock_unlock(&dev->static_identity.lock);

    /* Expire keypairs outside of locks.
     * expire_current_keypairs takes handshake.wrlock, so it must not
     * be called while holding peers.lock or static_identity.lock. */
    if (expire_fallback) {
        /* Alloc failed — re-iterate under read lock to expire. */
        pthread_rwlock_rdlock(&dev->peers.lock);
        for (size_t i = 0; i < dev->peers.capacity; i++) {
            if (!dev->peers.entries[i].occupied)
                continue;
            wg_peer_expire_current_keypairs(dev->peers.entries[i].peer);
        }
        pthread_rwlock_unlock(&dev->peers.lock);
    } else {
        for (size_t i = 0; i < expired_count; i++)
            wg_peer_expire_current_keypairs(expired_peers[i]);
    }
    free(expired_peers);

    /* Stop and destroy peers that were removed due to key conflict, now
     * that no lock is held. */
    retire_peers(dev, removed_peers, removed_count);
    free(removed_peers);

    return WG_OK;
}

/* ────────────────────────────────────────
 * Load detection
 * ──────────────────────────────────────── */

bool wg_device_is_under_load(wg_device_t *dev)
{
    int64_t now = mono_now_ns();
    size_t qcount = wg_queue_count(dev->queue.handshake);

    if (qcount >= WG_QUEUE_HANDSHAKE_SIZE / 8) {
        atomic_store(&dev->rate.under_load_until_ns, now + WG_UNDER_LOAD_AFTER_TIME_NS);
        return true;
    }

    return atomic_load(&dev->rate.under_load_until_ns) > now;
}

/* ────────────────────────────────────────
 * Peer management
 * ──────────────────────────────────────── */

struct wg_peer *wg_device_lookup_peer(wg_device_t *dev,
                                      const uint8_t public_key[WG_KEY_LEN])
{
    /* P0-3: acquire read lock for thread safety. */
    pthread_rwlock_rdlock(&dev->peers.lock);
    struct wg_peer *peer = wg_peer_map_lookup(&dev->peers, public_key);
    pthread_rwlock_unlock(&dev->peers.lock);
    return peer;
}

/* A sequential thread publishes the generation it is about to cache
 * before it takes peers.lock to copy the list (see the sequential
 * workers), and a peer reader before its lookups (wg_peer_reader_enter).
 * So once a remover, having unlinked a peer and bumped the generation to
 * `gen`, sees a thread at `gen` or later, or at 0, that thread either
 * looked after the removal or has finished with what it found before.
 * Sequential threads refresh at the top of every loop, which runs at
 * least once per FUTEX_WAIT timeout; readers leave their section at the
 * end of a batch or message. So the wait is short. */
static bool peer_cache_behind(_Atomic uint64_t *seen, uint64_t gen)
{
    /* seen holds the cached generation plus one; 0 means none. */
    uint64_t s = atomic_load_explicit(seen, memory_order_seq_cst);
    return s != 0 && s - 1 < gen;
}

static bool peer_readers_behind(wg_device_t *dev, uint64_t gen)
{
    return peer_cache_behind(&dev->seq_send_peer_gen, gen) ||
           peer_cache_behind(&dev->seq_recv_peer_gen, gen) ||
           peer_cache_behind(&dev->hs_peer_gen, gen) ||
           peer_cache_behind(&dev->tun_peer_gen, gen) ||
           peer_cache_behind(&dev->udp_peer_gen, gen);
}

void wg_device_wait_peer_readers(wg_device_t *dev, uint64_t gen)
{
    /* Pairs with the fence in wg_peer_reader_enter(). */
    atomic_thread_fence(memory_order_seq_cst);
    if (!peer_readers_behind(dev, gen))
        return;
    /* Wake both sequential threads so they reach the top of their loop,
     * and the cache refresh, now rather than at their FUTEX_WAIT timeout. */
    wg_seq_wake_signal(&dev->seq_wake_send, &dev->seq_wake_send_waiting);
    wg_seq_wake_signal(&dev->seq_wake_recv, &dev->seq_wake_recv_waiting);
    while (peer_readers_behind(dev, gen))
        sched_yield();
}

wg_error_t wg_device_remove_peer(wg_device_t *dev, const wg_key_t *public_key)
{
    pthread_rwlock_wrlock(&dev->peers.lock);

    struct wg_peer *peer = NULL;
    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        if (sodium_memcmp(dev->peers.entries[i].public_key, public_key->key,
                          WG_KEY_LEN) == 0) {
            peer = dev->peers.entries[i].peer;
            break;
        }
    }

    if (peer)
        remove_peer_locked(dev, peer, public_key->key);

    pthread_rwlock_unlock(&dev->peers.lock);

    if (peer) {
        retire_peers(dev, &peer, 1);
        return WG_OK;
    }
    return WG_ERR_PEER_NOT_FOUND;
}

void wg_device_remove_all_peers(wg_device_t *dev)
{
    pthread_rwlock_wrlock(&dev->peers.lock);

    /* Collect peers to destroy after releasing the lock. */
    struct wg_peer **to_destroy = NULL;
    size_t count = 0;

    if (dev->peers.count > 0) {
        to_destroy = calloc(dev->peers.count, sizeof(struct wg_peer *));
        for (size_t i = 0; i < dev->peers.capacity; i++) {
            if (!dev->peers.entries[i].occupied)
                continue;
            struct wg_peer *p = dev->peers.entries[i].peer;
            unlink_peer_locked(dev, p);
            if (to_destroy)
                to_destroy[count++] = p;
        }

        /* Clear the map. */
        for (size_t i = 0; i < dev->peers.capacity; i++)
            dev->peers.entries[i].occupied = false;
        dev->peers.count = 0;
        atomic_fetch_add_explicit(&dev->peers.generation, 1, memory_order_release);
    }

    pthread_rwlock_unlock(&dev->peers.lock);

    /* Stop and destroy peers outside of lock. */
    retire_peers(dev, to_destroy, count);
    free(to_destroy);
}

/* ────────────────────────────────────────
 * Public API wrappers (declared in wireguard.h)
 * ──────────────────────────────────────── */

wg_error_t wg_device_add_peer(wg_device_t *dev, const wg_key_t *public_key,
                              const wg_key_t *preshared_key, wg_peer_t **out)
{
    return wg_peer_new(dev, public_key->key, preshared_key ? preshared_key->key : NULL,
                       out);
}

wg_error_t wg_device_get_peer_stats(wg_device_t *dev, wg_peer_stats_t *out, size_t *count)
{
    if (!dev || !count)
        return WG_ERR_INVALID_ARGUMENT;

    pthread_rwlock_rdlock(&dev->peers.lock);
    size_t n = dev->peers.count;

    if (!out) {
        /* Caller wants just the count. */
        *count = n;
        pthread_rwlock_unlock(&dev->peers.lock);
        return WG_OK;
    }

    size_t cap = *count;
    size_t idx = 0;
    for (size_t i = 0; i < dev->peers.capacity && idx < cap; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        struct wg_peer *p = dev->peers.entries[i].peer;
        memcpy(out[idx].public_key.key, dev->peers.entries[i].public_key, WG_KEY_LEN);

        wg_peer_get_endpoint(p, &out[idx].endpoint);
        out[idx].tx_bytes = atomic_load(&p->tx_bytes);
        out[idx].rx_bytes = atomic_load(&p->rx_bytes);

        int64_t hs_ns = atomic_load(&p->last_handshake_ns);
        out[idx].last_handshake_sec = (int64_t)(hs_ns / 1000000000LL);
        out[idx].last_handshake_nsec = (int32_t)(hs_ns % 1000000000LL);

        out[idx].persistent_keepalive =
            (uint16_t)atomic_load(&p->persistent_keepalive_interval);
        idx++;
    }

    *count = idx;
    pthread_rwlock_unlock(&dev->peers.lock);
    return WG_OK;
}

/* ════════════════════════════════════════
 * Module init / cleanup
 * ════════════════════════════════════════ */

const char *wg_version(void)
{
    return WG_VERSION;
}

void wg_device_disable_roaming(wg_device_t *dev)
{
    if (!dev)
        return;

    pthread_rwlock_wrlock(&dev->net.lock);
    dev->net.broken_roaming = true;
    pthread_rwlock_unlock(&dev->net.lock);

    /* Peers configured with an endpoint keep it from now on; peers
     * without one still learn it from the first packet they send. Peers
     * added later are handled when their UAPI section ends. */
    pthread_rwlock_rdlock(&dev->peers.lock);
    for (size_t i = 0; i < dev->peers.capacity; i++) {
        if (!dev->peers.entries[i].occupied)
            continue;
        struct wg_peer *peer = dev->peers.entries[i].peer;
        pthread_mutex_lock(&peer->endpoint.lock);
        peer->endpoint.disable_roaming = peer->endpoint.has_value;
        pthread_mutex_unlock(&peer->endpoint.lock);
    }
    pthread_rwlock_unlock(&dev->peers.lock);
}

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static bool init_ok;

static void init_module(void)
{
    /* sodium_init is safe to repeat; wg_noise_module_init rewrites the
     * handshake constants every tunnel reads, so it must run only once. */
    if (sodium_init() < 0)
        return;
    wg_noise_module_init();
    init_ok = true;
}

wg_error_t wg_init(void)
{
    pthread_once(&init_once, init_module);
    return init_ok ? WG_OK : WG_ERR_NO_MEMORY; /* sodium_init failed */
}

void wg_cleanup(void)
{
    /* libsodium has no cleanup requirement.
     * This function exists for API symmetry and future use. */
}

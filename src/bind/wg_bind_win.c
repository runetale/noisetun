/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * WinRingBind: Windows Registered I/O (RIO) UDP bind implementation.
 *
 * Architecture:
 * - Two sockets: IPv4 + IPv6 (dual-stack, same port)
 * - RIO completion via IOCP (I/O Completion Ports)
 * - Pre-registered ring buffers for zero-copy packet I/O
 * - Spin + IOCP wait for receive (similar to wireguard-go's receiveSpins)
 *
 * If RIO is unavailable, falls back to standard Winsock sendto/recvfrom.
 *
 * Reference: wireguard-go/conn/bind_windows.go
 *            wireguard-go/conn/winrio/rio_windows.go
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "wg_bind_win.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include "wg_rio_compat.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#pragma comment(lib, "ws2_32.lib")

/* ────────────────────────────────────────
 * RIO constants and types
 * ──────────────────────────────────────── */

#define PACKETS_PER_RING 1024
#define BYTES_PER_PACKET (2048 - 32)
#define RECEIVE_SPINS    4096

/* SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER */
#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 0xc8000024
#endif

/* GUID for RIO extension functions.
 * Use a local name to avoid conflict with SDK's WSAID_MULTIPLE_RIO. */
static const GUID wg_rio_guid = {
    0x8509e081, 0x96dd, 0x4005, {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}};

/* Use the SDK's RIO extension function table directly. */
typedef RIO_EXTENSION_FUNCTION_TABLE rio_ftable_t;

/* Ring packet: address + data in a contiguous registered buffer. */
typedef struct {
    SOCKADDR_INET addr;
    uint8_t pad[32 - sizeof(SOCKADDR_INET)]; /* align data */
    uint8_t data[BYTES_PER_PACKET];
} ring_packet_t;

/* Ring buffer for either RX or TX direction. */
typedef struct {
    ring_packet_t *packets; /* VirtualAlloc'd array */
    uint32_t head, tail;
    RIO_BUFFERID buf_id;
    HANDLE iocp;
    RIO_CQ cq;
    OVERLAPPED overlapped;
    CRITICAL_SECTION lock;
    BOOL is_full;
} ring_buffer_t;

/* Per-address-family RIO socket. */
typedef struct {
    SOCKET sock;
    ring_buffer_t rx, tx;
    RIO_RQ rq;
    CRITICAL_SECTION rq_lock;
    BOOL blackhole;
    BOOL tx_deferred; /* sends queued with RIO_MSG_DEFER, not yet committed */
} af_bind_t;

/* Completions dequeued per bind_recv call (#65: one per call before). */
#define WG_RIO_RECV_BATCH 32

/* Bind state: open status. */
#define BIND_CLOSED  0
#define BIND_OPEN    1
#define BIND_CLOSING 2

struct wg_win_bind {
    af_bind_t v4, v6;
    rio_ftable_t rio;
    BOOL rio_available;
    atomic_int is_open;
    SRWLOCK mu;
    HANDLE recv_iocp; /* Shared IOCP for v4+v6 rx (key=4 for v4, key=6 for v6) */
};

/* ────────────────────────────────────────
 * RIO initialization
 * ──────────────────────────────────────── */

static BOOL init_rio(wg_win_bind_t *bind)
{
    SOCKET sock =
        WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_REGISTERED_IO);
    if (sock == INVALID_SOCKET)
        return FALSE;

    DWORD bytes_returned = 0;
    int result = WSAIoctl(sock, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                          (void *)&wg_rio_guid, sizeof(wg_rio_guid), &bind->rio,
                          sizeof(bind->rio), &bytes_returned, NULL, NULL);
    closesocket(sock);

    return (result == 0);
}

/* ────────────────────────────────────────
 * Ring buffer management
 * ──────────────────────────────────────── */

static BOOL ring_open(ring_buffer_t *ring, rio_ftable_t *rio, HANDLE shared_iocp,
                      ULONG_PTR iocp_key)
{
    SIZE_T alloc_size = sizeof(ring_packet_t) * PACKETS_PER_RING;
    ring->packets = (ring_packet_t *)VirtualAlloc(
        NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ring->packets)
        return FALSE;

    ring->buf_id = rio->RIORegisterBuffer((PCHAR)ring->packets, (DWORD)alloc_size);
    if (ring->buf_id == RIO_INVALID_BUFFERID)
        return FALSE;

    if (shared_iocp) {
        ring->iocp = shared_iocp;
    } else {
        ring->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (!ring->iocp)
            return FALSE;
    }

    RIO_NOTIFICATION_COMPLETION completion;
    completion.Type = RIO_IOCP_COMPLETION;
    completion.Iocp.IocpHandle = ring->iocp;
    completion.Iocp.CompletionKey = (void *)iocp_key;
    completion.Iocp.Overlapped = &ring->overlapped;

    ring->cq = rio->RIOCreateCompletionQueue(PACKETS_PER_RING, &completion);
    if (ring->cq == RIO_INVALID_CQ)
        return FALSE;

    InitializeCriticalSection(&ring->lock);
    ring->head = 0;
    ring->tail = 0;
    ring->is_full = FALSE;
    return TRUE;
}

static void ring_close(ring_buffer_t *ring, rio_ftable_t *rio, BOOL owns_iocp)
{
    if (ring->cq != RIO_INVALID_CQ && ring->cq != 0) {
        rio->RIOCloseCompletionQueue(ring->cq);
        ring->cq = 0;
    }
    if (ring->iocp && owns_iocp) {
        CloseHandle(ring->iocp);
        ring->iocp = NULL;
    }
    if (ring->buf_id != RIO_INVALID_BUFFERID && ring->buf_id != 0) {
        rio->RIODeregisterBuffer(ring->buf_id);
        ring->buf_id = 0;
    }
    if (ring->packets) {
        VirtualFree(ring->packets, 0, MEM_RELEASE);
        ring->packets = NULL;
    }
    DeleteCriticalSection(&ring->lock);
}

static ring_packet_t *ring_push(ring_buffer_t *ring)
{
    ring_packet_t *pkt = &ring->packets[ring->tail % PACKETS_PER_RING];
    ring->tail++;
    if (ring->tail % PACKETS_PER_RING == ring->head % PACKETS_PER_RING)
        ring->is_full = TRUE;
    return pkt;
}

static void ring_return(ring_buffer_t *ring, uint32_t count)
{
    if (ring->head % PACKETS_PER_RING == ring->tail % PACKETS_PER_RING && !ring->is_full)
        return;
    ring->head += count;
    ring->is_full = FALSE;
}

/* ────────────────────────────────────────
 * Per-AF socket setup
 * ──────────────────────────────────────── */

static BOOL af_open(af_bind_t *af, rio_ftable_t *rio, int family, struct sockaddr *sa,
                    int salen, HANDLE recv_iocp, ULONG_PTR recv_key)
{
    af->sock =
        WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_REGISTERED_IO);
    if (af->sock == INVALID_SOCKET)
        return FALSE;

    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(af->sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only,
                   sizeof(v6only));
    }

    if (!ring_open(&af->rx, rio, recv_iocp, recv_key))
        return FALSE;
    if (!ring_open(&af->tx, rio, NULL, 0))
        return FALSE;

    af->rq = rio->RIOCreateRequestQueue(af->sock, PACKETS_PER_RING, 1, PACKETS_PER_RING,
                                        1, af->rx.cq, af->tx.cq, NULL);
    if (af->rq == RIO_INVALID_RQ)
        return FALSE;

    InitializeCriticalSection(&af->rq_lock);

    if (bind(af->sock, sa, salen) == SOCKET_ERROR)
        return FALSE;

    return TRUE;
}

static void af_close(af_bind_t *af, rio_ftable_t *rio)
{
    ring_close(&af->rx, rio, FALSE); /* shared iocp — don't close */
    ring_close(&af->tx, rio, TRUE);  /* tx owns its own iocp */
    if (af->sock != INVALID_SOCKET) {
        closesocket(af->sock);
        af->sock = INVALID_SOCKET;
    }
    DeleteCriticalSection(&af->rq_lock);
    af->blackhole = FALSE;
    af->tx_deferred = FALSE;
}

/* Insert a receive request into the RIO queue. */
static BOOL af_insert_recv(af_bind_t *af, rio_ftable_t *rio)
{
    ring_packet_t *pkt = ring_push(&af->rx);

    RIO_BUF data_buf;
    data_buf.BufferId = af->rx.buf_id;
    data_buf.Offset = (ULONG)((PCHAR)pkt->data - (PCHAR)af->rx.packets);
    data_buf.Length = BYTES_PER_PACKET;

    RIO_BUF addr_buf;
    addr_buf.BufferId = af->rx.buf_id;
    addr_buf.Offset = (ULONG)((PCHAR)&pkt->addr - (PCHAR)af->rx.packets);
    addr_buf.Length = sizeof(pkt->addr) + sizeof(pkt->pad);

    EnterCriticalSection(&af->rq_lock);
    BOOL ok = rio->RIOReceiveEx(af->rq, &data_buf, 1, NULL, &addr_buf, NULL, NULL, 0,
                                (PVOID)pkt);
    LeaveCriticalSection(&af->rq_lock);
    return ok;
}

/* ────────────────────────────────────────
 * Receive path
 * ──────────────────────────────────────── */

/* Dequeue up to max completions into bufs/sizes/eps. Returns how many
 * packets were copied out (0 if the queue was empty), or -1 on a failed
 * receive with nothing usable. sizes[] holds each buffer's capacity on
 * entry. Every dequeued slot is returned to the ring and re-posted. */
static int af_dequeue_many(af_bind_t *af, rio_ftable_t *rio, uint8_t **bufs, int *sizes,
                           wg_endpoint_t *eps, int max)
{
    RIORESULT results[WG_RIO_RECV_BATCH];
    if (max > WG_RIO_RECV_BATCH)
        max = WG_RIO_RECV_BATCH;
    ULONG count = rio->RIODequeueCompletion(af->rx.cq, results, (ULONG)max);
    if (count == 0)
        return 0;

    int got = 0;
    BOOL failed = FALSE;
    for (ULONG i = 0; i < count; i++) {
        ring_packet_t *pkt = (ring_packet_t *)(uintptr_t)results[i].RequestContext;
        int n = (int)results[i].BytesTransferred;
        ULONG pkt_status = results[i].Status;

        if (pkt_status == 0 && n > 0) {
            if (n > sizes[got])
                n = sizes[got];
            memcpy(bufs[got], pkt->data, (size_t)n);
            memset(&eps[got], 0, sizeof(eps[got]));
            if (pkt->addr.si_family == AF_INET)
                memcpy(&eps[got].addr.sa4, &pkt->addr.Ipv4, sizeof(struct sockaddr_in));
            else if (pkt->addr.si_family == AF_INET6)
                memcpy(&eps[got].addr.sa6, &pkt->addr.Ipv6, sizeof(struct sockaddr_in6));
            sizes[got] = n;
            got++;
        } else if (pkt_status != 0 && pkt_status != WSAEMSGSIZE) {
            failed = TRUE;
        }
        /* WSAEMSGSIZE: oversized, skipped. */
    }

    ring_return(&af->rx, count);
    for (ULONG i = 0; i < count; i++)
        af_insert_recv(af, rio);

    if (got == 0 && failed)
        return -1;
    return got;
}

/* ────────────────────────────────────────
 * Send path
 * ──────────────────────────────────────── */

/* Commit sends queued with RIO_MSG_DEFER. Called with tx.lock held.
 * A failed commit keeps tx_deferred set so a later call retries it: those
 * sends never complete until committed. */
static void af_commit_sends(af_bind_t *af, rio_ftable_t *rio)
{
    if (!af->tx_deferred)
        return;
    EnterCriticalSection(&af->rq_lock);
    BOOL ok = rio->RIOSendEx(af->rq, NULL, 0, NULL, NULL, NULL, NULL, RIO_MSG_COMMIT_ONLY,
                             NULL);
    LeaveCriticalSection(&af->rq_lock);
    if (ok)
        af->tx_deferred = FALSE;
}

/* flags: RIO_MSG_DEFER queues the send for a later commit (one kernel
 * transition for a whole bind_send batch, #65), 0 commits at once. */
static int af_send(af_bind_t *af, rio_ftable_t *rio, const uint8_t *buf, int len,
                   const wg_endpoint_t *ep, atomic_int *is_open, DWORD flags)
{
    if (atomic_load(is_open) != BIND_OPEN)
        return -1;
    if (len > BYTES_PER_PACKET)
        return -1;
    if (af->blackhole)
        return len; /* Silently drop. */

    EnterCriticalSection(&af->tx.lock);

    /* Drain completed sends. */
    RIORESULT results[PACKETS_PER_RING];
    ULONG count = rio->RIODequeueCompletion(af->tx.cq, results, PACKETS_PER_RING);
    if (count == 0 && af->tx.is_full) {
        /* Deferred sends never complete until committed; do that before
         * waiting for completions. */
        if (af->tx_deferred) {
            af_commit_sends(af, rio);
            count = rio->RIODequeueCompletion(af->tx.cq, results, PACKETS_PER_RING);
            if (count > 0)
                goto tx_drained;
            if (af->tx_deferred) {
                /* The commit failed: the ring is full of sends that will
                 * not complete, so waiting would never return. Drop this
                 * packet; the next call retries the commit. */
                LeaveCriticalSection(&af->tx.lock);
                return -1;
            }
        }
        int err = rio->RIONotify(af->tx.cq);
        if (err != ERROR_SUCCESS) {
            /* WSAEALREADY: notification already armed. Retry dequeue. */
            count = rio->RIODequeueCompletion(af->tx.cq, results, PACKETS_PER_RING);
            if (count > 0)
                goto tx_drained;
            /* Fall through to GQCS — notification is armed. */
        }
        DWORD bytes;
        ULONG_PTR key;
        OVERLAPPED *ol;
        GetQueuedCompletionStatus(af->tx.iocp, &bytes, &key, &ol, INFINITE);
        if (atomic_load(is_open) != BIND_OPEN) {
            LeaveCriticalSection(&af->tx.lock);
            return -1;
        }
        count = rio->RIODequeueCompletion(af->tx.cq, results, PACKETS_PER_RING);
    }
tx_drained:
    if (count > 0)
        ring_return(&af->tx, count);

    /* Push packet. */
    ring_packet_t *pkt = ring_push(&af->tx);
    memcpy(pkt->data, buf, (size_t)len);

    /* Set destination address. */
    if (ep->addr.sa4.sin_family == AF_INET) {
        memcpy(&pkt->addr.Ipv4, &ep->addr.sa4, sizeof(struct sockaddr_in));
        pkt->addr.si_family = AF_INET;
    } else {
        memcpy(&pkt->addr.Ipv6, &ep->addr.sa6, sizeof(struct sockaddr_in6));
        pkt->addr.si_family = AF_INET6;
    }

    RIO_BUF data_buf;
    data_buf.BufferId = af->tx.buf_id;
    data_buf.Offset = (ULONG)((PCHAR)pkt->data - (PCHAR)af->tx.packets);
    data_buf.Length = (ULONG)len;

    RIO_BUF addr_buf;
    addr_buf.BufferId = af->tx.buf_id;
    addr_buf.Offset = (ULONG)((PCHAR)&pkt->addr - (PCHAR)af->tx.packets);
    addr_buf.Length = sizeof(pkt->addr) + sizeof(pkt->pad);

    EnterCriticalSection(&af->rq_lock);
    BOOL ok =
        rio->RIOSendEx(af->rq, &data_buf, 1, NULL, &addr_buf, NULL, NULL, flags, NULL);
    LeaveCriticalSection(&af->rq_lock);
    if (ok)
        af->tx_deferred = (flags & RIO_MSG_DEFER) != 0;

    LeaveCriticalSection(&af->tx.lock);

    return ok ? len : -1;
}

/* ────────────────────────────────────────
 * wg_bind_ops_t callbacks
 * ──────────────────────────────────────── */

static int bind_open(void *ctx, uint16_t port)
{
    wg_win_bind_t *bind = (wg_win_bind_t *)ctx;

    int state = atomic_load(&bind->is_open);
    if (state != BIND_CLOSED)
        return -1;

    /* Create shared IOCP for v4+v6 receive (single wait point). */
    bind->recv_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!bind->recv_iocp)
        return -1;

    /* IPv4 — completion key 4 */
    struct sockaddr_in sa4 = {0};
    sa4.sin_family = AF_INET;
    sa4.sin_port = htons(port);
    sa4.sin_addr.s_addr = INADDR_ANY;

    if (!af_open(&bind->v4, &bind->rio, AF_INET, (struct sockaddr *)&sa4, sizeof(sa4),
                 bind->recv_iocp, 4))
        goto fail;

    /* Get assigned port. */
    struct sockaddr_in bound4;
    int bound4_len = sizeof(bound4);
    getsockname(bind->v4.sock, (struct sockaddr *)&bound4, &bound4_len);
    uint16_t assigned_port = ntohs(bound4.sin_port);

    /* IPv6 — same port, completion key 6 */
    struct sockaddr_in6 sa6 = {0};
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons(assigned_port);
    sa6.sin6_addr = in6addr_any;

    if (!af_open(&bind->v6, &bind->rio, AF_INET6, (struct sockaddr *)&sa6, sizeof(sa6),
                 bind->recv_iocp, 6))
        goto fail;

    /* Pre-fill receive queues. */
    for (int i = 0; i < PACKETS_PER_RING; i++) {
        if (!af_insert_recv(&bind->v4, &bind->rio) ||
            !af_insert_recv(&bind->v6, &bind->rio))
            goto fail;
    }

    atomic_store(&bind->is_open, BIND_OPEN);
    return (int)assigned_port;

fail:
    af_close(&bind->v4, &bind->rio);
    af_close(&bind->v6, &bind->rio);
    if (bind->recv_iocp) {
        CloseHandle(bind->recv_iocp);
        bind->recv_iocp = NULL;
    }
    return -1;
}

static void bind_close(void *ctx)
{
    wg_win_bind_t *bind = (wg_win_bind_t *)ctx;

    if (atomic_load(&bind->is_open) != BIND_OPEN)
        return;

    atomic_store(&bind->is_open, BIND_CLOSING);

    /* Post completion to unblock any waiting receives/sends. */
    PostQueuedCompletionStatus(bind->recv_iocp, 0, 0, NULL);
    PostQueuedCompletionStatus(bind->v4.tx.iocp, 0, 0, NULL);
    PostQueuedCompletionStatus(bind->v6.tx.iocp, 0, 0, NULL);

    /* Spin-wait for send/recv to release their shared locks.
     * They check is_open and exit quickly once CLOSING is set. */
    for (int i = 0; i < 1000; i++) {
        if (TryAcquireSRWLockExclusive(&bind->mu)) {
            af_close(&bind->v4, &bind->rio);
            af_close(&bind->v6, &bind->rio);
            if (bind->recv_iocp) {
                CloseHandle(bind->recv_iocp);
                bind->recv_iocp = NULL;
            }
            atomic_store(&bind->is_open, BIND_CLOSED);
            ReleaseSRWLockExclusive(&bind->mu);
            return;
        }
        SleepEx(1, FALSE);
    }
    af_close(&bind->v4, &bind->rio);
    af_close(&bind->v6, &bind->rio);
    if (bind->recv_iocp) {
        CloseHandle(bind->recv_iocp);
        bind->recv_iocp = NULL;
    }
    atomic_store(&bind->is_open, BIND_CLOSED);
}

/* ────────────────────────────────────────
 * Interface binding (routing loop prevention)
 *
 * Sets IP_UNICAST_IF / IPV6_UNICAST_IF to force packets out a specific
 * interface, preventing routing loops when the WireGuard interface is
 * the default route.
 *
 * Reference: wireguard-go/conn/bind_windows.go bindSocketToInterface4/6
 * ──────────────────────────────────────── */

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif

int wg_win_bind_socket_to_interface4(wg_win_bind_t *bind, uint32_t iface_index,
                                     BOOL blackhole)
{
    if (!bind || atomic_load(&bind->is_open) != BIND_OPEN)
        return -1;

    /* MSDN: For IPv4, interface index must be in network byte order. */
    uint32_t index_be = htonl(iface_index);
    int err = setsockopt(bind->v4.sock, IPPROTO_IP, IP_UNICAST_IF,
                         (const char *)&index_be, sizeof(index_be));
    if (err == SOCKET_ERROR)
        return -1;

    bind->v4.blackhole = blackhole;
    return 0;
}

int wg_win_bind_socket_to_interface6(wg_win_bind_t *bind, uint32_t iface_index,
                                     BOOL blackhole)
{
    if (!bind || atomic_load(&bind->is_open) != BIND_OPEN)
        return -1;

    int err = setsockopt(bind->v6.sock, IPPROTO_IPV6, IPV6_UNICAST_IF,
                         (const char *)&iface_index, sizeof(iface_index));
    if (err == SOCKET_ERROR)
        return -1;

    bind->v6.blackhole = blackhole;
    return 0;
}

static int bind_send(void *ctx, uint8_t **bufs, int *sizes, int count,
                     const wg_endpoint_t *ep)
{
    wg_win_bind_t *bind = (wg_win_bind_t *)ctx;
    int sent = 0;

    if (atomic_load(&bind->is_open) != BIND_OPEN)
        return -1;

    AcquireSRWLockShared(&bind->mu);

    af_bind_t *af;
    if (ep->addr.sa4.sin_family == AF_INET)
        af = &bind->v4;
    else
        af = &bind->v6;

    /* Defer all but the last send; the last one commits the batch. If
     * the loop ends early, commit what was queued. */
    for (int i = 0; i < count; i++) {
        if (sizes[i] <= 0)
            continue;
        DWORD flags = (i + 1 < count) ? RIO_MSG_DEFER : 0;
        int ret = af_send(af, &bind->rio, bufs[i], sizes[i], ep, &bind->is_open, flags);
        if (ret < 0)
            break;
        sent++;
    }
    if (af->tx_deferred) {
        EnterCriticalSection(&af->tx.lock);
        af_commit_sends(af, &bind->rio);
        LeaveCriticalSection(&af->tx.lock);
    }

    ReleaseSRWLockShared(&bind->mu);
    return sent > 0 ? sent : -1;
}

/* Receive one packet from either v4 or v6.
 * Strategy: spin-poll both CQs (high iteration count catches most packets
 * without syscall), then GQCS(INFINITE) on shared recv_iocp for idle wait.
 * The shared IOCP wakes on either v4 or v6 completion — zero latency. */
static int bind_recv(void *ctx, uint8_t **bufs, int *sizes, int count, wg_endpoint_t *eps)
{
    wg_win_bind_t *bind = (wg_win_bind_t *)ctx;
    int n;

retry:
    if (atomic_load(&bind->is_open) != BIND_OPEN)
        return -1;

    AcquireSRWLockShared(&bind->mu);

    /* Phase 1: Spin-poll both v4 and v6 completion queues, taking up to
     * count packets at a time (#65). */
    for (int tries = 0; tries < RECEIVE_SPINS; tries++) {
        if ((tries & 255) == 255 && atomic_load(&bind->is_open) != BIND_OPEN) {
            ReleaseSRWLockShared(&bind->mu);
            return -1;
        }

        n = af_dequeue_many(&bind->v4, &bind->rio, bufs, sizes, eps, count);
        if (n != 0) {
            ReleaseSRWLockShared(&bind->mu);
            return n;
        }
        n = af_dequeue_many(&bind->v6, &bind->rio, bufs, sizes, eps, count);
        if (n != 0) {
            ReleaseSRWLockShared(&bind->mu);
            return n;
        }
    }

    /* Phase 2: Spin exhausted — arm notification and block (INFINITE).
     * Both v4.rx and v6.rx share the same IOCP (recv_iocp), so a single
     * GQCS wakes on either AF. No 1ms polling latency. */
    bind->rio.RIONotify(bind->v4.rx.cq);
    bind->rio.RIONotify(bind->v6.rx.cq);

    /* Dequeue once more after arming (race: packet arrived between last
     * spin iteration and RIONotify). */
    n = af_dequeue_many(&bind->v4, &bind->rio, bufs, sizes, eps, count);
    if (n != 0) {
        ReleaseSRWLockShared(&bind->mu);
        return n;
    }
    n = af_dequeue_many(&bind->v6, &bind->rio, bufs, sizes, eps, count);
    if (n != 0) {
        ReleaseSRWLockShared(&bind->mu);
        return n;
    }

    ReleaseSRWLockShared(&bind->mu);

    /* Block until a packet arrives on either AF. */
    DWORD bytes;
    ULONG_PTR key;
    OVERLAPPED *ol;
    BOOL ok = GetQueuedCompletionStatus(bind->recv_iocp, &bytes, &key, &ol, INFINITE);
    if (!ok || atomic_load(&bind->is_open) != BIND_OPEN)
        return -1;

    goto retry;
}

static int bind_set_mark(void *ctx, uint32_t mark)
{
    (void)ctx;
    (void)mark;
    /* Windows doesn't support socket marks. */
    return 0;
}

static int bind_batch_size(void *ctx)
{
    (void)ctx;
    return WG_RIO_RECV_BATCH;
}

static void bind_get_gso_stats(void *ctx, wg_bind_gso_stats_t *out)
{
    (void)ctx;
    /* GSO not available on Windows. */
    if (out)
        memset(out, 0, sizeof(*out));
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_win_bind_create(wg_win_bind_t **out)
{
    if (!out)
        return WG_ERR_INVALID_ARGUMENT;

    /* Initialize Winsock. */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return WG_ERR_BIND;

    wg_win_bind_t *bind = (wg_win_bind_t *)calloc(1, sizeof(*bind));
    if (!bind)
        return WG_ERR_NO_MEMORY;

    InitializeSRWLock(&bind->mu);
    atomic_store(&bind->is_open, BIND_CLOSED);
    bind->v4.sock = INVALID_SOCKET;
    bind->v6.sock = INVALID_SOCKET;

    /* Try to initialize RIO. */
    bind->rio_available = init_rio(bind);
    if (!bind->rio_available) {
        /* TODO: implement fallback with standard WSASendTo/WSARecvFrom. */
        free(bind);
        return WG_ERR_BIND;
    }

    *out = bind;
    return WG_OK;
}

wg_bind_ops_t wg_win_bind_ops(wg_win_bind_t *bind)
{
    wg_bind_ops_t ops = {0};
    if (bind) {
        ops.open = bind_open;
        ops.close = bind_close;
        ops.send = bind_send;
        ops.recv = bind_recv;
        ops.set_mark = bind_set_mark;
        ops.batch_size = bind_batch_size;
        ops.get_gso_stats = bind_get_gso_stats;
        ops.ctx = bind;
    }
    return ops;
}

void wg_win_bind_destroy(wg_win_bind_t *bind)
{
    if (!bind)
        return;

    bind_close(bind);
    free(bind);
    WSACleanup();
}

#endif /* _WIN32 */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * StdNetBind: standard UDP socket bind implementation.
 *
 * Reference: wireguard-go/conn/bind_std.go
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wg_bind_std.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <netinet/in.h>
#if defined(__APPLE__)
#include <sys/event.h>
#else
#include <poll.h>
#endif
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Busy-poll socket options (Linux 5.11+). */
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

/* Maximum number of packets to send/receive in a single syscall. */
#if defined(__linux__)
#define WG_BIND_BATCH_SIZE 128
#elif defined(__APPLE__)
#define WG_BIND_BATCH_SIZE 32
#else
#define WG_BIND_BATCH_SIZE 1
#endif

#if defined(__APPLE__)
/* ────────────────────────────────────────
 * macOS batched message API: sendmsg_x / recvmsg_x.
 *
 * Darwin-private syscalls available since macOS 10.11 (El Capitan).
 * Equivalent to Linux sendmmsg/recvmmsg — batch multiple UDP datagrams
 * in a single syscall, reducing per-packet syscall overhead.
 *
 * wireguard-go cannot use these (Go stdlib doesn't expose them, and cgo
 * breaks goroutine scheduling).  This is a key advantage of C.
 *
 * Reference: https://github.com/apple/darwin-xnu/blob/main/bsd/sys/socket.h
 * ──────────────────────────────────────── */
struct msghdr_x {
    void *msg_name;           /* optional address */
    socklen_t msg_namelen;    /* size of address */
    struct iovec *msg_iov;    /* scatter/gather array */
    int msg_iovlen;           /* # elements in msg_iov */
    void *msg_control;        /* ancillary data */
    socklen_t msg_controllen; /* ancillary data buffer len */
    int msg_flags;            /* flags on received message */
    size_t msg_datalen;       /* byte length of buffer in msg_iov */
};

/* Linked from libsystem_kernel — no header needed. */
extern ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
extern ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
#endif /* __APPLE__ */

/* Number of recvmmsg slots for GRO batch receive.
 * Each slot holds one GRO-coalesced buffer (up to 65535 bytes).
 * With ~5 segments/message, 8 messages yield ~40 segments.
 * Using 32 causes retransmissions due to aggressive socket draining.
 * Total staging memory: 8 * 65536 = 512KB. */
#define WG_GRO_BATCH_SIZE 8
#define WG_GRO_BUF_SIZE   65536

#if defined(__linux__)
/*
 * Sticky socket helpers (Linux only).
 *
 * When IP_PKTINFO / IPV6_RECVPKTINFO is enabled, recvmsg() delivers
 * ancillary data describing the destination address and interface the
 * packet arrived on.  We store this control message and replay it in
 * sendmsg() so that replies are sent from the same IP/interface.
 *
 * Reference: wireguard-go/conn/sticky_linux.go
 */

/* IP_PKTINFO / IPV6_PKTINFO / IPV6_RECVPKTINFO constants.
 * These are Linux-specific and may not be defined under strict POSIX. */
#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 50
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO 49
#endif

/* struct in_pktinfo / in6_pktinfo may not be visible under _POSIX_C_SOURCE.
 * Define the sizes directly (verified on x86_64 Linux). */
/* Verified on x86_64 Linux. If porting to a new arch, build will fail
 * here if the kernel struct sizes differ — update the constants. */
#define WG_SIZEOF_IN_PKTINFO  12 /* sizeof(struct in_pktinfo)  */
#define WG_SIZEOF_IN6_PKTINFO 20 /* sizeof(struct in6_pktinfo) */

/* Ensure our control buffer can hold the largest PKTINFO cmsg. */
_Static_assert(CMSG_SPACE(WG_SIZEOF_IN6_PKTINFO) <= WG_STICKY_CONTROL_SIZE,
               "WG_STICKY_CONTROL_SIZE too small for in6_pktinfo");

static void sticky_parse_control(const struct msghdr *msg, wg_endpoint_t *ep)
{
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {

        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            size_t space = CMSG_SPACE(WG_SIZEOF_IN_PKTINFO);
            if (space <= WG_STICKY_CONTROL_SIZE) {
                memcpy(ep->src_control, cmsg, space);
                ep->src_control_len = (uint32_t)space;
            }
            return;
        }

        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            size_t space = CMSG_SPACE(WG_SIZEOF_IN6_PKTINFO);
            if (space <= WG_STICKY_CONTROL_SIZE) {
                memcpy(ep->src_control, cmsg, space);
                ep->src_control_len = (uint32_t)space;
            }
            return;
        }
    }
}
#endif /* __linux__ */

/* UDP GSO (segmentation offload) and GRO (receive offload).
 *
 * UDP_SEGMENT (sendmsg cmsg): sends one large buffer as multiple UDP
 * datagrams of `segment_size` bytes each.  Replaces sendmmsg(N).
 *
 * UDP_GRO (setsockopt + recvmsg cmsg): receives multiple same-size UDP
 * datagrams coalesced into one large buffer.  Replaces recvmmsg(N).
 *
 * Reference: wireguard-go/conn/bind_std.go
 */
#if defined(__linux__)
#include <linux/udp.h>
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#endif /* __linux__ */

/* Socket buffer size: 7MB, matching wireguard-go.
 * Without large buffers, UDP packets are dropped at high throughput
 * due to socket receive buffer overflow, which triggers TCP congestion
 * control and dramatically reduces throughput.
 * Reference: wireguard-go/conn/controlfns.go socketBufferSize */
#define WG_SOCKET_BUFFER_SIZE (7 << 20)

struct wg_std_bind {
    int fd4;            /* IPv4 UDP socket, -1 if closed */
    int fd6;            /* IPv6 UDP socket, -1 if closed */
    int cancel_pipe[2]; /* [0]=read, [1]=write for recv cancellation */
    bool is_open;
    bool cancelled;  /* std_cancel() ran since the last std_open() */
    bool udp_gso_ok; /* kernel supports UDP_SEGMENT (GSO) */
    bool udp_gro_ok; /* kernel supports UDP_GRO */
    pthread_mutex_t lock;
    uint16_t port;        /* actual bound port */
    uint8_t *gro_staging; /* heap buffer for recvmmsg GRO: WG_GRO_BATCH_SIZE *
                             WG_GRO_BUF_SIZE */

    /* GSO send stats (for diagnostics via SIGUSR1). */
    _Atomic uint64_t gso_send_ok;
    _Atomic uint64_t gso_send_fail;
    _Atomic uint64_t gso_send_skip;
    _Atomic uint64_t gso_send_packets;

#if defined(__APPLE__)
    int kq; /* kqueue fd for recv wait — replaces poll() */
#endif
};

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/* ────────────────────────────────────────
 * Bind ops callbacks
 * ──────────────────────────────────────── */

static int std_open(void *ctx, uint16_t port)
{
    wg_std_bind_t *b = ctx;

    pthread_mutex_lock(&b->lock);
    if (b->is_open) {
        pthread_mutex_unlock(&b->lock);
        return -1; /* already open */
    }

    /* Close any leftover cancel pipe read end from a previous std_close().
     * std_close() intentionally keeps cancel_pipe[0] open so that poll()
     * can wake reliably on macOS; we clean it up here before re-opening. */
    close_fd(&b->cancel_pipe[0]);

    /* Create cancel pipe. */
    if (pipe(b->cancel_pipe) < 0) {
        b->cancel_pipe[0] = b->cancel_pipe[1] = -1;
        pthread_mutex_unlock(&b->lock);
        return -1;
    }

    /* IPv4 UDP socket. */
    b->fd4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (b->fd4 < 0)
        goto fail;

    int one = 1;
    setsockopt(b->fd4, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /* Set large socket buffers to avoid packet loss under load. */
    int bufsize = WG_SOCKET_BUFFER_SIZE;
    setsockopt(b->fd4, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(b->fd4, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
#if defined(__linux__)
    /* SO_RCVBUFFORCE bypasses net.core.rmem_max (requires CAP_NET_ADMIN). */
    setsockopt(b->fd4, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize));
    setsockopt(b->fd4, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize));
    setsockopt(b->fd4, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));

    /* Probe UDP GSO: try setting a default segment size via setsockopt.
     * The kernel handler expects an int (not uint16_t) for setsockopt. */
    {
        int seg = 0;
        b->udp_gso_ok =
            (setsockopt(b->fd4, SOL_UDP, UDP_SEGMENT, &seg, sizeof(seg)) == 0);
    }
    /* Enable UDP GRO: coalesce multiple incoming UDP datagrams. */
    b->udp_gro_ok = (setsockopt(b->fd4, SOL_UDP, UDP_GRO, &one, sizeof(one)) == 0);

    /* Enable busy-polling: kernel polls NAPI in recvmmsg context,
     * increasing batch sizes under sustained load.
     * 200µs gives NAPI more time to accumulate packets before returning,
     * improving pkt/call from ~4 to potentially 20+. */
    {
        int busy_us = 200;
        setsockopt(b->fd4, SOL_SOCKET, SO_BUSY_POLL, &busy_us, sizeof(busy_us));
        setsockopt(b->fd4, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one));
        setsockopt(b->fd4, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &(int){128}, sizeof(int));
    }
#endif

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(port);
    addr4.sin_addr.s_addr = INADDR_ANY;

    if (bind(b->fd4, (struct sockaddr *)&addr4, sizeof(addr4)) < 0)
        goto fail;

    /* Get actual port (if port==0, kernel assigned one). */
    socklen_t slen = sizeof(addr4);
    if (getsockname(b->fd4, (struct sockaddr *)&addr4, &slen) < 0)
        goto fail;
    b->port = ntohs(addr4.sin_port);

    /* IPv6 UDP socket on same port. */
    b->fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (b->fd6 < 0)
        goto fail;

    setsockopt(b->fd6, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(b->fd6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    setsockopt(b->fd6, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(b->fd6, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
#if defined(__linux__)
    setsockopt(b->fd6, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize));
    setsockopt(b->fd6, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize));
    setsockopt(b->fd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    /* Enable UDP GRO on v6 socket too. */
    setsockopt(b->fd6, SOL_UDP, UDP_GRO, &one, sizeof(one));
    /* Busy-poll on v6 too. */
    {
        int busy_us = 200;
        setsockopt(b->fd6, SOL_SOCKET, SO_BUSY_POLL, &busy_us, sizeof(busy_us));
        setsockopt(b->fd6, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one));
        setsockopt(b->fd6, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &(int){128}, sizeof(int));
    }
#endif

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(b->port);
    addr6.sin6_addr = in6addr_any;

    if (bind(b->fd6, (struct sockaddr *)&addr6, sizeof(addr6)) < 0)
        goto fail;

#if defined(__APPLE__)
    /* Create kqueue and register all fds for EVFILT_READ.
     * This replaces poll() in std_recv — kevent() is macOS-native
     * and avoids rebuilding the fd set on each call. */
    b->kq = kqueue();
    if (b->kq < 0)
        goto fail;
    {
        struct kevent evs[3];
        int nev = 0;
        if (b->fd4 >= 0)
            EV_SET(&evs[nev++], b->fd4, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (b->fd6 >= 0)
            EV_SET(&evs[nev++], b->fd6, EVFILT_READ, EV_ADD, 0, 0, NULL);
        EV_SET(&evs[nev++], b->cancel_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
        kevent(b->kq, evs, nev, NULL, 0, NULL);
    }
#endif

    b->cancelled = false;
    b->is_open = true;
    int bound = b->port;
    pthread_mutex_unlock(&b->lock);
    /* The port actually bound, which the kernel chose if port was 0. */
    return bound;

fail:
    close_fd(&b->fd4);
    close_fd(&b->fd6);
    close_fd(&b->cancel_pipe[0]);
    close_fd(&b->cancel_pipe[1]);
#if defined(__APPLE__)
    close_fd(&b->kq);
#endif
    b->port = 0;
    pthread_mutex_unlock(&b->lock);
    return -1;
}

/* Wake a recv blocked in poll()/kevent() and make later recv calls
 * return -1, but keep the sockets open: the device joins its receive
 * thread before it calls std_close(), so the fds are never closed (and
 * their numbers reused) under a thread that still holds them. */
static void std_cancel(void *ctx)
{
    wg_std_bind_t *b = ctx;

    pthread_mutex_lock(&b->lock);
    if (b->is_open && !b->cancelled) {
        b->cancelled = true;
        if (b->cancel_pipe[1] >= 0) {
            char c = 0;
            (void)write(b->cancel_pipe[1], &c, 1);
        }
    }
    pthread_mutex_unlock(&b->lock);
}

static void std_close(void *ctx)
{
    wg_std_bind_t *b = ctx;

    pthread_mutex_lock(&b->lock);
    if (!b->is_open) {
        pthread_mutex_unlock(&b->lock);
        return;
    }
    b->is_open = false;

    /* Wake any blocked kevent()/poll() in std_recv. */
    if (b->cancel_pipe[1] >= 0) {
        char c = 0;
        (void)write(b->cancel_pipe[1], &c, 1);
    }

    /* Close sockets and the cancel pipe write end.
     * Keep cancel_pipe[0] (read end) open so that the wait in std_recv()
     * can reliably see readiness and exit.  On macOS with kqueue, the
     * cancel_pipe write triggers EVFILT_READ; on Linux, poll() sees
     * POLLIN / POLLHUP.
     *
     * cancel_pipe[0] is closed later — either by the next std_open()
     * (bind_update) or by wg_std_bind_destroy(). */
    close_fd(&b->fd4);
    close_fd(&b->fd6);
    close_fd(&b->cancel_pipe[1]);
#if defined(__APPLE__)
    close_fd(&b->kq);
#endif

    pthread_mutex_unlock(&b->lock);
}

/* ────────────────────────────────────────
 * Linux batch receive via recvmmsg
 *
 * Reads up to `count` packets from a single socket in one syscall.
 * Returns the number of packets received, or -1 on error.
 * ──────────────────────────────────────── */

#if defined(__linux__)
/* ────────────────────────────────────────
 * recv_gro_batch: batch receive with per-message GRO cmsg parsing.
 *
 * Uses recvmmsg to receive multiple GRO-coalesced buffers in one syscall.
 * Each message may contain multiple same-size UDP datagrams coalesced by
 * the kernel's GRO engine.  We parse each message's cmsg for UDP_GRO
 * segment size and split into individual packets.
 *
 * This replaces the old recv_gro (single recvmsg) with recvmmsg batch,
 * combining the batch efficiency of recvmmsg with GRO segment splitting.
 *
 * Returns total number of segments, or -1 on error/EAGAIN.
 * ──────────────────────────────────────── */
static int recv_gro_batch(int fd, int af, uint8_t **bufs, int *sizes, int count,
                          wg_endpoint_t *eps, uint8_t *gro_staging)
{
    int msg_count = WG_GRO_BATCH_SIZE;
    if (msg_count > count)
        msg_count = count;

    struct mmsghdr msgs[WG_GRO_BATCH_SIZE];
    struct iovec iovs[WG_GRO_BATCH_SIZE];
    union {
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
    } addrs[WG_GRO_BATCH_SIZE];
    /* Per-message control buffer: pktinfo + UDP_GRO + padding. */
    uint8_t controls[WG_GRO_BATCH_SIZE][CMSG_SPACE(WG_SIZEOF_IN6_PKTINFO) +
                                        CMSG_SPACE(sizeof(uint16_t)) + 64];

    socklen_t addr_len = (af == AF_INET6) ? (socklen_t)sizeof(struct sockaddr_in6)
                                          : (socklen_t)sizeof(struct sockaddr_in);

    for (int i = 0; i < msg_count; i++) {
        iovs[i].iov_base = gro_staging + (size_t)i * WG_GRO_BUF_SIZE;
        iovs[i].iov_len = WG_GRO_BUF_SIZE;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = addr_len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = controls[i];
        msgs[i].msg_hdr.msg_controllen = sizeof(controls[i]);
    }

    int n = recvmmsg(fd, msgs, (unsigned int)msg_count, MSG_DONTWAIT, NULL);
    if (n <= 0)
        return -1;

    int seg_count = 0;

    for (int i = 0; i < n && seg_count < count; i++) {
        int msg_len = (int)msgs[i].msg_len;
        if (msg_len == 0)
            continue;

        struct msghdr *hdr = &msgs[i].msg_hdr;

        /* Parse cmsg for GRO segment size and pktinfo. */
        uint16_t gro_seg_size = 0;
        wg_endpoint_t ep0;
        memset(&ep0, 0, sizeof(ep0));
        if (af == AF_INET6)
            ep0.addr.sa6 = addrs[i].sa6;
        else
            ep0.addr.sa4 = addrs[i].sa4;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(hdr); cmsg;
             cmsg = CMSG_NXTHDR(hdr, cmsg)) {
            if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
                memcpy(&gro_seg_size, CMSG_DATA(cmsg), sizeof(gro_seg_size));
            }
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                size_t space = CMSG_SPACE(WG_SIZEOF_IN_PKTINFO);
                if (space <= WG_STICKY_CONTROL_SIZE) {
                    memcpy(ep0.src_control, cmsg, space);
                    ep0.src_control_len = (uint32_t)space;
                }
            }
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
                size_t space = CMSG_SPACE(WG_SIZEOF_IN6_PKTINFO);
                if (space <= WG_STICKY_CONTROL_SIZE) {
                    memcpy(ep0.src_control, cmsg, space);
                    ep0.src_control_len = (uint32_t)space;
                }
            }
        }

        /* If no GRO cmsg, this is a single (non-coalesced) packet. */
        if (gro_seg_size == 0)
            gro_seg_size = (uint16_t)msg_len;

        /* Split GRO buffer into individual segments. */
        uint8_t *gro_buf = gro_staging + (size_t)i * WG_GRO_BUF_SIZE;
        size_t offset = 0;
        while (offset < (size_t)msg_len && seg_count < count) {
            size_t seg_len = (size_t)gro_seg_size;
            if (offset + seg_len > (size_t)msg_len)
                seg_len = (size_t)msg_len - offset;
            memcpy(bufs[seg_count], gro_buf + offset, seg_len);
            sizes[seg_count] = (int)seg_len;
            if (eps)
                eps[seg_count] = ep0;
            seg_count++;
            offset += seg_len;
        }
    }

    return seg_count > 0 ? seg_count : -1;
}

static int recv_batch(int fd, int af, uint8_t **bufs, int *sizes, int count,
                      wg_endpoint_t *eps)
{
    if (count > WG_BIND_BATCH_SIZE)
        count = WG_BIND_BATCH_SIZE;

    struct mmsghdr msgs[WG_BIND_BATCH_SIZE];
    struct iovec iovs[WG_BIND_BATCH_SIZE];
    union {
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
    } addrs[WG_BIND_BATCH_SIZE];
    uint8_t controls[WG_BIND_BATCH_SIZE][WG_STICKY_CONTROL_SIZE];

    socklen_t addr_len = (af == AF_INET6) ? (socklen_t)sizeof(struct sockaddr_in6)
                                          : (socklen_t)sizeof(struct sockaddr_in);

    for (int i = 0; i < count; i++) {
        iovs[i] = (struct iovec){.iov_base = bufs[i], .iov_len = (size_t)sizes[i]};
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = addr_len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = controls[i];
        msgs[i].msg_hdr.msg_controllen = WG_STICKY_CONTROL_SIZE;
    }

    int n = recvmmsg(fd, msgs, (unsigned int)count, MSG_DONTWAIT, NULL);
    if (n <= 0)
        return -1;

    for (int i = 0; i < n; i++) {
        sizes[i] = (int)msgs[i].msg_len;
        if (eps) {
            memset(&eps[i], 0, sizeof(eps[i]));
            if (af == AF_INET6)
                eps[i].addr.sa6 = addrs[i].sa6;
            else
                eps[i].addr.sa4 = addrs[i].sa4;
            sticky_parse_control(&msgs[i].msg_hdr, &eps[i]);
        }
    }

    return n;
}
#endif /* __linux__ */

#if defined(__APPLE__)
/* ────────────────────────────────────────
 * macOS batch receive via recvmsg_x
 *
 * Reads up to `count` packets from a single socket in one syscall.
 * Returns the number of packets received, or -1 on error.
 * ──────────────────────────────────────── */
static int recv_batch_darwin(int fd, int af, uint8_t **bufs, int *sizes, int count,
                             wg_endpoint_t *eps)
{
    if (count > WG_BIND_BATCH_SIZE)
        count = WG_BIND_BATCH_SIZE;

    struct msghdr_x msgs[WG_BIND_BATCH_SIZE];
    struct iovec iovs[WG_BIND_BATCH_SIZE];
    union {
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
    } addrs[WG_BIND_BATCH_SIZE];

    socklen_t addr_len = (af == AF_INET6) ? (socklen_t)sizeof(struct sockaddr_in6)
                                          : (socklen_t)sizeof(struct sockaddr_in);

    for (int i = 0; i < count; i++) {
        iovs[i] = (struct iovec){.iov_base = bufs[i], .iov_len = (size_t)sizes[i]};
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_name = &addrs[i];
        msgs[i].msg_namelen = addr_len;
        msgs[i].msg_iov = &iovs[i];
        msgs[i].msg_iovlen = 1;
    }

    ssize_t n = recvmsg_x(fd, msgs, (u_int)count, MSG_DONTWAIT);
    if (n <= 0)
        return -1;

    int valid = 0;
    for (int i = 0; i < (int)n; i++) {
        /* Skip truncated datagrams — buffer was too small. */
        if (msgs[i].msg_flags & MSG_TRUNC)
            continue;

        sizes[valid] = (int)msgs[i].msg_datalen;
        if (eps) {
            memset(&eps[valid], 0, sizeof(eps[valid]));
            if (af == AF_INET6)
                eps[valid].addr.sa6 = addrs[i].sa6;
            else
                eps[valid].addr.sa4 = addrs[i].sa4;
        }
        valid++;
    }

    return valid > 0 ? valid : -1;
}
#endif /* __APPLE__ */

static int std_recv(void *ctx, uint8_t **bufs, int *sizes, int count, wg_endpoint_t *eps)
{
    wg_std_bind_t *b = ctx;

    if (count < 1)
        return 0;

    /* Snapshot fds under lock to avoid racing with std_close(). */
    pthread_mutex_lock(&b->lock);
    int fd4 = b->fd4;
    int fd6 = b->fd6;
    int cancel_fd = b->cancel_pipe[0];
    bool open = b->is_open && !b->cancelled;
#if defined(__linux__)
    bool use_gro = b->udp_gro_ok;
    uint8_t *gro_staging = b->gro_staging;
#endif
#if defined(__APPLE__)
    int kq = b->kq;
#endif
    pthread_mutex_unlock(&b->lock);

    if (!open)
        return -1;

#if defined(__APPLE__)
    /* macOS: kqueue fds are pre-registered in std_open(). */
    if (fd4 < 0 && fd6 < 0)
        return -1;
#else
    /* Linux / other POSIX: build pollfd array each call. */
    struct pollfd fds[3];
    int nfds = 0;

    int idx4 = -1, idx6 = -1, idx_cancel = -1;

    if (fd4 >= 0) {
        idx4 = nfds;
        fds[nfds].fd = fd4;
        fds[nfds].events = POLLIN;
        nfds++;
    }
    if (fd6 >= 0) {
        idx6 = nfds;
        fds[nfds].fd = fd6;
        fds[nfds].events = POLLIN;
        nfds++;
    }
    if (cancel_fd >= 0) {
        idx_cancel = nfds;
        fds[nfds].fd = cancel_fd;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    if (nfds == 0)
        return -1;
#endif

    for (;;) {
#if defined(__linux__) || defined(__APPLE__)
        /* Optimistic path: try recv before poll().
         * Under sustained load, packets are almost always queued —
         * this eliminates the poll() syscall on the hot path.
         *
         * Linux: When UDP GRO is enabled, use recv_gro which receives one
         * large coalesced buffer and splits it into segments.
         *
         * macOS: Use recvmsg_x to batch-receive multiple datagrams in one
         * syscall (equivalent to Linux recvmmsg, but wireguard-go can't use it).
         *
         * Accumulation spin: if we got few packets (< count/4),
         * spin briefly to let more arrive, then retry once. */
        {
            int total = 0;

            if (fd4 >= 0) {
#if defined(__linux__)
                int n = use_gro ? recv_gro_batch(fd4, AF_INET, bufs, sizes, count, eps,
                                                 gro_staging)
                                : recv_batch(fd4, AF_INET, bufs, sizes, count, eps);
#else
                int n = recv_batch_darwin(fd4, AF_INET, bufs, sizes, count, eps);
#endif
                if (n > 0)
                    total += n;
            }

            if (fd6 >= 0 && total < count) {
#if defined(__linux__)
                int n = use_gro ? recv_gro_batch(fd6, AF_INET6, bufs + total,
                                                 sizes + total, count - total,
                                                 eps ? eps + total : NULL, gro_staging)
                                : recv_batch(fd6, AF_INET6, bufs + total, sizes + total,
                                             count - total, eps ? eps + total : NULL);
#else
                int n = recv_batch_darwin(fd6, AF_INET6, bufs + total, sizes + total,
                                          count - total, eps ? eps + total : NULL);
#endif
                if (n > 0)
                    total += n;
            }

            if (total > 0) {
                /* Accumulation: if batch is small, spin briefly and
                 * try to grab more packets before returning. */
                if (total < count / 4) {
                    for (int spin = 0; spin < 512; spin++) {
#if defined(__x86_64__) || defined(__i386__)
                        __builtin_ia32_pause();
#elif defined(__aarch64__)
                        __asm__ volatile("yield");
#endif
                    }

                    if (fd4 >= 0 && total < count) {
#if defined(__linux__)
                        int n =
                            use_gro
                                ? recv_gro_batch(fd4, AF_INET, bufs + total,
                                                 sizes + total, count - total,
                                                 eps ? eps + total : NULL, gro_staging)
                                : recv_batch(fd4, AF_INET, bufs + total, sizes + total,
                                             count - total, eps ? eps + total : NULL);
#else
                        int n =
                            recv_batch_darwin(fd4, AF_INET, bufs + total, sizes + total,
                                              count - total, eps ? eps + total : NULL);
#endif
                        if (n > 0)
                            total += n;
                    }
                }
                return total;
            }
        }
        /* No data available — fall through to wait. */
#endif

#if defined(__APPLE__)
        /* macOS: kevent() — kqueue fds pre-registered in std_open(). */
        {
            struct kevent events[3];
            int n = kevent(kq, NULL, 0, events, 3, NULL);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }

            bool got4 = false, got6 = false;
            for (int i = 0; i < n; i++) {
                int ident = (int)events[i].ident;
                if (ident == cancel_fd)
                    return -1; /* cancelled */
                /* EV_EOF means the fd was closed (race with std_close). */
                if (events[i].flags & EV_EOF)
                    return -1;
                if (ident == fd4)
                    got4 = true;
                else if (ident == fd6)
                    got6 = true;
            }

            /* Batch receive after kevent(). */
            int total = 0;
            if (got4) {
                int nr = recv_batch_darwin(fd4, AF_INET, bufs, sizes, count, eps);
                if (nr > 0)
                    total += nr;
            }
            if (got6 && total < count) {
                int nr = recv_batch_darwin(fd6, AF_INET6, bufs + total, sizes + total,
                                           count - total, eps ? eps + total : NULL);
                if (nr > 0)
                    total += nr;
            }
            if (total > 0)
                return total;
            continue; /* EAGAIN — loop back to kevent. */
        }
#else /* !__APPLE__ */
        int ret = poll(fds, (nfds_t)nfds, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        /* Cancel pipe triggered → bind is closing.
         * Check POLLNVAL/POLLHUP too — the pipe fd may already be closed
         * if std_close() raced with poll(). */
        if (idx_cancel >= 0 &&
            (fds[idx_cancel].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
            return -1;

        /* If any socket fd became invalid, the bind was closed. */
        if ((idx4 >= 0 && (fds[idx4].revents & POLLNVAL)) ||
            (idx6 >= 0 && (fds[idx6].revents & POLLNVAL)))
            return -1;

#if defined(__linux__)
        /* Batch receive after poll(). */
        {
            int total = 0;

            if (idx4 >= 0 && (fds[idx4].revents & POLLIN)) {
                int n = use_gro ? recv_gro_batch(fd4, AF_INET, bufs, sizes, count, eps,
                                                 gro_staging)
                                : recv_batch(fd4, AF_INET, bufs, sizes, count, eps);
                if (n > 0)
                    total += n;
            }

            if (idx6 >= 0 && (fds[idx6].revents & POLLIN) && total < count) {
                int n = use_gro ? recv_gro_batch(fd6, AF_INET6, bufs + total,
                                                 sizes + total, count - total,
                                                 eps ? eps + total : NULL, gro_staging)
                                : recv_batch(fd6, AF_INET6, bufs + total, sizes + total,
                                             count - total, eps ? eps + total : NULL);
                if (n > 0)
                    total += n;
            }

            if (total > 0)
                return total;

            /* Batch recv returned 0 or EAGAIN — loop back to poll. */
            continue;
        }

#else  /* !__linux__: single-packet fallback (Windows etc.) */

        /* Try IPv4 first. */
        if (idx4 >= 0 && (fds[idx4].revents & POLLIN)) {
            struct sockaddr_in src;
            struct iovec iov = {.iov_base = bufs[0], .iov_len = (size_t)sizes[0]};
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &src;
            msg.msg_namelen = sizeof(src);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            ssize_t n = recvmsg(fd4, &msg, 0);
            if (n < 0)
                return -1;

            sizes[0] = (int)n;
            if (eps) {
                memset(&eps[0], 0, sizeof(eps[0]));
                eps[0].addr.sa4 = src;
            }
            return 1;
        }

        /* Try IPv6. */
        if (idx6 >= 0 && (fds[idx6].revents & POLLIN)) {
            struct sockaddr_in6 src;
            struct iovec iov = {.iov_base = bufs[0], .iov_len = (size_t)sizes[0]};
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &src;
            msg.msg_namelen = sizeof(src);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            ssize_t n = recvmsg(fd6, &msg, 0);
            if (n < 0)
                return -1;

            sizes[0] = (int)n;
            if (eps) {
                memset(&eps[0], 0, sizeof(eps[0]));
                eps[0].addr.sa6 = src;
            }
            return 1;
        }
#endif /* __linux__ */
#endif /* !__APPLE__ */
    }
}

static int std_send(void *ctx, uint8_t **bufs, int *sizes, int count,
                    const wg_endpoint_t *ep)
{
    wg_std_bind_t *b = ctx;

    if (!ep)
        return -1;

    int fd;
    const struct sockaddr *addr;
    socklen_t addr_len;

    if (ep->addr.sa.sa_family == AF_INET6) {
        fd = b->fd6;
        addr = (const struct sockaddr *)&ep->addr.sa6;
        addr_len = sizeof(ep->addr.sa6);
    } else {
        fd = b->fd4;
        addr = (const struct sockaddr *)&ep->addr.sa4;
        addr_len = sizeof(ep->addr.sa4);
    }

    if (fd < 0)
        return -1;

#if defined(__linux__)
    /* Filter valid buffers. */
    struct iovec iovs[WG_BIND_BATCH_SIZE];
    int valid = 0;
    for (int i = 0; i < count && valid < WG_BIND_BATCH_SIZE; i++) {
        if (!bufs[i] || sizes[i] <= 0)
            continue;
        iovs[valid] = (struct iovec){.iov_base = bufs[i], .iov_len = (size_t)sizes[i]};
        valid++;
    }
    if (valid == 0)
        return 0;

    /* Try UDP GSO: send packets as sendmsg with UDP_SEGMENT cmsg.
     * All segments must be the same size (except possibly the last).
     * Total payload must fit in 65535 bytes (UDP GSO limit). */
    if (b->udp_gso_ok && valid > 1) {
        int seg_size = iovs[0].iov_len;
        bool gso_ok = true;
        for (int i = 1; i < valid - 1; i++) {
            if ((int)iovs[i].iov_len != seg_size) {
                gso_ok = false;
                break;
            }
        }
        if (gso_ok && (int)iovs[valid - 1].iov_len > seg_size)
            gso_ok = false;

        if (gso_ok && seg_size > 0) {
            /* Send via sendmsg with UDP_SEGMENT cmsg (zero-copy iovec).
             * Max payload: min(65507, 64*seg_size) per sendmsg.
             * Use scatter-gather iovecs — no memcpy needed. */
            /* Cap segments per GSO call to limit burst size.
             * Large bursts (44 segs = 64KB) cause receiver-side congestion
             * and massive TCP retransmissions.
             * History: 44 segs → 187K retrans, 16 segs → 2K retrans.
             * Now trying 12 segs to further reduce retrans while
             * maintaining throughput (burst ~18KB vs 24KB). */
            int max_payload = 65507; /* 65535 - IP(20) - UDP(8) */
            int max_segs_payload = max_payload / seg_size;
            int max_segs = max_segs_payload < 12 ? max_segs_payload : 12;
            if (max_segs < 2)
                max_segs = 2;

            int gso_sent = 0;

            while (gso_sent < valid) {
                int chunk = valid - gso_sent;
                if (chunk > max_segs)
                    chunk = max_segs;
                if (chunk < 2)
                    break;

                union {
                    char buf[CMSG_SPACE(sizeof(uint16_t)) +
                             CMSG_SPACE(WG_STICKY_CONTROL_SIZE)];
                    struct cmsghdr align;
                } ctrl;
                memset(&ctrl, 0, sizeof(ctrl));

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_name = (void *)addr;
                msg.msg_namelen = addr_len;
                msg.msg_iov = &iovs[gso_sent];
                msg.msg_iovlen = (size_t)chunk;
                msg.msg_control = ctrl.buf;
                msg.msg_controllen = sizeof(ctrl.buf);

                size_t ctrl_len = 0;
                struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type = UDP_SEGMENT;
                cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                *(uint16_t *)CMSG_DATA(cm) = (uint16_t)seg_size;
                ctrl_len = CMSG_SPACE(sizeof(uint16_t));

                if (ep->src_control_len > 0 &&
                    ep->src_control_len <= WG_STICKY_CONTROL_SIZE) {
                    struct cmsghdr *cm2 = (struct cmsghdr *)((char *)ctrl.buf + ctrl_len);
                    memcpy(cm2, ep->src_control, ep->src_control_len);
                    ctrl_len += ep->src_control_len;
                }
                msg.msg_controllen = ctrl_len;

                ssize_t n = sendmsg(fd, &msg, 0);
                if (n >= 0) {
                    atomic_fetch_add_explicit(&b->gso_send_ok, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&b->gso_send_packets, (uint64_t)chunk,
                                              memory_order_relaxed);
                    gso_sent += chunk;
                } else {
                    atomic_fetch_add_explicit(&b->gso_send_fail, 1, memory_order_relaxed);
                    break;
                }
            }

            if (gso_sent == valid)
                return valid;

            /* Remainder via sendmmsg fallback. */
            if (gso_sent > 0) {
                int remaining = valid - gso_sent;
                struct iovec *rem_iovs = &iovs[gso_sent];
                struct mmsghdr msgs[WG_BIND_BATCH_SIZE];
                uint8_t ctrl_copies[WG_BIND_BATCH_SIZE][WG_STICKY_CONTROL_SIZE];
                for (int i = 0; i < remaining; i++) {
                    msgs[i].msg_hdr.msg_name = (void *)addr;
                    msgs[i].msg_hdr.msg_namelen = addr_len;
                    msgs[i].msg_hdr.msg_iov = &rem_iovs[i];
                    msgs[i].msg_hdr.msg_iovlen = 1;
                    msgs[i].msg_len = 0;
                    if (ep->src_control_len > 0 &&
                        ep->src_control_len <= WG_STICKY_CONTROL_SIZE) {
                        memcpy(ctrl_copies[i], ep->src_control, ep->src_control_len);
                        msgs[i].msg_hdr.msg_control = ctrl_copies[i];
                        msgs[i].msg_hdr.msg_controllen = ep->src_control_len;
                    } else {
                        msgs[i].msg_hdr.msg_control = NULL;
                        msgs[i].msg_hdr.msg_controllen = 0;
                    }
                    msgs[i].msg_hdr.msg_flags = 0;
                }
                sendmmsg(fd, msgs, (unsigned int)remaining, 0);
                return valid;
            }
        } else {
            atomic_fetch_add_explicit(&b->gso_send_skip, 1, memory_order_relaxed);
        }
    } else {
        atomic_fetch_add_explicit(&b->gso_send_skip, 1, memory_order_relaxed);
    }

    /* Fallback: sendmmsg (also used for single packets). */
    {
        struct mmsghdr msgs[WG_BIND_BATCH_SIZE];
        uint8_t ctrl_copies[WG_BIND_BATCH_SIZE][WG_STICKY_CONTROL_SIZE];

        for (int i = 0; i < valid; i++) {
            memset(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name = (void *)addr;
            msgs[i].msg_hdr.msg_namelen = addr_len;
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;

            if (ep->src_control_len > 0 &&
                ep->src_control_len <= WG_STICKY_CONTROL_SIZE) {
                memcpy(ctrl_copies[i], ep->src_control, ep->src_control_len);
                msgs[i].msg_hdr.msg_control = ctrl_copies[i];
                msgs[i].msg_hdr.msg_controllen = ep->src_control_len;
            }
        }

        int sent = sendmmsg(fd, msgs, (unsigned int)valid, 0);
        if (sent < 0) {
            if (errno == EHOSTUNREACH || errno == ENETUNREACH)
                return 0;
            return -1;
        }
        return sent;
    }

#elif defined(__APPLE__)
    /* macOS batch send via sendmsg_x. */
    {
        struct msghdr_x msgs[WG_BIND_BATCH_SIZE];
        struct iovec iovs[WG_BIND_BATCH_SIZE];
        int valid = 0;

        for (int i = 0; i < count && valid < WG_BIND_BATCH_SIZE; i++) {
            if (!bufs[i] || sizes[i] <= 0)
                continue;
            iovs[valid] =
                (struct iovec){.iov_base = bufs[i], .iov_len = (size_t)sizes[i]};
            memset(&msgs[valid], 0, sizeof(msgs[valid]));
            msgs[valid].msg_name = (void *)addr;
            msgs[valid].msg_namelen = addr_len;
            msgs[valid].msg_iov = &iovs[valid];
            msgs[valid].msg_iovlen = 1;
            /* msg_datalen must be zero on input — kernel computes it
             * from iov.  Setting non-zero violates XNU API contract. */
            valid++;
        }

        if (valid == 0)
            return 0;

        ssize_t sent = sendmsg_x(fd, msgs, (u_int)valid, 0);
        if (sent < 0) {
            /* Silently drop on unreachable routes (blackhole).
             * These errors indicate no valid route exists — not a fatal
             * condition for a VPN that may be the default route itself. */
            if (errno == EHOSTUNREACH || errno == ENETUNREACH)
                return 0;
            return -1;
        }
        return (int)sent;
    }

#else  /* !__linux__ && !__APPLE__: single-packet fallback */

    for (int i = 0; i < count; i++) {
        if (!bufs[i] || sizes[i] <= 0)
            continue;

        struct iovec iov = {.iov_base = bufs[i], .iov_len = (size_t)sizes[i]};
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void *)addr;
        msg.msg_namelen = addr_len;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t n = sendmsg(fd, &msg, 0);
        if (n < 0)
            return -1;
    }

    return count;
#endif /* __linux__ */
}

static int std_set_mark(void *ctx, uint32_t mark)
{
    wg_std_bind_t *b = ctx;

#if defined(__linux__) && defined(SO_MARK)
    if (b->fd4 >= 0)
        setsockopt(b->fd4, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (b->fd6 >= 0)
        setsockopt(b->fd6, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
#else
    (void)b;
    (void)mark;
#endif
    return 0;
}

static int std_batch_size(void *ctx)
{
    (void)ctx;
    return WG_BIND_BATCH_SIZE;
}

static void std_get_gso_stats(void *ctx, wg_bind_gso_stats_t *out)
{
    wg_std_bind_t *b = ctx;
    out->ok = atomic_load_explicit(&b->gso_send_ok, memory_order_relaxed);
    out->fail = atomic_load_explicit(&b->gso_send_fail, memory_order_relaxed);
    out->skip = atomic_load_explicit(&b->gso_send_skip, memory_order_relaxed);
    out->packets = atomic_load_explicit(&b->gso_send_packets, memory_order_relaxed);
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_std_bind_new(wg_std_bind_t **out)
{
    wg_std_bind_t *b = calloc(1, sizeof(*b));
    if (!b)
        return WG_ERR_NO_MEMORY;

    b->fd4 = -1;
    b->fd6 = -1;
    b->cancel_pipe[0] = -1;
    b->cancel_pipe[1] = -1;
#if defined(__APPLE__)
    b->kq = -1;
#endif
    b->is_open = false;
    b->port = 0;
    pthread_mutex_init(&b->lock, NULL);

    /* Pre-allocate GRO staging buffers for recvmmsg batch receive. */
    b->gro_staging = calloc(WG_GRO_BATCH_SIZE, WG_GRO_BUF_SIZE);
    if (!b->gro_staging) {
        free(b);
        return WG_ERR_NO_MEMORY;
    }

    *out = b;
    return WG_OK;
}

wg_bind_ops_t wg_std_bind_ops(wg_std_bind_t *bind)
{
    return (wg_bind_ops_t){
        .open = std_open,
        .close = std_close,
        .cancel = std_cancel,
        .send = std_send,
        .recv = std_recv,
        .set_mark = std_set_mark,
        .batch_size = std_batch_size,
        .get_gso_stats = std_get_gso_stats,
        .ctx = bind,
    };
}

int wg_std_bind_socket_fd(wg_std_bind_t *b, int family)
{
    if (!b)
        return -1;
    pthread_mutex_lock(&b->lock);
    int fd = family == AF_INET ? b->fd4 : family == AF_INET6 ? b->fd6 : -1;
    pthread_mutex_unlock(&b->lock);
    return fd;
}

void wg_std_bind_destroy(wg_std_bind_t *bind)
{
    if (!bind)
        return;

    /* Ensure sockets are closed. */
    std_close(bind);

    /* Close leftover cancel pipe read end (std_close keeps it open). */
    close_fd(&bind->cancel_pipe[0]);

    free(bind->gro_staging);
    pthread_mutex_destroy(&bind->lock);
    free(bind);
}

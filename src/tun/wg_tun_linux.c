/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Linux TUN device implementation.
 *
 * Provides /dev/net/tun based TUN with:
 *   - IFF_TUN | IFF_NO_PI | IFF_VNET_HDR (raw IP, virtio offload)
 *   - Non-blocking I/O via rwcancel
 *   - Netlink-based event monitoring (up/down/MTU changes)
 *   - batch_size = 128 with GRO/GSO via virtio_net_hdr
 *
 * Reference: wireguard-go/tun/tun_linux.go
 */

#ifdef __linux__

/* _GNU_SOURCE is needed for O_CLOEXEC, SOCK_CLOEXEC on Linux.
 * Must be defined before any system header. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wg_tun_linux.h"
#include "wg_tun_offload_linux.h"
#include "../rwcancel/wg_rwcancel.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#if WG_USE_IO_URING
#include <liburing.h>
#endif

#define TUN_CLONE_DEVICE "/dev/net/tun"

/* ────────────────────────────────────────
 * Internal state
 * ──────────────────────────────────────── */

#define WG_TUN_BATCH_SIZE 128
/* Max read buffer: virtio header + max IP packet. */
#define WG_TUN_READ_BUF_SIZE (WG_VIRTIO_NET_HDR_LEN + 65535)

struct wg_tun_linux {
    int tun_fd;
    wg_rwcancel_t *rwc; /* cancellable I/O on tun_fd */
    char name[IFNAMSIZ];
    int32_t if_index;

    /* Netlink event monitoring */
    int netlink_fd;
    wg_rwcancel_t *netlink_rwc;
    pthread_t netlink_thread;
    bool netlink_started;

    _Atomic uint32_t events; /* bitmask of WG_TUN_EVENT_* */
    _Atomic bool closed;

    bool vnet_hdr; /* true if IFF_VNET_HDR is enabled */
    bool udp_gso;  /* true if TUN_F_USO4/USO6 enabled */

    /* Read buffer for virtio header + coalesced packet. */
    uint8_t read_buf[WG_TUN_READ_BUF_SIZE];

    /* GRO tables for write path (protected by write_mu). */
    wg_tcp_gro_table_t tcp_gro_table;
    wg_udp_gro_table_t udp_gro_table;
    int gro_write_idx[WG_TUN_BATCH_SIZE];
    int gro_sizes[WG_TUN_BATCH_SIZE]; /* mutable copy of sizes for GRO */

    void *gro_stats; /* optional wg_stats_t* for GRO diagnostics */

#if WG_USE_IO_URING
    struct io_uring write_ring;
    bool write_ring_ok;       /* true if io_uring ring initialized */
    bool write_ring_fixed_fd; /* true if tun_fd registered as fixed file */
#endif

    pthread_mutex_t read_mu;
    pthread_mutex_t write_mu;
};

/* ────────────────────────────────────────
 * Helpers: interface index and MTU via ioctl
 * ──────────────────────────────────────── */

static int get_ifindex(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    int ret = -1;
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0)
        ret = ifr.ifr_ifindex;

    close(fd);
    return ret;
}

static int get_mtu(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    int ret = -1;
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
        ret = ifr.ifr_mtu;

    close(fd);
    return ret;
}

static int set_mtu(const char *name, int mtu)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    int ret = ioctl(fd, SIOCSIFMTU, &ifr);
    close(fd);
    return ret;
}

static int get_name_from_fd(int tun_fd, char *out, size_t out_len)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (ioctl(tun_fd, TUNGETIFF, &ifr) < 0)
        return -1;

    strncpy(out, ifr.ifr_name, out_len - 1);
    out[out_len - 1] = '\0';
    return 0;
}

/* ────────────────────────────────────────
 * Netlink event listener
 *
 * Monitors RTM_NEWLINK for IFF_RUNNING changes on our interface.
 * Reference: tun_linux.go routineNetlinkListener
 * ──────────────────────────────────────── */

static int create_netlink_socket(void)
{
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0)
        return -1;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static void *netlink_listener(void *arg)
{
    wg_tun_linux_t *tun = arg;
    uint8_t buf[1 << 16];
    bool was_ever_up = false;

    while (!atomic_load(&tun->closed)) {
        ssize_t n = wg_rwcancel_read(tun->netlink_rwc, buf, sizeof(buf));
        if (n <= 0)
            break;

        /* Parse netlink messages */
        size_t remaining = (size_t)n;
        uint8_t *ptr = buf;

        while (remaining >= sizeof(struct nlmsghdr)) {
            struct nlmsghdr *hdr = (struct nlmsghdr *)ptr;

            if (hdr->nlmsg_len > remaining)
                break;

            if (hdr->nlmsg_type == NLMSG_DONE) {
                remaining = 0;
                break;
            }

            if (hdr->nlmsg_type == RTM_NEWLINK &&
                hdr->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg))) {

                struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);

                if (ifi->ifi_index == tun->if_index) {
                    if (ifi->ifi_flags & IFF_RUNNING) {
                        atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_UP);
                        was_ever_up = true;
                    } else if (was_ever_up) {
                        atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_DOWN);
                    }
                    atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_MTU_UPDATE);
                }
            }

            size_t aligned = NLMSG_ALIGN(hdr->nlmsg_len);
            if (aligned > remaining)
                break;
            ptr += aligned;
            remaining -= aligned;
        }
    }

    return NULL;
}

/* ────────────────────────────────────────
 * TUN ops callbacks
 * ──────────────────────────────────────── */

static int tun_linux_read(void *ctx, uint8_t **bufs, int *sizes, int count, int offset)
{
    wg_tun_linux_t *tun = ctx;

    pthread_mutex_lock(&tun->read_mu);

    if (!tun->vnet_hdr) {
        /* No virtio header — read a single raw packet. */
        if (sizes[0] <= offset) {
            pthread_mutex_unlock(&tun->read_mu);
            return -1;
        }
        ssize_t n =
            wg_rwcancel_read(tun->rwc, bufs[0] + offset, (size_t)(sizes[0] - offset));
        if (n <= 0) {
            pthread_mutex_unlock(&tun->read_mu);
            return (n == 0) ? 0 : -1;
        }
        sizes[0] = (int)n;
        pthread_mutex_unlock(&tun->read_mu);
        return 1;
    }

    /* ── IFF_VNET_HDR path with multi-packet batching. ──
     *
     * The first read blocks via rwcancel (poll + cancel support).
     * Subsequent reads use raw read() on the non-blocking fd to drain
     * queued packets without poll() overhead.  This dramatically
     * improves batching for non-GSO packets: instead of returning 1
     * packet per call (each requiring a full poll cycle), we return
     * all queued packets in a single call.
     *
     * For GSO packets (large coalesced TCP): split into segments and
     * stop — one GSO packet typically fills most of the batch. */

    int total = 0;

    for (;;) {
        ssize_t n;
        if (total == 0) {
            /* First read: block until data arrives (cancellable). */
            n = wg_rwcancel_read(tun->rwc, tun->read_buf, sizeof(tun->read_buf));
        } else {
            /* Subsequent reads: non-blocking drain of TUN queue. */
            n = read(tun->tun_fd, tun->read_buf, sizeof(tun->read_buf));
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break; /* queue drained — return what we have */
        }

        if (n <= 0) {
            if (total > 0)
                break;
            pthread_mutex_unlock(&tun->read_mu);
            return (n == 0) ? 0 : -1;
        }

        if ((size_t)n < WG_VIRTIO_NET_HDR_LEN) {
            if (total > 0)
                break;
            pthread_mutex_unlock(&tun->read_mu);
            return -1;
        }

        /* Parse virtio header. */
        wg_virtio_net_hdr_t vhdr;
        memcpy(&vhdr, tun->read_buf, WG_VIRTIO_NET_HDR_LEN);

        const uint8_t *pkt_data = tun->read_buf + WG_VIRTIO_NET_HDR_LEN;
        size_t pkt_len = (size_t)n - WG_VIRTIO_NET_HDR_LEN;

        uint8_t gso_type = vhdr.gso_type & ~WG_VIRTIO_NET_HDR_GSO_ECN;
        if (gso_type != WG_VIRTIO_NET_HDR_GSO_NONE && vhdr.gso_size != 0) {
            /* GSO: split into remaining slots. */
            int nsegs = wg_gso_split(pkt_data, pkt_len, &vhdr, bufs + total,
                                     sizes + total, count - total, offset);
            if (nsegs > 0)
                total += nsegs;
            break; /* GSO typically fills the batch */
        }

        /* Non-GSO: single packet — copy and fix checksum. */
        if (total >= count || pkt_len == 0)
            break;

        memcpy(bufs[total] + offset, pkt_data, pkt_len);
        sizes[total] = (int)pkt_len;

        if (vhdr.flags & WG_VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            wg_complete_partial_checksum(bufs[total] + offset, pkt_len, vhdr.csum_start,
                                         vhdr.csum_offset);
        }

        total++;
        if (total >= count)
            break;
    }

    pthread_mutex_unlock(&tun->read_mu);
    return (total > 0) ? total : -1;
}

static int tun_linux_write(void *ctx, uint8_t **bufs, const int *sizes, int count,
                           int offset)
{
    wg_tun_linux_t *tun = ctx;
    int total = 0;

    pthread_mutex_lock(&tun->write_mu);

    if (tun->vnet_hdr) {
        /* IFF_VNET_HDR path with GRO coalescing.
         *
         * wg_handle_gro merges compatible TCP segments, prepends
         * virtio_net_hdr at offset - WG_VIRTIO_NET_HDR_LEN into each
         * packet's buffer (the space is available because the caller
         * places plaintext at WG_MESSAGE_TRANSPORT_HEADER=16, and
         * virtio_net_hdr is only 10 bytes).
         *
         * After GRO, wg_handle_gro updates sizes[idx] to include
         * the coalesced length + offset, so we can compute write_len
         * consistently. */
        /* Copy sizes — GRO may update entries for coalesced packets. */
        int gro_count = (count <= WG_TUN_BATCH_SIZE) ? count : WG_TUN_BATCH_SIZE;
        memcpy(tun->gro_sizes, sizes, (size_t)gro_count * sizeof(int));

        int write_count =
            wg_handle_gro(bufs, tun->gro_sizes, gro_count, offset, &tun->tcp_gro_table,
                          &tun->udp_gro_table, tun->gro_write_idx, tun->gro_stats);

        int write_offset = offset - WG_VIRTIO_NET_HDR_LEN;

#if WG_USE_IO_URING
        if (tun->write_ring_ok && write_count > 0) {
            /* io_uring batch: submit all writes as SQEs, then one
             * io_uring_enter() instead of N write() syscalls. */
            int submitted = 0;
            for (int i = 0; i < write_count; i++) {
                int idx = tun->gro_write_idx[i];
                size_t pkt_len = (tun->gro_sizes[idx] > offset)
                                     ? (size_t)(tun->gro_sizes[idx] - offset)
                                     : 0;
                size_t write_len = WG_VIRTIO_NET_HDR_LEN + pkt_len;

                struct io_uring_sqe *sqe = io_uring_get_sqe(&tun->write_ring);
                if (!sqe)
                    break; /* ring full — shouldn't happen with proper sizing */
                if (tun->write_ring_fixed_fd) {
                    io_uring_prep_write(sqe, 0, bufs[idx] + write_offset, write_len, 0);
                    sqe->flags |= IOSQE_FIXED_FILE;
                } else {
                    io_uring_prep_write(sqe, tun->tun_fd, bufs[idx] + write_offset,
                                        write_len, 0);
                }
                submitted++;
            }

            if (submitted > 0) {
                int ret = io_uring_submit_and_wait(&tun->write_ring, submitted);
                if (ret >= 0) {
                    /* Drain completions. */
                    struct io_uring_cqe *cqe;
                    unsigned head;
                    int nr_cqes = 0;
                    io_uring_for_each_cqe(&tun->write_ring, head, cqe)
                    {
                        if (cqe->res >= 0)
                            total++;
                        nr_cqes++;
                    }
                    io_uring_cq_advance(&tun->write_ring, nr_cqes);
                }
            }
        } else
#endif
        {
            for (int i = 0; i < write_count; i++) {
                int idx = tun->gro_write_idx[i];
                size_t pkt_len = (tun->gro_sizes[idx] > offset)
                                     ? (size_t)(tun->gro_sizes[idx] - offset)
                                     : 0;
                size_t write_len = WG_VIRTIO_NET_HDR_LEN + pkt_len;

                ssize_t nw = write(tun->tun_fd, bufs[idx] + write_offset, write_len);
                if (nw < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        nw = wg_rwcancel_write(tun->rwc, bufs[idx] + write_offset,
                                               write_len);
                        if (nw < 0) {
                            if (errno == EINVAL || errno == ENOBUFS)
                                continue;
                            break;
                        }
                    } else if (errno == EINVAL || errno == ENOBUFS) {
                        continue;
                    } else {
                        break;
                    }
                }
                total++;
            }
        }
    } else {
        /* No virtio header — raw packets.
         * sizes[i] includes offset; subtract it to get packet length. */
        for (int i = 0; i < count; i++) {
            if (sizes[i] <= offset)
                continue;
            size_t pkt_len = (size_t)(sizes[i] - offset);

            ssize_t nw = write(tun->tun_fd, bufs[i] + offset, pkt_len);
            if (nw < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    nw = wg_rwcancel_write(tun->rwc, bufs[i] + offset, pkt_len);
                    if (nw < 0) {
                        if (errno == EINVAL || errno == ENOBUFS)
                            continue;
                        break;
                    }
                } else if (errno == EINVAL || errno == ENOBUFS) {
                    continue;
                } else {
                    break;
                }
            }
            total++;
        }
    }

    pthread_mutex_unlock(&tun->write_mu);
    return total;
}

static int tun_linux_mtu(void *ctx)
{
    wg_tun_linux_t *tun = ctx;
    return get_mtu(tun->name);
}

static const char *tun_linux_name(void *ctx)
{
    wg_tun_linux_t *tun = ctx;
    return tun->name;
}

static int tun_linux_batch_size(void *ctx)
{
    wg_tun_linux_t *tun = ctx;
    return tun->vnet_hdr ? WG_TUN_BATCH_SIZE : 1;
}

static int tun_linux_events(void *ctx)
{
    wg_tun_linux_t *tun = ctx;
    return (int)atomic_exchange(&tun->events, 0);
}

static void tun_linux_close(void *ctx)
{
    wg_tun_linux_destroy(ctx);
}

/* Wake a reader or writer blocked on the TUN fd; frees nothing. */
static void tun_linux_cancel(void *ctx)
{
    wg_tun_linux_t *tun = ctx;
    if (tun->rwc)
        wg_rwcancel_cancel(tun->rwc);
}

/*
 * Match our view of the device to the fd: if it was opened with
 * IFF_VNET_HDR, every read and write carries a virtio_net_hdr, and the
 * kernel must be told which offloads we handle. An fd handed to us (a
 * daemon child, an Android VpnService) may or may not have the flag, so
 * read it rather than assume it. The same as wireguard-go's
 * initFromFlags.
 */
static wg_error_t tun_linux_setup_offloads(int fd, bool *vnet_hdr, bool *udp_gso)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    *vnet_hdr = false;
    *udp_gso = false;
    if (ioctl(fd, TUNGETIFF, &ifr) < 0)
        return WG_ERR_TUN;
    if (!(ifr.ifr_flags & IFF_VNET_HDR))
        return WG_OK;

    /* TCP offloads date from Linux 2.6; with IFF_VNET_HDR set they are
     * required, because the header is on every packet regardless. */
    unsigned int tcp_offloads = WG_TUN_F_CSUM | WG_TUN_F_TSO4 | WG_TUN_F_TSO6;
    if (ioctl(fd, TUNSETOFFLOAD, tcp_offloads) < 0)
        return WG_ERR_TUN;
    *vnet_hdr = true;
    /* UDP offloads need Linux 6.2; without them we still work. */
    *udp_gso =
        ioctl(fd, TUNSETOFFLOAD, tcp_offloads | WG_TUN_F_USO4 | WG_TUN_F_USO6) == 0;
    return WG_OK;
}

/* ────────────────────────────────────────
 * Common initialisation (shared by create and create_from_fd)
 * ──────────────────────────────────────── */

static wg_error_t tun_linux_init_common(wg_tun_linux_t *tun)
{
    atomic_store(&tun->events, 0);
    atomic_store(&tun->closed, false);

    if (pthread_mutex_init(&tun->read_mu, NULL) != 0)
        return WG_ERR_NO_MEMORY;
    if (pthread_mutex_init(&tun->write_mu, NULL) != 0) {
        pthread_mutex_destroy(&tun->read_mu);
        return WG_ERR_NO_MEMORY;
    }

    /* Create rwcancel wrapper for the tun fd. */
    wg_error_t err = wg_rwcancel_new(&tun->rwc, tun->tun_fd);
    if (err != WG_OK) {
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        return err;
    }

    /* Get the interface name from the fd. */
    if (get_name_from_fd(tun->tun_fd, tun->name, sizeof(tun->name)) < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        return WG_ERR_TUN;
    }

#if WG_USE_IO_URING
    /* Initialize io_uring for batched TUN writes.
     * Batches N write() syscalls into one io_uring_enter(). */
    {
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ret =
            io_uring_queue_init_params(WG_TUN_BATCH_SIZE * 2, &tun->write_ring, &params);
        if (ret == 0) {
            int fds[1] = {tun->tun_fd};
            if (io_uring_register_files(&tun->write_ring, fds, 1) == 0)
                tun->write_ring_fixed_fd = true;
        }
        tun->write_ring_ok = (ret == 0);
    }
#endif

    /* Get interface index. */
    tun->if_index = get_ifindex(tun->name);
    if (tun->if_index < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        return WG_ERR_TUN;
    }

    return WG_OK;
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_tun_linux_create(wg_tun_linux_t **out, const char *name, int mtu)
{
    if (!out || !name)
        return WG_ERR_INVALID_ARGUMENT;

    /* Open /dev/net/tun */
    int fd = open(TUN_CLONE_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return WG_ERR_TUN;

    /* Configure the TUN device with IFF_VNET_HDR for GRO/GSO offload.
     * Each packet is prefixed with a 10-byte virtio_net_hdr that carries
     * checksum and segmentation metadata.  The TUN reader must be
     * batch-aware to handle GSO-split output from the kernel. */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* With IFF_VNET_HDR accepted, the TCP offloads make the kernel hand us
     * coalesced TCP packets (up to 64 KB) that we split via GSO. */
    bool got_vnet_hdr, got_udp_gso;
    if (tun_linux_setup_offloads(fd, &got_vnet_hdr, &got_udp_gso) != WG_OK) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* Set non-blocking before handing to rwcancel */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* Allocate state */
    wg_tun_linux_t *tun = calloc(1, sizeof(*tun));
    if (!tun) {
        close(fd);
        return WG_ERR_NO_MEMORY;
    }
    tun->tun_fd = fd;
    tun->netlink_fd = -1;
    tun->vnet_hdr = got_vnet_hdr;
    tun->udp_gso = got_udp_gso;

    wg_error_t err = tun_linux_init_common(tun);
    if (err != WG_OK) {
        close(fd);
        free(tun);
        return err;
    }

    /* Set MTU */
    if (mtu > 0 && set_mtu(tun->name, mtu) < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        close(fd);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Start netlink event listener */
    tun->netlink_fd = create_netlink_socket();
    if (tun->netlink_fd >= 0) {
        err = wg_rwcancel_new(&tun->netlink_rwc, tun->netlink_fd);
        if (err == WG_OK) {
            if (pthread_create(&tun->netlink_thread, NULL, netlink_listener, tun) == 0) {
                tun->netlink_started = true;
            } else {
                wg_rwcancel_destroy(tun->netlink_rwc);
                tun->netlink_rwc = NULL;
            }
        }
        /* Non-fatal if netlink fails — device still works, just no events */
        if (!tun->netlink_started && tun->netlink_fd >= 0) {
            close(tun->netlink_fd);
            tun->netlink_fd = -1;
        }
    }

    *out = tun;
    return WG_OK;
}

wg_error_t wg_tun_linux_create_from_fd(wg_tun_linux_t **out, int fd)
{
    if (!out || fd < 0)
        return WG_ERR_INVALID_ARGUMENT;

    /* Set non-blocking (restore original flags on failure). */
    int orig_flags = fcntl(fd, F_GETFL, 0);
    if (orig_flags < 0)
        return WG_ERR_TUN;
    if (!(orig_flags & O_NONBLOCK)) {
        if (fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK) < 0)
            return WG_ERR_TUN;
    }

    wg_tun_linux_t *tun = calloc(1, sizeof(*tun));
    if (!tun) {
        fcntl(fd, F_SETFL, orig_flags);
        return WG_ERR_NO_MEMORY;
    }

    tun->tun_fd = fd;
    tun->netlink_fd = -1;

    wg_error_t err = tun_linux_setup_offloads(fd, &tun->vnet_hdr, &tun->udp_gso);
    if (err == WG_OK)
        err = tun_linux_init_common(tun);
    if (err != WG_OK) {
        fcntl(fd, F_SETFL, orig_flags);
        free(tun);
        return err;
    }

    /* No netlink monitoring for inherited FDs */
    *out = tun;
    return WG_OK;
}

int wg_tun_linux_fd(wg_tun_linux_t *tun)
{
    return tun ? tun->tun_fd : -1;
}

wg_tun_ops_t wg_tun_linux_ops(wg_tun_linux_t *tun)
{
    return (wg_tun_ops_t){
        .read = tun_linux_read,
        .write = tun_linux_write,
        .mtu = tun_linux_mtu,
        .name = tun_linux_name,
        .batch_size = tun_linux_batch_size,
        .events = tun_linux_events,
        .close = tun_linux_close,
        .cancel = tun_linux_cancel,
        .ctx = tun,
    };
}

void wg_tun_linux_set_gro_stats(wg_tun_linux_t *tun, void *stats)
{
    if (tun)
        tun->gro_stats = stats;
}

void wg_tun_linux_destroy(wg_tun_linux_t *tun)
{
    if (!tun)
        return;

    bool already_closed = atomic_exchange(&tun->closed, true);
    if (already_closed)
        return;

    /* Cancel the TUN fd I/O */
    if (tun->rwc)
        wg_rwcancel_cancel(tun->rwc);

    /* Stop netlink listener */
    if (tun->netlink_rwc)
        wg_rwcancel_cancel(tun->netlink_rwc);
    if (tun->netlink_started)
        pthread_join(tun->netlink_thread, NULL);
    if (tun->netlink_rwc)
        wg_rwcancel_destroy(tun->netlink_rwc);
    if (tun->netlink_fd >= 0)
        close(tun->netlink_fd);

    /* Clean up TUN */
    if (tun->rwc)
        wg_rwcancel_destroy(tun->rwc);
    if (tun->tun_fd >= 0)
        close(tun->tun_fd);

#if WG_USE_IO_URING
    if (tun->write_ring_ok) {
        if (tun->write_ring_fixed_fd)
            io_uring_unregister_files(&tun->write_ring);
        io_uring_queue_exit(&tun->write_ring);
    }
#endif

    pthread_mutex_destroy(&tun->read_mu);
    pthread_mutex_destroy(&tun->write_mu);

    free(tun);
}

#endif /* __linux__ */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * macOS utun device implementation.
 *
 * Provides utun-based TUN with:
 *   - PF_SYSTEM control socket (com.apple.net.utun_control)
 *   - 4-byte AF header handling (stripped on read, prepended on write)
 *   - Non-blocking I/O via rwcancel
 *   - AF_ROUTE-based event monitoring (up/down/MTU changes)
 *   - batch_size = 1
 *
 * Reference: wireguard-go/tun/tun_darwin.go
 */

#ifdef __APPLE__

#include "wg_tun_darwin.h"
#include "../rwcancel/wg_rwcancel.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* Creating a utun takes the kernel-control API, which the iOS SDK leaves
 * out along with the routing socket; there the Network Extension creates
 * the utun and hands over its fd, which needs only the two constants
 * below (values as in the macOS SDK). */
#if __has_include(<net/if_utun.h>) && __has_include(<sys/kern_control.h>) &&              \
    __has_include(<net/route.h>)
#define WG_TUN_DARWIN_CAN_CREATE 1
#include <net/if_utun.h>
#include <net/route.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#else
#define WG_TUN_DARWIN_CAN_CREATE 0
#define SYSPROTO_CONTROL         2
#define UTUN_OPT_IFNAME          2
#endif

/* ────────────────────────────────────────
 * Constants
 * ──────────────────────────────────────── */

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"

/* Maximum read buffer: MTU + 4-byte AF header */
#define UTUN_READ_BUF_SIZE (65535 + 4)

/* ────────────────────────────────────────
 * Internal state
 * ──────────────────────────────────────── */

struct wg_tun_darwin {
    int tun_fd;
    wg_rwcancel_t *rwc; /* cancellable I/O on tun_fd */
    char name[IFNAMSIZ];
    int32_t if_index;

    /* AF_ROUTE event monitoring */
    int route_fd;
    pthread_t route_thread;
    bool route_started;

    _Atomic uint32_t events; /* bitmask of WG_TUN_EVENT_* */
    _Atomic bool closed;

    pthread_mutex_t read_mu;
    pthread_mutex_t write_mu;

    /*
     * I/O buffers for read/write with 4-byte AF header.
     * Kept in the struct to avoid 64KB+ stack allocations.
     * Protected by read_mu / write_mu respectively.
     */
    uint8_t read_buf[UTUN_READ_BUF_SIZE];
    uint8_t write_buf[UTUN_READ_BUF_SIZE];
};

/* ────────────────────────────────────────
 * Helpers: create socket with CLOEXEC
 *
 * macOS does not support SOCK_CLOEXEC, so we set FD_CLOEXEC via fcntl.
 * ──────────────────────────────────────── */

static int socket_cloexec(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);
    if (fd >= 0)
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* ────────────────────────────────────────
 * Helpers: MTU via ioctl
 * ──────────────────────────────────────── */

static int get_mtu(const char *name)
{
    int fd = socket_cloexec(AF_INET, SOCK_DGRAM, 0);
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
    int fd = socket_cloexec(AF_INET, SOCK_DGRAM, 0);
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

#if WG_TUN_DARWIN_CAN_CREATE
/* ────────────────────────────────────────
 * AF_ROUTE event listener
 *
 * Monitors RTM_IFINFO for IFF_UP changes and MTU updates.
 * Reference: tun_darwin.go routineRouteListener
 * ──────────────────────────────────────── */

static void *route_listener(void *arg)
{
    wg_tun_darwin_t *tun = arg;
    uint8_t buf[4096];
    bool status_up = false;
    int status_mtu = 0;

    while (!atomic_load(&tun->closed)) {
        ssize_t n = read(tun->route_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break; /* fd was shutdown or error */
        }

        if ((size_t)n < sizeof(struct if_msghdr))
            continue;

        struct if_msghdr *ifm = (struct if_msghdr *)buf;

        if (ifm->ifm_type != RTM_IFINFO)
            continue;
        if ((int32_t)ifm->ifm_index != tun->if_index)
            continue;

        bool up = (ifm->ifm_flags & IFF_UP) != 0;
        if (up != status_up && up) {
            atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_UP);
        }
        if (up != status_up && !up) {
            atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_DOWN);
        }
        status_up = up;

        uint32_t mtu = ifm->ifm_data.ifi_mtu;
        if ((int)mtu != status_mtu) {
            atomic_fetch_or(&tun->events, (uint32_t)WG_TUN_EVENT_MTU_UPDATE);
            status_mtu = (int)mtu;
        }
    }

    return NULL;
}
#endif /* WG_TUN_DARWIN_CAN_CREATE */

/* ────────────────────────────────────────
 * TUN ops callbacks
 * ──────────────────────────────────────── */

/* utun hands over one packet per read(2). The first read waits (rwcancel:
 * kqueue, cancellable); the ones after it are plain non-blocking reads
 * that stop at EAGAIN, so a busy tunnel yields a batch and an idle one
 * a single packet without extra syscalls (performance-analysis.md #65).
 * Each packet arrives with a 4-byte AF header, which is stripped. */
static int tun_darwin_read(void *ctx, uint8_t **bufs, int *sizes, int count, int offset)
{
    wg_tun_darwin_t *tun = ctx;
    int got = 0;

    pthread_mutex_lock(&tun->read_mu);

    while (got < count) {
        ssize_t n;
        if (got == 0) {
            n = wg_rwcancel_read(tun->rwc, tun->read_buf, sizeof(tun->read_buf));
            if (n <= 4) {
                pthread_mutex_unlock(&tun->read_mu);
                return (n == 0) ? 0 : -1;
            }
        } else {
            n = read(tun->tun_fd, tun->read_buf, sizeof(tun->read_buf));
            if (n <= 4)
                break; /* EAGAIN, or nothing usable: the batch ends here */
        }

        size_t payload_len = (size_t)(n - 4);
        int avail = sizes[got] - offset;
        if (avail <= 0 || payload_len > (size_t)avail) {
            if (got == 0) {
                pthread_mutex_unlock(&tun->read_mu);
                return -1;
            }
            break; /* drop this one, keep the batch */
        }

        memcpy(bufs[got] + offset, tun->read_buf + 4, payload_len);
        sizes[got] = (int)payload_len;
        got++;
    }

    pthread_mutex_unlock(&tun->read_mu);
    return got;
}

static int tun_darwin_write(void *ctx, uint8_t **bufs, const int *sizes, int count,
                            int offset)
{
    wg_tun_darwin_t *tun = ctx;
    int total = 0;

    pthread_mutex_lock(&tun->write_mu);

    for (int i = 0; i < count; i++) {
        if (sizes[i] <= offset)
            continue;
        size_t pkt_len = (size_t)(sizes[i] - offset);
        uint8_t *pkt = bufs[i] + offset;

        /* Determine address family from IP version nibble */
        uint8_t af_hdr[4] = {0, 0, 0, 0};
        switch (pkt[0] >> 4) {
        case 4:
            af_hdr[3] = AF_INET;
            break;
        case 6:
            af_hdr[3] = AF_INET6;
            break;
        default:
            continue; /* unsupported protocol */
        }

        /*
         * Build a contiguous buffer: 4-byte AF header + IP packet.
         * Uses the struct's write buffer (protected by write_mu).
         */
        size_t total_len = 4 + pkt_len;
        if (total_len > sizeof(tun->write_buf))
            continue;

        memcpy(tun->write_buf, af_hdr, 4);
        memcpy(tun->write_buf + 4, pkt, pkt_len);

        ssize_t n = wg_rwcancel_write(tun->rwc, tun->write_buf, total_len);
        if (n < 0) {
            if (errno == EINVAL || errno == ENOBUFS)
                continue;
            break;
        }
        total++;
    }

    pthread_mutex_unlock(&tun->write_mu);
    return total;
}

static int tun_darwin_mtu(void *ctx)
{
    wg_tun_darwin_t *tun = ctx;
    return get_mtu(tun->name);
}

static const char *tun_darwin_name(void *ctx)
{
    wg_tun_darwin_t *tun = ctx;
    return tun->name;
}

static int tun_darwin_batch_size(void *ctx)
{
    (void)ctx;
    return 32; /* reads until EAGAIN, see tun_darwin_read */
}

static int tun_darwin_events(void *ctx)
{
    wg_tun_darwin_t *tun = ctx;
    return (int)atomic_exchange(&tun->events, 0);
}

static void tun_darwin_close(void *ctx)
{
    wg_tun_darwin_destroy(ctx);
}

/* Wake a reader or writer blocked on the utun fd; frees nothing. */
static void tun_darwin_cancel(void *ctx)
{
    wg_tun_darwin_t *tun = ctx;
    if (tun->rwc)
        wg_rwcancel_cancel(tun->rwc);
}

/* ────────────────────────────────────────
 * Common initialisation (shared by create and create_from_fd)
 * ──────────────────────────────────────── */

static wg_error_t tun_darwin_init_common(wg_tun_darwin_t *tun)
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

    return WG_OK;
}

/* ────────────────────────────────────────
 * Helper: get interface name from utun fd
 * ──────────────────────────────────────── */

static int get_name_from_fd(int fd, char *out, size_t out_len)
{
    socklen_t len = (socklen_t)out_len;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, out, &len) < 0)
        return -1;
    return 0;
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

#if !WG_TUN_DARWIN_CAN_CREATE
/* The iOS SDK has no utun control API: there the Network Extension
 * creates the utun and wg-c takes its fd (wg_tun_darwin_create_from_fd). */
wg_error_t wg_tun_darwin_create(wg_tun_darwin_t **out, const char *name, int mtu)
{
    (void)out;
    (void)name;
    (void)mtu;
    return WG_ERR_TUN;
}
#else
wg_error_t wg_tun_darwin_create(wg_tun_darwin_t **out, const char *name, int mtu)
{
    if (!out || !name)
        return WG_ERR_INVALID_ARGUMENT;

    /* Parse "utunN" → ifIndex=N, "utun" → ifIndex=-1 (auto) */
    int if_index = -1;
    if (strcmp(name, "utun") != 0) {
        if (sscanf(name, "utun%d", &if_index) != 1 || if_index < 0)
            return WG_ERR_INVALID_ARGUMENT;
    }

    /* Create the utun control socket */
    int fd = socket_cloexec(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
        return WG_ERR_TUN;

    /* Resolve the utun control ID */
    struct ctl_info ctl_info;
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name) - 1);

    if (ioctl(fd, CTLIOCGINFO, &ctl_info) < 0) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* Connect to the utun control */
    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = (uint32_t)(if_index + 1); /* 0 = auto-assign */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return WG_ERR_TUN;
    }

    /* Allocate state */
    wg_tun_darwin_t *tun = calloc(1, sizeof(*tun));
    if (!tun) {
        close(fd);
        return WG_ERR_NO_MEMORY;
    }
    tun->tun_fd = fd;
    tun->route_fd = -1;

    wg_error_t err = tun_darwin_init_common(tun);
    if (err != WG_OK) {
        close(fd);
        free(tun);
        return err;
    }

    /* Get interface name */
    if (get_name_from_fd(fd, tun->name, sizeof(tun->name)) < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        close(fd);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Get interface index */
    unsigned int idx = if_nametoindex(tun->name);
    if (idx == 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        close(fd);
        free(tun);
        return WG_ERR_TUN;
    }
    tun->if_index = (int32_t)idx;

    /* Set MTU */
    if (mtu > 0 && set_mtu(tun->name, mtu) < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        close(fd);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Start AF_ROUTE event listener */
    tun->route_fd = socket_cloexec(AF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (tun->route_fd >= 0) {
        if (pthread_create(&tun->route_thread, NULL, route_listener, tun) == 0) {
            tun->route_started = true;
        } else {
            close(tun->route_fd);
            tun->route_fd = -1;
        }
    }
    /* Non-fatal if route socket fails — device still works, just no events */

    *out = tun;
    return WG_OK;
}
#endif /* WG_TUN_DARWIN_CAN_CREATE */

wg_error_t wg_tun_darwin_create_from_fd(wg_tun_darwin_t **out, int fd)
{
    if (!out || fd < 0)
        return WG_ERR_INVALID_ARGUMENT;

    /* Set non-blocking */
    int orig_flags = fcntl(fd, F_GETFL, 0);
    if (orig_flags < 0)
        return WG_ERR_TUN;
    if (!(orig_flags & O_NONBLOCK)) {
        if (fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK) < 0)
            return WG_ERR_TUN;
    }

    wg_tun_darwin_t *tun = calloc(1, sizeof(*tun));
    if (!tun) {
        fcntl(fd, F_SETFL, orig_flags);
        return WG_ERR_NO_MEMORY;
    }

    tun->tun_fd = fd;
    tun->route_fd = -1;

    wg_error_t err = tun_darwin_init_common(tun);
    if (err != WG_OK) {
        fcntl(fd, F_SETFL, orig_flags);
        free(tun);
        return err;
    }

    /* Get interface name from fd */
    if (get_name_from_fd(fd, tun->name, sizeof(tun->name)) < 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        fcntl(fd, F_SETFL, orig_flags);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Get interface index */
    unsigned int idx = if_nametoindex(tun->name);
    if (idx == 0) {
        wg_rwcancel_destroy(tun->rwc);
        pthread_mutex_destroy(&tun->write_mu);
        pthread_mutex_destroy(&tun->read_mu);
        fcntl(fd, F_SETFL, orig_flags);
        free(tun);
        return WG_ERR_TUN;
    }
    tun->if_index = (int32_t)idx;

    /* No route monitoring for inherited FDs */
    *out = tun;
    return WG_OK;
}

int wg_tun_darwin_fd(wg_tun_darwin_t *tun)
{
    return tun ? tun->tun_fd : -1;
}

wg_tun_ops_t wg_tun_darwin_ops(wg_tun_darwin_t *tun)
{
    return (wg_tun_ops_t){
        .read = tun_darwin_read,
        .write = tun_darwin_write,
        .mtu = tun_darwin_mtu,
        .name = tun_darwin_name,
        .batch_size = tun_darwin_batch_size,
        .events = tun_darwin_events,
        .close = tun_darwin_close,
        .cancel = tun_darwin_cancel,
        .ctx = tun,
    };
}

void wg_tun_darwin_destroy(wg_tun_darwin_t *tun)
{
    if (!tun)
        return;

    bool already_closed = atomic_exchange(&tun->closed, true);
    if (already_closed)
        return;

    /* Cancel the TUN fd I/O */
    if (tun->rwc)
        wg_rwcancel_cancel(tun->rwc);

    /* Stop route listener: shutdown unblocks the read() call */
    if (tun->route_fd >= 0)
        shutdown(tun->route_fd, SHUT_RDWR);
    if (tun->route_started)
        pthread_join(tun->route_thread, NULL);
    if (tun->route_fd >= 0)
        close(tun->route_fd);

    /* Clean up TUN */
    if (tun->rwc)
        wg_rwcancel_destroy(tun->rwc);
    if (tun->tun_fd >= 0)
        close(tun->tun_fd);

    pthread_mutex_destroy(&tun->read_mu);
    pthread_mutex_destroy(&tun->write_mu);

    free(tun);
}

#endif /* __APPLE__ */

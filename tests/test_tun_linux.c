/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Test: Linux TUN device implementation.
 *
 * Requires CAP_NET_ADMIN (typically root).
 * Skips gracefully if /dev/net/tun is not accessible.
 */

#ifdef __linux__

#include "wireguard.h"
#include "../src/tun/wg_tun.h"
#include "../src/tun/wg_tun_linux.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void skip(const char *reason)
{
    printf("SKIP: %s\n", reason);
    exit(0);
}

static void check_permissions(void)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM)
            skip("no permission to open /dev/net/tun (need root or CAP_NET_ADMIN)");
        if (errno == ENOENT)
            skip("/dev/net/tun does not exist");
        skip("cannot open /dev/net/tun");
    }

    /* Also check that TUNSETIFF works (requires CAP_NET_ADMIN) */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wgperm0", sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        skip("TUNSETIFF failed (need root or CAP_NET_ADMIN)");
    }
    close(fd);
}

/* ────────────────────────────────────────
 * Test: create, query name/MTU, destroy
 * ──────────────────────────────────────── */
static void test_create_destroy(void)
{
    printf("  test_create_destroy... ");

    wg_tun_linux_t *tun = NULL;
    wg_error_t err = wg_tun_linux_create(&tun, "wgtest0", 1420);
    assert(err == WG_OK);
    assert(tun != NULL);

    wg_tun_ops_t ops = wg_tun_linux_ops(tun);
    assert(wg_tun_ops_valid(&ops));

    /* Check name */
    const char *name = ops.name(ops.ctx);
    assert(name != NULL);
    assert(strcmp(name, "wgtest0") == 0);

    /* Batches when the kernel took IFF_VNET_HDR, one packet otherwise. */
    int batch = ops.batch_size(ops.ctx);
    assert(batch == 1 || batch == 128);

    /* Check MTU */
    int mtu = ops.mtu(ops.ctx);
    assert(mtu == 1420);

    /* Check events (should be empty initially or have UP from netlink) */
    int ev = ops.events(ops.ctx);
    (void)ev; /* events are asynchronous, just verify it doesn't crash */

    /* Close */
    ops.close(ops.ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test: ops valid helper
 * ──────────────────────────────────────── */
static void test_ops_valid(void)
{
    printf("  test_ops_valid... ");

    wg_tun_ops_t empty;
    memset(&empty, 0, sizeof(empty));
    assert(!wg_tun_ops_valid(&empty));
    assert(!wg_tun_ops_valid(NULL));

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test: create from fd
 * ──────────────────────────────────────── */
static void test_create_from_fd(void)
{
    printf("  test_create_from_fd... ");

    /* First create a TUN device the normal way to get an fd */
    int fd = open("/dev/net/tun", O_RDWR);
    assert(fd >= 0);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wgtest1", sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        skip("TUNSETIFF failed");
    }

    wg_tun_linux_t *tun = NULL;
    wg_error_t err = wg_tun_linux_create_from_fd(&tun, fd);
    assert(err == WG_OK);
    assert(tun != NULL);

    wg_tun_ops_t ops = wg_tun_linux_ops(tun);
    const char *name = ops.name(ops.ctx);
    assert(name != NULL);
    assert(strcmp(name, "wgtest1") == 0);
    /* No IFF_VNET_HDR on this fd (as with an Android VpnService fd):
     * plain packets, one at a time. */
    assert(ops.batch_size(ops.ctx) == 1);

    ops.close(ops.ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test: create from an fd opened with IFF_VNET_HDR
 *
 * A daemonised wg-c hands its child such an fd. Reading it as plain
 * packets misreads every packet by the 10-byte virtio header.
 * ──────────────────────────────────────── */
static void test_create_from_fd_vnet_hdr(void)
{
    printf("  test_create_from_fd_vnet_hdr... ");

    int fd = open("/dev/net/tun", O_RDWR);
    assert(fd >= 0);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wgtest2", sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        skip("TUNSETIFF with IFF_VNET_HDR failed");
    }

    wg_tun_linux_t *tun = NULL;
    assert(wg_tun_linux_create_from_fd(&tun, fd) == WG_OK);
    wg_tun_ops_t ops = wg_tun_linux_ops(tun);
    assert(ops.batch_size(ops.ctx) == 128);
    ops.close(ops.ctx);

    printf("OK\n");
}

int main(void)
{
    check_permissions();

    printf("test_tun_linux:\n");
    test_ops_valid();
    test_create_destroy();
    test_create_from_fd();
    test_create_from_fd_vnet_hdr();
    printf("All TUN Linux tests passed.\n");
    return 0;
}

#else /* !__linux__ */

#include <stdio.h>
int main(void)
{
    printf("SKIP: Linux TUN tests only run on Linux\n");
    return 0;
}

#endif /* __linux__ */

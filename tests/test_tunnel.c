/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Runetale Inc.
 *
 * The embedding API (wg_tunnel_*) on a TUN fd opened the way a platform
 * hands one over: plain packets, no virtio header, as from Android's
 * VpnService or an Apple Network Extension. Needs permission to create a
 * TUN device; skips without it.
 */

#include "wireguard.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#elif defined(__APPLE__)
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#define PASS(name) printf("  PASS: %s\n", name)

/* A TUN fd as a platform would pass it, or -1 without permission. */
static int open_platform_tun(void)
{
#if defined(__linux__)
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wgtun%d", sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
#elif defined(__APPLE__)
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
        return -1;
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0)
        goto fail;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; /* the kernel picks utunN */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
#else
    return -1;
#endif
}

static bool fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static void random_key_hex(char hex[65])
{
    uint8_t k[32];
    randombytes_buf(k, sizeof(k));
    sodium_bin2hex(hex, 65, k, sizeof(k));
    sodium_memzero(k, sizeof(k));
}

static void random_pub_hex(char hex[65])
{
    uint8_t priv[32], pub[32];
    randombytes_buf(priv, sizeof(priv));
    crypto_scalarmult_base(pub, priv);
    sodium_bin2hex(hex, 65, pub, sizeof(pub));
    sodium_memzero(priv, sizeof(priv));
}

/* listen_port as the tunnel reports it, 0 if absent. */
static unsigned listen_port(wg_tunnel_t *t)
{
    char *conf = NULL;
    assert(wg_tunnel_get(t, &conf) == WG_OK);
    const char *p = strstr(conf, "listen_port=");
    unsigned port = p ? (unsigned)strtoul(p + strlen("listen_port="), NULL, 10) : 0;
    free(conf);
    return port;
}

static void test_bad_arguments(void)
{
    wg_tunnel_t *t = (wg_tunnel_t *)1;
    assert(wg_tunnel_start(&t, -1, NULL, NULL) == WG_ERR_INVALID_ARGUMENT);
    assert(t == (wg_tunnel_t *)1); /* untouched: nothing to return */
    assert(wg_tunnel_set(NULL, "") == WG_ERR_INVALID_ARGUMENT);
    char *out;
    assert(wg_tunnel_get(NULL, &out) == WG_ERR_INVALID_ARGUMENT);
    assert(wg_tunnel_socket_fd(NULL, AF_INET) == -1);
    wg_tunnel_stop(NULL);
    PASS("bad arguments are refused");
}

/* A start that fails still takes the fd: the caller must not close it. */
static void test_failed_start_closes_fd(void)
{
    int fd = open_platform_tun();
    assert(fd >= 0);
    wg_tunnel_t *t = NULL;
    assert(wg_tunnel_start(&t, fd, "not_a_key=1\n", NULL) != WG_OK);
    assert(t == NULL);
    assert(!fd_is_open(fd));
    PASS("a failed start closes the TUN fd");
}

static void test_lifecycle(void)
{
    char priv[65], peer[65], settings[512];
    random_key_hex(priv);
    random_pub_hex(peer);
    snprintf(settings, sizeof(settings), "private_key=%s\nlisten_port=0\n", priv);

    int fd = open_platform_tun();
    assert(fd >= 0);
    wg_tunnel_t *t = NULL;
    assert(wg_tunnel_start(&t, fd, settings, NULL) == WG_OK);
    assert(t != NULL && wg_tunnel_device(t) != NULL);

    /* The configuration reads back, private key included. */
    char *conf = NULL;
    assert(wg_tunnel_get(t, &conf) == WG_OK);
    char want[80];
    snprintf(want, sizeof(want), "private_key=%s\n", priv);
    assert(strstr(conf, want) != NULL);
    assert(strstr(conf, "listen_port=") != NULL);
    free(conf);

    /* The sockets are open once up; at least one family exists. */
    int fd4 = wg_tunnel_socket_fd(t, AF_INET);
    int fd6 = wg_tunnel_socket_fd(t, AF_INET6);
    assert(fd4 >= 0 || fd6 >= 0);
    assert(wg_tunnel_socket_fd(t, AF_UNIX) == -1);

    /* Reconfigure while running. */
    snprintf(settings, sizeof(settings),
             "public_key=%s\nendpoint=192.0.2.1:51820\nallowed_ip=10.9.0.2/32\n", peer);
    assert(wg_tunnel_set(t, settings) == WG_OK);
    assert(wg_tunnel_get(t, &conf) == WG_OK);
    snprintf(want, sizeof(want), "public_key=%s\n", peer);
    assert(strstr(conf, want) != NULL);
    assert(strstr(conf, "allowed_ip=10.9.0.2/32\n") != NULL);
    free(conf);

    /* A network change: the sockets are reopened on the same port, the
     * one the kernel picked for listen_port=0. */
    unsigned port_before = listen_port(t);
    assert(port_before != 0);
    assert(wg_tunnel_bump_sockets(t) == WG_OK);
    assert(wg_tunnel_socket_fd(t, AF_INET) >= 0 || wg_tunnel_socket_fd(t, AF_INET6) >= 0);
    assert(listen_port(t) == port_before);

    wg_tunnel_disable_roaming(t);
    wg_tunnel_stop(t);
    PASS("start, get, set, bump sockets, stop");
}

int main(void)
{
    printf("=== test_tunnel ===\n");
    assert(wg_init() == WG_OK);
    assert(wg_version() != NULL && strchr(wg_version(), '.') != NULL);

    test_bad_arguments();

    int probe = open_platform_tun();
    if (probe < 0) {
        printf("SKIP: cannot create a TUN device (need root or CAP_NET_ADMIN)\n");
        return 0;
    }
    close(probe);

    test_failed_start_closes_fd();
    test_lifecycle();
    printf("All tunnel tests passed.\n");
    return 0;
}

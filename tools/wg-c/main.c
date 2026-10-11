/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * wg-c: standalone userspace WireGuard daemon.
 *
 * Usage: wg-c [-f/--foreground] <interface-name>
 *
 * Creates a TUN device, opens a real UDP socket (StdNetBind),
 * starts the WireGuard device, and listens on a UAPI unix socket
 * at /var/run/wireguard/<name>.sock for configuration via the `wg` tool.
 *
 * Compatible with wireguard-go command-line interface and IPC protocol.
 * Like wireguard-go, it creates the interface and the UAPI socket, then
 * re-executes itself in the background with both passed as fds 3 and 4
 * and returns, unless -f is given; wg-quick(8) relies on this.
 *
 * Environment variables:
 *   WG_TUN_FD             - Use existing TUN fd instead of creating one
 *   WG_UAPI_FD            - Use existing UAPI socket fd
 *   WG_PROCESS_FOREGROUND - 1: stay in the foreground, as with -f
 *   WG_TUN_NAME_FILE      - macOS: with the name "utun", write the name
 *                           the kernel picked to this file
 *   LOG_LEVEL             - verbose, error, silent (default: error)
 *
 * Reference: wireguard-go/main.go
 */

#if defined(__linux__) || defined(__APPLE__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wireguard.h"
#include "device/wg_device.h"
#include "device/wg_stats.h"
#include "noise/wg_noise.h"
#include "uapi/wg_uapi_server.h"
#include "bind/wg_bind_std.h"

#ifdef __linux__
#include "tun/wg_tun_linux.h"
#endif
#ifdef __APPLE__
#include "tun/wg_tun_darwin.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* ────────────────────────────────────────
 * Globals for signal handling
 * ──────────────────────────────────────── */

static volatile sig_atomic_t g_uapi_server_valid = 0;
static wg_uapi_server_t *g_uapi_server = NULL;
static volatile sig_atomic_t g_stats_requested = 0;
static wg_device_t *g_device = NULL;

static void signal_handler(int sig)
{
    if (sig == SIGUSR1) {
        g_stats_requested = 1;
        return;
    }
    if (g_uapi_server_valid)
        wg_uapi_server_stop(g_uapi_server);
}

/* ────────────────────────────────────────
 * Logger
 * ──────────────────────────────────────── */

static wg_log_level_t g_log_level = WG_LOG_ERROR;

static void logger_fn(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    (void)ctx;
    if (level < g_log_level)
        return;

    const char *prefix = (level == WG_LOG_ERROR) ? "ERROR: " : "";
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s", prefix);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ────────────────────────────────────────
 * UAPI server thread
 * ──────────────────────────────────────── */

static volatile sig_atomic_t g_uapi_done;

static void *uapi_thread(void *arg)
{
    wg_uapi_server_t *srv = arg;
    wg_uapi_server_run(srv);
    g_uapi_done = 1;
    return NULL;
}

/* ────────────────────────────────────────
 * Usage
 * ──────────────────────────────────────── */

/* ────────────────────────────────────────
 * Daemonising (wireguard-go main.go)
 *
 * The parent has created the TUN device and the UAPI socket; it starts a
 * copy of itself with them as fds 3 and 4 (WG_TUN_FD / WG_UAPI_FD) and
 * WG_PROCESS_FOREGROUND=1, then returns, so the interface exists when the
 * command does. stdin is /dev/null; stdout/stderr stay only when
 * LOG_LEVEL asks for output. Everything the child needs before execve is
 * prepared here, because after fork in a threaded process only
 * async-signal-safe calls are allowed.
 * ──────────────────────────────────────── */

static int self_exe_path(char *out, size_t len)
{
#ifdef __linux__
    ssize_t n = readlink("/proc/self/exe", out, len - 1);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return 0;
#else
    char tmp[PATH_MAX];
    uint32_t sz = sizeof(tmp);
    if (_NSGetExecutablePath(tmp, &sz) != 0 || !realpath(tmp, out))
        return -1;
    (void)len;
    return 0;
#endif
}

static int daemonize(char **argv, int tun_fd, int uapi_fd, bool keep_output)
{
    extern char **environ;
    char exe[PATH_MAX];
    if (self_exe_path(exe, sizeof(exe)) != 0) {
        fprintf(stderr, "Failed to determine executable\n");
        return -1;
    }

    /* Environment: ours minus any stale values of the three, plus them. */
    size_t n = 0;
    while (environ[n])
        n++;
    char **envp = calloc(n + 4, sizeof(char *));
    if (!envp)
        return -1;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (strncmp(environ[i], "WG_TUN_FD=", 10) == 0 ||
            strncmp(environ[i], "WG_UAPI_FD=", 11) == 0 ||
            strncmp(environ[i], "WG_PROCESS_FOREGROUND=", 22) == 0)
            continue;
        envp[k++] = environ[i];
    }
    envp[k++] = "WG_TUN_FD=3";
    envp[k++] = "WG_UAPI_FD=4";
    envp[k++] = "WG_PROCESS_FOREGROUND=1";
    envp[k] = NULL;

    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) {
        free(envp);
        return -1;
    }
    /* Move both fds above 4 first, so the dup2s below cannot clobber one
     * with the other. */
    int t = fcntl(tun_fd, F_DUPFD, 10);
    int u = fcntl(uapi_fd, F_DUPFD, 10);
    if (t < 0 || u < 0) {
        close(devnull);
        free(envp);
        return -1;
    }

    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(devnull);
        free(envp);
        return -1;
    }
    if (pid == 0) {
        setsid();
        dup2(devnull, 0);
        if (!keep_output) {
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        dup2(t, 3); /* dup2 clears FD_CLOEXEC on the new fd */
        dup2(u, 4);
        execve(exe, argv, envp);
        _exit(1);
    }
    close(devnull);
    free(envp);
    return 0;
}

static void print_usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s [-f/--foreground] INTERFACE-NAME\n", argv0);
}

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *iface_name = NULL;
    bool foreground = false;

    /* Parse args. */
    if (argc == 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("wg-c v0.1.0\n\n"
                   "Userspace WireGuard daemon (C implementation).\n"
                   "https://github.com/runetale/noisetun\n");
            return 0;
        }
        iface_name = argv[1];
    } else if (argc == 3) {
        if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--foreground") == 0) {
            iface_name = argv[2];
            foreground = true;
        }
    }
    {
        const char *fg = getenv("WG_PROCESS_FOREGROUND");
        if (fg && strcmp(fg, "1") == 0)
            foreground = true;
    }

    if (!iface_name) {
        print_usage(argv[0]);
        return 1;
    }

    /* Log level from environment. */
    const char *log_env = getenv("LOG_LEVEL");
    if (log_env) {
        if (strcmp(log_env, "verbose") == 0 || strcmp(log_env, "debug") == 0)
            g_log_level = WG_LOG_VERBOSE;
        else if (strcmp(log_env, "silent") == 0)
            g_log_level = WG_LOG_SILENT;
        else
            g_log_level = WG_LOG_ERROR;
    }

    wg_logger_t logger = {.log = logger_fn, .ctx = NULL};

    /* Ignore SIGPIPE — write() to a closed pipe/socket should return
     * EPIPE rather than killing the process. */
    signal(SIGPIPE, SIG_IGN);

    /* Initialize noisetun (libsodium + Noise constants). */
    if (wg_init() != WG_OK) {
        fprintf(stderr, "wg_init failed\n");
        return 1;
    }

    wg_error_t err;

    /* ── Create TUN device ── */
    wg_tun_ops_t tun_ops;
    memset(&tun_ops, 0, sizeof(tun_ops));

    const char *tun_fd_str = getenv("WG_TUN_FD");
    if (tun_fd_str) {
        char *endptr;
        long fd_long = strtol(tun_fd_str, &endptr, 10);
        if (*endptr != '\0' || fd_long < 0 || fd_long > INT_MAX) {
            fprintf(stderr, "Invalid WG_TUN_FD: %s\n", tun_fd_str);
            return 1;
        }
        int fd = (int)fd_long;
#ifdef __linux__
        wg_tun_linux_t *tun;
        err = wg_tun_linux_create_from_fd(&tun, fd);
        if (err != WG_OK) {
            fprintf(stderr, "Failed to create TUN from fd %d: %s\n", fd,
                    wg_error_str(err));
            return 1;
        }
        tun_ops = wg_tun_linux_ops(tun);
        (void)tun;
#elif defined(__APPLE__)
        wg_tun_darwin_t *tun;
        err = wg_tun_darwin_create_from_fd(&tun, fd);
        if (err != WG_OK) {
            fprintf(stderr, "Failed to create TUN from fd %d: %s\n", fd,
                    wg_error_str(err));
            return 1;
        }
        tun_ops = wg_tun_darwin_ops(tun);
        (void)tun;
#endif
        /* The name comes from the device, not the command line: a
         * background child started with "utun" must use "utunN" for the
         * UAPI socket and the liveness check (wireguard-go does the same). */
        const char *fd_name = tun_ops.name ? tun_ops.name(tun_ops.ctx) : NULL;
        if (fd_name && fd_name[0])
            iface_name = fd_name;
    } else {
#ifdef __linux__
        wg_tun_linux_t *tun;
        err = wg_tun_linux_create(&tun, iface_name, WG_DEFAULT_MTU);
        if (err != WG_OK) {
            fprintf(stderr, "Failed to create TUN '%s': %s\n", iface_name,
                    wg_error_str(err));
            return 1;
        }
        tun_ops = wg_tun_linux_ops(tun);
        (void)tun;
        /* Update interface name to the actual name assigned. */
        const char *real_name = tun_ops.name(tun_ops.ctx);
        if (real_name)
            iface_name = real_name;
#elif defined(__APPLE__)
        wg_tun_darwin_t *tun;
        err = wg_tun_darwin_create(&tun, iface_name, WG_DEFAULT_MTU);
        if (err != WG_OK) {
            fprintf(stderr, "Failed to create utun '%s': %s\n", iface_name,
                    wg_error_str(err));
            return 1;
        }
        tun_ops = wg_tun_darwin_ops(tun);
        (void)tun;
        const char *real_name = tun_ops.name(tun_ops.ctx);
        /* "utun" lets the kernel pick the unit; tell wg-quick which one
         * (wireguard-go tun_darwin.go). */
        const char *name_file = getenv("WG_TUN_NAME_FILE");
        if (real_name && name_file && name_file[0] && strcmp(iface_name, "utun") == 0) {
            int nf = open(name_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0400);
            if (nf >= 0) {
                dprintf(nf, "%s\n", real_name);
                close(nf);
            }
        }
        if (real_name)
            iface_name = real_name;
#endif

        /* Not in the foreground: hand the TUN device and a fresh UAPI
         * socket to a background copy and return (wireguard-go). */
        if (!foreground) {
#ifdef __linux__
            int tun_fd = wg_tun_linux_fd((wg_tun_linux_t *)tun_ops.ctx);
#else
            int tun_fd = wg_tun_darwin_fd((wg_tun_darwin_t *)tun_ops.ctx);
#endif
            int uapi_fd = wg_uapi_listen(iface_name);
            if (uapi_fd < 0) {
                fprintf(stderr, "Failed to create UAPI socket for '%s'\n", iface_name);
                return 1;
            }
            bool keep_output = getenv("LOG_LEVEL") && g_log_level != WG_LOG_SILENT;
            if (daemonize(argv, tun_fd, uapi_fd, keep_output) != 0) {
                fprintf(stderr, "Failed to daemonize\n");
                return 1;
            }
            /* _exit: no cleanup that would close the device or unlink the
             * socket the child now owns. */
            _exit(0);
        }
    }

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Starting wg-c", iface_name);

    /* ── Create StdNetBind ── */
    wg_std_bind_t *std_bind;
    err = wg_std_bind_new(&std_bind);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create StdNetBind: %s\n", wg_error_str(err));
        tun_ops.close(tun_ops.ctx);
        return 1;
    }
    wg_bind_ops_t bind_ops = wg_std_bind_ops(std_bind);

    /* ── Create WireGuard device ── */
    wg_device_t *dev;
    err = wg_device_new(&dev, &tun_ops, &bind_ops, &logger);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create device: %s\n", wg_error_str(err));
        tun_ops.close(tun_ops.ctx);
        wg_std_bind_destroy(std_bind);
        return 1;
    }

    /* Wire up GRO diagnostic counters to device stats. */
#ifdef __linux__
    wg_tun_linux_set_gro_stats((wg_tun_linux_t *)dev->tun.tun.ctx, &dev->stats);
#endif

    /* Bring device up (starts worker threads). */
    err = wg_device_up(dev);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to bring device up: %s\n", wg_error_str(err));
        wg_device_close(dev);
        wg_std_bind_destroy(std_bind);
        return 1;
    }

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Device started", iface_name);

    /* ── Create UAPI server ── */
    wg_uapi_server_t *uapi_srv;
    const char *uapi_fd_str = getenv("WG_UAPI_FD");
    if (uapi_fd_str) {
        char *endptr;
        long fd_long = strtol(uapi_fd_str, &endptr, 10);
        if (*endptr != '\0' || fd_long < 0 || fd_long > INT_MAX) {
            fprintf(stderr, "Invalid WG_UAPI_FD: %s\n", uapi_fd_str);
            wg_device_close(dev);
            wg_std_bind_destroy(std_bind);
            return 1;
        }
        int fd = (int)fd_long;
        err = wg_uapi_server_create_from_fd(&uapi_srv, dev, fd, iface_name);
    } else {
        err = wg_uapi_server_create(&uapi_srv, dev, iface_name);
    }

    if (err != WG_OK) {
        fprintf(stderr, "Failed to create UAPI server: %s\n", wg_error_str(err));
        wg_device_close(dev);
        wg_std_bind_destroy(std_bind);
        return 1;
    }
    g_uapi_server = uapi_srv;
    g_uapi_server_valid = 1;

    /* Start UAPI accept loop in a thread. */
    pthread_t uapi_tid;
    if (pthread_create(&uapi_tid, NULL, uapi_thread, uapi_srv) != 0) {
        fprintf(stderr, "Failed to start UAPI thread\n");
        wg_uapi_server_destroy(uapi_srv);
        wg_device_close(dev);
        wg_std_bind_destroy(std_bind);
        return 1;
    }

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) UAPI listener started", iface_name);

    /* ── Wait for termination signal ── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) != 0 || sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGUSR1, &sa, NULL) != 0) {
        fprintf(stderr, "Warning: failed to install signal handlers\n");
    }

    g_device = dev;

    /* Poll: check for SIGUSR1 stats dump requests while waiting for
     * the UAPI thread to exit (triggered by SIGTERM/SIGINT). */
    /* WG_STATS_INTERVAL=<seconds>: also dump the stats periodically
     * (Windows has no SIGUSR1). */
    int stats_every = 0;
    if (getenv("WG_STATS_INTERVAL"))
        stats_every = atoi(getenv("WG_STATS_INTERVAL")) * 5; /* in 200 ms ticks */
    int ticks = 0;
    /* Like wireguard-go, shut down when the interface is deleted
     * (`ip link del`, `wg-quick down`, `ifconfig utunN destroy`) or the
     * UAPI socket is removed (`rm /var/run/wireguard/<name>.sock`). */
    char sock_path[PATH_MAX];
    snprintf(sock_path, sizeof(sock_path), "/var/run/wireguard/%s.sock", iface_name);
    while (!g_uapi_done) {
        usleep(200000); /* 200ms */
        struct stat sock_st;
        /* if_nametoindex also returns 0 when it cannot get a socket
         * (EMFILE/ENFILE/ENOBUFS/ENOMEM); that is not "interface gone". */
        errno = 0;
        int if_gone = if_nametoindex(iface_name) == 0 && errno != EMFILE &&
                      errno != ENFILE && errno != ENOBUFS && errno != ENOMEM;
        if (if_gone || stat(sock_path, &sock_st) != 0) {
            logger_fn(NULL, WG_LOG_VERBOSE,
                      "(%s) Interface or UAPI socket gone, shutting down", iface_name);
            wg_uapi_server_stop(uapi_srv);
            break;
        }
        if (stats_every > 0 && ++ticks >= stats_every) {
            ticks = 0;
            g_stats_requested = 1;
        }
        if (g_stats_requested) {
            g_stats_requested = 0;
            fprintf(stderr, "\n(%s) Pipeline Stats (SIGUSR1):\n", iface_name);
            wg_stats_dump(&dev->stats, &dev->net.bind, stderr);
            fprintf(stderr, "\n");
            fflush(stderr); /* redirected stderr is buffered on Windows */
        }
    }
    pthread_join(uapi_tid, NULL);

    /* ── Cleanup ── */
    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Shutting down", iface_name);

    /* Dump final pipeline stats to stderr. */
    fprintf(stderr, "\n(%s) Final Pipeline Stats:\n", iface_name);
    wg_stats_dump(&dev->stats, &dev->net.bind, stderr);
    fprintf(stderr, "\n");

    g_uapi_server_valid = 0;
    g_uapi_server = NULL;
    wg_device_close(dev);
    wg_uapi_server_destroy(uapi_srv);
    wg_std_bind_destroy(std_bind);

    return 0;
}

#elif defined(_WIN32)

/* ════════════════════════════════════════════════════════════════════
 * Windows wg-c daemon
 *
 * Uses Wintun for TUN, RIO for UDP, Named Pipe for UAPI.
 * SetConsoleCtrlHandler for graceful shutdown.
 *
 * Reference: wireguard-go/main_windows.go
 * ════════════════════════════════════════════════════════════════════ */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include "wireguard.h"
#include "device/wg_device.h"
#include "noise/wg_noise.h"
#include "uapi/wg_uapi_server.h"
#include "tun/wg_tun_windows.h"
#include "bind/wg_bind_win.h"
#include "platform/wg_platform.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static wg_uapi_server_t *g_uapi_server = NULL;
static volatile LONG g_uapi_server_valid = 0;
static volatile LONG g_shutdown = 0;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    (void)ctrl_type;
    InterlockedExchange(&g_shutdown, 1);
    if (InterlockedCompareExchange(&g_uapi_server_valid, 0, 1) == 1)
        wg_uapi_server_stop(g_uapi_server);
    return TRUE;
}

static wg_log_level_t g_log_level = WG_LOG_ERROR;

static void logger_fn(void *ctx, wg_log_level_t level, const char *fmt, ...)
{
    (void)ctx;
    if (level < g_log_level)
        return;

    const char *prefix = (level == WG_LOG_VERBOSE) ? "[VERBOSE] "
                         : (level == WG_LOG_ERROR) ? "[ERROR] "
                                                   : "";

    va_list ap;
    va_start(ap, fmt);
    _lock_file(stderr);
    fputs(prefix, stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    _unlock_file(stderr);
    va_end(ap);
}

static void *uapi_thread(void *arg)
{
    wg_uapi_server_t *srv = (wg_uapi_server_t *)arg;
    wg_uapi_server_run(srv);
    return NULL;
}

static void print_usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s [-f/--foreground] INTERFACE-NAME\n", argv0);
}

int main(int argc, char *argv[])
{
    const char *iface_name = NULL;

    if (argc == 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("wg-c v0.1.0 (Windows)\n\n"
                   "Userspace WireGuard daemon (C implementation).\n"
                   "https://github.com/runetale/noisetun\n");
            return 0;
        }
        iface_name = argv[1];
    } else if (argc == 3) {
        if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--foreground") == 0)
            iface_name = argv[2];
    }

    if (!iface_name) {
        print_usage(argv[0]);
        return 1;
    }

    const char *log_env = getenv("LOG_LEVEL");
    if (log_env) {
        if (strcmp(log_env, "verbose") == 0 || strcmp(log_env, "debug") == 0)
            g_log_level = WG_LOG_VERBOSE;
        else if (strcmp(log_env, "silent") == 0)
            g_log_level = WG_LOG_SILENT;
        else
            g_log_level = WG_LOG_ERROR;
    }

    wg_logger_t logger = {.log = logger_fn, .ctx = NULL};

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    /* Initialize noisetun (libsodium + Noise constants). */
    if (wg_init() != WG_OK) {
        fprintf(stderr, "wg_init failed\n");
        return 1;
    }

    wg_error_t err;

    /* ── Create Wintun TUN device ── */
    wg_tun_windows_t *tun;
    err = wg_tun_windows_create(&tun, iface_name, "WireGuard", NULL, WG_DEFAULT_MTU);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create TUN '%s': %s (run as Administrator)\n",
                iface_name, wg_error_str(err));
        return 1;
    }
    wg_tun_ops_t tun_ops = wg_tun_windows_ops(tun);

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Starting wg-c (Windows)", iface_name);

    /* ── Create RIO UDP bind ── */
    wg_win_bind_t *win_bind;
    err = wg_win_bind_create(&win_bind);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create WinRingBind: %s\n", wg_error_str(err));
        tun_ops.close(tun_ops.ctx);
        return 1;
    }
    wg_bind_ops_t bind_ops = wg_win_bind_ops(win_bind);

    /* ── Create WireGuard device ── */
    wg_device_t *dev;
    err = wg_device_new(&dev, &tun_ops, &bind_ops, &logger);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create device: %s\n", wg_error_str(err));
        tun_ops.close(tun_ops.ctx);
        wg_win_bind_destroy(win_bind);
        return 1;
    }

    err = wg_device_up(dev);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to bring device up: %s\n", wg_error_str(err));
        wg_device_close(dev);
        wg_win_bind_destroy(win_bind);
        return 1;
    }

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Device started", iface_name);

    /* ── Create Named Pipe UAPI server ── */
    wg_uapi_server_t *uapi_srv;
    err = wg_uapi_server_create(&uapi_srv, dev, iface_name);
    if (err != WG_OK) {
        fprintf(stderr, "Failed to create UAPI server: %s\n", wg_error_str(err));
        wg_device_close(dev);
        wg_win_bind_destroy(win_bind);
        return 1;
    }
    g_uapi_server = uapi_srv;
    InterlockedExchange(&g_uapi_server_valid, 1);

    pthread_t uapi_tid;
    if (pthread_create(&uapi_tid, NULL, uapi_thread, uapi_srv) != 0) {
        fprintf(stderr, "Failed to start UAPI thread\n");
        wg_uapi_server_destroy(uapi_srv);
        wg_device_close(dev);
        wg_win_bind_destroy(win_bind);
        return 1;
    }

    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) UAPI listener started", iface_name);

    /* ── Wait for shutdown ── */
    /* WG_STATS_INTERVAL=<seconds>: dump the pipeline stats periodically
     * (no SIGUSR1 here). */
    int stats_every = 0;
    if (getenv("WG_STATS_INTERVAL"))
        stats_every = atoi(getenv("WG_STATS_INTERVAL")) * 5; /* 200 ms ticks */
    int ticks = 0;
    while (!g_shutdown) {
        Sleep(200);
        if (stats_every > 0 && ++ticks >= stats_every) {
            ticks = 0;
            fprintf(stderr, "\n(%s) Pipeline Stats:\n", iface_name);
            wg_stats_dump(&dev->stats, &dev->net.bind, stderr);
            fprintf(stderr, "\n");
            fflush(stderr);
        }
    }
    pthread_join(uapi_tid, NULL);

    /* ── Cleanup ── */
    logger_fn(NULL, WG_LOG_VERBOSE, "(%s) Shutting down", iface_name);

    InterlockedExchange(&g_uapi_server_valid, 0);
    g_uapi_server = NULL;
    wg_device_close(dev);
    wg_uapi_server_destroy(uapi_srv);
    wg_win_bind_destroy(win_bind);

    return 0;
}

#else /* Unsupported platform */

#include <stdio.h>

int main(void)
{
    fprintf(stderr, "wg-c is not supported on this platform\n");
    return 1;
}

#endif

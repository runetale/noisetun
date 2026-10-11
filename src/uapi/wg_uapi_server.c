/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * UAPI socket server implementation.
 *
 * Listens on /var/run/wireguard/<name>.sock for IPC connections
 * from wireguard-tools `wg` command (or any compatible client).
 *
 * Protocol (matching wireguard-go IpcHandle):
 *   Client sends "get=1\n\n" → server writes device state, then "errno=0\n\n"
 *   Client sends "set=1\n<config>\n" → server applies config, then "errno=0\n\n"
 *   On error: "errno=<code>\n\n"
 *
 * Reference: wireguard-go/device/uapi.go      IpcHandle()
 *            wireguard-go/ipc/uapi_unix.go     UAPIOpen()
 */

#if defined(__linux__) || defined(__APPLE__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wg_uapi_server.h"
#include "../device/wg_device.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define UAPI_SOCKET_DIR   "/var/run/wireguard"
#define UAPI_GET_BUF_SIZE (64 * 1024)
#define UAPI_SET_BUF_SIZE (64 * 1024)
#define UAPI_LINE_MAX     512
#define UAPI_MAX_REQUESTS 128 /* max operations per connection */

struct wg_uapi_server {
    wg_device_t *dev;
    int listen_fd;
    int cancel_pipe[2]; /* write to [1] to unblock poll */
    char sock_path[256];
    char iface_name[64];
};

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static wg_error_t create_socket_dir(void)
{
    if (mkdir(UAPI_SOCKET_DIR, 0755) != 0 && errno != EEXIST)
        return WG_ERR_BIND;
    return WG_OK;
}

static int create_listening_socket(const char *path)
{
    /* Remove stale socket if it exists. */
    struct stat st;
    if (stat(path, &st) == 0) {
        /* Try connecting to see if it's in use. */
        int test_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (test_fd >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

            if (connect(test_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                /* Socket is in use. */
                close(test_fd);
                return -1;
            }
            close(test_fd);
        }
        /* Not in use — remove stale socket. */
        unlink(path);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    /* Set umask to restrict socket permissions (owner only). */
    mode_t old_umask = umask(0077);
    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);

    if (ret != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 4) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}

/* ────────────────────────────────────────
 * Read a line from the connection fd.
 * Returns length excluding '\n', or -1 on error/EOF.
 * ──────────────────────────────────────── */

static ssize_t read_line(int fd, char *buf, size_t cap)
{
    size_t pos = 0;
    while (pos < cap - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0)
            return -1;
        if (c == '\n') {
            buf[pos] = '\0';
            return (ssize_t)pos;
        }
        buf[pos++] = c;
    }
    /* Buffer full without newline — line too long, protocol error. */
    buf[pos] = '\0';
    return -1;
}

/* ────────────────────────────────────────
 * Read the set config body until empty line.
 * Returns total bytes read, or -1 on error.
 * ──────────────────────────────────────── */

static ssize_t read_set_body(int fd, char *buf, size_t cap)
{
    size_t total = 0;
    char line[UAPI_LINE_MAX];

    for (;;) {
        ssize_t len = read_line(fd, line, sizeof(line));
        if (len < 0)
            return (total > 0) ? (ssize_t)total : -1;

        /* Empty line terminates the config. */
        if (len == 0)
            break;

        /* Append "line\n" to buffer. */
        size_t needed = (size_t)len + 1;
        if (total + needed >= cap)
            break;

        memcpy(buf + total, line, (size_t)len);
        total += (size_t)len;
        buf[total++] = '\n';
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

/* ────────────────────────────────────────
 * Write full buffer to fd.
 * ──────────────────────────────────────── */

static bool write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0)
            return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

/* ────────────────────────────────────────
 * Handle a single IPC connection.
 *
 * Protocol (from wireguard-go IpcHandle):
 *   Loop: read operation line, process, write errno, flush.
 *   "get=1" → read '\n', call uapi_get, write result + "errno=0\n\n"
 *   "set=1" → read config lines, call uapi_set, write "errno=0\n\n"
 * ──────────────────────────────────────── */

static void handle_connection(wg_uapi_server_t *srv, int conn_fd)
{
    char op_line[64];
    int requests = 0;

    for (;;) {
        if (++requests > UAPI_MAX_REQUESTS)
            break;

        ssize_t op_len = read_line(conn_fd, op_line, sizeof(op_line));
        if (op_len <= 0)
            break;

        if (strcmp(op_line, "get=1") == 0) {
            /* Read the expected empty line after "get=1\n". */
            char next_line[4];
            ssize_t nl = read_line(conn_fd, next_line, sizeof(next_line));
            if (nl < 0)
                break;
            if (nl != 0) {
                /* Trailing characters — protocol error. */
                dprintf(conn_fd, "errno=%d\n\n", -EINVAL);
                break;
            }

            /* Perform get. */
            char *buf = malloc(UAPI_GET_BUF_SIZE);
            if (!buf) {
                dprintf(conn_fd, "errno=%d\n\n", -ENOMEM);
                break;
            }

            size_t len = UAPI_GET_BUF_SIZE;
            wg_error_t err = wg_uapi_get(srv->dev, buf, &len);
            if (err != WG_OK && err != WG_ERR_BUFFER_TOO_SMALL) {
                free(buf);
                dprintf(conn_fd, "errno=%d\n\n", -EIO);
                break;
            }

            /*
             * wg_uapi_get appends a trailing "\n" (empty line terminator).
             * The IPC protocol expects data lines followed immediately by
             * "errno=0\n\n" — strip only the final terminator "\n" so
             * the last key=value line keeps its newline.
             */
            if (len > 0 && buf[len - 1] == '\n')
                len--;
            if (len > 0)
                write_all(conn_fd, buf, len);
            free(buf);

            dprintf(conn_fd, "errno=0\n\n");

        } else if (strcmp(op_line, "set=1") == 0) {
            /* Read config body. */
            char *buf = malloc(UAPI_SET_BUF_SIZE);
            if (!buf) {
                dprintf(conn_fd, "errno=%d\n\n", -ENOMEM);
                break;
            }

            ssize_t body_len = read_set_body(conn_fd, buf, UAPI_SET_BUF_SIZE);
            if (body_len < 0) {
                free(buf);
                dprintf(conn_fd, "errno=%d\n\n", -EIO);
                break;
            }

            wg_error_t err = wg_uapi_set(srv->dev, buf, (size_t)body_len);
            free(buf);

            if (err == WG_OK) {
                dprintf(conn_fd, "errno=0\n\n");
            } else {
                int e;
                switch (err) {
                case WG_ERR_INVALID_ARGUMENT:
                    e = -EINVAL;
                    break;
                case WG_ERR_NO_MEMORY:
                    e = -ENOMEM;
                    break;
                case WG_ERR_PEER_NOT_FOUND:
                    e = -ENOENT;
                    break;
                case WG_ERR_MAX_PEERS:
                    e = -ENOSPC;
                    break;
                default:
                    e = -EINVAL;
                    break;
                }
                dprintf(conn_fd, "errno=%d\n\n", e);
            }

        } else {
            /* Unknown operation. */
            break;
        }
    }
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_uapi_server_create(wg_uapi_server_t **out, wg_device_t *dev,
                                 const char *iface_name)
{
    if (!out || !dev || !iface_name)
        return WG_ERR_INVALID_ARGUMENT;

    wg_error_t err = create_socket_dir();
    if (err != WG_OK)
        return err;

    wg_uapi_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv)
        return WG_ERR_NO_MEMORY;

    srv->dev = dev;
    snprintf(srv->iface_name, sizeof(srv->iface_name), "%s", iface_name);
    snprintf(srv->sock_path, sizeof(srv->sock_path), "%s/%s.sock", UAPI_SOCKET_DIR,
             iface_name);

    if (pipe(srv->cancel_pipe) != 0) {
        free(srv);
        return WG_ERR_BIND;
    }

    /* Set cancel_pipe read end to non-blocking. */
    fcntl(srv->cancel_pipe[0], F_SETFL, fcntl(srv->cancel_pipe[0], F_GETFL) | O_NONBLOCK);

    srv->listen_fd = create_listening_socket(srv->sock_path);
    if (srv->listen_fd < 0) {
        close(srv->cancel_pipe[0]);
        close(srv->cancel_pipe[1]);
        free(srv);
        return WG_ERR_BIND;
    }

    *out = srv;
    return WG_OK;
}

int wg_uapi_listen(const char *iface_name)
{
    if (!iface_name || create_socket_dir() != WG_OK)
        return -1;
    char path[sizeof(((wg_uapi_server_t *)0)->sock_path)];
    snprintf(path, sizeof(path), "%s/%s.sock", UAPI_SOCKET_DIR, iface_name);
    return create_listening_socket(path);
}

wg_error_t wg_uapi_server_create_from_fd(wg_uapi_server_t **out, wg_device_t *dev, int fd,
                                         const char *iface_name)
{
    if (!out || !dev || fd < 0 || !iface_name)
        return WG_ERR_INVALID_ARGUMENT;

    wg_uapi_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv)
        return WG_ERR_NO_MEMORY;

    srv->dev = dev;
    srv->listen_fd = fd;
    snprintf(srv->iface_name, sizeof(srv->iface_name), "%s", iface_name);
    snprintf(srv->sock_path, sizeof(srv->sock_path), "%s/%s.sock", UAPI_SOCKET_DIR,
             iface_name);

    if (pipe(srv->cancel_pipe) != 0) {
        free(srv);
        return WG_ERR_BIND;
    }

    fcntl(srv->cancel_pipe[0], F_SETFL, fcntl(srv->cancel_pipe[0], F_GETFL) | O_NONBLOCK);

    *out = srv;
    return WG_OK;
}

wg_error_t wg_uapi_server_run(wg_uapi_server_t *srv)
{
    if (!srv)
        return WG_ERR_INVALID_ARGUMENT;

    struct pollfd fds[2];
    fds[0].fd = srv->listen_fd;
    fds[0].events = POLLIN;
    fds[1].fd = srv->cancel_pipe[0];
    fds[1].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return WG_ERR_BIND;
        }

        /* Cancel pipe signaled? */
        if (fds[1].revents & POLLIN)
            break;

        if (fds[0].revents & POLLIN) {
            int conn = accept(srv->listen_fd, NULL, NULL);
            if (conn < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                break;
            }
            handle_connection(srv, conn);
            close(conn);
        }
    }

    return WG_OK;
}

void wg_uapi_server_stop(wg_uapi_server_t *srv)
{
    if (!srv)
        return;
    /* Write a byte to unblock poll. Safe from signal handlers. */
    char c = 1;
    (void)write(srv->cancel_pipe[1], &c, 1);
}

void wg_uapi_server_destroy(wg_uapi_server_t *srv)
{
    if (!srv)
        return;

    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }

    close(srv->cancel_pipe[0]);
    close(srv->cancel_pipe[1]);

    /* Unlink socket file. */
    if (srv->sock_path[0])
        unlink(srv->sock_path);

    free(srv);
}

#endif /* __linux__ || __APPLE__ */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Windows Named Pipe UAPI server implementation.
 *
 * Listens on \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>
 * for IPC connections from wireguard-tools `wg` command.
 *
 * Protocol is identical to the UNIX socket implementation:
 *   Client sends "get=1\n\n" → server writes device state, then "errno=0\n\n"
 *   Client sends "set=1\n<config>\n" → server applies config, then "errno=0\n\n"
 *
 * Reference: wireguard-go/ipc/uapi_windows.go
 *            wireguard-go/ipc/namedpipe/namedpipe.go
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "wg_uapi_server.h"
#include "../device/wg_device.h"

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UAPI_PIPE_PREFIX     "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\"
#define UAPI_GET_BUF_SIZE    (64 * 1024)
#define UAPI_SET_BUF_SIZE    (64 * 1024)
#define UAPI_LINE_MAX        512
#define UAPI_MAX_REQUESTS    128
#define UAPI_PIPE_BUFSIZE    4096
#define UAPI_READ_TIMEOUT_MS 30000 /* 30 seconds — disconnect hung clients */

struct wg_uapi_server {
    wg_device_t *dev;
    HANDLE pipe_handle;
    HANDLE cancel_event;
    char pipe_path[256];
    char iface_name[64];
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd;
};

/* ────────────────────────────────────────
 * Security descriptor for the named pipe.
 * Only SYSTEM and Administrators have access (matching wireguard-go).
 * SDDL: O:SY D:P(A;;GA;;;SY)(A;;GA;;;BA) S:(ML;;NWNRNX;;;HI)
 * ──────────────────────────────────────── */

static BOOL create_pipe_security(wg_uapi_server_t *srv)
{
    /* Same SDDL as wireguard-go UAPISecurityDescriptor */
    const char *sddl = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1,
                                                              &srv->psd, NULL)) {
        return FALSE;
    }

    srv->sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    srv->sa.lpSecurityDescriptor = srv->psd;
    srv->sa.bInheritHandle = FALSE;
    return TRUE;
}

/* ────────────────────────────────────────
 * Create a named pipe instance.
 * ──────────────────────────────────────── */

static HANDLE create_pipe_instance(wg_uapi_server_t *srv, BOOL first_instance)
{
    DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (first_instance)
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    return CreateNamedPipeA(
        srv->pipe_path, open_mode,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, UAPI_PIPE_BUFSIZE, UAPI_PIPE_BUFSIZE, 0, &srv->sa);
}

/* ────────────────────────────────────────
 * Read a single byte from pipe with timeout.
 * Returns TRUE on success, FALSE on timeout/error.
 * ──────────────────────────────────────── */

static BOOL pipe_read_byte_timeout(HANDLE pipe, char *out, DWORD timeout_ms)
{
    OVERLAPPED ol = {0};
    ol.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent)
        return FALSE;

    DWORD bytes_read = 0;
    BOOL ok = ReadFile(pipe, out, 1, &bytes_read, &ol);
    if (ok) {
        CloseHandle(ol.hEvent);
        return bytes_read == 1;
    }

    if (GetLastError() != ERROR_IO_PENDING) {
        CloseHandle(ol.hEvent);
        return FALSE;
    }

    DWORD wait = WaitForSingleObject(ol.hEvent, timeout_ms);
    if (wait == WAIT_OBJECT_0) {
        ok = GetOverlappedResult(pipe, &ol, &bytes_read, FALSE);
        CloseHandle(ol.hEvent);
        return ok && bytes_read == 1;
    }

    /* Timeout or error — cancel the I/O. */
    CancelIoEx(pipe, &ol);
    GetOverlappedResult(pipe, &ol, &bytes_read, TRUE);
    CloseHandle(ol.hEvent);
    return FALSE;
}

/* ────────────────────────────────────────
 * Read a line from the pipe (byte by byte until '\n').
 * Returns length excluding '\n', or -1 on error/EOF/timeout.
 * ──────────────────────────────────────── */

static int pipe_read_line(HANDLE pipe, char *buf, size_t cap)
{
    size_t pos = 0;
    while (pos < cap - 1) {
        char c;
        if (!pipe_read_byte_timeout(pipe, &c, UAPI_READ_TIMEOUT_MS))
            return -1;
        if (c == '\n') {
            buf[pos] = '\0';
            return (int)pos;
        }
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return -1;
}

/* ────────────────────────────────────────
 * Read set config body until empty line.
 * ──────────────────────────────────────── */

static int pipe_read_set_body(HANDLE pipe, char *buf, size_t cap)
{
    size_t total = 0;
    char line[UAPI_LINE_MAX];

    for (;;) {
        int len = pipe_read_line(pipe, line, sizeof(line));
        if (len < 0)
            return (total > 0) ? (int)total : -1;
        if (len == 0)
            break;

        size_t needed = (size_t)len + 1;
        if (total + needed >= cap)
            break;

        memcpy(buf + total, line, (size_t)len);
        total += (size_t)len;
        buf[total++] = '\n';
    }

    buf[total] = '\0';
    return (int)total;
}

/* ────────────────────────────────────────
 * Write full buffer to pipe.
 * ──────────────────────────────────────── */

static BOOL pipe_write_all(HANDLE pipe, const char *buf, size_t len)
{
    while (len > 0) {
        DWORD written;
        if (!WriteFile(pipe, buf, (DWORD)len, &written, NULL))
            return FALSE;
        buf += written;
        len -= written;
    }
    return TRUE;
}

/* Helper: write a formatted string to pipe */
static BOOL pipe_printf(HANDLE pipe, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return FALSE;
    return pipe_write_all(pipe, buf, (size_t)n);
}

/* ────────────────────────────────────────
 * Handle a single IPC connection on pipe.
 * ──────────────────────────────────────── */

static void handle_connection(wg_uapi_server_t *srv, HANDLE pipe)
{
    char op_line[64];
    int requests = 0;

    for (;;) {
        if (++requests > UAPI_MAX_REQUESTS)
            break;

        int op_len = pipe_read_line(pipe, op_line, sizeof(op_line));
        if (op_len <= 0)
            break;

        if (strcmp(op_line, "get=1") == 0) {
            /* Read expected empty line after "get=1\n". */
            char next_line[4];
            int nl = pipe_read_line(pipe, next_line, sizeof(next_line));
            if (nl < 0)
                break;
            if (nl != 0) {
                pipe_printf(pipe, "errno=%d\n\n", -22 /* EINVAL */);
                break;
            }

            char *buf = (char *)malloc(UAPI_GET_BUF_SIZE);
            if (!buf) {
                pipe_printf(pipe, "errno=%d\n\n", -12 /* ENOMEM */);
                break;
            }

            size_t len = UAPI_GET_BUF_SIZE;
            wg_error_t err = wg_uapi_get(srv->dev, buf, &len);
            if (err != WG_OK && err != WG_ERR_BUFFER_TOO_SMALL) {
                free(buf);
                pipe_printf(pipe, "errno=%d\n\n", -5 /* EIO */);
                break;
            }

            if (len > 0 && buf[len - 1] == '\n')
                len--;
            if (len > 0)
                pipe_write_all(pipe, buf, len);
            free(buf);

            pipe_printf(pipe, "errno=0\n\n");

        } else if (strcmp(op_line, "set=1") == 0) {
            char *buf = (char *)malloc(UAPI_SET_BUF_SIZE);
            if (!buf) {
                pipe_printf(pipe, "errno=%d\n\n", -12 /* ENOMEM */);
                break;
            }

            int body_len = pipe_read_set_body(pipe, buf, UAPI_SET_BUF_SIZE);
            if (body_len < 0) {
                free(buf);
                pipe_printf(pipe, "errno=%d\n\n", -5 /* EIO */);
                break;
            }

            wg_error_t err = wg_uapi_set(srv->dev, buf, (size_t)body_len);
            free(buf);

            if (err == WG_OK) {
                pipe_printf(pipe, "errno=0\n\n");
            } else {
                int e;
                switch (err) {
                case WG_ERR_INVALID_ARGUMENT:
                    e = -22; /* EINVAL */
                    break;
                case WG_ERR_NO_MEMORY:
                    e = -12; /* ENOMEM */
                    break;
                case WG_ERR_PEER_NOT_FOUND:
                    e = -2; /* ENOENT */
                    break;
                case WG_ERR_MAX_PEERS:
                    e = -28; /* ENOSPC */
                    break;
                default:
                    e = -22; /* EINVAL */
                    break;
                }
                pipe_printf(pipe, "errno=%d\n\n", e);
            }

        } else {
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

    wg_uapi_server_t *srv = (wg_uapi_server_t *)calloc(1, sizeof(*srv));
    if (!srv)
        return WG_ERR_NO_MEMORY;

    srv->dev = dev;
    snprintf(srv->iface_name, sizeof(srv->iface_name), "%s", iface_name);
    snprintf(srv->pipe_path, sizeof(srv->pipe_path), "%s%s", UAPI_PIPE_PREFIX,
             iface_name);

    /* Create security descriptor. */
    if (!create_pipe_security(srv)) {
        free(srv);
        return WG_ERR_BIND;
    }

    /* Create cancellation event. */
    srv->cancel_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!srv->cancel_event) {
        LocalFree(srv->psd);
        free(srv);
        return WG_ERR_BIND;
    }

    /* Create the first pipe instance. */
    srv->pipe_handle = create_pipe_instance(srv, TRUE);
    if (srv->pipe_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(srv->cancel_event);
        LocalFree(srv->psd);
        free(srv);
        return WG_ERR_BIND;
    }

    *out = srv;
    return WG_OK;
}

wg_error_t wg_uapi_server_run(wg_uapi_server_t *srv)
{
    if (!srv)
        return WG_ERR_INVALID_ARGUMENT;

    for (;;) {
        /* Use overlapped ConnectNamedPipe so we can cancel via event. */
        OVERLAPPED ol = {0};
        ol.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!ol.hEvent)
            return WG_ERR_BIND;

        BOOL connected = ConnectNamedPipe(srv->pipe_handle, &ol);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* Wait for either a client connection or cancellation. */
                HANDLE events[2] = {ol.hEvent, srv->cancel_event};
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

                if (wait == WAIT_OBJECT_0 + 1) {
                    /* Cancel event signaled — stop. */
                    CancelIo(srv->pipe_handle);
                    CloseHandle(ol.hEvent);
                    break;
                }

                if (wait != WAIT_OBJECT_0) {
                    CloseHandle(ol.hEvent);
                    break;
                }

                /* Check overlapped result. */
                DWORD bytes;
                if (!GetOverlappedResult(srv->pipe_handle, &ol, &bytes, FALSE)) {
                    DWORD result_err = GetLastError();
                    CloseHandle(ol.hEvent);
                    if (result_err == ERROR_PIPE_CONNECTED) {
                        /* Client connected before ConnectNamedPipe — OK. */
                    } else {
                        DisconnectNamedPipe(srv->pipe_handle);
                        continue;
                    }
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                /* Client already connected. */
            } else {
                CloseHandle(ol.hEvent);
                break;
            }
        }

        CloseHandle(ol.hEvent);

        /* Handle the connection. */
        handle_connection(srv, srv->pipe_handle);

        /* Disconnect and reuse the pipe instance. */
        FlushFileBuffers(srv->pipe_handle);
        DisconnectNamedPipe(srv->pipe_handle);
    }

    return WG_OK;
}

void wg_uapi_server_stop(wg_uapi_server_t *srv)
{
    if (!srv)
        return;
    SetEvent(srv->cancel_event);
}

void wg_uapi_server_destroy(wg_uapi_server_t *srv)
{
    if (!srv)
        return;

    if (srv->pipe_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(srv->pipe_handle);
        srv->pipe_handle = INVALID_HANDLE_VALUE;
    }

    if (srv->cancel_event) {
        CloseHandle(srv->cancel_event);
        srv->cancel_event = NULL;
    }

    if (srv->psd) {
        LocalFree(srv->psd);
        srv->psd = NULL;
    }

    free(srv);
}

/* Windows doesn't use create_from_fd — stub for API compatibility. */
wg_error_t wg_uapi_server_create_from_fd(wg_uapi_server_t **out, wg_device_t *dev, int fd,
                                         const char *iface_name)
{
    (void)out;
    (void)dev;
    (void)fd;
    (void)iface_name;
    return WG_ERR_INVALID_ARGUMENT;
}

#endif /* _WIN32 */

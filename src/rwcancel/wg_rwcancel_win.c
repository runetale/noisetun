/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * RWCancel: Windows implementation using Events + overlapped I/O.
 *
 * On Windows, file handles (pipes, sockets, etc.) use overlapped I/O
 * for async operations. We use WaitForMultipleObjects with a cancel
 * event to implement cancellable read/write.
 */

#ifdef _WIN32

#include "wg_rwcancel.h"

#include <stdlib.h>

struct wg_rwcancel {
    HANDLE handle;
    HANDLE cancel_event; /* Manual-reset event, signaled on cancel */
    HANDLE io_event;     /* Auto-reset event for overlapped I/O completion */
};

wg_error_t wg_rwcancel_new(wg_rwcancel_t **out, HANDLE handle)
{
    if (!out || handle == INVALID_HANDLE_VALUE)
        return WG_ERR_INVALID_ARGUMENT;

    wg_rwcancel_t *rwc = (wg_rwcancel_t *)calloc(1, sizeof(*rwc));
    if (!rwc)
        return WG_ERR_NO_MEMORY;

    rwc->handle = handle;

    rwc->cancel_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!rwc->cancel_event) {
        free(rwc);
        return WG_ERR_INVALID_ARGUMENT;
    }

    rwc->io_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!rwc->io_event) {
        CloseHandle(rwc->cancel_event);
        free(rwc);
        return WG_ERR_INVALID_ARGUMENT;
    }

    *out = rwc;
    return WG_OK;
}

ssize_t wg_rwcancel_read(wg_rwcancel_t *rwc, void *buf, size_t len)
{
    OVERLAPPED ol = {0};
    ol.hEvent = rwc->io_event;

    DWORD bytes_read = 0;
    BOOL ok = ReadFile(rwc->handle, buf, (DWORD)len, &bytes_read, &ol);
    if (ok)
        return (ssize_t)bytes_read;

    DWORD err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        return -1;
    }

    /* Wait for either I/O completion or cancellation. */
    HANDLE events[2] = {rwc->io_event, rwc->cancel_event};
    DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

    if (wait == WAIT_OBJECT_0) {
        /* I/O completed. */
        if (!GetOverlappedResult(rwc->handle, &ol, &bytes_read, FALSE))
            return -1;
        return (ssize_t)bytes_read;
    }

    /* Cancelled or error. */
    CancelIoEx(rwc->handle, &ol);
    /* Wait for the cancelled I/O to complete. */
    GetOverlappedResult(rwc->handle, &ol, &bytes_read, TRUE);
    return -1;
}

ssize_t wg_rwcancel_write(wg_rwcancel_t *rwc, const void *buf, size_t len)
{
    OVERLAPPED ol = {0};
    ol.hEvent = rwc->io_event;

    DWORD bytes_written = 0;
    BOOL ok = WriteFile(rwc->handle, buf, (DWORD)len, &bytes_written, &ol);
    if (ok)
        return (ssize_t)bytes_written;

    DWORD err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        return -1;
    }

    HANDLE events[2] = {rwc->io_event, rwc->cancel_event};
    DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

    if (wait == WAIT_OBJECT_0) {
        if (!GetOverlappedResult(rwc->handle, &ol, &bytes_written, FALSE))
            return -1;
        return (ssize_t)bytes_written;
    }

    CancelIoEx(rwc->handle, &ol);
    GetOverlappedResult(rwc->handle, &ol, &bytes_written, TRUE);
    return -1;
}

void wg_rwcancel_cancel(wg_rwcancel_t *rwc)
{
    if (!rwc)
        return;
    SetEvent(rwc->cancel_event);
}

void wg_rwcancel_destroy(wg_rwcancel_t *rwc)
{
    if (!rwc)
        return;

    if (rwc->cancel_event)
        CloseHandle(rwc->cancel_event);
    if (rwc->io_event)
        CloseHandle(rwc->io_event);

    free(rwc);
}

#endif /* _WIN32 */

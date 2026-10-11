/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * RWCancel: cancellable read/write on file descriptors (POSIX) or HANDLEs (Windows).
 *
 * POSIX: Uses a pipe to interrupt blocking reads/writes via kqueue (macOS) or poll().
 * Windows: Uses Events + WaitForMultipleObjects to interrupt blocking I/O.
 *
 * Calling wg_rwcancel_cancel() wakes any blocked read/write.
 *
 * Reference: wireguard-go/rwcancel/rwcancel.go
 */

#ifndef WG_RWCANCEL_H
#define WG_RWCANCEL_H

#include "wg_error.h"

#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

typedef struct wg_rwcancel wg_rwcancel_t;

#ifdef _WIN32

/*
 * Create an RWCancel wrapper for a HANDLE.
 * Does NOT take ownership of the handle.
 */
wg_error_t wg_rwcancel_new(wg_rwcancel_t **out, HANDLE handle);

/*
 * Cancellable read: blocks until handle is readable or cancelled.
 * Returns bytes read, or -1 on cancellation or error.
 */
ssize_t wg_rwcancel_read(wg_rwcancel_t *rwc, void *buf, size_t len);

/*
 * Cancellable write: blocks until handle is writable or cancelled.
 * Returns bytes written, or -1 on cancellation/error.
 */
ssize_t wg_rwcancel_write(wg_rwcancel_t *rwc, const void *buf, size_t len);

#else /* POSIX */

/*
 * Create an RWCancel wrapper for fd.
 * Sets fd to non-blocking. Does NOT take ownership of fd.
 */
wg_error_t wg_rwcancel_new(wg_rwcancel_t **out, int fd);

/*
 * Cancellable read: blocks until fd is readable or cancelled.
 * Returns bytes read, or -1 on cancellation (errno = ECANCELED)
 * or other error.
 */
ssize_t wg_rwcancel_read(wg_rwcancel_t *rwc, void *buf, size_t len);

/*
 * Cancellable write: blocks until fd is writable or cancelled.
 * Returns bytes written, or -1 on cancellation/error.
 */
ssize_t wg_rwcancel_write(wg_rwcancel_t *rwc, const void *buf, size_t len);

#endif /* _WIN32 */

/*
 * Cancel any blocked read/write. Safe to call from any thread.
 */
void wg_rwcancel_cancel(wg_rwcancel_t *rwc);

/*
 * Destroy the RWCancel, closing internal resources.
 * Does NOT close the wrapped fd/handle.
 */
void wg_rwcancel_destroy(wg_rwcancel_t *rwc);

#endif /* WG_RWCANCEL_H */

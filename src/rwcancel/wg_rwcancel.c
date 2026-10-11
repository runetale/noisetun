/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * RWCancel: cancellable read/write on file descriptors.
 *
 * Reference: wireguard-go/rwcancel/rwcancel.go
 */

#ifndef _WIN32 /* POSIX implementation — Windows is in wg_rwcancel_win.c */

#include "wg_rwcancel.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/event.h>
#else
#include <poll.h>
#endif

struct wg_rwcancel {
    int fd;
    int cancel_pipe[2]; /* [0]=read, [1]=write */
#if defined(__APPLE__)
    int kq; /* kqueue fd — registered once, used for all waits */
#endif
};

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

wg_error_t wg_rwcancel_new(wg_rwcancel_t **out, int fd)
{
    wg_rwcancel_t *rwc = calloc(1, sizeof(*rwc));
    if (!rwc)
        return WG_ERR_NO_MEMORY;

    rwc->fd = fd;
    rwc->cancel_pipe[0] = -1;
    rwc->cancel_pipe[1] = -1;
#if defined(__APPLE__)
    rwc->kq = -1;
#endif

    if (set_nonblock(fd) < 0) {
        free(rwc);
        return WG_ERR_INVALID_ARGUMENT;
    }

    if (pipe(rwc->cancel_pipe) < 0) {
        free(rwc);
        return WG_ERR_INVALID_ARGUMENT;
    }

    /* Make the read side non-blocking too. */
    set_nonblock(rwc->cancel_pipe[0]);

#if defined(__APPLE__)
    rwc->kq = kqueue();
    if (rwc->kq < 0) {
        close(rwc->cancel_pipe[0]);
        close(rwc->cancel_pipe[1]);
        free(rwc);
        return WG_ERR_INVALID_ARGUMENT;
    }

    /* Register cancel_pipe[0] for EVFILT_READ once — it never changes. */
    struct kevent ev;
    EV_SET(&ev, rwc->cancel_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(rwc->kq, &ev, 1, NULL, 0, NULL);
#endif

    *out = rwc;
    return WG_OK;
}

#if defined(__APPLE__)
/*
 * kqueue-based readiness wait (macOS).
 * Registers fd for the requested filter (EVFILT_READ or EVFILT_WRITE)
 * using EV_ADD|EV_ONESHOT so it auto-deregisters after firing.
 * cancel_pipe[0] is always registered (persistent EVFILT_READ).
 */
static bool ready_kqueue(wg_rwcancel_t *rwc, int16_t filter)
{
    /* Add fd with ONESHOT — auto-removed after one event. */
    struct kevent change;
    EV_SET(&change, rwc->fd, filter, EV_ADD | EV_ONESHOT, 0, 0, NULL);

    struct kevent events[2];
    for (;;) {
        int n = kevent(rwc->kq, &change, 1, events, 2, NULL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        /* After first call, no more changes needed — clear changelist
         * for subsequent iterations (EINTR retry). */
        change.flags = 0;

        for (int i = 0; i < n; i++) {
            if ((int)events[i].ident == rwc->cancel_pipe[0])
                return false; /* cancelled */
            if ((int)events[i].ident == rwc->fd)
                return true; /* fd ready */
        }
    }
}
#else
/*
 * poll()-based readiness wait (Linux / other POSIX).
 */
static bool ready_read(wg_rwcancel_t *rwc)
{
    struct pollfd fds[2];
    fds[0].fd = rwc->fd;
    fds[0].events = POLLIN;
    fds[1].fd = rwc->cancel_pipe[0];
    fds[1].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (fds[1].revents & POLLIN)
            return false; /* cancelled */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR))
            return true;
    }
}

static bool ready_write(wg_rwcancel_t *rwc)
{
    struct pollfd fds[2];
    fds[0].fd = rwc->fd;
    fds[0].events = POLLOUT;
    fds[1].fd = rwc->cancel_pipe[0];
    fds[1].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (fds[1].revents & POLLIN)
            return false; /* cancelled */
        if (fds[0].revents & (POLLOUT | POLLHUP | POLLERR))
            return true;
    }
}
#endif /* __APPLE__ */

ssize_t wg_rwcancel_read(wg_rwcancel_t *rwc, void *buf, size_t len)
{
    for (;;) {
        ssize_t n = read(rwc->fd, buf, len);
        if (n >= 0)
            return n;

        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;

        /* EAGAIN: wait for readiness or cancel. */
#if defined(__APPLE__)
        if (!ready_kqueue(rwc, EVFILT_READ)) {
#else
        if (!ready_read(rwc)) {
#endif
            errno = ECANCELED;
            return -1;
        }
    }
}

ssize_t wg_rwcancel_write(wg_rwcancel_t *rwc, const void *buf, size_t len)
{
    for (;;) {
        ssize_t n = write(rwc->fd, buf, len);
        if (n >= 0)
            return n;

        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;

#if defined(__APPLE__)
        if (!ready_kqueue(rwc, EVFILT_WRITE)) {
#else
        if (!ready_write(rwc)) {
#endif
            errno = ECANCELED;
            return -1;
        }
    }
}

void wg_rwcancel_cancel(wg_rwcancel_t *rwc)
{
    if (!rwc)
        return;

    /* Write a single byte to wake kevent()/poll(). Ignore errors
     * (pipe may already have data, or be closed). */
    char c = 0;
    (void)write(rwc->cancel_pipe[1], &c, 1);
}

void wg_rwcancel_destroy(wg_rwcancel_t *rwc)
{
    if (!rwc)
        return;

#if defined(__APPLE__)
    if (rwc->kq >= 0)
        close(rwc->kq);
#endif

    if (rwc->cancel_pipe[0] >= 0)
        close(rwc->cancel_pipe[0]);
    if (rwc->cancel_pipe[1] >= 0)
        close(rwc->cancel_pipe[1]);

    free(rwc);
}

#endif /* !_WIN32 */

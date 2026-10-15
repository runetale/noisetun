/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Platform abstraction: threading and network headers.
 * Include this instead of <pthread.h> / <netinet/in.h> directly.
 */

#ifndef WG_PLATFORM_H
#define WG_PLATFORM_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <synchapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <errno.h>

/* ────────────────────────────────────────
 * pthread_mutex_t → CRITICAL_SECTION
 * ──────────────────────────────────────── */
typedef CRITICAL_SECTION pthread_mutex_t;

static inline int pthread_mutex_init(pthread_mutex_t *m, const void *attr)
{
    (void)attr;
    InitializeCriticalSection(m);
    return 0;
}
static inline int pthread_mutex_destroy(pthread_mutex_t *m)
{
    DeleteCriticalSection(m);
    return 0;
}
static inline int pthread_mutex_lock(pthread_mutex_t *m)
{
    EnterCriticalSection(m);
    return 0;
}
static inline int pthread_mutex_trylock(pthread_mutex_t *m)
{
    return TryEnterCriticalSection(m) ? 0 : EBUSY;
}
static inline int pthread_mutex_unlock(pthread_mutex_t *m)
{
    LeaveCriticalSection(m);
    return 0;
}

/* ────────────────────────────────────────
 * pthread_rwlock_t → SRWLOCK + tracking bit
 *
 * SRWLOCK doesn't have a unified unlock; we track
 * whether the lock was acquired shared or exclusive
 * using a per-lock flag (safe because write is exclusive).
 * ──────────────────────────────────────── */
typedef struct {
    SRWLOCK srw;
    volatile LONG exclusive;
} pthread_rwlock_t;

static inline int pthread_rwlock_init(pthread_rwlock_t *rw, const void *attr)
{
    (void)attr;
    InitializeSRWLock(&rw->srw);
    rw->exclusive = 0;
    return 0;
}
static inline int pthread_rwlock_destroy(pthread_rwlock_t *rw)
{
    (void)rw;
    return 0;
}
static inline int pthread_rwlock_rdlock(pthread_rwlock_t *rw)
{
    AcquireSRWLockShared(&rw->srw);
    return 0;
}
static inline int pthread_rwlock_wrlock(pthread_rwlock_t *rw)
{
    AcquireSRWLockExclusive(&rw->srw);
    InterlockedExchange(&rw->exclusive, 1);
    return 0;
}
static inline int pthread_rwlock_tryrdlock(pthread_rwlock_t *rw)
{
    return TryAcquireSRWLockShared(&rw->srw) ? 0 : EBUSY;
}
static inline int pthread_rwlock_trywrlock(pthread_rwlock_t *rw)
{
    if (!TryAcquireSRWLockExclusive(&rw->srw))
        return EBUSY;
    InterlockedExchange(&rw->exclusive, 1);
    return 0;
}
static inline int pthread_rwlock_unlock(pthread_rwlock_t *rw)
{
    if (InterlockedExchange(&rw->exclusive, 0)) {
        ReleaseSRWLockExclusive(&rw->srw);
    } else {
        ReleaseSRWLockShared(&rw->srw);
    }
    return 0;
}

/* ────────────────────────────────────────
 * pthread_cond_t → CONDITION_VARIABLE
 * ──────────────────────────────────────── */
typedef CONDITION_VARIABLE pthread_cond_t;

static inline int pthread_cond_init(pthread_cond_t *c, const void *attr)
{
    (void)attr;
    InitializeConditionVariable(c);
    return 0;
}
static inline int pthread_cond_destroy(pthread_cond_t *c)
{
    (void)c;
    return 0;
}
static inline int pthread_cond_signal(pthread_cond_t *c)
{
    WakeConditionVariable(c);
    return 0;
}
static inline int pthread_cond_broadcast(pthread_cond_t *c)
{
    WakeAllConditionVariable(c);
    return 0;
}
static inline int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
    SleepConditionVariableCS(c, m, INFINITE);
    return 0;
}

/* ────────────────────────────────────────
 * pthread_t → HANDLE
 * ──────────────────────────────────────── */
/* pthread_once → InitOnceExecuteOnce */
typedef INIT_ONCE pthread_once_t;
#define PTHREAD_ONCE_INIT INIT_ONCE_STATIC_INIT

struct wg_once_arg {
    void (*fn)(void);
};

static BOOL CALLBACK wg_once_thunk(PINIT_ONCE once, PVOID arg, PVOID *ctx)
{
    (void)once;
    (void)ctx;
    ((struct wg_once_arg *)arg)->fn();
    return TRUE;
}

static inline int pthread_once(pthread_once_t *once, void (*fn)(void))
{
    struct wg_once_arg arg = {fn};
    return InitOnceExecuteOnce(once, wg_once_thunk, &arg, NULL) ? 0 : -1;
}

typedef HANDLE pthread_t;

typedef struct {
    void *(*start_routine)(void *);
    void *arg;
} wg_thread_trampoline_t;

static inline DWORD WINAPI wg_thread_trampoline(LPVOID param)
{
    wg_thread_trampoline_t *t = (wg_thread_trampoline_t *)param;
    void *(*fn)(void *) = t->start_routine;
    void *arg = t->arg;
    free(t);
    fn(arg);
    return 0;
}

static inline int pthread_create(pthread_t *thread, const void *attr,
                                 void *(*start_routine)(void *), void *arg)
{
    (void)attr;
    wg_thread_trampoline_t *t = (wg_thread_trampoline_t *)malloc(sizeof(*t));
    if (!t)
        return ENOMEM;
    t->start_routine = start_routine;
    t->arg = arg;
    *thread = CreateThread(NULL, 0, wg_thread_trampoline, t, 0, NULL);
    if (*thread == NULL) {
        free(t);
        return EAGAIN;
    }
    return 0;
}

static inline int pthread_join(pthread_t thread, void **retval)
{
    (void)retval;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

/* ────────────────────────────────────────
 * POSIX compatibility shims
 * ──────────────────────────────────────── */
#include <io.h>
#include <process.h>

/* MSVC has no __builtin_clz and needs one written out. GCC and clang have
 * it as a builtin, and a static function by that name is a redeclaration
 * they refuse — which is how a mingw build stops before it starts. clang-cl
 * is both: it defines _MSC_VER and has the builtin, so it goes with clang. */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
static inline int __builtin_clz(unsigned int x)
{
    unsigned long idx;
    _BitScanReverse(&idx, x);
    return 31 - (int)idx;
}
#endif

#define sched_yield() SwitchToThread()

/* ────────────────────────────────────────
 * clock_gettime shim
 *
 * mingw-w64 declares clock_gettime and the clock ids itself, so this is for
 * the toolchains that do not: defining them again is a redefinition the
 * compiler stops on.
 * ──────────────────────────────────────── */
#include <time.h>

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#if defined(_MSC_VER) && !defined(__clang__)
static inline int clock_gettime(int clk_id, struct timespec *tp)
{
    (void)clk_id;
    LARGE_INTEGER freq, count;
    if (clk_id == CLOCK_MONOTONIC) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);
        tp->tv_sec = (long long)(count.QuadPart / freq.QuadPart);
        tp->tv_nsec =
            (long)(((count.QuadPart % freq.QuadPart) * 1000000000LL) / freq.QuadPart);
    } else {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        /* FILETIME is 100ns intervals since 1601-01-01 */
        /* Unix epoch offset: 11644473600 seconds */
        uli.QuadPart -= 116444736000000000ULL;
        tp->tv_sec = (long long)(uli.QuadPart / 10000000ULL);
        tp->tv_nsec = (long)((uli.QuadPart % 10000000ULL) * 100);
    }
    return 0;
}

/* Millisecond resolution is enough for the callers (tests, back-off). */
static inline int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)rem;
    DWORD ms = (DWORD)(req->tv_sec * 1000 + (req->tv_nsec + 999999) / 1000000);
    Sleep(ms);
    return 0;
}
#endif /* _MSC_VER */

#define usleep(us) Sleep((us) / 1000)
#define sleep(s)   Sleep((s) * 1000)

static inline int wg_get_nprocs(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}
#define sysconf(x)           wg_get_nprocs()
#define _SC_NPROCESSORS_ONLN 0

static inline int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    *memptr = _aligned_malloc(size, alignment);
    return (*memptr) ? 0 : ENOMEM;
}

/* _aligned_malloc memory must be released with _aligned_free, not free. */
static inline void wg_aligned_free(void *ptr)
{
    _aligned_free(ptr);
}

/* pthread_cond_timedwait with absolute timeout */
static inline int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                                         const struct timespec *abstime)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long ms = (abstime->tv_sec - now.tv_sec) * 1000LL +
                   (abstime->tv_nsec - now.tv_nsec) / 1000000LL;
    if (ms <= 0)
        ms = 0;
    if (!SleepConditionVariableCS(c, m, (DWORD)ms))
        return (GetLastError() == ERROR_TIMEOUT) ? ETIMEDOUT : -1;
    return 0;
}

/* pthread_condattr (no-op on Windows, clock is always monotonic) */
typedef int pthread_condattr_t;
static inline int pthread_condattr_init(pthread_condattr_t *a)
{
    (void)a;
    return 0;
}
static inline int pthread_condattr_destroy(pthread_condattr_t *a)
{
    (void)a;
    return 0;
}
static inline int pthread_condattr_setclock(pthread_condattr_t *a, int c)
{
    (void)a;
    (void)c;
    return 0;
}

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

/* ────────────────────────────────────────
 * Network headers (already included above via winsock2/ws2tcpip)
 * ──────────────────────────────────────── */

#else /* POSIX */

#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

/* Whether pthread_condattr_setclock(CLOCK_MONOTONIC) does what it says.
 * ESP-IDF returns 0 from it and still measures every timed wait against
 * gettimeofday(), so a caller must not take its word and should give
 * deadlines on CLOCK_REALTIME there. */
#ifdef ESP_PLATFORM
#define WG_CONDATTR_SETCLOCK_WORKS 0
#else
#define WG_CONDATTR_SETCLOCK_WORKS 1
#endif

/* Frees memory from posix_memalign; the Windows shim needs _aligned_free. */
static inline void wg_aligned_free(void *ptr)
{
    free(ptr);
}

/* os_sync_wait_on_address (the macOS futex) ships in the macOS 14.4 SDK.
 * Older SDKs build the sched_yield()/pipe fallbacks only; newer ones
 * still check the running OS with __builtin_available. */
#ifdef __APPLE__
#if __has_include(<os/os_sync_wait_on_address.h>)
#include <os/os_sync_wait_on_address.h>
#define WG_HAVE_OS_SYNC 1
/* Whether the running OS has it. Every Apple OS must be named: "*" would
 * count the others as having it since their deployment target, so an iOS
 * build would call it on iOS 15. */
#define WG_OS_SYNC_AVAILABLE() \
    __builtin_available(macOS 14.4, iOS 17.4, tvOS 17.4, watchOS 10.4, visionOS 1.1, *)
#endif
#endif
#ifndef WG_HAVE_OS_SYNC
#define WG_HAVE_OS_SYNC 0
#endif

#endif /* _WIN32 */

#endif /* WG_PLATFORM_H */

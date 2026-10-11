/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Signal side of the sequential send/recv thread wake-up, shared by the
 * crypto workers (wg_send.c, wg_receive.c) and peer removal
 * (wg_device.c). Kept out of wg_workers.h because syscall() needs
 * _GNU_SOURCE/_DEFAULT_SOURCE, which not every includer has.
 */

#ifndef WG_SEQ_WAKE_H
#define WG_SEQ_WAKE_H

#include "platform/wg_platform.h"
#include <stdatomic.h>
#include <stdint.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <sched.h>
#endif

/* Wake a sequential thread sleeping on word (dev->seq_wake_send or
 * seq_wake_recv; waiting is its _waiting flag). The one copy of the
 * signal side of seq_wake_*_wait() in wg_send.c / wg_receive.c.
 *
 * Linux: Dekker with the waiter: we store the word then load the flag,
 * it stores the flag then loads the word, so at least one side sees the
 * other. Skipping FUTEX_WAKE while nobody sleeps removes a syscall per
 * crypto batch. Other platforms besides Windows poll with sched_yield()
 * and need no signal. */
static inline void wg_seq_wake_signal(_Atomic uint32_t *word, _Atomic uint32_t *waiting)
{
#if defined(__linux__)
    atomic_store_explicit(word, 1, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
    if (atomic_load_explicit(waiting, memory_order_relaxed))
        syscall(SYS_futex, word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
#elif defined(_WIN32)
    (void)waiting;
    atomic_store_explicit(word, 1, memory_order_release);
    WakeByAddressSingle((PVOID)word);
#elif defined(__APPLE__)
    /* macOS 14.4 has a futex: os_sync_wait_on_address. Same Dekker as
     * Linux. Before 14.4 the waiter polls with sched_yield() and needs
     * no signal. */
    atomic_store_explicit(word, 1, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
#if WG_HAVE_OS_SYNC
    if (atomic_load_explicit(waiting, memory_order_relaxed)) {
        if (WG_OS_SYNC_AVAILABLE())
            os_sync_wake_by_address_any(word, sizeof(*word),
                                        OS_SYNC_WAKE_BY_ADDRESS_NONE);
    }
#else
    (void)waiting;
#endif
#else
    (void)word;
    (void)waiting;
#endif
}

#endif /* WG_SEQ_WAKE_H */

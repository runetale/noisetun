/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Windows TUN device implementation using Wintun.
 *
 * Wintun uses a ring-buffer based interface:
 * - WintunAllocateSendPacket / WintunSendPacket for outbound
 * - WintunReceivePacket / WintunReleaseReceivePacket for inbound
 *
 * The read event (WintunGetReadWaitEvent) is signaled when packets arrive.
 * We use this with WaitForMultipleObjects for cancellable reads.
 *
 * Reference: wireguard-go/tun/tun_windows.go
 *            https://git.zx2c4.com/wintun/about/
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "wg_tun_windows.h"

#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

/* ────────────────────────────────────────
 * Wintun API types and function pointers
 * (loaded dynamically from wintun.dll)
 * ──────────────────────────────────────── */

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

/* Wintun ring capacity: must be power of 2, between 128KB and 64MB.
 * 8 MB matches wireguard-go's 0x800000 for sufficient buffering. */
#define WINTUN_RING_CAPACITY (8 * 1024 * 1024) /* 8 MB */

/* Spin iterations before blocking on WaitForMultipleObjects.
 * Similar to wireguard-go's rate juggling — avoids context switch overhead
 * during high-throughput bursts. */
#define TUN_READ_SPINS 512

/* Wintun function signatures. */
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
    const WCHAR *Name, const WCHAR *TunnelType, const GUID *RequestedGUID);
typedef void(WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session,
                                                   DWORD *PacketSize);
typedef void(WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session,
                                                         const BYTE *Packet);
typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session,
                                                         DWORD PacketSize);
typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session,
                                              const BYTE *Packet);
typedef void(WINAPI *WINTUN_DELETE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef DWORD(WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE Adapter,
                                                    void *Luid);

/* All loaded Wintun function pointers. */
typedef struct {
    HMODULE dll;
    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter;
    WINTUN_DELETE_ADAPTER_FUNC DeleteAdapter;
    WINTUN_START_SESSION_FUNC StartSession;
    WINTUN_END_SESSION_FUNC EndSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket;
    WINTUN_SEND_PACKET_FUNC SendPacket;
    WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLUID;
} wintun_api_t;

struct wg_tun_windows {
    wintun_api_t api;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE read_event;   /* Wintun read wait event */
    HANDLE cancel_event; /* Manual-reset, signaled on close */
    int mtu;
    char name[128];
    atomic_int events;
    atomic_int closed;
};

/* ────────────────────────────────────────
 * Wintun DLL loading
 * ──────────────────────────────────────── */

static BOOL load_wintun(wintun_api_t *api)
{
    api->dll = LoadLibraryA("wintun.dll");
    if (!api->dll)
        return FALSE;

#define LOAD_FUNC(field, type, dllname)                   \
    api->field = (type)GetProcAddress(api->dll, dllname); \
    if (!api->field) {                                    \
        FreeLibrary(api->dll);                            \
        api->dll = NULL;                                  \
        return FALSE;                                     \
    }

    LOAD_FUNC(CreateAdapter, WINTUN_CREATE_ADAPTER_FUNC, "WintunCreateAdapter")
    LOAD_FUNC(CloseAdapter, WINTUN_CLOSE_ADAPTER_FUNC, "WintunCloseAdapter")
    LOAD_FUNC(StartSession, WINTUN_START_SESSION_FUNC, "WintunStartSession")
    LOAD_FUNC(EndSession, WINTUN_END_SESSION_FUNC, "WintunEndSession")
    LOAD_FUNC(GetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC, "WintunGetReadWaitEvent")
    LOAD_FUNC(ReceivePacket, WINTUN_RECEIVE_PACKET_FUNC, "WintunReceivePacket")
    LOAD_FUNC(ReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC,
              "WintunReleaseReceivePacket")
    LOAD_FUNC(AllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC,
              "WintunAllocateSendPacket")
    LOAD_FUNC(SendPacket, WINTUN_SEND_PACKET_FUNC, "WintunSendPacket")

#undef LOAD_FUNC

    /* Optional functions — not fatal if missing. */
    api->DeleteAdapter =
        (WINTUN_DELETE_ADAPTER_FUNC)GetProcAddress(api->dll, "WintunDeleteAdapter");
    api->GetAdapterLUID =
        (WINTUN_GET_ADAPTER_LUID_FUNC)GetProcAddress(api->dll, "WintunGetAdapterLUID");

    return TRUE;
}

/* ────────────────────────────────────────
 * wg_tun_ops_t callbacks
 * ──────────────────────────────────────── */

static int tun_read(void *ctx, uint8_t **bufs, int *sizes, int count, int offset)
{
    wg_tun_windows_t *tun = (wg_tun_windows_t *)ctx;
    int n = 0;

    for (int i = 0; i < count; i++) {
    retry:
        if (atomic_load(&tun->closed))
            return n > 0 ? n : -1;

        DWORD pkt_size = 0;
        BYTE *pkt = tun->api.ReceivePacket(tun->session, &pkt_size);

        if (!pkt) {
            if (n > 0)
                break; /* Return what we have so far. */

            /* Spin phase: try repeatedly before blocking (rate juggling).
             * Avoids context switch overhead during high-throughput bursts.
             * ~128 iterations ≈ sub-microsecond on modern x86_64. */
            for (int spin = 0; spin < TUN_READ_SPINS; spin++) {
                if (atomic_load(&tun->closed))
                    return -1;
                YieldProcessor();
                pkt = tun->api.ReceivePacket(tun->session, &pkt_size);
                if (pkt)
                    goto got_packet;
            }

            /* Block phase: wait for Wintun signal or cancellation. */
            HANDLE events[2] = {tun->read_event, tun->cancel_event};
            DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait != WAIT_OBJECT_0) {
                return n > 0 ? n : -1; /* Cancelled or error. */
            }

            pkt = tun->api.ReceivePacket(tun->session, &pkt_size);
            if (!pkt)
                goto retry; /* Spurious wake — retry wait. */
        }

    got_packet:
        /* Copy packet to caller's buffer. */
        if (pkt_size > 0 && bufs[i]) {
            memcpy(bufs[i] + offset, pkt, pkt_size);
            sizes[i] = (int)pkt_size;
        }

        tun->api.ReleaseReceivePacket(tun->session, pkt);
        n++;
    }

    return n;
}

static int tun_write(void *ctx, uint8_t **bufs, const int *sizes, int count, int offset)
{
    wg_tun_windows_t *tun = (wg_tun_windows_t *)ctx;
    int n = 0;

    for (int i = 0; i < count; i++) {
        if (sizes[i] <= offset)
            continue;

        DWORD pkt_len = (DWORD)(sizes[i] - offset);
        BYTE *ip_data = (BYTE *)(bufs[i] + offset);

        /* WireGuard pads plaintext to 16-byte boundary. Wintun requires the
         * exact IP packet length, so trim using the IP header's length field
         * (same approach as wireguard-nt's PacketConsumeDataDone). */
        if (pkt_len >= 20 && (ip_data[0] >> 4) == 4) {
            DWORD ip_total = ((DWORD)ip_data[2] << 8) | (DWORD)ip_data[3];
            if (ip_total >= 20 && ip_total <= pkt_len)
                pkt_len = ip_total;
        } else if (pkt_len >= 40 && (ip_data[0] >> 4) == 6) {
            DWORD ip6_payload = ((DWORD)ip_data[4] << 8) | (DWORD)ip_data[5];
            DWORD ip6_total = ip6_payload + 40;
            if (ip6_total <= pkt_len)
                pkt_len = ip6_total;
        }

        BYTE *pkt = tun->api.AllocateSendPacket(tun->session, pkt_len);
        if (!pkt)
            break; /* Ring full — stop. */

        memcpy(pkt, ip_data, pkt_len);
        tun->api.SendPacket(tun->session, pkt);
        n++;
    }

    return n;
}

static int tun_mtu(void *ctx)
{
    wg_tun_windows_t *tun = (wg_tun_windows_t *)ctx;
    return tun->mtu;
}

static const char *tun_name(void *ctx)
{
    wg_tun_windows_t *tun = (wg_tun_windows_t *)ctx;
    return tun->name;
}

static int tun_batch_size(void *ctx)
{
    (void)ctx;
    /* Wintun supports batching via repeated ReceivePacket/AllocateSendPacket. */
    return 16;
}

static int tun_events(void *ctx)
{
    wg_tun_windows_t *tun = (wg_tun_windows_t *)ctx;
    return atomic_exchange(&tun->events, 0);
}

static void tun_close(void *ctx)
{
    wg_tun_windows_destroy((wg_tun_windows_t *)ctx);
}

/* Wake a reader blocked in WaitForMultipleObjects; frees nothing. The
 * cancel event is manual-reset, so it stays signalled for later reads. */
static void tun_cancel(void *ctx)
{
    wg_tun_windows_t *tun = ctx;
    if (tun->cancel_event)
        SetEvent(tun->cancel_event);
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_tun_windows_create(wg_tun_windows_t **out, const char *name,
                                 const char *tunnel_type, const char *guid, int mtu)
{
    if (!out || !name || !tunnel_type)
        return WG_ERR_INVALID_ARGUMENT;

    wg_tun_windows_t *tun = (wg_tun_windows_t *)calloc(1, sizeof(*tun));
    if (!tun)
        return WG_ERR_NO_MEMORY;

    tun->mtu = mtu > 0 ? mtu : 1420;
    snprintf(tun->name, sizeof(tun->name), "%s", name);

    /* Load wintun.dll. */
    if (!load_wintun(&tun->api)) {
        free(tun);
        return WG_ERR_TUN;
    }

    /* Convert name and tunnel_type to wide strings. */
    WCHAR wname[128], wtype[128];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 128);
    MultiByteToWideChar(CP_UTF8, 0, tunnel_type, -1, wtype, 128);

    /* Parse GUID if provided. */
    GUID adapter_guid = {0};
    GUID *pguid = NULL;
    if (guid) {
        WCHAR wguid[64];
        MultiByteToWideChar(CP_UTF8, 0, guid, -1, wguid, 64);
        if (CLSIDFromString(wguid, &adapter_guid) == S_OK)
            pguid = &adapter_guid;
    }

    /* Create adapter. */
    tun->adapter = tun->api.CreateAdapter(wname, wtype, pguid);
    if (!tun->adapter) {
        FreeLibrary(tun->api.dll);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Start session. */
    tun->session = tun->api.StartSession(tun->adapter, WINTUN_RING_CAPACITY);
    if (!tun->session) {
        tun->api.CloseAdapter(tun->adapter);
        FreeLibrary(tun->api.dll);
        free(tun);
        return WG_ERR_TUN;
    }

    /* Get read wait event (owned by Wintun, do not close). */
    tun->read_event = tun->api.GetReadWaitEvent(tun->session);

    /* Create cancel event. */
    tun->cancel_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!tun->cancel_event) {
        tun->api.EndSession(tun->session);
        tun->api.CloseAdapter(tun->adapter);
        FreeLibrary(tun->api.dll);
        free(tun);
        return WG_ERR_TUN;
    }

    atomic_store(&tun->events, WG_TUN_EVENT_UP);
    atomic_store(&tun->closed, 0);

    *out = tun;
    return WG_OK;
}

wg_tun_ops_t wg_tun_windows_ops(wg_tun_windows_t *tun)
{
    wg_tun_ops_t ops = {0};
    if (tun) {
        ops.read = tun_read;
        ops.write = tun_write;
        ops.mtu = tun_mtu;
        ops.name = tun_name;
        ops.batch_size = tun_batch_size;
        ops.events = tun_events;
        ops.close = tun_close;
        ops.cancel = tun_cancel;
        ops.ctx = tun;
    }
    return ops;
}

void wg_tun_windows_destroy(wg_tun_windows_t *tun)
{
    if (!tun)
        return;

    if (atomic_exchange(&tun->closed, 1))
        return; /* Already closed. */

    /* Signal cancel to unblock any waiting read. */
    if (tun->cancel_event)
        SetEvent(tun->cancel_event);

    if (tun->session) {
        tun->api.EndSession(tun->session);
        tun->session = NULL;
    }

    if (tun->adapter) {
        tun->api.CloseAdapter(tun->adapter);
        tun->adapter = NULL;
    }

    if (tun->cancel_event) {
        CloseHandle(tun->cancel_event);
        tun->cancel_event = NULL;
    }

    if (tun->api.dll) {
        FreeLibrary(tun->api.dll);
        tun->api.dll = NULL;
    }

    free(tun);
}

int wg_tun_windows_get_luid(wg_tun_windows_t *tun, void *luid, size_t luid_size)
{
    if (!tun || !luid || luid_size < 8)
        return -1;

    if (!tun->api.GetAdapterLUID || !tun->adapter)
        return -1;

    /* NET_LUID is 8 bytes (a ULONG64). */
    tun->api.GetAdapterLUID(tun->adapter, luid);
    return 0;
}

#endif /* _WIN32 */

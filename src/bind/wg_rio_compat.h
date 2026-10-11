/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Registered I/O declarations for toolchains whose headers lack them.
 *
 * The Windows SDK declares RIO in <mswsock.h>; MinGW-w64's headers do not.
 * These follow the SDK's documented layout (the same one wireguard-go's
 * conn/winrio uses) and are only compiled in when the SDK's are missing.
 */

#ifndef WG_RIO_COMPAT_H
#define WG_RIO_COMPAT_H

#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>

#ifndef RIO_INVALID_BUFFERID

typedef struct RIO_BUFFERID_t *RIO_BUFFERID, **PRIO_BUFFERID;
typedef struct RIO_CQ_t *RIO_CQ, **PRIO_CQ;
typedef struct RIO_RQ_t *RIO_RQ, **PRIO_RQ;

#define RIO_INVALID_BUFFERID ((RIO_BUFFERID)(ULONG_PTR)0xFFFFFFFF)
#define RIO_INVALID_CQ       ((RIO_CQ)0)
#define RIO_INVALID_RQ       ((RIO_RQ)0)
#define RIO_CORRUPT_CQ       0xFFFFFFFF
#define RIO_MAX_CQ_SIZE      0x8000000

#define RIO_MSG_DONT_NOTIFY 0x00000001
#define RIO_MSG_DEFER       0x00000002
#define RIO_MSG_WAIT_ALL    0x00000004
#define RIO_MSG_COMMIT_ONLY 0x00000008

typedef struct _RIO_BUF {
    RIO_BUFFERID BufferId;
    ULONG Offset;
    ULONG Length;
} RIO_BUF, *PRIO_BUF;

typedef struct _RIORESULT {
    LONG Status;
    ULONG BytesTransferred;
    ULONGLONG SocketContext;
    ULONGLONG RequestContext;
} RIORESULT, *PRIORESULT;

typedef enum _RIO_NOTIFICATION_COMPLETION_TYPE {
    RIO_EVENT_COMPLETION = 1,
    RIO_IOCP_COMPLETION = 2,
} RIO_NOTIFICATION_COMPLETION_TYPE,
    *PRIO_NOTIFICATION_COMPLETION_TYPE;

typedef struct _RIO_NOTIFICATION_COMPLETION {
    RIO_NOTIFICATION_COMPLETION_TYPE Type;
    union {
        struct {
            HANDLE EventHandle;
            BOOL NotifyReset;
        } Event;
        struct {
            HANDLE IocpHandle;
            PVOID CompletionKey;
            PVOID Overlapped;
        } Iocp;
    };
} RIO_NOTIFICATION_COMPLETION, *PRIO_NOTIFICATION_COMPLETION;

typedef BOOL(WINAPI *LPFN_RIORECEIVE)(RIO_RQ, PRIO_BUF, ULONG, DWORD, PVOID);
typedef int(WINAPI *LPFN_RIORECEIVEEX)(RIO_RQ, PRIO_BUF, ULONG, PRIO_BUF, PRIO_BUF,
                                       PRIO_BUF, PRIO_BUF, DWORD, PVOID);
typedef BOOL(WINAPI *LPFN_RIOSEND)(RIO_RQ, PRIO_BUF, ULONG, DWORD, PVOID);
typedef BOOL(WINAPI *LPFN_RIOSENDEX)(RIO_RQ, PRIO_BUF, ULONG, PRIO_BUF, PRIO_BUF,
                                     PRIO_BUF, PRIO_BUF, DWORD, PVOID);
typedef VOID(WINAPI *LPFN_RIOCLOSECOMPLETIONQUEUE)(RIO_CQ);
typedef RIO_CQ(WINAPI *LPFN_RIOCREATECOMPLETIONQUEUE)(DWORD,
                                                      PRIO_NOTIFICATION_COMPLETION);
typedef RIO_RQ(WINAPI *LPFN_RIOCREATEREQUESTQUEUE)(SOCKET, ULONG, ULONG, ULONG, ULONG,
                                                   RIO_CQ, RIO_CQ, PVOID);
typedef ULONG(WINAPI *LPFN_RIODEQUEUECOMPLETION)(RIO_CQ, PRIORESULT, ULONG);
typedef VOID(WINAPI *LPFN_RIODEREGISTERBUFFER)(RIO_BUFFERID);
typedef INT(WINAPI *LPFN_RIONOTIFY)(RIO_CQ);
typedef RIO_BUFFERID(WINAPI *LPFN_RIOREGISTERBUFFER)(PCHAR, DWORD);
typedef BOOL(WINAPI *LPFN_RIORESIZECOMPLETIONQUEUE)(RIO_CQ, DWORD);
typedef BOOL(WINAPI *LPFN_RIORESIZEREQUESTQUEUE)(RIO_RQ, DWORD, DWORD);

/* Filled in by WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
 * WSAID_MULTIPLE_RIO); the order is fixed by the SDK. */
typedef struct _RIO_EXTENSION_FUNCTION_TABLE {
    DWORD cbSize;
    LPFN_RIORECEIVE RIOReceive;
    LPFN_RIORECEIVEEX RIOReceiveEx;
    LPFN_RIOSEND RIOSend;
    LPFN_RIOSENDEX RIOSendEx;
    LPFN_RIOCLOSECOMPLETIONQUEUE RIOCloseCompletionQueue;
    LPFN_RIOCREATECOMPLETIONQUEUE RIOCreateCompletionQueue;
    LPFN_RIOCREATEREQUESTQUEUE RIOCreateRequestQueue;
    LPFN_RIODEQUEUECOMPLETION RIODequeueCompletion;
    LPFN_RIODEREGISTERBUFFER RIODeregisterBuffer;
    LPFN_RIONOTIFY RIONotify;
    LPFN_RIOREGISTERBUFFER RIORegisterBuffer;
    LPFN_RIORESIZECOMPLETIONQUEUE RIOResizeCompletionQueue;
    LPFN_RIORESIZEREQUESTQUEUE RIOResizeRequestQueue;
} RIO_EXTENSION_FUNCTION_TABLE, *PRIO_EXTENSION_FUNCTION_TABLE;

#endif /* RIO_INVALID_BUFFERID */

#ifndef SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER _WSAIORW(IOC_WS2, 36)
#endif

#endif /* WG_RIO_COMPAT_H */

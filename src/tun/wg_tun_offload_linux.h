/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * GRO/GSO offload for Linux TUN with IFF_VNET_HDR.
 *
 * When IFF_VNET_HDR is enabled on a TUN device, each packet is prefixed
 * with a 12-byte virtio_net_hdr that carries checksum and segmentation
 * offload metadata.
 *
 * GRO (write path): coalesce small TCP/UDP segments into large packets
 * before writing to TUN, reducing per-packet overhead.
 *
 * GSO (read path): the kernel may deliver large (up to 64K) coalesced
 * packets from the TUN; we split them into MTU-sized segments before
 * encryption.
 *
 * Reference: wireguard-go/tun/offload_linux.go
 */

#ifndef WG_TUN_OFFLOAD_LINUX_H
#define WG_TUN_OFFLOAD_LINUX_H

#ifdef __linux__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ────────────────────────────────────────
 * virtio_net_hdr (12 bytes)
 * ──────────────────────────────────────── */

#define WG_VIRTIO_NET_HDR_LEN 10

typedef struct {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    /* Followed by the packet data */
} __attribute__((packed)) wg_virtio_net_hdr_t;

_Static_assert(sizeof(wg_virtio_net_hdr_t) == WG_VIRTIO_NET_HDR_LEN,
               "virtio_net_hdr must be 10 bytes");

/* virtio_net_hdr flags */
#define WG_VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define WG_VIRTIO_NET_HDR_F_DATA_VALID 2

/* virtio_net_hdr GSO types */
#define WG_VIRTIO_NET_HDR_GSO_NONE   0
#define WG_VIRTIO_NET_HDR_GSO_TCPV4  1
#define WG_VIRTIO_NET_HDR_GSO_UDP    3
#define WG_VIRTIO_NET_HDR_GSO_TCPV6  4
#define WG_VIRTIO_NET_HDR_GSO_UDP_L4 5
#define WG_VIRTIO_NET_HDR_GSO_ECN    0x80

/* TUN offload flags (for TUNSETOFFLOAD ioctl) */
#define WG_TUN_F_CSUM    0x01
#define WG_TUN_F_TSO4    0x02
#define WG_TUN_F_TSO6    0x04
#define WG_TUN_F_TSO_ECN 0x80
#define WG_TUN_F_USO4    0x20
#define WG_TUN_F_USO6    0x40

/* ────────────────────────────────────────
 * TCP/IP constants
 * ──────────────────────────────────────── */

#define WG_IP_HEADER_MIN_LEN  20
#define WG_IP6_HEADER_LEN     40
#define WG_TCP_HEADER_MIN_LEN 20
#define WG_UDP_HEADER_LEN     8

/* TCP flags byte offset within TCP header */
#define WG_TCP_FLAGS_OFFSET 13

/* TCP flag bits */
#define WG_TCP_FLAG_FIN 0x01
#define WG_TCP_FLAG_SYN 0x02
#define WG_TCP_FLAG_RST 0x04
#define WG_TCP_FLAG_PSH 0x08
#define WG_TCP_FLAG_ACK 0x10

/* ────────────────────────────────────────
 * GRO table
 *
 * Accumulates coalesced packets during a single write batch.
 * ──────────────────────────────────────── */

#define WG_GRO_MAX_ITEMS 128

/* A single coalesced item (represents one or more merged segments). */
typedef struct {
    int buf_idx;       /* index into bufs[] array */
    size_t buf_offset; /* start of packet data (after virtio hdr) */
    size_t buf_len;    /* total length of coalesced packet */

    uint8_t ip_hdr_len;  /* 20 for IPv4, 40 for IPv6 */
    uint8_t tcp_hdr_len; /* TCP header length (data offset * 4) */
    uint16_t gso_size;   /* segment size for GSO */

    uint32_t sent_seq;   /* TCP: initial sequence number */
    uint16_t num_merged; /* number of additional segments merged */

    bool psh_set;      /* TCP PSH flag seen */
    bool is_v6;        /* true if IPv6 */
    bool csum_invalid; /* UDP: checksum known invalid */
} wg_gro_item_t;

/* Flow key for TCP coalescing. */
typedef struct {
    uint8_t src_addr[16]; /* 4 or 16 bytes used */
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t rx_ack; /* TCP ACK value */
    bool is_v6;
} wg_tcp_flow_key_t;

/* Flow key for UDP coalescing. */
typedef struct {
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    bool is_v6;
} wg_udp_flow_key_t;

/* GRO table: one per protocol, cleared after each write batch. */
typedef struct {
    wg_gro_item_t items[WG_GRO_MAX_ITEMS];
    int count;
    /* Flow keys parallel to items for lookup. */
    wg_tcp_flow_key_t keys[WG_GRO_MAX_ITEMS];
} wg_tcp_gro_table_t;

typedef struct {
    wg_gro_item_t items[WG_GRO_MAX_ITEMS];
    int count;
    wg_udp_flow_key_t keys[WG_GRO_MAX_ITEMS];
} wg_udp_gro_table_t;

/* ────────────────────────────────────────
 * Partial checksum completion (NEEDS_CSUM)
 *
 * When the kernel delivers a non-GSO packet with NEEDS_CSUM,
 * the checksum field contains only the pseudo-header sum.
 * This function computes and stores the full checksum.
 * ──────────────────────────────────────── */
void wg_complete_partial_checksum(uint8_t *pkt, size_t pkt_len, uint16_t csum_start,
                                  uint16_t csum_offset);

/* ────────────────────────────────────────
 * GRO: coalesce packets before writing to TUN
 *
 * Called on the TUN write path (after decryption).
 * Processes bufs[0..count-1] at offset, populates to_write[] with
 * the indices of buffers to actually write.
 *
 * Returns the number of entries in to_write.
 * ──────────────────────────────────────── */
/* Forward declare stats for GRO diagnostics (may be NULL). */
struct wg_stats_t_tag;
typedef struct wg_stats_t_tag wg_stats_fwd_t;

int wg_handle_gro(uint8_t **bufs, int *sizes, int count, int offset,
                  wg_tcp_gro_table_t *tcp_table, wg_udp_gro_table_t *udp_table,
                  int *to_write, void *stats);

/* ────────────────────────────────────────
 * GSO split: split a coalesced packet from TUN read
 *
 * When the kernel delivers a large packet via GRO/GSO, split it
 * into MTU-sized segments for encryption.
 *
 * Input: single packet in `in` with virtio_net_hdr.
 * Output: segments written to bufs[] starting at offset.
 * Returns the number of segments produced, or -1 on error.
 * ──────────────────────────────────────── */
int wg_gso_split(const uint8_t *in, size_t in_len, const wg_virtio_net_hdr_t *hdr,
                 uint8_t **bufs, int *sizes, int count, int offset);

/* ────────────────────────────────────────
 * Checksum utilities
 * ──────────────────────────────────────── */
uint16_t wg_ip_checksum(const uint8_t *data, size_t len);
uint16_t wg_pseudo_header_checksum(uint8_t protocol, const uint8_t *src_addr,
                                   const uint8_t *dst_addr, int addr_len,
                                   uint16_t total_len);
uint16_t wg_transport_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                               const uint8_t *transport, size_t transport_len, bool is_v6,
                               uint8_t protocol);

#endif /* __linux__ */
#endif /* WG_TUN_OFFLOAD_LINUX_H */

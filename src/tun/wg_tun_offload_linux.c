/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * GRO/GSO offload for Linux TUN with IFF_VNET_HDR.
 *
 * Reference: wireguard-go/tun/offload_linux.go
 *            wireguard-go/tun/checksum.go
 */

#ifdef __linux__

#include "wg_tun_offload_linux.h"
#include "../device/wg_stats.h"

#include <arpa/inet.h>
#include <string.h>

/* ────────────────────────────────────────
 * Checksum utilities
 * ──────────────────────────────────────── */

/* Compute ones-complement sum over `len` bytes, with no folding. */
static uint32_t checksum_no_fold(const uint8_t *data, size_t len, uint32_t initial)
{
    uint32_t sum = initial;
    while (len > 1) {
        uint16_t w = ((uint16_t)data[0] << 8) | data[1];
        sum += w;
        data += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint16_t)data[0] << 8;
    return sum;
}

static uint16_t fold_checksum(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t wg_ip_checksum(const uint8_t *data, size_t len)
{
    return fold_checksum(checksum_no_fold(data, len, 0));
}

uint16_t wg_pseudo_header_checksum(uint8_t protocol, const uint8_t *src_addr,
                                   const uint8_t *dst_addr, int addr_len,
                                   uint16_t total_len)
{
    uint32_t sum = 0;
    sum = checksum_no_fold(src_addr, (size_t)addr_len, sum);
    sum = checksum_no_fold(dst_addr, (size_t)addr_len, sum);
    sum += (uint32_t)protocol;
    sum += (uint32_t)total_len;
    return fold_checksum(sum);
}

uint16_t wg_transport_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                               const uint8_t *transport, size_t transport_len, bool is_v6,
                               uint8_t protocol)
{
    const uint8_t *src_addr, *dst_addr;
    int addr_len;

    if (is_v6) {
        src_addr = ip_hdr + 8;
        dst_addr = ip_hdr + 24;
        addr_len = 16;
    } else {
        src_addr = ip_hdr + 12;
        dst_addr = ip_hdr + 16;
        addr_len = 4;
    }

    uint32_t sum = 0;
    sum = checksum_no_fold(src_addr, (size_t)addr_len, sum);
    sum = checksum_no_fold(dst_addr, (size_t)addr_len, sum);
    sum += (uint32_t)protocol;
    sum += (uint32_t)transport_len;
    sum = checksum_no_fold(transport, transport_len, sum);
    return fold_checksum(sum);

    (void)ip_hdr_len;
}

/* ────────────────────────────────────────
 * Packet classification helpers
 * ──────────────────────────────────────── */

/* IP protocol numbers */
#define IPPROTO_TCP_NUM 6
#define IPPROTO_UDP_NUM 17

/* Extract IP header length. Returns 0 on error. */
static int get_ip_hdr_len(const uint8_t *pkt, size_t pkt_len, bool *is_v6_out,
                          uint8_t *proto_out, size_t *ip_payload_len_out)
{
    if (pkt_len < 1)
        return 0;

    uint8_t version = (pkt[0] >> 4) & 0x0F;

    if (version == 4) {
        if (pkt_len < WG_IP_HEADER_MIN_LEN)
            return 0;
        int ihl = (pkt[0] & 0x0F) * 4;
        if (ihl < WG_IP_HEADER_MIN_LEN || (size_t)ihl > pkt_len)
            return 0;

        /* Check for fragmentation — reject fragments. */
        uint16_t frag_off = ((uint16_t)pkt[6] << 8) | pkt[7];
        if (frag_off & 0x3FFF) /* MF flag or fragment offset != 0 */
            return 0;

        uint16_t total_len = ((uint16_t)pkt[2] << 8) | pkt[3];
        if (total_len > pkt_len)
            return 0;

        *is_v6_out = false;
        *proto_out = pkt[9];
        *ip_payload_len_out = (size_t)total_len - (size_t)ihl;
        return ihl;
    }

    if (version == 6) {
        if (pkt_len < WG_IP6_HEADER_LEN)
            return 0;
        uint16_t payload_len = ((uint16_t)pkt[4] << 8) | pkt[5];

        *is_v6_out = true;
        *proto_out = pkt[6]; /* next header */
        *ip_payload_len_out = (size_t)payload_len;
        return WG_IP6_HEADER_LEN;
    }

    return 0;
}

/* ────────────────────────────────────────
 * Partial checksum completion (NEEDS_CSUM)
 *
 * When virtio_net_hdr.flags has NEEDS_CSUM, the transport checksum field
 * contains only the pseudo-header sum.  We fold in the data checksum to
 * produce the final value.
 *
 * Reference: wireguard-go/tun/offload_linux.go gsoNoneChecksum
 * ──────────────────────────────────────── */

void wg_complete_partial_checksum(uint8_t *pkt, size_t pkt_len, uint16_t csum_start,
                                  uint16_t csum_offset)
{
    size_t csum_at = (size_t)csum_start + (size_t)csum_offset;
    if (csum_at + 2 > pkt_len || (size_t)csum_start > pkt_len)
        return;

    /* Read the initial value (pseudo-header checksum placed by kernel). */
    uint16_t initial = ((uint16_t)pkt[csum_at] << 8) | pkt[csum_at + 1];

    /* Zero the checksum field before computing. */
    pkt[csum_at] = 0;
    pkt[csum_at + 1] = 0;

    /* Compute checksum over the data from csum_start to end of packet,
     * seeded with the pseudo-header checksum. */
    uint32_t sum = (uint32_t)initial;
    const uint8_t *data = pkt + csum_start;
    size_t len = pkt_len - (size_t)csum_start;

    while (len > 1) {
        uint16_t w = ((uint16_t)data[0] << 8) | data[1];
        sum += w;
        data += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint16_t)data[0] << 8;

    /* Fold and complement. */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t result = (uint16_t)~sum;

    /* Store in network byte order. */
    pkt[csum_at] = (uint8_t)(result >> 8);
    pkt[csum_at + 1] = (uint8_t)(result & 0xFF);
}

/* ────────────────────────────────────────
 * GSO split: split coalesced packet into segments
 *
 * Reference: wireguard-go/tun/offload_linux.go gsoSplit
 * ──────────────────────────────────────── */

int wg_gso_split(const uint8_t *in, size_t in_len, const wg_virtio_net_hdr_t *hdr,
                 uint8_t **bufs, int *sizes, int count, int offset)
{
    if (hdr->gso_type == WG_VIRTIO_NET_HDR_GSO_NONE || hdr->gso_size == 0) {
        /* Not a GSO packet — copy as-is. */
        if (count < 1 || in_len == 0)
            return 0;
        memcpy(bufs[0] + offset, in, in_len);
        sizes[0] = (int)in_len;
        return 1;
    }

    bool is_v6;
    uint8_t proto;
    size_t ip_payload_len;
    int ip_hdr_len = get_ip_hdr_len(in, in_len, &is_v6, &proto, &ip_payload_len);
    if (ip_hdr_len == 0)
        return -1;

    int transport_hdr_len;
    if (proto == IPPROTO_TCP_NUM) {
        if (ip_payload_len < WG_TCP_HEADER_MIN_LEN)
            return -1;
        const uint8_t *tcp = in + ip_hdr_len;
        transport_hdr_len = ((tcp[12] >> 4) & 0x0F) * 4;
        if (transport_hdr_len < WG_TCP_HEADER_MIN_LEN)
            return -1;
    } else if (proto == IPPROTO_UDP_NUM) {
        transport_hdr_len = WG_UDP_HEADER_LEN;
    } else {
        return -1; /* unsupported protocol for GSO */
    }

    int hdr_total = ip_hdr_len + transport_hdr_len;
    if ((size_t)hdr_total >= in_len)
        return -1;

    const uint8_t *payload = in + hdr_total;
    size_t payload_len = in_len - (size_t)hdr_total;
    uint16_t gso_size = hdr->gso_size; /* host byte order */

    if (gso_size == 0)
        return -1;

    int num_segs = 0;
    size_t payload_off = 0;

    /* For TCP: track sequence number for each segment. */
    uint32_t tcp_seq = 0;
    if (proto == IPPROTO_TCP_NUM) {
        const uint8_t *tcp = in + ip_hdr_len;
        tcp_seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                  ((uint32_t)tcp[6] << 8) | tcp[7];
    }

    while (payload_off < payload_len && num_segs < count) {
        size_t seg_payload = payload_len - payload_off;
        if (seg_payload > gso_size)
            seg_payload = gso_size;

        size_t seg_total = (size_t)hdr_total + seg_payload;
        uint8_t *out = bufs[num_segs] + offset;

        /* Copy headers. */
        memcpy(out, in, (size_t)hdr_total);

        /* Copy segment payload. */
        memcpy(out + hdr_total, payload + payload_off, seg_payload);

        /* Update IP total length. */
        if (is_v6) {
            uint16_t pl = htons((uint16_t)(transport_hdr_len + seg_payload));
            memcpy(out + 4, &pl, 2);
        } else {
            uint16_t tl = htons((uint16_t)seg_total);
            memcpy(out + 2, &tl, 2);

            /* Update IPv4 ID field (increment per segment). */
            if (num_segs > 0) {
                uint16_t id;
                memcpy(&id, out + 4, 2);
                id = htons(ntohs(id) + (uint16_t)num_segs);
                memcpy(out + 4, &id, 2);
            }

            /* Recalculate IPv4 header checksum. */
            out[10] = 0;
            out[11] = 0;
            uint16_t csum = wg_ip_checksum(out, (size_t)ip_hdr_len);
            out[10] = (uint8_t)(csum >> 8);
            out[11] = (uint8_t)(csum & 0xFF);
        }

        /* Update TCP sequence number. */
        if (proto == IPPROTO_TCP_NUM) {
            uint8_t *tcp = out + ip_hdr_len;
            uint32_t seq = htonl(tcp_seq + (uint32_t)payload_off);
            memcpy(tcp + 4, &seq, 4);

            /* Clear PSH/FIN flags on non-final segments. */
            if (payload_off + seg_payload < payload_len) {
                tcp[WG_TCP_FLAGS_OFFSET] &= (uint8_t)~(WG_TCP_FLAG_PSH | WG_TCP_FLAG_FIN);
            }

            /* Zero TCP checksum — the receiver's GRO will set NEEDS_CSUM
             * so the kernel computes the final checksum on TUN write.
             * This saves expensive per-segment checksum computation
             * on the sender's TUN reader hot path. */
            tcp[16] = 0;
            tcp[17] = 0;
        }

        /* Update UDP length (skip checksum — receiver handles via NEEDS_CSUM). */
        if (proto == IPPROTO_UDP_NUM) {
            uint8_t *udp = out + ip_hdr_len;
            uint16_t ulen = htons((uint16_t)(WG_UDP_HEADER_LEN + seg_payload));
            memcpy(udp + 4, &ulen, 2);

            udp[6] = 0;
            udp[7] = 0;
        }

        sizes[num_segs] = (int)seg_total;
        num_segs++;
        payload_off += seg_payload;
    }

    return num_segs;
}

/* ────────────────────────────────────────
 * GRO: coalesce packets before writing to TUN
 *
 * TCP flow matching: same src/dst addr+port and ACK value.
 * Contiguous TCP sequence numbers → append payload.
 *
 * For now, implement a simplified version that focuses on TCP
 * coalescing which gives the main throughput benefit.
 *
 * Reference: wireguard-go/tun/offload_linux.go handleGRO
 * ──────────────────────────────────────── */

static bool tcp_flow_eq(const wg_tcp_flow_key_t *a, const wg_tcp_flow_key_t *b)
{
    if (a->is_v6 != b->is_v6 || a->src_port != b->src_port ||
        a->dst_port != b->dst_port || a->rx_ack != b->rx_ack)
        return false;

    int addr_len = a->is_v6 ? 16 : 4;
    return memcmp(a->src_addr, b->src_addr, (size_t)addr_len) == 0 &&
           memcmp(a->dst_addr, b->dst_addr, (size_t)addr_len) == 0;
}

/* Build a TCP flow key from a packet. Returns false if not a valid TCP packet. */
static bool build_tcp_flow_key(const uint8_t *pkt, size_t pkt_len, wg_tcp_flow_key_t *key,
                               int *ip_hdr_len_out, int *tcp_hdr_len_out,
                               size_t *payload_len_out, uint32_t *seq_out, bool *psh_out)
{
    bool is_v6;
    uint8_t proto;
    size_t ip_payload_len;
    int ip_hdr_len = get_ip_hdr_len(pkt, pkt_len, &is_v6, &proto, &ip_payload_len);
    if (ip_hdr_len == 0 || proto != IPPROTO_TCP_NUM)
        return false;

    if (ip_payload_len < WG_TCP_HEADER_MIN_LEN)
        return false;

    const uint8_t *tcp = pkt + ip_hdr_len;
    int tcp_hdr_len = ((tcp[12] >> 4) & 0x0F) * 4;
    if (tcp_hdr_len < WG_TCP_HEADER_MIN_LEN || (size_t)tcp_hdr_len > ip_payload_len)
        return false;

    size_t payload_len = ip_payload_len - (size_t)tcp_hdr_len;
    if (payload_len == 0)
        return false; /* no payload to coalesce */

    /* Only coalesce ACK or ACK+PSH. */
    uint8_t flags = tcp[WG_TCP_FLAGS_OFFSET];
    if (flags & (WG_TCP_FLAG_SYN | WG_TCP_FLAG_FIN | WG_TCP_FLAG_RST))
        return false;
    if (!(flags & WG_TCP_FLAG_ACK))
        return false;

    memset(key, 0, sizeof(*key));
    key->is_v6 = is_v6;

    if (is_v6) {
        memcpy(key->src_addr, pkt + 8, 16);
        memcpy(key->dst_addr, pkt + 24, 16);
    } else {
        memcpy(key->src_addr, pkt + 12, 4);
        memcpy(key->dst_addr, pkt + 16, 4);
    }

    key->src_port = ((uint16_t)tcp[0] << 8) | tcp[1];
    key->dst_port = ((uint16_t)tcp[2] << 8) | tcp[3];
    /* ACK value at tcp[8..11] */
    key->rx_ack = ((uint32_t)tcp[8] << 24) | ((uint32_t)tcp[9] << 16) |
                  ((uint32_t)tcp[10] << 8) | tcp[11];

    *ip_hdr_len_out = ip_hdr_len;
    *tcp_hdr_len_out = tcp_hdr_len;
    *payload_len_out = payload_len;
    *seq_out = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
               ((uint32_t)tcp[6] << 8) | tcp[7];
    *psh_out = (flags & WG_TCP_FLAG_PSH) != 0;

    return true;
}

/* Check if TCP headers (options) match between existing item and new packet. */
static bool tcp_hdrs_can_coalesce(const uint8_t *pkt_a, const uint8_t *pkt_b,
                                  int ip_hdr_len, int tcp_hdr_len)
{
    if (tcp_hdr_len <= WG_TCP_HEADER_MIN_LEN)
        return true; /* no options to compare */

    /* Compare TCP options (bytes 20..tcp_hdr_len of TCP header). */
    const uint8_t *opts_a = pkt_a + ip_hdr_len + WG_TCP_HEADER_MIN_LEN;
    const uint8_t *opts_b = pkt_b + ip_hdr_len + WG_TCP_HEADER_MIN_LEN;
    return memcmp(opts_a, opts_b, (size_t)(tcp_hdr_len - WG_TCP_HEADER_MIN_LEN)) == 0;
}

/* ────────────────────────────────────────
 * UDP GRO: coalesce UDP packets before writing to TUN
 *
 * Reference: wireguard-go/tun/offload_linux.go udpGRO
 * ──────────────────────────────────────── */

static bool udp_flow_eq(const wg_udp_flow_key_t *a, const wg_udp_flow_key_t *b)
{
    if (a->is_v6 != b->is_v6 || a->src_port != b->src_port || a->dst_port != b->dst_port)
        return false;

    int addr_len = a->is_v6 ? 16 : 4;
    return memcmp(a->src_addr, b->src_addr, (size_t)addr_len) == 0 &&
           memcmp(a->dst_addr, b->dst_addr, (size_t)addr_len) == 0;
}

/* Check if IPv4/IPv6 headers are compatible for coalescing.
 * For IPv4: same ToS, TTL, DF/reserved flags.
 * For IPv6: same traffic class, hop limit. */
static bool ip_hdrs_can_coalesce(const uint8_t *pkt_a, const uint8_t *pkt_b, bool is_v6)
{
    if (is_v6) {
        /* traffic class: bits 4-11 of first 4 bytes (byte[0] low nibble + byte[1] high
         * nibble) */
        if (pkt_a[0] != pkt_b[0] || pkt_a[1] != pkt_b[1])
            return false;
        /* hop limit: byte[7] */
        if (pkt_a[7] != pkt_b[7])
            return false;
    } else {
        /* ToS: byte[1] */
        if (pkt_a[1] != pkt_b[1])
            return false;
        /* TTL: byte[8] */
        if (pkt_a[8] != pkt_b[8])
            return false;
        /* flags+fragment high byte: check DF/reserved, ignore ID */
        if ((pkt_a[6] & 0xE0) != (pkt_b[6] & 0xE0))
            return false;
    }
    return true;
}

/* Validate UDP checksum (returns true if valid). */
static bool udp_checksum_valid(const uint8_t *pkt, size_t pkt_len, int ip_hdr_len,
                               bool is_v6)
{
    if ((size_t)ip_hdr_len + WG_UDP_HEADER_LEN > pkt_len)
        return false;

    size_t transport_len = pkt_len - (size_t)ip_hdr_len;
    const uint8_t *udp = pkt + ip_hdr_len;

    /* UDP checksum field at offset 6-7. If 0 for IPv4, checksum is unused. */
    uint16_t csum_field = ((uint16_t)udp[6] << 8) | udp[7];
    if (!is_v6 && csum_field == 0)
        return true; /* IPv4 allows no checksum */

    uint16_t csum = wg_transport_checksum(pkt, ip_hdr_len, udp, transport_len, is_v6,
                                          IPPROTO_UDP_NUM);
    return csum == 0;
}

/* Build a UDP flow key from a packet. Returns false if not a valid UDP candidate. */
static bool build_udp_flow_key(const uint8_t *pkt, size_t pkt_len, wg_udp_flow_key_t *key,
                               int *ip_hdr_len_out, uint16_t *gso_size_out)
{
    bool is_v6;
    uint8_t proto;
    size_t ip_payload_len;
    int ip_hdr_len = get_ip_hdr_len(pkt, pkt_len, &is_v6, &proto, &ip_payload_len);
    if (ip_hdr_len == 0 || proto != IPPROTO_UDP_NUM)
        return false;

    if (ip_payload_len < WG_UDP_HEADER_LEN)
        return false;

    /* Reject IPv4 fragments. */
    if (!is_v6) {
        uint16_t frag_off = ((uint16_t)pkt[6] << 8) | pkt[7];
        if (frag_off & 0x3FFF) /* MF or offset != 0 */
            return false;
    }

    size_t payload_len = ip_payload_len - WG_UDP_HEADER_LEN;
    if (payload_len == 0)
        return false;

    const uint8_t *udp = pkt + ip_hdr_len;

    memset(key, 0, sizeof(*key));
    key->is_v6 = is_v6;

    if (is_v6) {
        memcpy(key->src_addr, pkt + 8, 16);
        memcpy(key->dst_addr, pkt + 24, 16);
    } else {
        memcpy(key->src_addr, pkt + 12, 4);
        memcpy(key->dst_addr, pkt + 16, 4);
    }

    key->src_port = ((uint16_t)udp[0] << 8) | udp[1];
    key->dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    *ip_hdr_len_out = ip_hdr_len;
    *gso_size_out = (uint16_t)payload_len;
    return true;
}

int wg_handle_gro(uint8_t **bufs, int *sizes, int count, int offset,
                  wg_tcp_gro_table_t *tcp_table, wg_udp_gro_table_t *udp_table,
                  int *to_write, void *stats_ptr)
{
    /* GRO diagnostic counters (accumulated locally, flushed to stats at end). */
    uint64_t _gro_tcp_input = 0, _gro_tcp_merged = 0, _gro_not_tcp = 0;
    uint64_t _gro_fail_seq = 0, _gro_fail_psh = 0, _gro_fail_size = 0;
    uint64_t _gro_fail_cap = 0, _gro_fail_hdrlen = 0, _gro_fail_opts = 0;
    uint64_t _gro_skip_no_payload = 0, _gro_skip_bad_flags = 0, _gro_skip_not_ip = 0;
    uint64_t _gro_udp_input = 0, _gro_udp_merged = 0;

    tcp_table->count = 0;
    udp_table->count = 0;
    int write_count = 0;

    for (int i = 0; i < count; i++) {
        uint8_t *pkt = bufs[i] + offset;
        /* sizes[i] includes the offset; strip it to get packet length. */
        size_t pkt_len = (sizes[i] > offset) ? (size_t)(sizes[i] - offset) : 0;

        if (pkt_len == 0)
            continue;

        wg_tcp_flow_key_t key;
        int ip_hdr_len, tcp_hdr_len;
        size_t payload_len;
        uint32_t seq;
        bool psh;

        /* Use IP total length (not buffer size which may include
         * WireGuard padding from the encryption layer). */
        {
            bool is_v6_tmp;
            uint8_t proto_tmp;
            size_t ip_payload_len_tmp;
            int ip_hdr_check =
                get_ip_hdr_len(pkt, pkt_len, &is_v6_tmp, &proto_tmp, &ip_payload_len_tmp);
            if (ip_hdr_check > 0) {
                size_t actual_len = (size_t)ip_hdr_check + ip_payload_len_tmp;
                if (actual_len < pkt_len) {
                    pkt_len = actual_len;
                    sizes[i] = offset + (int)pkt_len;
                }
            }
        }

        if (!build_tcp_flow_key(pkt, pkt_len, &key, &ip_hdr_len, &tcp_hdr_len,
                                &payload_len, &seq, &psh)) {
            /* Not TCP-coalescible. Try UDP GRO. */
            wg_udp_flow_key_t udp_key;
            int udp_ip_hdr_len;
            uint16_t udp_gso_size;

            if (build_udp_flow_key(pkt, pkt_len, &udp_key, &udp_ip_hdr_len,
                                   &udp_gso_size)) {
                _gro_udp_input++;

                /* Look for matching flow in UDP table. */
                int udp_match = -1;
                for (int j = 0; j < udp_table->count; j++) {
                    if (udp_flow_eq(&udp_table->keys[j], &udp_key)) {
                        udp_match = j;
                        break;
                    }
                }

                bool udp_merged = false;

                if (udp_match >= 0) {
                    wg_gro_item_t *item = &udp_table->items[udp_match];
                    uint8_t *existing = bufs[item->buf_idx] + offset;

                    /* Check IP headers match. */
                    if (!ip_hdrs_can_coalesce(existing, pkt, udp_key.is_v6))
                        goto udp_insert;

                    /* Current item's data must be aligned to gso_size. */
                    size_t existing_data =
                        item->buf_len - (size_t)item->ip_hdr_len - WG_UDP_HEADER_LEN;
                    if (existing_data % item->gso_size != 0)
                        goto udp_insert;

                    /* New gso_size must not exceed existing. */
                    if (udp_gso_size > item->gso_size)
                        goto udp_insert;

                    /* Total size check. */
                    size_t new_data = udp_gso_size;
                    if (item->buf_len + new_data > 65535)
                        goto udp_insert;

                    /* Validate checksums before first merge. */
                    if (item->num_merged == 0 && !item->csum_invalid) {
                        if (!udp_checksum_valid(existing, item->buf_len, item->ip_hdr_len,
                                                item->is_v6)) {
                            item->csum_invalid = true;
                            goto udp_insert;
                        }
                    } else if (item->csum_invalid) {
                        goto udp_insert;
                    }

                    if (!udp_checksum_valid(pkt, pkt_len, udp_ip_hdr_len, udp_key.is_v6))
                        goto udp_insert;

                    /* Append UDP payload. */
                    size_t hdr_total = (size_t)udp_ip_hdr_len + WG_UDP_HEADER_LEN;
                    memcpy(existing + item->buf_len, pkt + hdr_total, new_data);
                    item->buf_len += new_data;
                    item->num_merged++;
                    _gro_udp_merged++;
                    udp_merged = true;

                    /* Update IP total length. */
                    if (!item->is_v6) {
                        uint16_t tl = htons((uint16_t)item->buf_len);
                        memcpy(existing + 2, &tl, 2);
                    } else {
                        uint16_t pl =
                            htons((uint16_t)(item->buf_len - WG_IP6_HEADER_LEN));
                        memcpy(existing + 4, &pl, 2);
                    }
                }

            udp_insert:
                if (!udp_merged) {
                    /* Insert new entry or passthrough. */
                    if (udp_table->count < WG_GRO_MAX_ITEMS) {
                        int idx = udp_table->count++;
                        udp_table->keys[idx] = udp_key;
                        wg_gro_item_t *item = &udp_table->items[idx];
                        item->buf_idx = i;
                        item->buf_offset = (size_t)offset;
                        item->buf_len = pkt_len;
                        item->ip_hdr_len = (uint8_t)udp_ip_hdr_len;
                        item->tcp_hdr_len = 0;
                        item->gso_size = udp_gso_size;
                        item->sent_seq = 0;
                        item->num_merged = 0;
                        item->psh_set = false;
                        item->is_v6 = udp_key.is_v6;
                        item->csum_invalid = false;
                        to_write[write_count++] = i;
                    } else {
                        /* Table full — passthrough. */
                        if (offset >= WG_VIRTIO_NET_HDR_LEN)
                            memset(bufs[i] + offset - WG_VIRTIO_NET_HDR_LEN, 0,
                                   WG_VIRTIO_NET_HDR_LEN);
                        to_write[write_count++] = i;
                    }
                }
                continue;
            }

            /* Not TCP or UDP — passthrough. */
            {
                bool _v6;
                uint8_t _proto;
                size_t _ippl;
                int _ihl = get_ip_hdr_len(pkt, pkt_len, &_v6, &_proto, &_ippl);
                if (_ihl > 0 && _proto == IPPROTO_TCP_NUM &&
                    _ippl >= WG_TCP_HEADER_MIN_LEN) {
                    const uint8_t *_tcp = pkt + _ihl;
                    int _thl = ((_tcp[12] >> 4) & 0x0F) * 4;
                    if (_thl >= WG_TCP_HEADER_MIN_LEN && (size_t)_thl <= _ippl) {
                        size_t _plen = _ippl - (size_t)_thl;
                        uint8_t _flags = _tcp[WG_TCP_FLAGS_OFFSET];
                        if (_plen == 0)
                            _gro_skip_no_payload++;
                        else if (_flags &
                                 (WG_TCP_FLAG_SYN | WG_TCP_FLAG_FIN | WG_TCP_FLAG_RST))
                            _gro_skip_bad_flags++;
                        else
                            _gro_not_tcp++;
                    } else {
                        _gro_not_tcp++;
                    }
                } else if (_ihl == 0) {
                    _gro_skip_not_ip++;
                } else if (_proto != IPPROTO_TCP_NUM) {
                    _gro_not_tcp++;
                } else {
                    _gro_skip_not_ip++;
                }
            }
            if (offset >= WG_VIRTIO_NET_HDR_LEN) {
                memset(bufs[i] + offset - WG_VIRTIO_NET_HDR_LEN, 0,
                       WG_VIRTIO_NET_HDR_LEN);
            }
            to_write[write_count++] = i;
            continue;
        }

        _gro_tcp_input++;

        /* Look for matching flow in TCP table. */
        bool merged = false;
        int flow_match_idx = -1;
        for (int j = 0; j < tcp_table->count; j++) {
            if (!tcp_flow_eq(&tcp_table->keys[j], &key))
                continue;
            flow_match_idx = j;
            break; /* flow keys are unique in the table */
        }

        if (flow_match_idx >= 0) {
            wg_gro_item_t *item = &tcp_table->items[flow_match_idx];
            uint8_t *existing = bufs[item->buf_idx] + offset;

            /* Check TCP header options match. */
            if (item->tcp_hdr_len != (uint8_t)tcp_hdr_len) {
                _gro_fail_hdrlen++;
            } else if (!tcp_hdrs_can_coalesce(existing, pkt, ip_hdr_len, tcp_hdr_len)) {
                _gro_fail_opts++;
            } else {
                /* Check sequence number for append. */
                uint32_t expected_seq =
                    item->sent_seq + (uint32_t)item->gso_size * (1 + item->num_merged);

                if (seq == expected_seq && !item->psh_set &&
                    (item->gso_size == (uint16_t)payload_len ||
                     payload_len <= item->gso_size) &&
                    item->buf_len + payload_len <= 65535) {
                    /* Append: copy payload after existing data. */
                    memcpy(existing + item->buf_len, pkt + ip_hdr_len + tcp_hdr_len,
                           payload_len);
                    item->buf_len += payload_len;
                    item->num_merged++;
                    _gro_tcp_merged++;

                    if (psh)
                        item->psh_set = true;

                    /* Update IP total length in the coalesced buffer. */
                    if (!item->is_v6) {
                        uint16_t tl = htons((uint16_t)item->buf_len);
                        memcpy(existing + 2, &tl, 2);
                    } else {
                        uint16_t pl =
                            htons((uint16_t)(item->buf_len - WG_IP6_HEADER_LEN));
                        memcpy(existing + 4, &pl, 2);
                    }

                    merged = true;
                } else {
                    /* Coalesce failed — track reason. */
                    if (seq != expected_seq)
                        _gro_fail_seq++;
                    else if (item->psh_set)
                        _gro_fail_psh++;
                    else if (item->buf_len + payload_len > 65535)
                        _gro_fail_cap++;
                    else
                        _gro_fail_size++;
                }
            }

            if (!merged) {
                /* Flow matched but couldn't append. Flush old entry
                 * and replace with new packet to avoid duplicate flows. */
                to_write[write_count++] = item->buf_idx;

                /* Emit virtio header for the flushed item. */
                if (item->num_merged > 0) {
                    wg_virtio_net_hdr_t *vhdr =
                        (wg_virtio_net_hdr_t *)(bufs[item->buf_idx] + offset -
                                                WG_VIRTIO_NET_HDR_LEN);
                    memset(vhdr, 0, WG_VIRTIO_NET_HDR_LEN);
                    vhdr->gso_type = item->is_v6 ? WG_VIRTIO_NET_HDR_GSO_TCPV6
                                                 : WG_VIRTIO_NET_HDR_GSO_TCPV4;
                    vhdr->gso_size = item->gso_size;
                    vhdr->hdr_len = (uint16_t)(item->ip_hdr_len + item->tcp_hdr_len);
                    vhdr->flags = WG_VIRTIO_NET_HDR_F_NEEDS_CSUM;
                    vhdr->csum_start = (uint16_t)item->ip_hdr_len;
                    vhdr->csum_offset = 16;

                    uint8_t *epkt = bufs[item->buf_idx] + offset;
                    epkt[item->ip_hdr_len + 16] = 0;
                    epkt[item->ip_hdr_len + 17] = 0;
                    const uint8_t *sa, *da;
                    int alen;
                    if (item->is_v6) {
                        sa = epkt + 8;
                        da = epkt + 24;
                        alen = 16;
                    } else {
                        sa = epkt + 12;
                        da = epkt + 16;
                        alen = 4;
                        epkt[10] = 0;
                        epkt[11] = 0;
                        uint16_t ipc = wg_ip_checksum(epkt, (size_t)item->ip_hdr_len);
                        epkt[10] = (uint8_t)(ipc >> 8);
                        epkt[11] = (uint8_t)(ipc & 0xFF);
                    }
                    uint16_t tlen = (uint16_t)(item->buf_len - (size_t)item->ip_hdr_len);
                    uint16_t phc = (uint16_t)~wg_pseudo_header_checksum(
                        IPPROTO_TCP_NUM, sa, da, alen, tlen);
                    epkt[item->ip_hdr_len + 16] = (uint8_t)(phc >> 8);
                    epkt[item->ip_hdr_len + 17] = (uint8_t)(phc & 0xFF);
                    sizes[item->buf_idx] = offset + (int)item->buf_len;
                } else {
                    /* Single packet — still set NEEDS_CSUM. */
                    uint8_t *epkt = bufs[item->buf_idx] + offset;
                    wg_virtio_net_hdr_t *vhdr =
                        (wg_virtio_net_hdr_t *)(bufs[item->buf_idx] + offset -
                                                WG_VIRTIO_NET_HDR_LEN);
                    memset(vhdr, 0, WG_VIRTIO_NET_HDR_LEN);
                    vhdr->flags = WG_VIRTIO_NET_HDR_F_NEEDS_CSUM;
                    vhdr->csum_start = (uint16_t)item->ip_hdr_len;
                    vhdr->csum_offset = 16;

                    epkt[item->ip_hdr_len + 16] = 0;
                    epkt[item->ip_hdr_len + 17] = 0;
                    const uint8_t *sa, *da;
                    int alen;
                    if (item->is_v6) {
                        sa = epkt + 8;
                        da = epkt + 24;
                        alen = 16;
                    } else {
                        sa = epkt + 12;
                        da = epkt + 16;
                        alen = 4;
                    }
                    uint16_t tlen = (uint16_t)(item->buf_len - (size_t)item->ip_hdr_len);
                    uint16_t phc = (uint16_t)~wg_pseudo_header_checksum(
                        IPPROTO_TCP_NUM, sa, da, alen, tlen);
                    epkt[item->ip_hdr_len + 16] = (uint8_t)(phc >> 8);
                    epkt[item->ip_hdr_len + 17] = (uint8_t)(phc & 0xFF);
                }

                /* Replace entry with new packet. */
                item->buf_idx = i;
                item->buf_offset = (size_t)offset;
                item->buf_len = pkt_len;
                item->ip_hdr_len = (uint8_t)ip_hdr_len;
                item->tcp_hdr_len = (uint8_t)tcp_hdr_len;
                item->gso_size = (uint16_t)payload_len;
                item->sent_seq = seq;
                item->num_merged = 0;
                item->psh_set = psh;
                item->is_v6 = key.is_v6;
                merged = true; /* replaced, don't insert new entry */
            }
        }

        if (!merged) {
            /* New flow — insert into table. */
            if (tcp_table->count < WG_GRO_MAX_ITEMS) {
                int idx = tcp_table->count++;
                tcp_table->keys[idx] = key;
                wg_gro_item_t *item = &tcp_table->items[idx];
                item->buf_idx = i;
                item->buf_offset = (size_t)offset;
                item->buf_len = pkt_len;
                item->ip_hdr_len = (uint8_t)ip_hdr_len;
                item->tcp_hdr_len = (uint8_t)tcp_hdr_len;
                item->gso_size = (uint16_t)payload_len;
                item->sent_seq = seq;
                item->num_merged = 0;
                item->psh_set = psh;
                item->is_v6 = key.is_v6;
            }
        }
    }

    /* Flush GRO diagnostic counters to stats. */
    if (stats_ptr) {
        wg_stats_t *st = (wg_stats_t *)stats_ptr;
        atomic_fetch_add(&st->gro_tcp_input, _gro_tcp_input);
        atomic_fetch_add(&st->gro_tcp_merged, _gro_tcp_merged);
        atomic_fetch_add(&st->gro_not_tcp, _gro_not_tcp);
        atomic_fetch_add(&st->gro_fail_seq, _gro_fail_seq);
        atomic_fetch_add(&st->gro_fail_psh, _gro_fail_psh);
        atomic_fetch_add(&st->gro_fail_size, _gro_fail_size);
        atomic_fetch_add(&st->gro_fail_cap, _gro_fail_cap);
        atomic_fetch_add(&st->gro_fail_hdrlen, _gro_fail_hdrlen);
        atomic_fetch_add(&st->gro_fail_opts, _gro_fail_opts);
        atomic_fetch_add(&st->gro_skip_no_payload, _gro_skip_no_payload);
        atomic_fetch_add(&st->gro_skip_bad_flags, _gro_skip_bad_flags);
        atomic_fetch_add(&st->gro_skip_not_ip, _gro_skip_not_ip);
        atomic_fetch_add(&st->gro_udp_input, _gro_udp_input);
        atomic_fetch_add(&st->gro_udp_merged, _gro_udp_merged);
    }

    /* Emit all TCP table items. */
    for (int j = 0; j < tcp_table->count; j++) {
        wg_gro_item_t *item = &tcp_table->items[j];
        uint8_t *pkt = bufs[item->buf_idx] + offset;

        /* Set virtio_net_hdr for coalesced packets. */
        if (item->num_merged > 0) {
            /* Prepend virtio header at offset - WG_VIRTIO_NET_HDR_LEN. */
            wg_virtio_net_hdr_t *vhdr =
                (wg_virtio_net_hdr_t *)(bufs[item->buf_idx] + offset -
                                        WG_VIRTIO_NET_HDR_LEN);
            memset(vhdr, 0, WG_VIRTIO_NET_HDR_LEN);

            if (item->is_v6) {
                vhdr->gso_type = WG_VIRTIO_NET_HDR_GSO_TCPV6;
            } else {
                vhdr->gso_type = WG_VIRTIO_NET_HDR_GSO_TCPV4;
            }
            vhdr->gso_size = item->gso_size;
            vhdr->hdr_len = (uint16_t)(item->ip_hdr_len + item->tcp_hdr_len);

            /* Set NEEDS_CSUM so kernel computes checksum. */
            vhdr->flags = WG_VIRTIO_NET_HDR_F_NEEDS_CSUM;
            vhdr->csum_start = (uint16_t)item->ip_hdr_len;
            vhdr->csum_offset = 16; /* TCP checksum offset */

            /* Zero TCP checksum (kernel will compute). */
            pkt[item->ip_hdr_len + 16] = 0;
            pkt[item->ip_hdr_len + 17] = 0;

            /* Compute pseudo-header checksum for kernel. */
            const uint8_t *src_addr, *dst_addr;
            int addr_len;
            if (item->is_v6) {
                src_addr = pkt + 8;
                dst_addr = pkt + 24;
                addr_len = 16;
            } else {
                src_addr = pkt + 12;
                dst_addr = pkt + 16;
                addr_len = 4;

                /* Recalculate IPv4 header checksum. */
                pkt[10] = 0;
                pkt[11] = 0;
                uint16_t ipcsum = wg_ip_checksum(pkt, (size_t)item->ip_hdr_len);
                pkt[10] = (uint8_t)(ipcsum >> 8);
                pkt[11] = (uint8_t)(ipcsum & 0xFF);
            }

            uint16_t transport_len = (uint16_t)(item->buf_len - (size_t)item->ip_hdr_len);
            /* Store the non-complemented pseudo-header checksum.
             * wg_pseudo_header_checksum returns the complemented value,
             * so un-complement it — the kernel will add data checksum
             * and complement the final result (CHECKSUM_PARTIAL). */
            uint16_t phcsum = (uint16_t)~wg_pseudo_header_checksum(
                IPPROTO_TCP_NUM, src_addr, dst_addr, addr_len, transport_len);
            pkt[item->ip_hdr_len + 16] = (uint8_t)(phcsum >> 8);
            pkt[item->ip_hdr_len + 17] = (uint8_t)(phcsum & 0xFF);

            /* Update sizes so caller gets coalesced length. */
            sizes[item->buf_idx] = offset + (int)item->buf_len;
        } else {
            /* Single TCP packet — set NEEDS_CSUM so kernel computes
             * checksum.  This allows the sender's GSO split to skip
             * expensive per-segment checksum computation. */
            uint8_t *pkt = bufs[item->buf_idx] + offset;
            wg_virtio_net_hdr_t *vhdr =
                (wg_virtio_net_hdr_t *)(bufs[item->buf_idx] + offset -
                                        WG_VIRTIO_NET_HDR_LEN);
            memset(vhdr, 0, WG_VIRTIO_NET_HDR_LEN);
            vhdr->flags = WG_VIRTIO_NET_HDR_F_NEEDS_CSUM;
            vhdr->csum_start = (uint16_t)item->ip_hdr_len;
            vhdr->csum_offset = 16; /* TCP checksum offset */

            /* Zero TCP checksum and store pseudo-header checksum. */
            pkt[item->ip_hdr_len + 16] = 0;
            pkt[item->ip_hdr_len + 17] = 0;

            const uint8_t *src_addr, *dst_addr;
            int addr_len;
            if (item->is_v6) {
                src_addr = pkt + 8;
                dst_addr = pkt + 24;
                addr_len = 16;
            } else {
                src_addr = pkt + 12;
                dst_addr = pkt + 16;
                addr_len = 4;
            }
            uint16_t transport_len = (uint16_t)(item->buf_len - (size_t)item->ip_hdr_len);
            uint16_t phcsum = (uint16_t)~wg_pseudo_header_checksum(
                IPPROTO_TCP_NUM, src_addr, dst_addr, addr_len, transport_len);
            pkt[item->ip_hdr_len + 16] = (uint8_t)(phcsum >> 8);
            pkt[item->ip_hdr_len + 17] = (uint8_t)(phcsum & 0xFF);
        }

        to_write[write_count++] = item->buf_idx;
    }

    /* Emit all UDP table items: apply coalescing accounting. */
    for (int j = 0; j < udp_table->count; j++) {
        wg_gro_item_t *item = &udp_table->items[j];
        uint8_t *pkt = bufs[item->buf_idx] + offset;

        if (item->num_merged > 0) {
            /* Set virtio_net_hdr for coalesced UDP. */
            wg_virtio_net_hdr_t *vhdr =
                (wg_virtio_net_hdr_t *)(bufs[item->buf_idx] + offset -
                                        WG_VIRTIO_NET_HDR_LEN);
            memset(vhdr, 0, WG_VIRTIO_NET_HDR_LEN);
            vhdr->flags = WG_VIRTIO_NET_HDR_F_NEEDS_CSUM;
            vhdr->gso_type = WG_VIRTIO_NET_HDR_GSO_UDP_L4;
            vhdr->gso_size = item->gso_size;
            vhdr->hdr_len = (uint16_t)(item->ip_hdr_len + WG_UDP_HEADER_LEN);
            vhdr->csum_start = (uint16_t)item->ip_hdr_len;
            vhdr->csum_offset = 6; /* UDP checksum offset */

            /* Update IP total length. */
            if (!item->is_v6) {
                pkt[10] = 0;
                pkt[11] = 0;
                uint16_t tl = htons((uint16_t)item->buf_len);
                memcpy(pkt + 2, &tl, 2);
                uint16_t ipcsum = wg_ip_checksum(pkt, (size_t)item->ip_hdr_len);
                pkt[10] = (uint8_t)(ipcsum >> 8);
                pkt[11] = (uint8_t)(ipcsum & 0xFF);
            } else {
                uint16_t pl = htons((uint16_t)(item->buf_len - WG_IP6_HEADER_LEN));
                memcpy(pkt + 4, &pl, 2);
            }

            /* Update UDP length field. */
            uint16_t udp_len =
                htons((uint16_t)(item->buf_len - (size_t)item->ip_hdr_len));
            memcpy(pkt + item->ip_hdr_len + 4, &udp_len, 2);

            /* Zero UDP checksum and store pseudo-header checksum. */
            pkt[item->ip_hdr_len + 6] = 0;
            pkt[item->ip_hdr_len + 7] = 0;

            const uint8_t *src_addr, *dst_addr;
            int addr_len;
            if (item->is_v6) {
                src_addr = pkt + 8;
                dst_addr = pkt + 24;
                addr_len = 16;
            } else {
                src_addr = pkt + 12;
                dst_addr = pkt + 16;
                addr_len = 4;
            }
            uint16_t transport_len = (uint16_t)(item->buf_len - (size_t)item->ip_hdr_len);
            uint16_t phcsum = (uint16_t)~wg_pseudo_header_checksum(
                IPPROTO_UDP_NUM, src_addr, dst_addr, addr_len, transport_len);
            pkt[item->ip_hdr_len + 6] = (uint8_t)(phcsum >> 8);
            pkt[item->ip_hdr_len + 7] = (uint8_t)(phcsum & 0xFF);

            sizes[item->buf_idx] = offset + (int)item->buf_len;
        } else {
            /* Single UDP packet — empty virtio header (already valid). */
            if (offset >= WG_VIRTIO_NET_HDR_LEN) {
                memset(bufs[item->buf_idx] + offset - WG_VIRTIO_NET_HDR_LEN, 0,
                       WG_VIRTIO_NET_HDR_LEN);
            }
        }

        /* UDP items were already added to to_write during insertion.
         * Only coalesced items need a size update (already done above). */
    }

    return write_count;
}

#endif /* __linux__ */

/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Pipeline performance counters for bottleneck analysis.
 *
 * All counters are atomic — safe to read from any thread while
 * the pipeline is running.  Overhead is minimal (one atomic add
 * per counter per event).
 */

#ifndef WG_STATS_H
#define WG_STATS_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "wireguard.h" /* wg_bind_ops_t, wg_bind_gso_stats_t */

typedef struct {
    /* ── TUN read (GSO split output) ── */
    _Atomic uint64_t tun_read_calls;    /* TUN read() syscalls */
    _Atomic uint64_t tun_read_packets;  /* packets after GSO split */
    _Atomic uint64_t tun_read_bytes;    /* total bytes read */
    _Atomic uint64_t tun_read_gso;      /* reads that were GSO (multi-seg) */
    _Atomic uint64_t tun_read_gso_segs; /* total segments from GSO reads */

    /* ── Encryption ── */
    _Atomic uint64_t encrypt_count; /* packets encrypted */
    _Atomic uint64_t encrypt_ns;    /* cumulative encryption time (ns) */

    /* ── Sequential sender ── */
    _Atomic uint64_t send_batches; /* sendmmsg batches */
    _Atomic uint64_t send_packets; /* packets sent via UDP */
    _Atomic uint64_t send_wait_ns; /* time waiting for crypto completion */

    /* ── UDP recv ── */
    _Atomic uint64_t udp_recv_calls;   /* recvmmsg calls */
    _Atomic uint64_t udp_recv_packets; /* packets received */

    /* ── Decryption ── */
    _Atomic uint64_t decrypt_count; /* packets decrypted */
    _Atomic uint64_t decrypt_ns;    /* cumulative decryption time (ns) */

    /* ── Sequential receiver (GRO input) ── */
    _Atomic uint64_t recv_batches;    /* TUN write batches */
    _Atomic uint64_t recv_packets;    /* packets written to TUN */
    _Atomic uint64_t recv_bytes;      /* total bytes written */
    _Atomic uint64_t recv_wait_ns;    /* time waiting for crypto completion */
    _Atomic uint64_t tun_write_calls; /* actual TUN write() syscalls after GRO */

    /* ── Pipeline flow counters ── */
    _Atomic uint64_t staged_pushed; /* packets successfully pushed to staged */

    /* ── Decrypt failure breakdown ── */
    _Atomic uint64_t decrypt_aead_fail;   /* AEAD authentication failures */
    _Atomic uint64_t decrypt_replay_fail; /* replay counter rejections */
    _Atomic uint64_t decrypt_ok;          /* successful decryptions */

    /* ── Drop counters ── */
    _Atomic uint64_t staged_drops;    /* packets dropped at staged queue push */
    _Atomic uint64_t outbound_drops;  /* packets dropped at outbound queue push */
    _Atomic uint64_t encrypt_q_drops; /* packets dropped at encryption queue push */
    _Atomic uint64_t inbound_drops;   /* packets dropped at inbound queue push */
    _Atomic uint64_t decrypt_q_drops; /* packets dropped at decryption queue push */

    /* ── GRO diagnostics ── */
    _Atomic uint64_t gro_tcp_input;       /* TCP packets entering GRO */
    _Atomic uint64_t gro_tcp_merged;      /* successful TCP merges */
    _Atomic uint64_t gro_not_tcp;         /* non-TCP packets (skip GRO) */
    _Atomic uint64_t gro_skip_no_payload; /* TCP with zero payload (pure ACK) */
    _Atomic uint64_t gro_skip_bad_flags;  /* TCP with SYN/FIN/RST */
    _Atomic uint64_t gro_skip_not_ip;     /* not a valid IP packet */
    _Atomic uint64_t gro_fail_flow;       /* flow key mismatch */
    _Atomic uint64_t gro_fail_hdrlen;     /* TCP header length mismatch */
    _Atomic uint64_t gro_fail_opts;       /* TCP options mismatch */
    _Atomic uint64_t gro_fail_seq;        /* sequence number not adjacent */
    _Atomic uint64_t gro_fail_psh;        /* PSH blocked append */
    _Atomic uint64_t gro_fail_size;       /* payload size mismatch */
    _Atomic uint64_t gro_fail_cap;        /* buffer capacity exceeded */
    _Atomic uint64_t gro_udp_input;       /* UDP packets entering GRO */
    _Atomic uint64_t gro_udp_merged;      /* successful UDP merges */

    /* ── Crypto done by the sequential threads while idle (#63) ── */
    _Atomic uint64_t seq_inline_encrypt;
    _Atomic uint64_t seq_inline_decrypt;
    _Atomic uint64_t seq_inline_encrypt_head; /* of which: the peer's head element */
    _Atomic uint64_t seq_inline_decrypt_head;
    _Atomic uint64_t seq_send_waits; /* times the sequential sender went to wait */
    _Atomic uint64_t seq_recv_waits;
} wg_stats_t;

static inline void wg_stats_init(wg_stats_t *s)
{
    atomic_store(&s->tun_read_calls, 0);
    atomic_store(&s->tun_read_packets, 0);
    atomic_store(&s->tun_read_bytes, 0);
    atomic_store(&s->tun_read_gso, 0);
    atomic_store(&s->tun_read_gso_segs, 0);
    atomic_store(&s->encrypt_count, 0);
    atomic_store(&s->seq_inline_encrypt, 0);
    atomic_store(&s->seq_inline_decrypt, 0);
    atomic_store(&s->seq_inline_encrypt_head, 0);
    atomic_store(&s->seq_inline_decrypt_head, 0);
    atomic_store(&s->seq_send_waits, 0);
    atomic_store(&s->seq_recv_waits, 0);
    atomic_store(&s->encrypt_ns, 0);
    atomic_store(&s->send_batches, 0);
    atomic_store(&s->send_packets, 0);
    atomic_store(&s->send_wait_ns, 0);
    atomic_store(&s->udp_recv_calls, 0);
    atomic_store(&s->udp_recv_packets, 0);
    atomic_store(&s->decrypt_count, 0);
    atomic_store(&s->decrypt_ns, 0);
    atomic_store(&s->recv_batches, 0);
    atomic_store(&s->recv_packets, 0);
    atomic_store(&s->recv_bytes, 0);
    atomic_store(&s->recv_wait_ns, 0);
    atomic_store(&s->tun_write_calls, 0);
    atomic_store(&s->staged_pushed, 0);
    atomic_store(&s->staged_drops, 0);
    atomic_store(&s->outbound_drops, 0);
    atomic_store(&s->encrypt_q_drops, 0);
    atomic_store(&s->inbound_drops, 0);
    atomic_store(&s->decrypt_q_drops, 0);
    atomic_store(&s->decrypt_aead_fail, 0);
    atomic_store(&s->decrypt_replay_fail, 0);
    atomic_store(&s->decrypt_ok, 0);
    atomic_store(&s->gro_tcp_input, 0);
    atomic_store(&s->gro_tcp_merged, 0);
    atomic_store(&s->gro_not_tcp, 0);
    atomic_store(&s->gro_fail_flow, 0);
    atomic_store(&s->gro_fail_hdrlen, 0);
    atomic_store(&s->gro_fail_opts, 0);
    atomic_store(&s->gro_fail_seq, 0);
    atomic_store(&s->gro_fail_psh, 0);
    atomic_store(&s->gro_fail_size, 0);
    atomic_store(&s->gro_fail_cap, 0);
    atomic_store(&s->gro_skip_no_payload, 0);
    atomic_store(&s->gro_skip_bad_flags, 0);
    atomic_store(&s->gro_skip_not_ip, 0);
    atomic_store(&s->gro_udp_input, 0);
    atomic_store(&s->gro_udp_merged, 0);
}

/* Per-packet timing adds 2x clock_gettime per crypto op + 2x per crypto wait.
 * Define WG_STATS_TIMING=0 to disable for production benchmarks. */
#ifndef WG_STATS_TIMING
#define WG_STATS_TIMING 0
#endif

static inline int64_t wg_stats_now_ns(void)
{
#if WG_STATS_TIMING
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
#else
    return 0;
#endif
}

static inline void wg_stats_dump(const wg_stats_t *s, const wg_bind_ops_t *bind, FILE *f)
{
    uint64_t tun_calls = atomic_load(&s->tun_read_calls);
    uint64_t tun_pkts = atomic_load(&s->tun_read_packets);
    uint64_t tun_bytes = atomic_load(&s->tun_read_bytes);
    uint64_t tun_gso = atomic_load(&s->tun_read_gso);
    uint64_t tun_gso_segs = atomic_load(&s->tun_read_gso_segs);
    uint64_t enc_cnt = atomic_load(&s->encrypt_count);
    uint64_t enc_ns = atomic_load(&s->encrypt_ns);
    uint64_t snd_bat = atomic_load(&s->send_batches);
    uint64_t snd_pkt = atomic_load(&s->send_packets);
    uint64_t snd_wait = atomic_load(&s->send_wait_ns);
    uint64_t udp_calls = atomic_load(&s->udp_recv_calls);
    uint64_t udp_pkts = atomic_load(&s->udp_recv_packets);
    uint64_t dec_cnt = atomic_load(&s->decrypt_count);
    uint64_t dec_ns = atomic_load(&s->decrypt_ns);
    uint64_t rcv_bat = atomic_load(&s->recv_batches);
    uint64_t rcv_pkt = atomic_load(&s->recv_packets);
    uint64_t rcv_bytes = atomic_load(&s->recv_bytes);
    uint64_t rcv_wait = atomic_load(&s->recv_wait_ns);

    fprintf(f, "\n  ┌─── Pipeline Statistics ────────────────────────┐\n");

    fprintf(f, "  │ TUN read:   %8llu calls, %8llu pkts", (unsigned long long)tun_calls,
            (unsigned long long)tun_pkts);
    if (tun_calls > 0)
        fprintf(f, "  (%.1f pkt/call)", (double)tun_pkts / (double)tun_calls);
    fprintf(f, "\n");
    if (tun_pkts > 0)
        fprintf(f, "  │             avg pkt size: %llu B\n",
                (unsigned long long)(tun_bytes / tun_pkts));
    if (tun_calls > 0)
        fprintf(f, "  │             GSO: %llu/%llu reads (%.1f%%)",
                (unsigned long long)tun_gso, (unsigned long long)tun_calls,
                (double)tun_gso / (double)tun_calls * 100.0);
    if (tun_gso > 0)
        fprintf(f, ", avg %.1f seg/gso", (double)tun_gso_segs / (double)tun_gso);
    if (tun_calls > 0)
        fprintf(f, "\n");

    fprintf(f, "  │ Encrypt:    %8llu pkts", (unsigned long long)enc_cnt);
    if (enc_cnt > 0)
        fprintf(f, "  avg %.1f us/pkt", (double)enc_ns / (double)enc_cnt / 1000.0);
    fprintf(f, "  (%llu by seq sender, %llu of them head; %llu waits)\n",
            (unsigned long long)atomic_load(&s->seq_inline_encrypt),
            (unsigned long long)atomic_load(&s->seq_inline_encrypt_head),
            (unsigned long long)atomic_load(&s->seq_send_waits));

    fprintf(f, "  │ Seq sender: %8llu batches, %8llu pkts", (unsigned long long)snd_bat,
            (unsigned long long)snd_pkt);
    if (snd_bat > 0)
        fprintf(f, "  (%.1f pkt/batch)", (double)snd_pkt / (double)snd_bat);
    fprintf(f, "\n");
    if (snd_pkt > 0)
        fprintf(f, "  │             crypto wait: avg %.1f us/pkt\n",
                (double)snd_wait / (double)snd_pkt / 1000.0);

    {
        wg_bind_gso_stats_t gso = {0};
        if (bind && bind->get_gso_stats)
            bind->get_gso_stats(bind->ctx, &gso);
        if (snd_bat > 0)
            fprintf(f, "  │   GSO: ok=%llu fail=%llu skip=%llu pkts=%llu (%.1f%%)\n",
                    (unsigned long long)gso.ok, (unsigned long long)gso.fail,
                    (unsigned long long)gso.skip, (unsigned long long)gso.packets,
                    snd_bat > 0 ? (double)gso.ok / (double)snd_bat * 100.0 : 0.0);
    }

    fprintf(f, "  │ UDP recv:   %8llu calls, %8llu pkts", (unsigned long long)udp_calls,
            (unsigned long long)udp_pkts);
    if (udp_calls > 0)
        fprintf(f, "  (%.1f pkt/call)", (double)udp_pkts / (double)udp_calls);
    fprintf(f, "\n");

    fprintf(f, "  │ Decrypt:    %8llu pkts", (unsigned long long)dec_cnt);
    if (dec_cnt > 0)
        fprintf(f, "  avg %.1f us/pkt", (double)dec_ns / (double)dec_cnt / 1000.0);
    fprintf(f, "  (%llu by seq receiver, %llu of them head; %llu waits)\n",
            (unsigned long long)atomic_load(&s->seq_inline_decrypt),
            (unsigned long long)atomic_load(&s->seq_inline_decrypt_head),
            (unsigned long long)atomic_load(&s->seq_recv_waits));
    {
        uint64_t aead_fail = atomic_load(&s->decrypt_aead_fail);
        uint64_t replay_fail = atomic_load(&s->decrypt_replay_fail);
        uint64_t dec_ok = atomic_load(&s->decrypt_ok);
        if (aead_fail > 0 || replay_fail > 0)
            fprintf(f, "  │   decrypt: ok=%llu aead_fail=%llu replay_fail=%llu\n",
                    (unsigned long long)dec_ok, (unsigned long long)aead_fail,
                    (unsigned long long)replay_fail);
    }

    fprintf(f, "  │ Seq recvr:  %8llu batches, %8llu pkts", (unsigned long long)rcv_bat,
            (unsigned long long)rcv_pkt);
    if (rcv_bat > 0)
        fprintf(f, "  (%.1f pkt/batch)", (double)rcv_pkt / (double)rcv_bat);
    fprintf(f, "\n");
    if (rcv_pkt > 0) {
        fprintf(f, "  │             avg pkt size: %llu B\n",
                (unsigned long long)(rcv_bytes / rcv_pkt));
        fprintf(f, "  │             crypto wait: avg %.1f us/pkt\n",
                (double)rcv_wait / (double)rcv_pkt / 1000.0);
    }
    {
        uint64_t tw = atomic_load(&s->tun_write_calls);
        fprintf(f, "  │ TUN writes: %8llu syscalls", (unsigned long long)tw);
        if (rcv_pkt > 0 && tw > 0)
            fprintf(f, "  (GRO %.1fx coalesce)", (double)rcv_pkt / (double)tw);
        fprintf(f, "\n");
    }

    {
        uint64_t staged = atomic_load(&s->staged_pushed);
        if (staged > 0)
            fprintf(f, "  │ Staged:     %8llu pkts pushed\n", (unsigned long long)staged);
    }
    {
        uint64_t sd = atomic_load(&s->staged_drops);
        uint64_t od = atomic_load(&s->outbound_drops);
        uint64_t ed = atomic_load(&s->encrypt_q_drops);
        uint64_t id = atomic_load(&s->inbound_drops);
        uint64_t dd = atomic_load(&s->decrypt_q_drops);
        uint64_t total = sd + od + ed + id + dd;
        if (total > 0) {
            fprintf(f,
                    "  │ Drops:      staged=%llu outbound=%llu encQ=%llu "
                    "inbound=%llu decQ=%llu\n",
                    (unsigned long long)sd, (unsigned long long)od,
                    (unsigned long long)ed, (unsigned long long)id,
                    (unsigned long long)dd);
        }
    }

    {
        uint64_t gi = atomic_load(&s->gro_tcp_input);
        uint64_t gm = atomic_load(&s->gro_tcp_merged);
        uint64_t gnt = atomic_load(&s->gro_not_tcp);
        uint64_t gui = atomic_load(&s->gro_udp_input);
        uint64_t gum = atomic_load(&s->gro_udp_merged);
        if (gi > 0 || gnt > 0 || gui > 0) {
            fprintf(f,
                    "  │ GRO:        tcp_in=%llu merged=%llu not_tcp=%llu"
                    "  udp_in=%llu merged=%llu\n",
                    (unsigned long long)gi, (unsigned long long)gm,
                    (unsigned long long)gnt, (unsigned long long)gui,
                    (unsigned long long)gum);
            uint64_t ff = atomic_load(&s->gro_fail_flow);
            uint64_t fh = atomic_load(&s->gro_fail_hdrlen);
            uint64_t fo = atomic_load(&s->gro_fail_opts);
            uint64_t fs = atomic_load(&s->gro_fail_seq);
            uint64_t fp = atomic_load(&s->gro_fail_psh);
            uint64_t fz = atomic_load(&s->gro_fail_size);
            uint64_t fc = atomic_load(&s->gro_fail_cap);
            fprintf(f,
                    "  │   fail: flow=%llu hdr=%llu opts=%llu seq=%llu "
                    "psh=%llu size=%llu cap=%llu\n",
                    (unsigned long long)ff, (unsigned long long)fh,
                    (unsigned long long)fo, (unsigned long long)fs,
                    (unsigned long long)fp, (unsigned long long)fz,
                    (unsigned long long)fc);
            uint64_t snp = atomic_load(&s->gro_skip_no_payload);
            uint64_t sbf = atomic_load(&s->gro_skip_bad_flags);
            uint64_t sni = atomic_load(&s->gro_skip_not_ip);
            fprintf(f, "  │   skip: no_payload=%llu bad_flags=%llu not_ip=%llu\n",
                    (unsigned long long)snp, (unsigned long long)sbf,
                    (unsigned long long)sni);
        }
    }
    fprintf(f, "  └─────────────────────────────────────────────────┘\n");
}

#endif /* WG_STATS_H */

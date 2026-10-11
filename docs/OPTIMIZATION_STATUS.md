# noisetun Optimization Status

**Last updated**: 2026-09-26 (#64)
**Detailed log**: [performance-analysis.md](performance-analysis.md)

---

## Current throughput

### Linux x86 (#63b, 2026-09-26) — c6i.2xlarge, Ubuntu 26.04.1 / kernel 7.0.0-1012-aws, bench_rigorous.sh on the same host (seq inline crypto)

| | wg-c | wireguard-go | Ratio |
|---|---|---|---|
| #63 (run 1) | 8.72 Gbps | 8.37 Gbps | **104.1%** (main in the same run: 97.8%) |
| #63b (run 2) | 9.16 Gbps | 8.64 Gbps | **106.0%** (main in the same run: 98.8%) |

Interleaved (ABAB) runs against main, 6 rounds: +6.3% (6/6). On Graviton the feature is off by default and results match main (7.76 Gbps, 120% of wg-go).

### Linux benchmark (#55, 2026-09-25) — Ubuntu 26.04 / kernel 7.0.0-1012-aws, bench_rigorous.sh on the same host

| Host | wg-c (main 129419b) | wireguard-go | Ratio | Interleaved runs vs. pre-merge (1406b5c) |
|---|---|---|---|---|
| **EC2 c6i.2xlarge (x86)** | **8.19 Gbps** | 8.18 Gbps | **100.1%** | +2.93% (6/6) |
| **EC2 c7g.2xlarge (Graviton3)** | **7.43 Gbps** | 6.17 Gbps | **120.3%** | +8.85% (6/6) |

main after #124 (17bf731) shows no difference from 129419b (x86 −0.32%, Graviton −0.14%, both within noise). Details in performance-analysis.md #55.

### Linux two-host setup (#56, 2026-09-25) — c6in.4xlarge × 2, cluster placement group, over a real NIC, iperf3 single stream

| Implementation | Gbps | CPU send / receive (cores) |
|---|---|---|
| raw (no tunnel) | 9.18 | 0.13 / 0.29 |
| **wg-c (main 17bf731)** | **7.31** (pinned at the AWS per-UDP-flow cap) | 3.10 / **4.56** |
| wireguard-go | 7.01 | 2.59 / 2.77 |
| kernel WireGuard | 3.21 | 1.50 / 2.63 |

wg-c / wg-go = +4.3% (6/6, t = 6.1). However, wg-c is hitting the AWS cap of about 7.77 Gbps per UDP flow, so this is a lower bound on the gap. On the receive side wg-c uses 1.65x the CPU. Details in performance-analysis.md #56.

### Linux benchmark (#41) — EC2 c6i.2xlarge veth, iperf3 --omit 3, 30s×5 runs

> **Note (2026-09-23)**: The table below is from the environment at the time of #41 (OS, kernel and other versions were not recorded).
> Re-measuring on the same c6i.2xlarge with Ubuntu 26.04, kernel 7.0.0-1006-aws, GCC 15.2, OpenSSL 3.5.5, iperf3 3.20 and wireguard-go v0.0.20250522,
> main gave wg-c 8.09 Gbps / wg-go 8.63 Gbps = **93.6%**, below wireguard-go. In the same environment the #41 code also gave 92.1%,
> and the difference between Go 1.24 and 1.26 is 0.5%, so we believe the cause is the environment (mainly the kernel), not the code or Go.
> Next, compare the same binaries on a kernel 6.x AMI. From now on, every benchmark must record the OS, kernel, compiler and Go versions.

| Implementation | Mean | Median | Stddev | Retrans | CPU | Environment |
|------|------|--------|--------|---------|-----|------|
| **wg-c (userspace TUN)** | **9.41 Gbps** | 9.41 | 0.02 | 134 | **~20%** | GSO zero-copy, max_segs=12, SPSC 16K |
| **wireguard-go (userspace TUN)** | **7.37 Gbps** | 7.37 | 0.02 | 0 | ~17% | kernel module blacklisted |
| **Ratio** | **127.6%** | | | | | wg-c / wg-go |

### macOS benchmark (#64, 2026-09-26) — macOS 26.4, Apple M5 Max, utun + loopback, iperf3 --omit 3, 10 s × 5 interleaved rounds

| Implementation | Mean | Min | Max | CPU (13 s, sender / receiver) |
|------|------|-----|-----|---|
| **wg-c** (on macOS: single-thread path + lazy timers) | **592 Mbps** | 586 | 601 | 19.0 / 16.9 s |
| **wg-go** 0.0.20250522 | 547 Mbps | 542 | 552 | 35.1 / 29.6 s |
| **Ratio** | **108.2%** | | | CPU 54% |

main on the same day: 404 Mbps (76%). #40 (2026-05, 624 vs. 574 = 108.7%) did not record the machine model or OS, and does not reproduce on 26.x.

### Windows benchmark (#65, 2026-09-26) — Windows 11 ARM64 (26200), Parallels VM 4 vCPU, Wintun + loopback, iperf3 --omit 3, 10 s × 3 runs

| Implementation | Mean | Min | Max |
|------|------|-----|-----|
| **wg-c** (single-thread path + lazy timers + send batching / RIO deferred commit / receive batching) | **488 Mbps** | 481 | 497 |
| wg-go 0.0.20250522 | 499 Mbps | 487 | 518 |
| **Ratio** | **98%** (ranges overlap; on par) | | |

On the same VM, main (before #168) gave 184 Mbps (37%). The main causes: Wintun hands over 15.7 packets per read, but we called RIOSendEx one packet at a time (send 1.0 pkt/batch), and the receive side handled one completion per call. The threads run at 55–70% and are not saturated. The May numbers (65 vs. 94 Mbps, a different VM) are not used as a baseline.

wg-c also exceeds wireguard-go on macOS. The deciding factors:
- **sendmsg_x/recvmsg_x** (Darwin private API) — batched UDP syscalls that Go cannot use
- **SPSC tight spin 16K** — removes pipe overhead (ARM64 yield × 16384 ≈ 16µs)
- **kqueue** (replaces poll()) — native to macOS, no need to rebuild fd sets
- **MSG_TRUNC detection** — avoids wasted work on truncated packets

### Test conditions
- EC2 c6i.2xlarge: 8 vCPU (4 cores × 2 HT), Intel Xeon 8375C 2.9GHz
- Kernel WireGuard module blacklisted (`/etc/modprobe.d/wireguard-blacklist.conf`)
- wireguard-go: `WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1`, confirm `tun type tun` with `ip -d link show`
- iperf3: `--omit 3 -t 30`, cold start (process + namespace recreated every run), 10 interleaved runs
- Benchmark script: `scripts/bench_rigorous.sh`

---

## Bottleneck analysis

### perf profile (wg-c sender, #30)

| Item | CPU% | Category |
|------|------|----------|
| `raw_spin_rq_unlock_irq` (sched_yield) | 12.15% | scheduling |
| spin-wait PAUSE | 6.26% | spin-wait |
| `do_syscall_64` | 6.22% | syscall |
| `handle_softirqs` | 3.70% | kernel networking |
| `finish_task_switch` | 3.54% | context switch |
| `pthread_mutex_trylock` | 3.25% | mutex |
| `__sched_yield` + `do_sched_yield` | 4.38% | scheduling |
| OpenSSL crypto total | ~2% | encryption (not the bottleneck) |

**Total**: sched_yield-related **~26%**, mutex **~4.7%**, syscall **~6.2%**

### Pipeline statistics (wg-c, during a 12s test)

| Operation | calls | pkts | pkt/call | calls/sec | Assessment |
|------|-------|------|----------|-----------|------|
| TUN read (sender) | 102K | 4.5M | **44.3** | 8.5K/s | good |
| sendmmsg (sender) | 36K | 4.5M | **124.3** | 3K/s | good |
| **recvmmsg (receiver)** | **1,229K** | **4.5M** | **3.7** | **100K/s** | **poor** |
| TUN write (receiver) | 233K | 4.5M | **19.4** | 19K/s | room to improve |

### Per-thread CPU usage

| Thread | CPU% | Issue |
|----------|------|------|
| sequential_send | **100%** | spin-wait + sched_yield |
| sequential_recv | **97%** | spin-wait + sched_yield |
| crypto worker ×2 | 18-35% each | normal |
| mpstat %sys average | **46%** | syscall overhead dominates |

---

## What we have done (experiment history, newest first)

| # | Change | Results | Verdict |
|---|------|------|------|
| **65** | **Windows: lazy timers + send batching on the inline path + RIO deferred commit / receive batching** | On the ARM64 VM 184 → **488 Mbps**, 37% → **98% of wg-go (on par)**. Linux unchanged in #66 (x86 −0.11%, Graviton −0.33%) | **Adopted** (#169) |
| **64** | **macOS: single-thread path by default + lazy timers (macOS only) + os_sync_wait_on_address** | 404 → **592 Mbps** (+47%), 76% → **108% of wg-go** (5/5), half the CPU. The pipeline does not work: utun gives 1 pkt/read, so every hand-off becomes per-packet | **Adopted** (#168) |
| **63** | **The seq thread does crypto itself when idle** (claims INFLIGHT via CAS, protects elements with a reference count; enabled by default on Linux x86 only) | x86: **+6.3%** vs. main (ABAB 6/6), bench_rigorous **104.1% and 106.0%** (2 runs), CPU within 3 pt. On Graviton it is off by default (compiled out) and matches main (−0.03%); when on, +0.9% but small-UDP CPU +3.5–4.7 pt | **Adopted** (PR #166) |
| **41** | **GSO max_segs 16→12** | 7.09→**9.01 Gbps (+27%)**, retrans 4410→384 (-91%), ratio 99.75→**128.1%** | **Adopted** |
| **40** | **macOS kqueue + MSG_TRUNC + randomized benchmark order** | macOS: 607→**624 Mbps (+2.8%)**, ratio 106.8→**108.7%**. No Linux regression | **Adopted** |
| **37** | **SPSC 16K + spin-retry** (queue buffer enlarged 4x + SPSC push retry) | 6.90→**6.99 Gbps (+1.3%)**, outbound drops 2300→0, inbound drops 2000→30 | **Adopted** |
| **36** | **UDP GSO zero-copy send** (sendmsg UDP_SEGMENT, max_segs=16) | 3.77→**6.88 Gbps (+82%)**, on par with wg-go (100.8%), recv 50 pkt/call, GRO 20x | **Adopted** |
| 35 | Sequential hot path optimization (futex split, bind snapshot, batched keep_key_fresh, local stats) | Neutral (ratio 55.4%→55.9%); hot path atomics were not the bottleneck | **Neutral** |
| 34 | Container Lock pattern (wireguard-go style: batch-level futex wait) | 3.94→3.67 (-7%), retrans 78→1226, container pool overhead | **Rejected** |
| 33 | crypto worker inline drain (trylock + drain_rx/tx_order) | 3.94→3.90 (-1%), GRO 13.2x→11.3x, pipelining lost | **Rejected** |
| **32** | **adaptive spin+futex + recv accumulation** (SO_BUSY_POLL 200µs, PAUSE spin, futex_wait) | 3.80→**3.94 Gbps (+5%)**, recv pkt/call 3.7→9.7, retrans 351→78 | **Adopted** |
| 31 | io_uring TUN write + MSG_WAITFORONE | io_uring -16%, MSG_WAITFORONE -12% | **Rejected** |
| **30** | **Rigorous benchmark** (veth, --omit 3, 30s×10, kernel module blacklist) | wg-c 3.80 / wg-go 7.19 = **52.9%** | Earlier 107.8% is invalid |
| 29 | Spin-wait batch (PAUSE×256 in drain) | batch 4→49 pkt, ENA: 4.72 Gbps | Adopted (limited effect on veth) |
| 28 | eventfd + epoll_wait (sequential thread) | **-23% regression** (3.28 Gbps) | **Rejected** |
| 27 | Adaptive topology + vCPU-based scaling | 8 vCPU → 2+2 crypto auto | Adopted |
| 26 | HT-aware CPU affinity + parallel crypto (2+2) | +33% (1→2 workers) | Adopted |
| 25 | per-packet batch aggregation (validTailPacket) | +2-4% (less jitter) | Adopted |
| 24 | CPU affinity pinning (send→Core0-1, recv→Core2-3) | +19% | Adopted |
| 23 | Thread consolidation (7→5, crypto+sequential merged) | **-25% regression** (pipelining lost) | **Rejected** |
| 22 | recvmmsg + per-message GRO cmsg parsing | UDP GRO confirmed working | Adopted |
| 21 | recv_gro fix (UDP_GRO + recvmmsg mismatch) | Critical bug fix | Adopted |
| 20 | parallel crypto (num_recv=2) | overhead > benefit | Rejected |
| 19 | RTC architecture (SPSC fan-out + inline crypto) | +63% (MPMC → RTC) | Adopted |
| 18 | SO_BUSY_POLL (50µs) | slight recv batch improvement | Adopted |
| 17 | recv-side accumulation (GRO batch) | -14% regression | Rejected |
| 16 | eventfd notification (remove spin-wait) | regression | Rejected |
| 15 | switch to recv_gro (recvmsg) | GRO has no effect on veth | Reference |
| 9 | io_uring TUN write batching | syscall overhead too small to matter | Rejected |
| 0 | Lock-free Pool (Treiber stack) | mutex removed | Adopted |

### Rejected for good (no need to retry)

- io_uring (TUN write / SQPOLL / multishot recv) — syscall overhead is too small to matter (#9)
- eventfd + epoll — slower than sched_yield (#16, #28)
- Thread consolidation — -25% from lost pipelining (#23)
- Lock-free MPMC (Vyukov + eventfd) — eventfd overhead makes it zero-sum
- Fewer crypto workers — becomes crypto-bound and gets worse
- M:N threading — poor cost/benefit for the implementation effort
- DPDK / AF_XDP — conflicts with the portability requirement
- crypto worker inline drain — lost pipelining makes GRO worse (#33)
- Container Lock (wireguard-go style) — -7% from container pool + biased counter overhead (#34)
- Sequential hot path micro-opt — futex split, rwlock removal and fewer atomics make no measurable difference (#35)

### Key lessons

1. **Pipelining must be kept** — running crypto and I/O in parallel yields 25-30% of the throughput (#23)
2. **futex > sched_yield > eventfd** — futex (50µs timeout) + adaptive spin is best (#32); eventfd is -23% (#28)
3. **Encryption is not the bottleneck** — 2% in perf with OpenSSL AVX-512 (#20, #26)
4. **Reducing syscalls is key** — larger batch sizes are the biggest source of improvement (#29, #32)
5. **The sequential thread is a serialization point** — every packet passes through one thread; this is the fundamental limit (#32)
6. **Hot path micro-opts have no effect** — futex split, rwlock removal and fewer atomics are orders of magnitude smaller than the I/O syscalls (#35)
7. **Tuning UDP GSO max_segs is key** — at 44 segs the bursts are too large: retrans 187K and 4.4 Gbps. At 16 segs: retrans 2K and 6.88 Gbps (#36)
8. **GSO → GRO chain effect** — GSO on the sender dramatically improves UDP GRO on the receiver (pkt/call 9→51, coalesce 8x→20x) (#36)
9. **Retrans is the biggest enemy of throughput** — retrans 187K gives 4.4 Gbps → retrans 2K gives 6.88 Gbps. Burst control gives +56% (#36)
10. **Remaining retrans (~400/run) is OS scheduling jitter** — it happens even with drops=0. SCHED_FIFO is a -23% regression. BBR makes it worse. wg-go also occasionally records retrans=696. A structural limit of userspace VPNs (#37)
11. **On ARM64, OpenSSL AEAD is faster than libsodium** — even libsodium master's (unreleased) NEON ChaCha20 gives 8.9 Gbps vs. OpenSSL 12.9 Gbps (M5 Max, 1420B). Poly1305 has no NEON version and needs 2 passes. x86_64 not yet measured (#43)
12. **BoringSSL fused asm removed** — +2.1% over OpenSSL (within noise) while adding 3,024 lines of asm to the audit scope. AEAD has two backends: OpenSSL EVP / libsodium (#44)
13. **127.6% does not reproduce** — back on the same kernel 6.17 and with the #41 code, it is 97.8%. Do not use it as a baseline (#45)
14. **wg-c's slowness is the number of "sleep and get woken" cycles** — about 90% of writes are wake-up eventfds (#46); most futex calls are needless timer wake-ups and the replay-protection mutex (#47). CPU idle rate is about the same in every build; what matters is the number of wake-ups and migrations between CPUs (#51)
15. **VM (aarch64) results can flip on x86** — the timer fix was +5.3% on the VM and −2.3% on EC2 x86 (#48, #50). Make performance decisions with interleaved runs on EC2 x86
16. **Adding per-packet work to a serial thread is a loss** — moving the replay check to the sequential thread is −2.1% (#49)
17. **Adaptive spin in the sequential thread gives +3.0%** — context switches −18%, migrations between CPUs −23%, close to the wireguard-go level. 104.5% of wg-go in bench_rigorous on the same host (one host only) (#51)
18. **What worked was the FUTEX_WAIT timeout (50µs → 1ms)** — the extra adaptive spin is not needed (#54). main after the merge: x86 +2.9%, Graviton +8.9%. On the same host, x86 100.1%, Graviton 120.3% (#55)
19. **Measure changes that affect arm64 on Graviton too** — acq_rel on prev_queue changes the instructions on arm64, but it did not lose on Graviton. The size of the effect differs between x86 and Graviton (#55)
20. **In an AWS two-host setup, about 7.77 Gbps per UDP flow is the cap** — a WireGuard tunnel is a single UDP flow, so if the number levels off, suspect the cap. In the two-host setup wg-c exceeds wg-go by +4.3%, but since it is pinned at the cap this is a lower bound on the gap (#56)
21. **The safety fixes went in with no hot path cost** — peer lifetime management (#141, one fence per reader section) and the send queue fix (#144) show no difference in interleaved runs on either x86 or Graviton (|t| < 2). A single borderline difference should be re-measured on a different instance before drawing conclusions (#57)
22. **Reading the current keypair under the lock does not change throughput** — #146 (the TUN reader and the two sequential threads take the peer lock once per batch) shows no difference on x86 or Graviton. The CPU increase seen with 200 B UDP on Graviton did not reproduce when re-measured 5 times each (#58, #59)
23. **Bound the crypto worker's SPSC spin by time too** — the 512 PAUSEs on Linux took about 20 µs on x86. Changing to 2 µs (1 µs on arm64) cut c6i CPU by 3 points at TCP 1 Gbps and 17 points at 200 B UDP, with no change in throughput. The remaining gap between x86 and wg-go (about 18 points) is kernel wake-ups and context switches (#60)
24. **When measuring the "default", use `env -u VAR`, not `VAR=""`** — OpenSSL reads an empty OPENSSL_ia32cap as "disable everything". This mix-up made us wrongly conclude that AVX-512 was slow (#60)
25. **Not waking the timers (lazy timers) lowers max throughput because of placement** — pinning each thread to its own CPU makes the gap disappear on Graviton, and on x86 lazy exceeds main by 13.6%. Halting (idle=poll, haltpoll) is irrelevant. The direction is lazy timers + explicit placement. However, the current fixed assignment loses to unpinned main, so the assignment needs to be searched (#61)
26. **Static assignments cannot beat main on x86** — lazy + each of 4 pinning schemes is −8 to −26% vs. unpinned main. On Graviton, which has no HT, lazy + one thread per CPU matches main with CPU −9 / −14 points. The high x86 throughput comes from dynamic placement shaken up by timer wake-ups, and cannot be reproduced statically (#61)
27. **Max throughput on x86 is bound by stage hand-offs, not CPU** — even at max throughput 30% of the 8 vCPUs are idle and no thread exceeds 70%. wireguard-go runs one thread close to 100% and gets 4% more. Next: reduce hand-offs (the sequential thread doing its own crypto, spinning at high rates) (#62)
28. **The seq thread taking over just 1–2% gives x86 +6%** — during max throughput, the elements the seq thread processed itself were only 1.4–1.6% of the total. There are two hypotheses for why (it picks up the head that workers have not yet dequeued / processing even one item skips a sleep round trip), not yet distinguished. At low rates, the seq thread instead grabs work first and the workers come up empty; on Graviton, where wake-ups are cheap, CPU for 200 B UDP rises 3–5 pt (#63)
29. **On macOS, stage hand-offs happen per packet** — utun gives 1 packet per read, so the wake-ups and timer resets that happened once per 128 packets on Linux happen once per packet. The pipeline is slower than a single thread and uses 2.5x the CPU; timer signals alone take 16% of the send thread. Single thread + lazy timers gives wg-go +8% at half the CPU (#64)

---

## What is next (roadmap)

### ~~Phase A: enable io_uring~~ — Rejected (#31: -16% regression)

**Status**: tested → **Rejected**
**Results**: 3.85 → 3.23 Gbps (-16%). io_uring submit/completion overhead is heavier than a per-packet write().
Same conclusion as #9. io_uring is a poor fit for TUN write.

### ~~Phase B: recvmmsg MSG_WAITFORONE~~ — Rejected (#31: -12% regression)

**Status**: tested → **Rejected**
**Results**: 3.85 → 3.39 Gbps (-12%). MSG_WAITFORONE after poll(POLLIN) behaves the same as MSG_DONTWAIT.
recv pkt/call 3.7 → 3.2 (no improvement).

### Phase C-1: adaptive spin + futex + recv accumulation — Adopted (#32: +5%)

**Status**: tested → **Adopted**
**Results**: 3.80 → 3.94 Gbps (+5%), recv pkt/call 3.7 → 9.7, retrans 351 → 78
**Changes**:
- `sched_yield()` → PAUSE × 1024 spin + futex_wait (50µs timeout)
- Crypto workers wake the sequential thread with `futex(FUTEX_WAKE)`
- `SO_BUSY_POLL` 50µs → 200µs
- Accumulation spin in optimistic recv when there are few packets

### ~~Phase C-2: crypto worker inline drain~~ — Rejected (#33: -1% regression)

**Status**: tested → **Rejected**
**Results**: 3.94 → 3.90 Gbps (-1%), GRO 13.2x → 11.3x, pipelining lost.
When a crypto worker runs the drain, it blocks in write() and delays the next decrypt batch.
Batches do not accumulate enough and GRO coalescing gets worse. Same lesson as #23.

### Phase C-3: UDP GSO send — Adopted (#36: +82%)

**Status**: tested → **Adopted**
**Results**: 3.77 → **6.88 Gbps (+82%)**, on par with wg-go (100.8%)

**Changes**:
1. Added a `get_gso_stats` callback to `wg_bind_ops_t` (stats bridge)
2. GSO send: `sendmsg(UDP_SEGMENT)` + zero-copy iovec
3. **max_segs = 16** is optimal (44 makes retrans explode; 16 gives retrans 2K + max throughput)

**Finding**: tuning the GSO batch size (max_segs) is extremely important:
- max_segs=44: 4.41 Gbps, retrans 187K (bursts too large)
- max_segs=16: **6.88 Gbps**, retrans 2K (best balance of burst and throughput)
- no GSO: 3.77 Gbps, retrans 235 (syscall overhead dominates)
- **Remove write_mu**: the TUN fd is thread-safe (Linux), so the mutex may not be needed
- **Asynchronous TUN write**: hand write() off to a separate thread to free the sequential thread

### Phase D: kernel mode support (medium to long term)

**Status**: not started
**Overview**: like wireguard-go, work with the Linux kernel WireGuard module (`wireguard.ko`).
Create the kernel interface with `ip link add type wireguard`; userspace handles configuration only.
With the kernel module, 7.19 Gbps (= on par with wireguard-go) is achievable right away.

---

## Position in the WireGuard ecosystem

### Official projects

| Project | Language | Role |
|---|---|---|
| **wireguard-linux** (kernel module) | C | In-kernel WireGuard data path (fastest) |
| **wireguard-go** | Go | Userspace implementation (official reference) |
| **wireguard-tools** | C | `wg` / `wg-quick` configuration CLI only (no encryption) |

### noisetun (runetale, this project)

**A full userspace WireGuard implementation in C**.
The goal is to reimplement wireguard-go in C and exceed it in performance.

- TUN device creation, UDP sockets, ChaCha20-Poly1305 encryption/decryption, Noise IK handshake
- UAPI protocol compatible → configurable with the standard `wg` command
- Supports Linux / macOS / Windows (cross-platform)

### wireguard-go dual-mode operation

wireguard-go has **two modes**:

```
wireguard-go wg0
  ↓
Is wireguard.ko available in the kernel?
  ├── YES → "ip link add wg0 type wireguard" (create kernel interface)
  │         data path handled in the kernel (wireguard-go is only a config daemon)
  │
  └── NO  → create TUN device (userspace fallback)
            encryption/decryption handled in the Go runtime
```

| Mode | Data path | Use |
|---|---|---|
| **Kernel mode** | `wireguard.ko` | Linux (built in since kernel 5.6+) |
| **Userspace mode** | TUN + Go | macOS, Windows, older Linux |

noisetun plans to implement the same dual mode (Phase D).
If the kernel module is available it uses it; otherwise it processes in userspace.

---

## Environment

### EC2 c6i.2xlarge
- Two instances, S1 and S2 (public IPs changed per run and are not recorded here)
- 8 vCPU (4 cores × 2 HT), Intel Xeon 8375C 2.9GHz
- Kernel: 6.17.0-1007-aws
- WireGuard kernel module: blacklisted
- wireguard-go: `/usr/local/bin/wireguard-go`
- wg-c source: `~/noisetun/`
- Build: `cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS='-march=native'`

### Benchmark commands
```bash
# Rigorous test (10 interleaved runs, 30 seconds)
sudo scripts/bench_rigorous.sh ./build-release/tools/wg-c wireguard-go 10 30

# Quick test (wg-c only, 10 seconds)
sudo scripts/bench_veth_iperf3.sh ./build-release/tools/wg-c 10

# wireguard-go only
sudo scripts/bench_veth_wg_go.sh wireguard-go 10
```

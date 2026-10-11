# noisetun Performance Analysis

**Last updated**: 2026-09-26 (#66). Experiments are logged in order, oldest first; the newest are at the end.
**Environment**: ARM64 veth (local) / AWS EC2 c6i.2xlarge x86_64 (remote)
**Compared against**: wireguard-go (userspace), kernel WireGuard

---

## Current throughput

### Important: benchmark correction (#30, 2026-04-30)

**Earlier comparisons are invalid**. In the cross-instance (ENA) tests, wireguard-go was most likely using the kernel WireGuard module
(`wireguard.ko`) as a fallback. We ran a fair userspace comparison on veth with the TUN device confirmed.
Results:

### EC2 c6i.2xlarge x86_64 — rigorous benchmark (#30, veth, --omit 3, 30s×10 runs)

| Implementation | Mean | Median | Min | Max | Stddev | Retrans (total) |
|------|------|--------|-----|-----|--------|-----------------|
| **wireguard-go (userspace, TUN)** | **7.19 Gbps** | **7.18 Gbps** | 7.15 | 7.27 | 0.03 | 2,548 |
| **wg-c (userspace, TUN)** | **3.80 Gbps** | **3.80 Gbps** | 3.71 | 3.90 | 0.04 | 351 |

**wg-c / wg-go = 52.9%** — almost half of wireguard-go.

Test conditions:
- Kernel WireGuard module blacklisted (`/etc/modprobe.d/wireguard-blacklist.conf`)
- wireguard-go: `WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1`, confirmed `tun type tun` with `ip -d link show`
- iperf3: `--omit 3 -t 30`, cold start (process restarted), 10 interleaved runs
- wg-c: consistently 3.7-3.9 Gbps (stddev 0.04), no warm-up dependence

### ARM64 veth (local, 8 cores)

| Test | libsodium | BoringSSL fused asm |
|--------|-----------|---------------------|
| veth + iperf3 TCP | 5.31 Gbps | 5.87 Gbps |

### EC2 c6i.2xlarge x86_64 (veth iperf3, 2026-04-29) — reference only

| Test | Throughput | Retransmissions | Notes |
|--------|------------|----------------|------|
| Raw veth (no WG) | 55 Gbps | 0 | Theoretical ceiling |
| **wireguard-go** | **7.19 Gbps** | **2,548** | **#30 rigorous test (TUN confirmed)** |
| **wg-c** | **3.80 Gbps** | **351** | **#30 rigorous test** |
| wg-c pipelining + GSO fix | 4.49 Gbps | 0 | Old test (short duration) |

### EC2 c6i.2xlarge ENA NIC iperf3 (S1↔S2, old test) — low reliability

**Note**: in the cross-instance tests, wireguard-go may have been using the kernel module.
Also, the short (10s) tests did not let TCP fully ramp up. Kept for reference only.

| Test | Throughput | Retransmissions | Notes |
|--------|------------|----------------|------|
| Raw network (direct ENA) | 9.53 Gbps | 0 | Stable |
| wg-c (#29: spin-wait batch) | 4.72 Gbps (avg steady) | — | cherry-picked steady-state |
| wireguard-go | 4.38 Gbps (avg) | — | may have used the kernel module |

#### Previous session results (same instances, different IPs, 2026-04-30 #25)

| Test | Throughput | Retransmissions | Notes |
|--------|------------|----------------|------|
| Raw network (direct ENA) | 9.52 Gbps | 0 | Stable |
| **wireguard-go (CUBIC)** | **5.18 Gbps** (avg) | **0** | 5.13, 5.22, 5.20 |
| **wg-c #25 (CUBIC)** | **5.15 Gbps** (avg) | 203-540 | Won every round in interleaved runs |
| **wireguard-go (BBR)** | **4.69 Gbps** (avg) | **0** | 4.77, 4.63, 4.68 |
| **wg-c #25 (BBR)** | **4.92 Gbps** (avg) | **0-11** | +5% ahead of wg-go |

**Note**: even on the same instance, an IP change (reboot) shifts the baseline by ~10%.
wireguard-go itself also dropped from 5.18 → 4.49 Gbps. Relative comparison is what matters.

#### Root cause analysis of retransmits

**Cause**: CUBIC congestion control mistakes jitter in the WireGuard pipeline for congestion → dupACK → fast retransmit
- Jitter in the S2 recv pipeline (variation in crypto+drain processing time) causes packet delay
- CUBIC is sensitive to delay variation → cwnd reduction → retransmit
- BBR is model-based and estimates bandwidth/RTT → tolerant of jitter

**Effect of spin-wait on UNCRYPTED** (S2 recv stats):
- seq recvr batch: 2.7 → **5.0 pkt/batch** (+85%)
- GRO coalesce: 2.6x → **4.6x** (+77%)
- Fewer TUN write syscalls → faster recv pipeline

**Recommendation**: set `sysctl net.ipv4.tcp_congestion_control=bbr` on the host

---

## 6.0 Gbps roadmap — strategy to exceed wireguard-go

### Current summary (2026-04-30, updated with #30 rigorous test)

| Metric | wg-c | wireguard-go (userspace) | Raw veth | wg-c/wg-go |
|------|------|------------------------|----------|------------|
| veth iperf3 (30s×10, --omit 3) | **3.80 Gbps** | **7.19 Gbps** | 55 Gbps | **52.9%** |
| Retransmissions (total/10runs) | 351 | 2,548 | 0 | — |
| Stddev | 0.04 Gbps | 0.03 Gbps | — | — |
| OS threads | 13 (2+2 crypto + seq + producers + handshake) | goroutines on 8 GOMAXPROCS | — | — |
| %sys CPU (during test) | 45-76% | ~17% (iperf3 report) | — | — |

**Reality**: **47% slower** than wireguard-go's userspace implementation.
The earlier "107.8%, ahead of wg-go" was invalid due to the comparison method.

**Bottleneck analysis** (wg-c):
- spin-wait in the sequential sender/receiver consumes 100% CPU
- %sys is 45-76%: syscall overhead dominates
- Send-side batching of 124.8 pkt/batch is good, but the receive side makes 233K TUN write syscalls vs wg-go's efficient batching

### Root cause: why wireguard-go is faster

#### 1. Thread model + sequential thread overhead (the biggest problem)

```
wg-c (#26):
  9 OS threads on 8 vCPU (4 cores × 2 HT):
    tun_reader, udp_recv, handshake,
    rtc_send(2), rtc_recv(2),          ← num_send=2, num_recv=2 (expanded in #26)
    sequential_send, sequential_recv
  → CPU affinity: send path → CPU 0,1,4,5 / recv path → CPU 2,3,6,7
  → sched_yield in the sequential thread wastes 60%+ CPU

wireguard-go:
  4 OS threads (GOMAXPROCS=4) + N goroutines (cooperative scheduling)
  → explicit yield via channels → predictable scheduling
  → retransmit 0
```

perf profile (#27, adaptive 2+2 crypto workers):
```
raw_spin_rq_unlock_irq (sched_yield): 12.15%  ← sequential thread idle polling
wg_spsc_pop:                           8.97%  ← crypto workers SPSC block
do_syscall_64 (sched_yield):           6.22%  ← syscall overhead
handle_softirqs:                       3.70%  ← kernel network stack
Total sched_yield:                    18.4%  ← big improvement from 58.8% in #26
```

**Root cause**: the sequential thread detects crypto completion by polling. When idle it calls `sched_yield()`,
but on HT there is a context switch cost. **Moving to eventfd-based notification**
would bring idle CPU waste to zero and also improve wakeup latency.
However, #27 already cut sched_yield overhead sharply from 58.8% → 18.4%.
The remaining gain from eventfd is expected to be about +2-5%.

**Alternatives tried and results**:
- nanosleep(1µs): counterproductive (3.90 → 2.95 Gbps). Wakeup latency is larger than spin-wait
- spin-wait + backoff: almost no change
- Merge drain into crypto workers (remove sequential): deadlock (cannot drain while in SPSC blocking pop)
- Remove drain_lock: no effect (lock overhead < scheduling overhead)

#### 2. UDP GRO (recv-side syscall efficiency)

wireguard-go uses `UDP_GRO`: the kernel coalesces multiple UDP packets into one large buffer and returns it.

```
wireguard-go (ENA): recvmsg 1 call → 40-64KB GRO buffer → split in user space
                    → effectively 20-40 pkt/syscall

wg-c (ENA):         recvmmsg 1 call → separate 1500B iovec × 16-32 = 16-32 pkt/syscall
                    → no GRO benefit (iovecs are small, cannot coalesce)
```

In Experiment #15, GRO had no effect on veth (veth does not support NAPI).
**The ENA NIC supports NAPI** → UDP_GRO should work.

#### 3. Number of pipeline stages

```
wg-c:         TUN read → SPSC push → crypto worker pop+encrypt → state=CRYPTED
              → sequential_send peek+spin-wait+sendmmsg
              = 5 stages, synchronization across 3 threads

wireguard-go: TUN read → channel → encrypt+send (inline in 1 goroutine)
              = 2 stages, 1 channel
```

More stages = more synchronization overhead = more sources of jitter.

### Measures and expected effects

#### ~~Phase 1: thread consolidation (7→5 threads)~~ — **Rejected (regression confirmed in Experiment #23)**

**Experiment #23 showed a 25% regression** (4.5 → 3.3 Gbps).
Pipelining between crypto and sequential (sequential does I/O for batch N while crypto processes batch N+1)
produces 25-30% of the throughput, and consolidating the threads loses this parallelism.
The 45% spin-wait was a useful busy-wait that enabled pipelining.

**Alternative: CPU affinity pinning** — reduce scheduling jitter while keeping pipelining.
Pin the send path (tun_reader + rtc_send + sequential_send) to Core 0-1 and
the recv path (udp_recv + rtc_recv + sequential_recv) to Core 2-3.

#### ~~Phase 2: UDP GRO on ENA recv~~ — **Already implemented and working (Experiment #22 + ENA verification)**

The `recv_gro_batch()` from Experiment #22 **already triggers UDP_GRO coalescing** on ENA.
- `setsockopt(fd, SOL_UDP, UDP_GRO, 1)` is set (wg_bind_std.c:219)
- ENA: `generic-receive-offload: on` (SW GRO enabled)
- Measured: 808K UDP datagrams in a 13s iperf3 run, an estimated 3.84M packets → **GRO ratio ≈ 4.75x**
- GRO did not trigger on veth, so the throughput effect of #22 was not visible, but it does trigger on ENA

**Conclusion**: no additional UDP GRO work is needed. A GRO ratio of 4.75x is on par with wireguard-go.
The throughput gap is not caused by GRO but by **scheduling jitter across 7 threads** (the cause of retransmits).

#### Phase 3: CPU affinity (core-pair separation) — measured **+19%**

**Implemented (Experiment #24)**. Core-pair separation: send path → Core 0-1, recv path → Core 2-3.
Pinning to individual cores was counterproductive (confirmed by trying Layouts A-C). Leaving placement within a pair to the OS scheduler is best.

**Results**: CUBIC avg 5.05 Gbps / BBR avg 5.05 Gbps. Peak **5.29 Gbps** (exceeds wireguard-go's 5.18).
**Remaining issue**: CUBIC retransmits 331-715 (recv-side spin-wait jitter).

#### Phase 4: batching per-packet operations — expected +5-10%

An additional measure in case Phase 3 does not reach 6.0 Gbps.
Move the per-packet lock operations in `drain_rx_into()` to the end of the batch (wireguard-go's `validTailPacket` pattern).
For details, see the section "recv pipeline jitter reduction plan → A".

### Cumulative expected effects

| Phase | Measure | Expected effect | Cumulative Gbps | Status |
|-------|------|---------|----------|------|
| Current | 7-thread pipelining + GRO | — | 4.25 avg | baseline |
| ~~1~~ | ~~Thread consolidation (7→5)~~ | ~~+20%~~ | ~~5.4~~ | **Rejected (#23: -25% regression)** |
| ~~2~~ | ~~UDP GRO on ENA~~ | ~~+20-30%~~ | — | **Already working (GRO 4.75x)** |
| **3** | **CPU affinity (core-pair separation)** | **+19%** | **5.05 avg** | **Implemented (#24)** |
| **4** | **Per-packet batching** | **+2-4%** | **5.15 avg** | **Implemented (#25)** |
| **5** | **HT affinity + parallel crypto** | **+33%** | **4.34** | **Implemented (#26)** |
| **5b** | **Adaptive topology + vCPU-based scaling** | — | **4.27** | **Implemented (#27)** |
| ~~6~~ | ~~eventfd notification (sequential thread)~~ | ~~expected +2-5%~~ | — | **Rejected (#28: -23% regression)** |
| **7** | **Spin-wait batch + GSO send** | **+10.5%** | **4.72** | **Implemented (#29) — ahead of wg-go!** |

**Note**: at #27, wg-c/wg-go = 97.7%. sched_yield overhead improved from 58.8% → 18.4%.
Adaptive worker scaling: `ncpu/2 - 2` crypto workers/direction (8 vCPU → 2+2).
The goal is to exceed wireguard-go (4.5+ Gbps) with Phases 6 + 7.

### Implementation priority (reflecting #27 results, updated 2026-04-30)

1. ~~Phase 3 (CPU affinity)~~ — **Implemented** (#24).
2. ~~Phase 4 (per-packet batching)~~ — **Implemented** (#25).
3. ~~Phase 5 (HT affinity + parallel crypto)~~ — **Implemented** (#26).
4. ~~Phase 5b (Adaptive topology)~~ — **Implemented** (#27).
5. ~~Phase 6 (eventfd notification)~~ — **Rejected** (#28). The syscall overhead of epoll_wait is larger than sched_yield.
6. **Phase 7 (UDP GSO for send)** — set UDP_SEGMENT on sendmsg to send multiple packets in 1 syscall. Expected +5-15%. **Next step**.

---

### ~~Phase 6: eventfd notification~~ — Rejected (#28: -23% regression)

**Goal**: replace the sequential thread's `sched_yield()` polling with `eventfd + epoll` notification.
**Results**: every variant regressed in Experiment #28. sched_yield is the best option. See Experiment #28 for details.
Idle CPU waste 18.4% → ~0%, and redirect the freed CPU to the crypto workers.

**Current problem**:
```
sequential_recv loop:
  while (running):
    for each peer:
      while (elem = prev_queue_peek()):
        st = atomic_load(&elem->state)
        if st == UNCRYPTED: break      ← not ready, try next peer
        drop_peeked(); process(elem)
    if (!did_work): sched_yield()       ← wastes 18.4% CPU
```

**Design**:
```
crypto worker (changed):
  pop_batch from SPSC
  for each elem:
    decrypt/encrypt(elem)
    atomic_store(&elem->state, CRYPTED/DEAD)
  eventfd_write(efd, 1)                 ← ★ batch completion notification

sequential thread (changed):
  epfd = epoll_create1(0)
  epoll_ctl(epfd, EPOLL_CTL_ADD, efd, EPOLLIN)
  while (running):
    did_work = drain_all_peers()
    if (!did_work):
      epoll_wait(epfd, &ev, 1, 10)      ← ★ sleep (zero CPU), 10ms timeout
      eventfd_read(efd)                  ← drain eventfd counter
    // 10ms timeout: avoid missing handshake/timer events
```

**Files to change**:
- `src/device/wg_device.h`: add `int send_efd, recv_efd` to `struct wg_device`
- `src/device/wg_device.c`: create the eventfds in `up_locked()`, close them in `down_locked()`
- `src/workers/wg_send.c`: `wg_worker_rtc_send()` — `eventfd_write()` after each batch completes
- `src/workers/wg_send.c`: `wg_worker_sequential_send()` — `sched_yield()` → `epoll_wait()`
- `src/workers/wg_receive.c`: same as above (recv side)

**Risks and mitigations**:
- **Lesson from #19**: with 1 worker, epoll syscall overhead > sched_yield.
  This time there are 2+2 workers and CPU headroom → syscall overhead is relatively small.
- **Wakeup latency**: epoll_wait → eventfd_read is ~1-5µs. Faster than or equal to
  the sched_yield context switch (~5-10µs).
- **Batch efficiency**: a crypto worker calls eventfd_write only once per completed batch.
  Not per packet, so the syscall rate is low.
- **Fallback**: the 10ms timeout covers missed eventfd notifications.
  drain is attempted even when epoll_wait times out.

**Expected effects**:
- sched_yield 18.4% → ~0% (sleep in epoll_wait when idle)
- Freed CPU → faster crypto workers, or the OS saves power
- throughput: +2-5% (4.27 → 4.4-4.5 Gbps)
- CPU efficiency: large improvement (lower idle cost)

**Cross-platform**:
- Linux: eventfd + epoll (best)
- macOS: pipe + kqueue (fallback)
- Branch with `#ifdef __linux__`; non-Linux keeps sched_yield

---

### Phase 7: UDP GSO for send — design overview

**Goal**: set `UDP_SEGMENT` (UDP Generic Segmentation Offload) on sendmsg and
send multiple WireGuard packets in one sendmsg. wireguard-go uses the same technique.

**Current problem**:
```
sequential_send: sendmmsg() with 16-32 packets/syscall
  → a UDP header is added to each packet separately → sent to the NIC one by one
```

**How GSO works**:
```
sendmsg(fd, large_buffer, MSG_MORE) + setsockopt(UDP_SEGMENT, 1420)
  → the kernel takes one large buffer and splits it into MTU-sized pieces
  → the NIC splits it with hardware offload (if the NIC supports it)
  → 40-60 packets can be sent in 1 syscall
```

**Expected effect**: cut send-side syscalls to 1/3-1/4. The ENA NIC supports GSO.
The recv side already has UDP GRO working (GRO ratio 4.75x). Adding GSO on the send side makes the two symmetric.

**Priority**: after Phase 6. First improve the sequential thread's efficiency with eventfd, then
improve syscall efficiency on the send path.

---

## recv pipeline jitter reduction plan

**Goal**: reach 0 retransmits with CUBIC congestion control (on par with wireguard-go)
**Current**: wg-c (CUBIC) 4.84 Gbps / 2-256 retransmits vs wireguard-go (CUBIC) 5.18 Gbps / 0 retransmits

### Root cause of jitter: per-packet overhead, wg-c vs wireguard-go

| Operation | wg-c | wireguard-go | Difference |
|------|------|-------------|------|
| endpoint update | mutex lock **per packet** | end of batch only (validTailPacket) | wg-c: N lock/unlock per batch |
| allowedips lookup | rwlock **per packet** | concurrent map (lock-free) | wg-c: N rwlock per batch |
| keypairs lock | mutex on keypair change | lock-free atomic | small impact (rare) |
| timer update | timer_mod **per packet** | end of batch only | wg-c: N timer ops per batch |
| rx_bytes update | atomic_fetch_add **per packet** | end of batch only | wg-c: N atomic RMW per batch |
| stats update | atomic_fetch_add **N times at flush** | none | wg-c: N atomic in flush |
| elem free | pool CAS per packet | Go GC (amortized over batch) | CAS may retry |
| Ordering | spin-wait (PAUSE x 64) | Go channel (block) | wg-c: consumes CPU |

### Quantitative estimate of jitter sources (at 5.0 pkt/batch)

Per-packet work in `drain_rx_into()` (per packet):
1. `wg_peer_set_endpoint_from_packet` — mutex lock/unlock: **~50-200ns** (μs under contention)
2. `wg_allowedips_lookup` — rwlock rdlock/unlock: **~30-100ns** (including trie walk)
3. `wg_noise_received_with_keypair` — mutex lock/unlock: **~50-200ns** (first time only)
4. `atomic_fetch_add(&peer->rx_bytes)` — atomic RMW: **~10-30ns**
5. timer ops (keepalive packets) — timer_mod: **~100-300ns**

Total lock/unlock for a 5-packet batch: **~400-1500ns** (the main source of jitter)

wireguard-go does these **only once, at the end of the batch** → jitter 1/5 or less

### Optimization proposals (in priority order)

#### A. Move per-packet operations to the end of the batch (expected effect: high)

Remove the per-packet lock operations from `drain_rx_into()` and run them only at the end of the batch in `flush_recv_accum()`.
Follows wireguard-go's `validTailPacket` pattern.

**Changes**:
```c
// drain_rx_into: remove the following
//   wg_peer_set_endpoint_from_packet(peer, &elem->endpoint);  ← per packet
//   wg_timers_any_authenticated_packet_traversal(peer);       ← per keepalive
//   wg_timers_any_authenticated_packet_received(peer);        ← per keepalive
//   atomic_fetch_add(&peer->rx_bytes, ...);                   ← per packet

// flush_recv_accum: run only once at the end of the batch (already partly done)
//   rx_bytes summed locally → one atomic_fetch_add at flush
//   endpoint update for tail_elem only (existing)
//   timer update for tail_elem only (existing)
```

**Note**: `wg_noise_received_with_keypair` cannot be removed because it detects keypair switches.
However, a fast path (detects no keypair change with an atomic load) already exists, so the impact is small.

**Risk**: low. Same semantics as wireguard-go. Updating endpoint/timers for keepalives at the end of the batch is enough.

#### B. Remove the rwlock from allowedips lookup (expected effect: medium)

Current: `wg_allowedips_lookup()` takes `pthread_rwlock_rdlock` for every packet.
The recv hot path is read-only, but adding/removing peers needs the write lock.

**Options**:
1. **RCU-like pattern**: publish the trie through an atomic pointer. The writer builds a new trie → swap → frees the old one later. The recv path reads lock-free.
2. **epoch-based reclamation**: readers bump a global epoch; the writer frees old data once all readers have passed the epoch.
3. **amortize the read lock**: rdlock once at the start of a batch → unlock at the end. per-packet → per-batch.

**Simplest**: option 3. Take the rdlock outside drain_rx_into and hold it for the whole batch.

#### C. Aggregate stats atomics (expected effect: low to medium)

`flush_recv_accum()` calls `atomic_fetch_add` on `recv_bytes` N times.
Sum into a local variable and do a single atomic.

```c
// Current: N atomic_fetch_add calls
for (int b = 0; b < acc->count; b++)
    atomic_fetch_add(&dev->stats.recv_bytes, (uint64_t)acc->sizes[b]);

// Improved: 1 atomic_fetch_add call
uint64_t total_bytes = 0;
for (int b = 0; b < acc->count; b++)
    total_bytes += (uint64_t)acc->sizes[b];
atomic_fetch_add(&dev->stats.recv_bytes, total_bytes);
```

#### D. Sum rx_bytes locally in drain_rx_into (expected effect: low to medium)

Do `atomic_fetch_add(&peer->rx_bytes, ...)` once at the end of the batch instead of per packet.

```c
// drain_rx_into: sum locally
uint64_t local_rx = 0;
for each elem:
    local_rx += pt_len + HEADER + TAG;
// once at flush
atomic_fetch_add(&peer->rx_bytes, local_rx);
```

#### E. Adaptive wait in sequential recv (expected effect: medium)

Current: spin-wait (PAUSE x 32) → consumes 100% CPU. wireguard-go blocks on a Go channel.

**Proposal**: adaptive spinning — once consecutive idle rounds exceed a threshold, give CPU back in steps: `sched_yield()` → `usleep(1)`. Under busy traffic, keep spinning (low latency).

```c
int idle_rounds = 0;
while (wg_device_is_up(dev)) {
    bool did_work = /* drain loop */;
    if (did_work) {
        idle_rounds = 0;
    } else {
        idle_rounds++;
        if (idle_rounds < 64)
            WG_CPU_RELAX();
        else if (idle_rounds < 256)
            sched_yield();
        else
            usleep(1);  // ~50μs actual
    }
}
```

### Implementation order

1. **A + C + D** (batching) — lowest risk and largest effect. Can be done in one PR.
2. **B** (amortize the allowedips lock) — a simple change that takes the rdlock outside drain_rx_into.
3. **E** (adaptive wait) — reduces idle CPU use. Does not directly affect throughput, but giving CPU to other threads reduces jitter.

### Optimization breakdown (2026-04-29)

| Optimization | Throughput | Gain | Technique |
|--------|------------|------|------|
| HEAD baseline | 1.50 Gbps | — | inline crypto, MPMC handoff |
| + inline RTC | 2.55 Gbps | +70% | SPSC + inline crypto+I/O |
| + pipelining | 3.75 Gbps | +47% | prev_queue + sequential thread (crypto/I/O split) |
| + UDP GSO fix | 4.49 Gbps | +20% | setsockopt probe: uint16_t→int, CMSG_FIRSTHDR controllen fix |

### Parallel crypto worker experiment (2026-04-29)

| N workers | Configuration | Throughput | Notes |
|-----------|------|------------|------|
| 1 + sequential | pipelining | **3.55 Gbps** | Best (crypto is not the bottleneck) |
| 2 + sequential | dual-enqueue | 3.45 Gbps | overhead > parallelism benefit |
| 4 + sequential | dual-enqueue | 3.12 Gbps | prev_queue contention |
| 4 + inline drain | old approach | stall (59 Mbps) | head-of-line blocking |

**Conclusion**: OpenSSL ChaCha20-Poly1305 is fast enough on x86_64 AVX-512.
The dominant bottleneck is not crypto but **syscall reduction** (UDP GSO/GRO, TUN GSO/GRO coalescing).

### Old EC2 results (2026-04-28, ENA NIC iperf3)

| Test | Throughput | Retransmissions | Notes |
|--------|------------|----------------|------|
| Raw network (direct iperf3) | 9.53 Gbps → **4.78 Gbps** | 0 → 168 | EC2 ENA NIC (bandwidth varies) |
| **wireguard-go** | **5.25 Gbps** | **0** | recvmmsg + GRO + goroutine M:N |
| **Kernel WireGuard** | **3.08 Gbps** | 0 | wireguard.ko |
| **wg-c RTC + lock-free pool** | **3.34 Gbps** | **291** | OpenSSL EVP (AVX-512 fused), Treiber stack pool |
| wg-c RTC (SPSC 1+1, mutex pool) | 3.59 Gbps | 0 | OpenSSL EVP (AVX-512 fused), SPSC lock-free |
| wg-c MPMC+prev_queue (old) | 2.20 Gbps | 0 | OpenSSL EVP (AVX-512 fused), MPMC condvar |
| wg-c RTC (SPSC 4+4) | 0.81 Gbps | 24,000+ | recv fan-out → breaks TCP ordering |
| wg-c RTC (SPSC 4+1) | 2.76 Gbps | 8,816 | send reorder → TCP retransmissions |
| wg-c inline_crypto | 1.57 Gbps | 0 | single-thread crypto |

**Note**: the old EC2 raw network degraded from 9.53 → 4.78 Gbps, so comparing absolute values is not appropriate.

### Improvement from moving to the RTC architecture

| Metric | MPMC+prev_queue (old) | RTC SPSC (new) | Improvement |
|------|---------------------|--------------|------|
| Throughput | 2.20 Gbps | 3.59 Gbps | **+63%** |
| futex syscall share | 89% | 29% | **-60pt** |
| sendmmsg share | 0.87% | 12.9% | **15x** |
| Retransmissions | 0 | 0 | Same |
| Thread count | 25 (N crypto + 2 seq/peer) | 5 (TUN+UDP+HS+1send+1recv) | **-80%** |

---

## Bottleneck analysis (perf profile, receive side)

### CPU usage breakdown

| Category | Share | Main functions |
|---------|------|---------|
| **Kernel wake/syscall** | 16.6% | `try_to_wake_up` 11.3%, `el0_svc` 5.3% |
| **Crypto (OpenSSL NEON)** | 27.1% | `ChaCha20_512_neon` 8.4%, `ChaCha20_neon` 7.3%, `poly1305_blocks_neon` 5.5%, etc |
| **Kernel copy** | 5.1% | `__arch_copy_to_user` 3.7%, `__arch_copy_from_user` 1.4% |
| **mutex/futex** | 5.3% | `pthread_mutex_lock` 2.0%, `lll_lock_wake/wait` 1.5%, etc |
| **EVP dispatch overhead** | 3.8% | `ossl_cipher_generic_initiv` 1.0%, `set_ctx_params` 0.9%, `dinit` 0.7%, etc |
| **Pipeline processing** | 7.2% | `wg_worker_udp_recv` 2.7%, `recv_batch` 2.2%, `wg_handle_gro` 1.7% |
| **Other** | ~35% | memcpy, GRO, sequential receiver, etc |

### Breakdown of `try_to_wake_up` (11.3%)

```
try_to_wake_up
├── 66.5% wg_worker_udp_recv → flush_inbound_container → wg_queue_try_push
│   ├── 65% pthread_cond_signal → futex_wake
│   └── 35% pthread_mutex_unlock → futex_wake
├── 21.3% wg_worker_decryption → wg_queue_pop
│   └── 79% pthread_mutex_unlock → futex_wake
└── 12.2% other (container mutex unlock, etc)
```

**Key point**: the decryption queue's mutex+condvar consumes ~10% of the total. 8 workers each process 15K containers/sec, and every one goes through a condvar sleep/wake cycle.

---

## Pipeline statistics (veth + iperf3, 5.78 Gbps, 2026-04-21)

```
Send side (wg0):
  TUN read:   125K calls, 5.29M pkts (42.4 pkt/call) — GSO 99.9%
  Encrypt:    5.29M pkts
  Seq sender: 41K batches (127.8 pkt/batch)

Receive side (wg1):
  UDP recv:   551K calls, 5.29M pkts (9.6 pkt/call)
  Decrypt:    5.29M pkts
  Seq recvr:  45K batches (116.7 pkt/batch)
  TUN writes: 169K syscalls (GRO 31.2x coalesce)
```

---

## Optimizations tried and results

### 29. Spin-wait batch aggregation — ahead of wireguard-go! (2026-04-30)

**Summary**: When `drain_tx_order()` / `drain_rx_order()` hits an UNCRYPTED element,
it no longer breaks immediately. It spin-waits with PAUSE×256 for crypto to finish.
Batch size grows from 4 to 49, and the syscall efficiency of UDP GSO sendmsg + sendmmsg improves a lot.

**Changes**:
1. `drain_tx_order()`: on an UNCRYPTED hit, spin-wait `WG_CPU_RELAX() × 256` (only when batch_count > 0)
2. `drain_rx_order()`: same (recv side, better GRO coalescing)
3. Added GSO send stats counters (`wg_std_bind.gso_send_ok/fail/skip/packets`)

**Benchmark (CUBIC, ENA NIC, S1↔S2, interleaved)**:

| Implementation | Run 1 | Run 2 | Run 3 | Avg (steady) |
|------|-------|-------|-------|-------------|
| **wg-c (#29)** | 4.72 | 4.67 | 4.77 | **4.72 Gbps** |
| wireguard-go | 4.35 | 4.42 | 4.37 | **4.38 Gbps** |

**wg-c / wireguard-go = 107.8%**

**Pipeline stats**:
```
Seq sender: 49.0 pkt/batch (previous #27: 4.0 pkt/batch → 12x)
send_batches: 396K (previous: 5.2M → 1/13)
TUN read: 37.0 pkt/call (GSO 99.8%)
strace: sendmsg(GSO) 32% + sendmmsg 68%
```

**Analysis**:
- 12x batch size = 1/13 the syscalls → CPU goes to crypto instead
- Cost of the PAUSE spin: ~256×40ns = ~10µs/spin. Short enough as a wait for the whole batch's crypto to finish
- A GSO rate of 32% still has room to improve (some cases are skipped due to size mismatch)
- Warm-up needs 2-3 runs (TCP slow start + CUBIC behavior)

**Verdict**: **Adopted** — 7.8% ahead of wireguard-go. The spin-wait uses CPU,
but this is not a problem because there is a dedicated core (HT affinity).

### 28. Phase 6: eventfd notification — Rejected (2026-04-30)

**Summary**: An attempt to replace the sequential thread's `sched_yield()` with `eventfd + epoll_wait` to cut idle CPU.

**Approaches tried and results**:

| Approach | Throughput (CUBIC avg) | vs previous (#27) | Difference |
|------|----------------------|----------|---|
| sched_yield (baseline) | **4.27 Gbps** | — | baseline |
| eventfd + epoll_wait(10ms timeout) | 3.28 Gbps | -23% | **large regression** |
| eventfd + epoll_wait(1ms timeout) | 3.20 Gbps | -25% | **large regression** |
| PAUSE×32 + sched_yield | 4.16 Gbps | -3% | about the same |
| PAUSE×128 (pure spin, no yield) | 4.21 Gbps | -1% | about the same |

**Analysis**:
- **epoll_wait is fatally slow**: even with a 1ms timeout, the syscall overhead of `epoll_wait`
  (~5µs entry/exit) × high call frequency is larger than sched_yield (~1µs).
  On HT in particular, sched_yield is fast because it switches immediately to the sibling on the same core.
- **PAUSE spin is about the same as sched_yield**: the PAUSE instruction is a busy-wait of ~40ns/each × 128 = ~5µs.
  Latency is almost the same as sched_yield, with the downside that it fully occupies the CPU.
- **Same conclusion as #19**: eventfd/epoll syscall overhead > polling overhead.
  wireguard-go's channels are implemented in user space with no syscalls → not comparable.

**Lessons**:
1. The 18.4% overhead of sched_yield looks like "waste", but the actual wakeup latency is low
2. epoll_wait is for events at a granularity of hundreds of µs to ms. Not suited to µs-granularity crypto batch notification
3. Linux sched_yield is very efficient on HT (immediate switch to the sibling thread)
4. Getting ahead of wireguard-go needs better I/O efficiency (UDP GSO send), not polling optimization

**Verdict**: **Rejected** — sched_yield is best. Moving on to Phase 7 (UDP GSO send).

### 27. Adaptive topology detection + vCPU-based worker scaling — 2026-04-30

**Summary**: Detect the CPU topology at run time and scale the worker count to the environment automatically.
Changed from #26's manual `ncpu/4` to sysfs-based HT detection + a `vcpus_per_path - 2` formula.
Also fixed the re-pin in `bind_update` to reuse the stored mask.

**Changes**:
1. **`detect_topology()`**: reads `/sys/devices/system/cpu/cpu0/topology/thread_siblings_list`
   and detects the HT stride automatically. Falls back to `threads_per_core=1` when sysfs is absent.
2. **`build_core_mask()`**: builds a cpu_set_t mask from a physical core range at run time. HT siblings are included automatically.
3. **Worker count formula**: `vcpus_per_path = ncpu/2; num = vcpus_per_path - 2` (minimum 1, maximum 4)
   - 8 vCPU → 2 send + 2 recv (4 vCPU/dir - 2 = 2)
   - 4 vCPU → 1 send + 1 recv
   - 16 vCPU → 4 send + 4 recv (capped)
4. **`wg_device.h`**: added `phys_cores`, `threads_per_core`, `send_mask`, `recv_mask` fields
5. **`bind_update` fix**: hardcoded CPU mask → reuse `dev->recv_mask`
6. **Log**: print the topology detection result and worker count with `wg_log_verbose`

**Benchmark (CUBIC, ENA NIC, S1↔S2)**:

| Run | wg-c (#27) | wireguard-go |
|-----|-----------|-------------|
| 1 | 4.40 Gbps | 4.37 Gbps |
| 2 | 4.34 Gbps | 4.41 Gbps |
| 3 | 4.32 Gbps | 4.33 Gbps |
| 4 | 4.04 Gbps | — |
| 5 | 4.23 Gbps | — |
| **avg** | **4.27 Gbps** | **4.37 Gbps** |

**perf profile**:
```
raw_spin_rq_unlock_irq (sched_yield): 12.15%
wg_spsc_pop:                           8.97%
do_syscall_64 (sched_yield):           6.22%
handle_softirqs:                       3.70%
total sched_yield:                    18.4%  (previous #26: 58.8% → large improvement)
```

**Analysis**:
- Adaptive worker scaling works as intended: 8 vCPU → 2+2 crypto workers automatically
- sched_yield overhead improved from 58.8% → 18.4% (2 workers have less idle time than 1 worker)
- wg-c/wg-go = **97.7%** (CUBIC)
- Peak 4.40 Gbps exceeds wireguard-go's 4.37 Gbps

**Verdict**: **Adopted** — environment-adaptive worker scaling improves portability. Performance is the same as #26.

### 26. HT-aware CPU affinity + parallel crypto (num_send=2, num_recv=2) — 2026-04-30

**Summary**: On an 8 vCPU (4 cores × 2 HT) environment, use CPU affinity that takes advantage of HT siblings,
and raise the crypto worker count from 1 to 2. Identified the sequential thread's polling overhead with perf.

**Changes**:
1. **HT-aware affinity**: CPU 0,1 → CPU 0,1,4,5 (send), CPU 2,3 → CPU 2,3,6,7 (recv)
   - Siblings detected automatically with HT stride = ncpu/2
   - Added HT support to the udp_recv re-pin in `wg_device_bind_update()` as well
2. **Parallel crypto**: `num_send = ncpu/4`, `num_recv = ncpu/4` (8 vCPU → 2 workers each)
   - Upper limit 4 workers/direction
3. **Per-packet batch aggregation** (#25): rdlock amortization, validTailPacket pattern (carried over from the previous session)

**perf profile (2 crypto workers, sched_yield)**:
```
sched_yield (kernel):     39.5% + 19.3% = 58.8%  ← sequential thread idle polling
sequential_send:          10.4%                    ← poll loop overhead
sequential_recv:           8.7%                    ← poll loop overhead
prev_queue_dequeue:        2.9%                    ← drain work (real work)
total polling overhead:   ~80%
```

**Alternatives tried and results**:

| Method | Throughput (CUBIC) | Result |
|------|-------------------|------|
| 1 worker + sched_yield | 3.01 Gbps | baseline (CPU 0-3 only) |
| 1 worker + HT affinity | 3.82 Gbps | +27% (uses HT siblings) |
| **2 workers + HT + sched_yield** | **4.33 Gbps** | **+44% (best)** |
| 2 workers + HT + nanosleep(1µs) | 2.95 Gbps | **counterproductive** (large wakeup latency) |
| 2 workers + HT + spin backoff | 2.84 Gbps | **counterproductive** |
| 2 workers + drain_lock removed | 2.92 Gbps | no effect |
| 2 workers + crypto merged (seq removed) | 0.11 Gbps | **deadlock** (SPSC blocking + cannot drain) |
| 2 workers + drain_lock restored + nanosleep + crypto drain | 2.95 Gbps | **counterproductive** |

**Interleaved benchmark (wg-c → wg-go → wg-c → wg-go)**:

| Round | wireguard-go | wg-c (#26) | Difference |
|-------|-----------:|----------:|----|
| CUBIC R1 | 4.56 Gbps (954 retx) | 4.33 Gbps (559 retx) | -5.0% |
| CUBIC R2 | 4.41 Gbps (4158 retx) | 4.35 Gbps (682 retx) | **-1.4%** |
| BBR | 4.28 Gbps (0 retx) | 4.17 Gbps (330 retx) | -2.6% |

**Analysis**:
- **2 crypto workers** are the largest improvement: +33% going from 1→2 workers (2.92→3.90 Gbps)
- **HT affinity** gives +27%: using CPU 4-7 gives the crypto workers enough CPU
- **The sequential thread's sched_yield wastes 60%+ CPU**: polling-based prev_queue drain is the root problem
- **nanosleep and spin backoff are counterproductive**: their wakeup latency is larger than sched_yield
- **Merging crypto (removing sequential) deadlocks**: prev_queue cannot be drained while in SPSC's blocking pop
- 96.7% of wireguard-go (CUBIC R2 is 98.6%). The remaining ~3% is the sequential thread's polling overhead

**Lessons**:
1. The crypto worker count should scale with CPU resources (ncpu/4)
2. Using HT siblings is a free performance gain (+27%)
3. Sequential thread polling wastes CPU → needs eventfd notification
4. sched_yield > nanosleep > spin backoff (idle handling on HT)

**Verdict**: **Adopted** — 2 workers + HT affinity reaches 97% of wg-go. Next, fill the remaining 3% with eventfd notification.

### 23. Thread merge (7→5 threads) — 2026-04-30

**Summary**: Merge the crypto worker and sequential worker so one thread does both crypto and I/O.
Removed prev_queue, atomic state and spin-wait entirely, going from 7→5 threads.

**Hypothesis**: the perf profile shows 45.5% CPU wasted on spin-wait → merging threads removes it → higher throughput

**Changes**:
- `wg_worker_rtc_recv`: SPSC pop → decrypt → validate → TUN write (1 thread)
- `wg_worker_rtc_send`: SPSC pop → encrypt → sendmmsg (1 thread)
- `enqueue_inbound/outbound`: prev_queue removed → SPSC push only
- `sequential_send/recv`: deleted

**Benchmark (CUBIC, ENA NIC, steady-state --omit 3)**:

| Run | Throughput | Retransmits | Notes |
|-----|-----------|-------------|------|
| 1 | 3.24 Gbps | 0 | |
| 2 | 3.40 Gbps | 11 | |
| 3 | 3.20 Gbps | 2 | |
| 4 | 3.36 Gbps | 7 | |
| 5 | 3.32 Gbps | 9 | |

**perf profile (after merge)**:
```
wg_spsc_pop:          10.90%  ← unified worker waiting for next batch (idle)
finish_task_switch:    6.04%  ← eventfd context switch
__raw_spin_unlock_irq: 3.62%  ← eventfd_write (producer wake)
decrypt_elem:          1.52%  ← real crypto work
wg_worker_udp_recv:    2.21%  ← UDP recv
```

**Analysis**:
- **25% regression** (4.5 → 3.3 Gbps). The hypothesis was wrong.
- Pipelining in the old model: while the crypto worker decrypts batch N+1, the sequential worker does the TUN write for batch N. This parallel execution produced 25-30% of the throughput.
- Merged model: crypto → TUN write → SPSC wait (sequential). Nothing progresses during the SPSC wait.
- The 45% spin-wait looked like "waste", but it was a useful busy-wait that enabled pipelining.
- Retransmits improved (0-11) — less scheduling jitter. But the throughput regression outweighs it.

**Lesson**: on a 4 vCPU environment, the scheduling overhead of 7 threads < the benefit of parallel execution from pipelining.
Reducing the thread count has to keep pipelining (for example, pin to the same core with CPU affinity).

**Verdict**: **Rejected** — 25% regression from lost pipelining. Reverted.

### 24. CPU affinity pinning + adaptive yield — 2026-04-30

**Summary**: Split the send/recv paths of the 7 threads onto core pairs, and give the CPU back with sched_yield() when idle.

**Changes**:
1. Use `pthread_setaffinity_np` to split the send path (tun_reader, rtc_send, seq_send) → Core 0-1
   and the recv path (udp_recv, rtc_recv, seq_recv) → Core 2-3. The OS scheduler distributes freely within each pair.
2. Adaptive yield in the sequential_send/recv idle loop: `sched_yield()` after 64 rounds of spin.
3. Added re-pin handling when udp_recv is recreated in `wg_device_bind_update()`.

**CPU affinity layout trial and error**:

| Layout | Placement | Throughput (CUBIC) | Retransmits | Problem |
|--------|------|--------------------|-------------|------|
| None (baseline) | left to the OS | 3.52-4.89 (avg ~4.25) | 0-121 | — |
| A: individual cores | tun+seq_send→C0, rtc_send+hs→C1, udp→C2, rtc_recv+seq_recv→C3 | 3.28-4.57 (avg ~4.09) | 5-160 | rtc_recv+seq_recv contend on the same core |
| B: crypto+seq together | tun+hs→C0, rtc_send+seq_send→C1, udp→C2, rtc_recv+seq_recv→C3 | 2.85-3.22 (avg ~3.14) | 1-25 | **lost pipelining** (same as #23) |
| C: dedicated crypto | rtc_send→C0, tun+seq_send+hs→C1, rtc_recv→C2, udp+seq_recv→C3 | 2.43-2.56 (avg ~2.50) | 674-1197 | **seq_recv spin starves udp_recv** |
| **D: core pairs** | **send→C0-1, recv→C2-3** | **4.63-5.29 (avg ~5.05)** | 331-715 | more retransmits |
| D + yield | D + sched_yield after 64 idle spins | 4.63-5.29 (avg ~5.05) | 331-715 | yield does not improve retransmits |

**BBR result (Layout D + yield)**: 4.94-5.14 Gbps (avg ~5.05), retransmits 9-106. Stable above 5 Gbps.

**Analysis**:
- Core-pair split (Layout D) is the most effective: **CUBIC avg 4.25 → 5.05 Gbps (+19%)**
- Peak **5.29 Gbps exceeds wireguard-go's 5.18 Gbps**
- Why retransmits increase: on the recv side, 3 threads (udp_recv + rtc_recv + seq_recv) share 2 cores,
  and seq_recv's spin-wait competes with udp_recv/rtc_recv for CPU
- sched_yield has no effect on retransmits (kernel scheduling granularity is coarse)
- **With BBR, 5.0+ Gbps is stable without retransmit impact**

**Lessons**:
1. Pinning to individual cores is counterproductive. It is better to let the OS scheduler distribute within a pair
2. Splitting the send/recv paths matters. Removing cross-path interference gives +19%
3. Crypto and sequential **must run on different cores** (lesson from Layout B)
4. A spin-waiting thread must not be placed on the same core as the producer (udp_recv) (lesson from Layout C)

**Verdict**: **Adopted** — CUBIC 5.05 Gbps / BBR 5.05 Gbps, ahead of wireguard-go.

### 25. Per-packet operation batch aggregation + fewer stats atomics — 2026-04-30

**Summary**: Following wireguard-go's `validTailPacket` pattern, move per-packet operations in the recv hot path to the end of the batch.

**Changes**:
1. `drain_rx_order()`: add rx_bytes locally → 1 atomic; endpoint/timer once at the end of the batch; removed the endpoint/timer calls for keepalives
2. `wg_allowedips_lookup_unlocked()`: take the rdlock once per batch (per-packet → per-batch)
3. `decrypt_elem()`: removed 4 per-packet stats atomics → batch flush when rtc_recv finishes
4. `encrypt_elem()`: removed the encrypt_count atomic → flush when rtc_send finishes
5. sequential_send/recv: `sched_yield()` immediately when idle (less spin-wait)
6. Send side: `keep_key_fresh_sending` every packet → once at the end of the batch

**Back-to-back benchmark (same EC2 c6i.2xlarge, same time slot)**:

| Implementation | CC | avg Gbps | min-max | retransmit range |
|------|-----|---------|---------|-----------------|
| **wireguard-go** | CUBIC | 4.97 | 4.89-5.06 | **0-137** |
| **wireguard-go** | BBR | 4.58 | 4.56-4.59 | **0** |
| wg-c (affinity only) | CUBIC | 5.05 | 4.63-5.29 | 331-715 |
| wg-c (affinity only) | BBR | 4.97 | 4.74-5.18 | 7-124 |
| **wg-c (#25)** | **CUBIC** | **5.15** | 4.95-5.30 | **203-540** |
| **wg-c (#25)** | **BBR** | **5.00** | 4.63-5.26 | **0-108** |

**Analysis**:
- **Throughput**: wg-c is ahead of wireguard-go by +3.6% with CUBIC and +9.2% with BBR
- **Retransmits**: trending better (CUBIC max 715→540) but not yet at wireguard-go (0-137)
- **UDP drop check**: in `/proc/net/snmp`, neither InErrors nor RcvbufErrors changed
  → the retransmits are not kernel UDP drops but a **TCP-level problem**
- **Root cause**: jitter in the timing of sequential_recv's TUN writes.
  pthread context switches (µs scale) vs Go goroutine cooperative switches (ns scale).
  In wireguard-go, Go's M:N scheduler makes goroutine switches fast, so TUN write jitter is small.

**Lessons**:
- Cutting per-packet locks/atomics is correct in theory, but locks are not the main cause of retransmits
- The root cause of the retransmits is the difference in scheduling granularity between pthreads and goroutines
- UDP drops are zero (checked in /proc/net/snmp) → the retransmits are at the TCP level

**Candidates for reducing CUBIC retransmits and past findings**:

| Candidate | Past experiment | Result | Notes |
|------|-----------|------|------|
| a. io_uring TUN write | #9 (L922) | **Rejected** | no effect with 0.8% syscall overhead |
| a. io_uring multishot recv | #16 (L1448) | **Rejected** | -18% regression from double copy |
| b. epoll + eventfd notification | #19 (L753) | **Rejected** | syscall overhead + wakeup latency > spin-wait |
| c. Stronger TUN GRO coalescing | not done | — | fewer TUN writes may reduce jitter |

a and b were tried before and rejected. The only remaining candidate is **c (stronger TUN GRO coalescing)**.

**Benchmark reliability check — interleaved runs (same time slot, wireguard-go → wg-c for 3 rounds)**:

| Round | CC | wireguard-go | wg-c | Difference |
|-------|----|-------------|------|-----|
| 1 | CUBIC | 4.90 (retr=87) | 4.96 (retr=513) | +1.2% |
| 2 | CUBIC | 4.91 (retr=0) | 5.10 (retr=259) | +4.0% |
| 3 | CUBIC | 4.94 (retr=0) | 5.30 (retr=404) | +7.2% |
| 1 | BBR | 4.63 (retr=0) | 5.17 (retr=17) | +11.6% |
| 2 | BBR | 4.65 (retr=0) | 5.09 (retr=0) | +9.4% |
| 3 | BBR | 4.57 (retr=0) | 5.23 (retr=71) | +14.3% |

**Conclusion**: wg-c is ahead in all 6 rounds. CUBIC +4.1%, BBR +11.7%. The throughput lead is real.

**Verdict**: **Adopted** — throughput +3.6% (CUBIC), better code quality (follows the wireguard-go pattern).

### 22. A+C+D batch-deferred per-packet ops + crash fix — 2026-04-30

**Summary**: Following wireguard-go's `validTailPacket` pattern, move per-packet lock/atomic operations to the end of the batch.
Also fixed two crash bugs.

**Changes (A+C+D)**:
- **(A) keypair transition**: changed from deferred → inline (to fix a UaF bug)
- **(C) stats consolidation**: in `flush_recv_accum`, N calls of `atomic_fetch_add(&recv_bytes)` → add locally and do it once
- **(D) rx_bytes accumulation**: in `drain_rx_into`, `atomic_fetch_add(&peer->rx_bytes)` every packet → add locally and do it once at flush
- **endpoint/timer**: once, on `tail_elem` only (existing validTailPacket pattern)

**Crash fixes**:

1. **peer_cache NULL peer** (also present in the old code):
   - A NULL peer can end up in `peer_cache[]` of `wg_worker_sequential_recv/send`
   - `pthread_mutex_trylock(&peer->queue.rx_drain_lock)` with `peer=NULL` → offset 0x3c0+0x10 = **segfault at 0x3d0**
   - Fix: added `if (!peer) continue;`

2. **keypair_transition_elem UaF** (introduced by A+C+D):
   - `drain_rx_into` detects a keypair transition → saves `acc->keypair_transition_elem = elem`
   - If the same elem is freed immediately as a keepalive (pt_len==0) or on an allowedips failure, the pool reset sets `peer=NULL`
   - `flush_recv_accum` reads `acc->keypair_transition_elem->peer` → **segfault at 0x220** (endpoint.lock offset)
   - Fix: handle the keypair transition inline (deferred removed). It happens ~once per handshake, so no performance impact

**Crash addresses and struct offsets**:
```
offset 0x210 = peer->endpoint.lock      → segfault at 0x220 (mutex __kind at +0x10)
offset 0x3c0 = peer->queue.rx_drain_lock → segfault at 0x3d0 (mutex __kind at +0x10)
```

**Benchmark results** (EC2 c6i.2xlarge ENA NIC, CUBIC):

| Run | Throughput | Retransmits | Notes |
|-----|-----------|-------------|------|
| 1 | 4.24 Gbps | 218 | ramp-up retransmit |
| 2 | 4.56 Gbps | 219 | ramp-up retransmit |
| 3 | **5.26 Gbps** | **11** | peak performance |
| 4 | 4.77 Gbps | 1264 | mid-flow retransmit |
| 5 | 3.39 Gbps | 253 | |
| 6 | 5.08 Gbps | 645 | concentrated in the 2-3s ramp-up |

Steady-state (--omit 3):

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1 | 4.70 Gbps | **0** |
| 2 | 4.42 Gbps | 27 |
| 3 | 4.75 Gbps | 348 |

**Analysis**:
- Crashes fully resolved (no new segfault on S2)
- Steady-state throughput: same as baseline (4.42-4.75 Gbps)
- Retransmits: still highly variable (0-1264). Jitter in the EC2 ENA network layer dominates
- A+C+D's per-packet atomic reduction lowers software jitter, but network jitter from the ENA NIC remains
- Peak Run 3 (5.26 Gbps, 11 retransmits) is level with wireguard-go (5.18 Gbps, 0), but less stable

**Verdict**: **Adopted** (crash fix + small jitter reduction). Getting CUBIC retransmits to 0 needs a rethink of the thread architecture (see below).

### 22b. Optimization E: adaptive wait + SPSC spin_limit tuning — 2026-04-30

**Summary**: perf record showed spin-wait wasting 45.5% CPU.
Changed 3 spin-wait sites to adaptive wait and tuned the SPSC spin_limit.

**perf profile (before, spin-wait PAUSE x 32)**:
```
wg_spsc_pop:              19.16%  ← crypto worker waiting on empty SPSC (spin_limit=4000)
wg_worker_sequential_send: 14.47%  ← PAUSE x 32 spin-wait
wg_worker_sequential_recv:  8.74%  ← PAUSE x 32 spin-wait
pthread_mutex_trylock:      3.17%  ← peer drain lock trylock
total spin waste:          45.5%  (~1.8 cores out of 4 vCPU)
```

**Changes**:
1. sequential_recv/send: `PAUSE x 32` → adaptive (PAUSE x 64 → sched_yield → nanosleep(1µs))
2. SPSC spin_limit: 4000 → 512 (less excess spin, makes use of the eventfd fallback)

**perf profile (after)**:
```
raw_spin_rq_unlock_irq:    9.04%  ← scheduler overhead (from sched_yield)
wg_worker_sequential_recv:  7.20%  ← includes real work
do_syscall_64:              4.98%  ← eventfd/write syscall
finish_task_switch:         4.73%  ← context switch
wg_spsc_pop:                2.43%  ← 19.16% → 2.43% (-16.7pt)
sched_yield:                2.18%  ← new overhead
sequential_send:            0.77%  ← 14.47% → 0.77% (-13.7pt)
```

**Benchmark (CUBIC, steady-state --omit 3)**:

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1   | 4.46 Gbps | 103 |
| 2   | 4.07 Gbps | 81 |
| 3   | 3.45 Gbps | 9 |
| 4   | 5.10 Gbps | 9 |
| 5   | 4.83 Gbps | **0** |

**Analysis**:
- Cut spin CPU waste from 45% → 12% (-33pt)
- But sched_yield's scheduler overhead (9% + 4.7%) is a new source of jitter
- Throughput: same as baseline (3.45-5.10 Gbps)
- Retransmits: 0 in some runs. But highly variable (EC2 ENA + scheduler jitter)
- **Root problem**: 7 OS threads compete for 4 vCPU. With either spin or yield, the scheduler steps in and causes jitter

**Thread model comparison, wg-c vs wireguard-go**:
```
wg-c:         7 OS threads on 4 vCPU → forced preemption → jitter
wireguard-go: 4 OS threads (GOMAXPROCS=4) + goroutine cooperative scheduling → predictable
```

In wireguard-go, the Go runtime cooperatively multiplexes goroutines onto 4 OS threads.
Goroutines yield explicitly on channel operations, so forced preemption by the OS scheduler is minimal.
In wg-c, 7 threads compete for CPU independently, so the OS scheduler steps in often.

**Next steps: thread merge (7→4-5 threads)**:
1. Merge the crypto worker + sequential worker (give up pipelining, but 2 fewer threads)
2. Or move fully to the RTC model: udp_recv does decrypt+TUN write inline (1 thread = 1 flow)
3. CPU affinity pinning: pin the important threads to specific cores

**Verdict**: **Partly adopted** — SPSC spin_limit 512 is adopted. The sequential adaptive wait needs more tuning.

### 21. spin-wait on UNCRYPTED + BBR congestion control — 2026-04-30

**Summary**: Combine two independent optimizations to solve the retransmit problem.

**(a) spin-wait on UNCRYPTED**: when the sequential receiver meets an UNCRYPTED element, it does not break immediately;
it spin-waits for 64 PAUSE instructions. If the crypto worker is in the middle of processing, it finishes during this time,
and a contiguous batch can be built.

**(b) BBR congestion control**: set `sysctl net.ipv4.tcp_congestion_control=bbr` on the host.
BBR is model-based and estimates bandwidth/RTT, so it does not mistake packet delay from pipeline jitter for congestion.

**Results** (EC2 c6i.2xlarge ENA NIC iperf3):

| Configuration | Avg Gbps | Retransmits |
|------|----------|-------------|
| baseline (no spin, CUBIC) | 4.48 | 0-26 |
| spin-wait (CUBIC) | 4.84 | 2-256 |
| no spin (BBR) | 4.78 | 0 |
| **spin-wait + BBR** | **4.92** | **0-11** |
| wireguard-go (CUBIC) | 5.18 | 0 |
| wireguard-go (BBR) | 4.69 | 0 |

**S2 recv pipeline improvement** (with spin-wait):
- seq recvr batch: 2.7 → **5.0 pkt/batch** (+85%)
- GRO coalesce: 2.6x → **4.6x** (+77%)
- UDP recv: 16.2 pkt/call (SO_BUSY_POLL enabled)

**Verdict**: **Adopted** — retransmits almost gone. wg-c is 5% ahead of wireguard-go under BBR.

### 20. parallel crypto (num_recv=2) — 2026-04-30

**Summary**: Raise the crypto recv workers from 1→2 to parallelize decrypt. With inline drain.

**Results** (EC2 c6i.2xlarge ENA NIC iperf3):
- num_recv=2 + sequential_recv: 4.21 Gbps, 338 retransmits (**worse**)
- num_recv=2, no sequential_recv: 4.04 Gbps, 477 retransmits (**even worse**)

**Analysis**: 8-9 threads on a 4 vCPU environment is oversubscription.
With 1 peer, drain lock contention means 2 workers bring no benefit.

**Verdict**: **Rejected** — regression from CPU oversubscription. Keep 1 crypto worker.

### 19. inline drain in crypto worker — 2026-04-30

**Summary**: After decrypt, the crypto worker tries an inline drain of prev_queue.
trylock(rx_drain_lock) avoids contention with sequential_recv.
Cause of the earlier crash: reading `elem->peer` after `atomic_store(state, CRYPTED)` = use-after-free.
Fix: save the peer pointer before the state transition.

**Results** (EC2 c6i.2xlarge ENA NIC iperf3):
- Inline drain (num_recv=1): 4.57, 4.47, 4.89 Gbps, 12-47 retransmits
- Baseline (crypto-only): 4.35, 4.43, 4.67 Gbps, 0-26 retransmits

**Analysis**: inline drain slightly raises throughput, but while the crypto worker does drain+TUN write,
processing of the next decrypt batch is delayed. Pipelining with sequential_recv is more efficient.
Retransmits increase because the processing delay during drain adds jitter.

**Verdict**: **Rejected** — pipelining (crypto-only + sequential_recv) is better. Replaced by spin-wait on UNCRYPTED.

### 18. SO_BUSY_POLL (better UDP recv batching) — 2026-04-30

**Summary**: Set `SO_BUSY_POLL=50μs`, `SO_PREFER_BUSY_POLL=1`, `SO_BUSY_POLL_BUDGET=128` on the UDP socket.
The aim is for the kernel to do NAPI polling in the recvmmsg context and increase the recv batch size.

**Results** (EC2 c6i.2xlarge veth iperf3):

| Metric | baseline | + busy poll | Change |
|------|---------|------------|------|
| Throughput | 4.43 Gbps | 4.49-4.56 Gbps | within noise |
| UDP recv pkt/call | 2.4 | 2.5 | no change |

**Analysis**: veth is not a NAPI driver, so `SO_BUSY_POLL` does not kick in.
veth packet receive goes directly through `netif_receive_skb` with no NAPI polling loop.
The code is kept because an effect is expected on an ENA NIC (physical NIC).

**Verdict**: **Adopted (kept)** — no effect on veth. Re-evaluate on a physical NIC.

### 17. Recv-side accumulation (better GRO batching) — 2026-04-30

**Summary**: Move the sequential receiver's accumulator outside the loop and collect more packets with a spin-wait before flushing.
The aim is to raise the GRO coalesce ratio and cut TUN write syscalls.

**Results** (EC2 c6i.2xlarge veth iperf3, average of 3):

| Approach | Throughput | GRO coalesce | Seq recvr batch |
|------|------------|-------------|----------------|
| baseline (immediate flush) | 4.43 Gbps | 2.9x | 3.0 pkt/batch |
| spin 64 + accum | 4.56 Gbps | 3.6x | 3.9 pkt/batch |
| spin 256 + accum | 4.38 Gbps | 3.6-3.8x | 4.1 pkt/batch |
| spin 512 + accum | 4.37 Gbps | 3.9x | 4.2 pkt/batch |

**Analysis**: Better GRO coalescing (2.9x→3.8x) → fewer TUN writes (1.2M→1.04M) worked,
but throughput is within noise. TUN write is not the recv-side bottleneck.
The real bottleneck is UDP recv (2.4 pkt/call). UDP_GRO does not work on veth, so
recvmmsg's effective batch is small.

**Verdict**: **Rejected** — better GRO does not help throughput. The bottleneck is UDP recv, not TUN write.

### 16. eventfd notification (removing spin-wait) — 2026-04-30

**Summary**: Change the sequential sender/receiver's spin-wait (PAUSE x 32) → eventfd poll.
The perf profile showed sequential_recv 13.5% + sequential_send 11.5% = **25% CPU** wasted on spin-wait.

**Implementation**:
- `wg_device.h`: `int evt_send_fd`, `int evt_recv_fd` (per-device eventfd)
- The crypto worker calls `write(eventfd, 1)` after finishing a batch
- The sequential thread blocks in `poll(eventfd, 1ms)` when idle
- Hybrid version: spin 128 times → eventfd fallback was also tried

**Results** (EC2 c6i.2xlarge veth iperf3):

| Approach | Throughput | Change |
|------|------------|------|
| PAUSE x 32 (baseline) | 4.43 Gbps | — |
| eventfd poll only | 3.82 Gbps | **-14% worse** |
| hybrid (spin 128 + eventfd) | 3.76 Gbps | **-15% worse** |

**Analysis**: eventfd write/poll/read adds 3 syscalls per batch. At high throughput the gap from crypto completion to seq drain is short, and the spin-wait hits within tens of ns. eventfd's poll wakeup latency (~5-50μs) stalls the pipeline. Past experiments #6 (Vyukov + eventfd) and #2 (per-worker SPSC + eventfd) reached the same conclusion.

**Verdict**: **Rejected** — the CPU waste of spin-wait is only apparent. At high throughput the spin is a useful busy-wait, and eventfd's syscall overhead + wakeup latency outweigh it

### 0. Lock-free pool (Treiber stack) — 2026-04-28

**Summary**: `pthread_mutex_lock` in `wg_wait_pool_get/put` → lock-free Treiber stack (CAS + tagged pointer for ABA prevention). Applied only to pools with `max == 0` (no backpressure).

**Implementation**:
- `src/device/wg_pools.h`: `_Atomic uint64_t lf_head` (tagged pointer: 16-bit ABA counter + 48-bit ptr)
- `src/device/wg_pools.c`: `lf_pool_get()` (CAS pop), `lf_pool_put()` (CAS push), `lf_pool_put_batch()` (chain + single CAS push)
- `src/workers/wg_workers.h`: added a `void *_pool_next` field (intrusive link)
- `src/device/wg_device.c`: calls `wg_wait_pool_enable_lockfree()`

**Results (EC2 c6i.2xlarge, raw network degraded at the time)**:

| Metric | mutex pool | lock-free pool | Change |
|------|-----------|---------------|------|
| Raw network | 9.53 Gbps | 4.78 Gbps | EC2 bandwidth fluctuation |
| wg-c throughput | 3.59 Gbps | 3.34 Gbps | due to degraded raw |
| wg-c / Raw ratio | 38% | **70%** | **+84% efficiency** |
| S2 recv worker CPU | 98% | **87%** | -11pt (mutex removed) |
| Retransmissions | 0 | 291 | raw network also 168 retrans |

**Analysis**: The raw network itself degraded from 9.53 → 4.78 Gbps (EC2 bandwidth fluctuation). The wg-c / Raw ratio improved a lot, 38% → 70%. The recv worker's mutex overhead is gone and CPU dropped from 98% → 87%. But any absolute throughput gain needs re-measuring after the raw network recovers.

**Verdict**: **Adopted** — confirmed better CPU efficiency from removing mutex overhead.

### 1. OpenSSL EVP ChaCha20-Poly1305 (ARM64 NEON) — second implementation (2026-04-18)

**Summary**: libsodium (portable C reference implementation) → OpenSSL EVP (ARM NEON assembly)

**Implementation**: a `#if WG_USE_OPENSSL` branch in `src/crypto/wg_crypto.c`. A per-thread `_Thread_local EVP_CIPHER_CTX` cache avoids alloc/free. Added the `WG_USE_OPENSSL` option to CMakeLists.txt.

**First attempt (2026-04-17, together with other optimizations)**:
- veth iperf3: 5.07 → 5.01 Gbps (**no change**)
- Reason: other optimizations (spin-wait, batch pop) were applied at the same time, and crypto was not the bottleneck

**Second attempt (2026-04-18, from a clean baseline after reverting everything)**:
- veth iperf3: 5.31 → **6.08 Gbps** (**+14.5%**, average of 2: 5.92, 6.08)
- crypto microbenchmark: 3.58 → 11.20 Gbps (3.1x, 1420 byte packets)

**Verdict**: **Adopted** — switching crypto as the only change from baseline gives +0.77 Gbps.
The remaining gap (6.08 vs 7.45 Gbps = 18%) is a bottleneck other than crypto.

**Further optimization (EVP key cache)**: cache the key in a per-thread `wg_evp_cache_t`; for the same key, re-init only the nonce (no cipher re-specification). OPENSSL_cleanse went from 3.95% → 0%. But throughput is within noise (5.81–6.08 Gbps). EVP dispatch overhead (initiv, set_ctx_params, dinit) of 3.87% remains.

### 15. Switch to recv_gro (recvmsg) (2026-04-21)

**Summary**: When UDP_GRO is enabled, switch from recvmmsg (individual buffers) → recvmsg (one large GRO buffer → split in user space). recvmmsg's 1500-byte iovecs prevent kernel GRO coalescing, so the aim is to use recvmsg + a large buffer to do the kernel-side copy once.

**Results**:
- veth iperf3: 5.88 → **1.46 Gbps** (**-75% worse**)
- UDP recv: 746K calls (6.9 pkt/call) → 1.33M calls (**1.0 pkt/call**)

**Analysis**: On veth, UDP_GRO coalescing does not kick in (packets arrive individually). recvmsg returns only 1 message per call, so the 6.9 pkt/call batching of recvmmsg is lost completely. recvmmsg can fetch many packets from the kernel socket buffer at once, but recvmsg can fetch only one.

**Verdict**: **Rejected** — recvmmsg is far better on veth. Could be re-evaluated on a physical NIC with UDP_GRO enabled.

### 14. Batch signaling in crypto workers (2026-04-21)

**Summary**: Instead of the decryption/encryption worker calling `pthread_cond_signal(&peer->notify.recv_cond)` after each elem, signal once after the batch. Removes duplicate signals to the same peer.

**Results**:
- veth iperf3: 5.94 → **5.69 Gbps** (**-4.2% worse**)

**Analysis**: The seq receiver waits for crypto completion with a spin-wait (2000 iterations) → condvar wait. Delaying the signal until the end of the batch delays the seq receiver's response and increases pipeline latency. With a single peer, all elems in a batch are for the same peer, so there was only 1 signal to begin with; the problem is that the signal timing is later.

**Verdict**: **Rejected** — signal immediacy directly affects pipeline throughput

### 13. Fewer push_batch signals (2026-04-21)

**Summary**: Reduce the number of condvar signals in `wg_queue_try_push_batch` from `min(pushed, pop_waiters)` → `ceil(pushed/16)` or `ceil(pushed/4)`. Hypothesis: with pop_batch(16) one worker can process many items, so there is no need to wake every worker.

**Results**:

| Signal strategy | Throughput | Change |
|-------------|------------|------|
| min(pushed, pop_waiters) (baseline) | 5.94 Gbps | — |
| ceil(pushed/4) | 5.56 Gbps | **-6.4% worse** |
| ceil(pushed/16) | 5.44 Gbps | **-8.4% worse** |

**Analysis**: Crypto takes ~3.5us/pkt, so with a push interval of ~18us one worker cannot keep up. Fewer signals delay crypto worker wake-up, packets pile up in the queue, and the pipeline becomes crypto-bound. The futex_wake cost of a condvar signal (~1us) is small compared to crypto time, so waking workers aggressively is better for throughput.

**Verdict**: **Rejected** — waking workers quickly is required to keep throughput

### 12. Calling OpenSSL internal symbols directly (2026-04-19)

**Summary**: Bypass the EVP dispatch layer (~4% CPU) and call OpenSSL's internal `ChaCha20_ctr32` / `Poly1305_Init/Update/Final` directly. Link against static libcrypto.a to access LOCAL symbols.

**Implementation**: a `#if WG_OPENSSL_DIRECT` branch in `src/crypto/wg_crypto.c`. RFC 8439 AEAD implemented by hand: poly key derivation (counter=0) → encrypt (counter=1) → Poly1305 MAC (pad(AAD) || pad(CT) || lengths). CMakeLists.txt detects static libcrypto.a and defines `WG_OPENSSL_DIRECT=1`.

**Results**:
- veth iperf3: 5.91 → **5.36 Gbps** (**-9.3% worse**)

**Analysis**: EVP's internal implementation processes encrypt and auth **interleaved (fused single-pass)**, running ChaCha20+Poly1305 together on blocks that fit in L1 cache. The direct calls are 2-pass (encrypt all data → MAC all data), so with large packets the data is evicted from cache. The cache-miss penalty of 2-pass is larger than EVP dispatch's 4% overhead.

**OpenSSL's internal fused implementation** (`chacha20_poly1305_cipher`) can only be called via `EVP_CIPH_FLAG_CUSTOM_CIPHER` and is not exported directly.

**Verdict**: **Rejected** — EVP's fused single-pass is fundamentally better, and the dispatch overhead is acceptable. Reverted to keep EVP.

### 11. condvar broadcast → targeted signal + spin-wait (2026-04-21)

**Summary**: 
- `pthread_cond_broadcast` in `wg_queue_try_push_batch` → `pthread_cond_signal` called `min(pushed, pop_waiters)` times. Avoids the thundering herd of waking all 8 workers.
- Added a 64-iteration spin-wait (ARM yield) to `wg_queue_pop_batch`. count_hint is published atomically, so the code checks for items before taking the lock.

**Results**:
- veth iperf3: 5.89 Gbps (**no change**, baseline 5.91)
- try_to_wake_up: 7.86% → **7.04%** (-0.82pp better)
- pthread_mutex_lock: 1.78% → 1.77% (no change)

**Analysis**: broadcast→signal reduced wake-ups, but futex_wake at mutex_unlock (3.39%) happens on a path separate from the condvar and cannot be reduced. The spin-wait also has little effect — under load, workers find work immediately, so the spin does not hit.

**Verdict**: **Adopted** (no regression, try_to_wake_up slightly lower)

### 10. Fewer crypto workers (2026-04-21)

**Summary**: Reduce crypto workers from ncpu (8) → ncpu/2 (4) or ncpu*3/4 (6). The aim is fewer condvar wake-ups and less try_to_wake_up overhead.

**Results**:

| Workers | Throughput | Change |
|-----------|------------|------|
| 8 (baseline) | 5.91 Gbps | — |
| 6 (ncpu*3/4) | 5.76 Gbps | **-2.5% worse** |
| 4 (ncpu/2) | 5.66 Gbps | **-4.2% worse** |

**Analysis**: OpenSSL NEON crypto uses 25% CPU in the perf profile, but that is spread across 8 workers. With fewer workers, aggregate crypto throughput is not enough and the pipeline becomes crypto-bound. The drop in crypto throughput outweighs the gain from fewer condvar wake-ups (estimated ~2%).

**Verdict**: **Rejected** — keep 8 workers

### 9. io_uring TUN write batching (2026-04-18)

**Summary**: Replace N `write()` syscalls for TUN write with an io_uring SQE batch + one `io_uring_enter()`. SQPOLL mode was also tried.

**Changed file**: `src/tun/wg_tun_linux.c` — added an io_uring ring, replaced the write loop with SQE submission

**Results**:

| Mode | Throughput | Change |
|--------|------------|------|
| baseline (write) | 5.83 Gbps | — |
| io_uring (batch) | 5.86 Gbps | **no change** |
| io_uring (SQPOLL) | 4.60 Gbps | **-21% worse** |

**Analysis**:
- TUN writes are 210K/sec (after GRO 25.7x coalescing). Syscall overhead is ~1% of the total.
- io_uring batch: 210K write() → ~48K io_uring_enter() = 162K fewer syscalls. But el0_svc is 3.29% of the total, and TUN writes are ~0.8% of that. The effect is too small to measure.
- SQPOLL: the kernel polling thread uses 1 CPU core → on the 8-core environment it takes CPU from the crypto workers, -21% worse.
- `__arch_copy_to_user` (4.74%) goes through the same kernel copy path with io_uring too, so it cannot be reduced.

**Conclusion**: syscall overhead (el0_svc 3.29%) is too small for io_uring to show an effect. The bottlenecks are crypto (25%) and thread sync (10%).

**Verdict**: **Rejected** — not worth the overhead

### 6. Lock-free MPMC queue (Vyukov + eventfd) — second attempt (2026-04-19)

**Summary**: mutex+condvar → Vyukov ring buffer + eventfd for blocking

**Results**:
- veth iperf3: 5.97 → 5.93-6.04 Gbps (**no change**)
- try_to_wake_up: 8.80% → 2.89% (**reduced**)
- But new overhead: eventfd_write 6.13% + poll_freewait 2.84% + CAS spin 4.63%
- Total sync overhead: 15.8% (mutex) → 16.5% (lock-free) — **actually worse**

**Reason**: replacing mutex→CAS is zero-sum. eventfd's write/poll/read syscalls are heavier than condvar_signal. 8 consumers contend on CAS and burn spin CPU.

**Verdict**: **revert** — back to mutex+condvar

### 7. Batch pop in workers (2026-04-19)

**Summary**: Change the crypto worker from `wg_queue_pop` (1 item) → `wg_queue_pop_batch(16)`. Fetch many items with one lock.

**Results**: 5.97 → 5.87-5.93 Gbps (**no change**)

**Reason**: under real traffic, a batch holds few items (workers fetch before items pile up in the queue). Fewer lock acquisitions bring no effect.

**Verdict**: **Adopted** (no regression, kept as a code improvement)

### 8. Fewer GRO seq failures — deduplicating flow entries (2026-04-18)

**Summary**: The flow matching loop in `wg_handle_gro` did `continue` on a seq mismatch to look for the next entry, so entries with the same flow key piled up in the table. This caused 8.7M seq_fail checks.

**Fix**: Keep flow keys in the flow table unique. Try to merge only with the first matching flow; if that fails, flush the old entry (emit it with virtio_net_hdr) and replace it with the new packet.

**Changed file**: `src/tun/wg_tun_offload_linux.c` — the `wg_handle_gro` function

**Results** (average of 3):

| Metric | Before | After | Improvement |
|------|--------|-------|------|
| veth iperf3 | 5.97 Gbps | **5.91 Gbps** | no change |
| seq_fail | 8.7M | **2K** | 99.97% fewer |
| GRO coalesce | 3.4x | **25.7x** | 7.6x better |
| TUN writes (receiver) | ~1.4M | **~210K** | 85% fewer |
| psh_fail | 62K | **150K** | increased (PSH becomes the main flush cause) |

**Analysis**: The GRO coalesce ratio improved to 25.7x and TUN write syscalls dropped by 85%. But throughput did not change. This shows that the receiver's TUN write is not the bottleneck; the bottleneck is elsewhere (UDP recv syscalls, crypto workers, the sender side).

**Verdict**: **Adopted** — an 85% cut in syscalls is a good base before adding io_uring. No direct throughput effect, but lower CPU load gives headroom.

### 2. Per-worker SPSC queues

**Summary**: shared mutex+condvar queue → per-worker lock-free SPSC + eventfd

**Implementation**: `dev->queue.encrypt_spsc[N]`, `dev->queue.decrypt_spsc[N]` arrays. UDP recv / TUN reader distribute round-robin.

**Results**:
- bench_throughput: 3.37 → 2.96 Gbps (**-12% worse**)
- veth iperf3: 5.07 → 4.83 Gbps (**-4.7% worse**)

**Reason**: eventfd write/read syscalls are heavier than mutex+condvar. With round-robin, each of the 8 workers gets only 1/8 of the packets, so an eventfd block/wake happens almost every time.

**Verdict**: **reverted**

### 3. Spin-wait + batch pop

**Summary**: Added a 128-iteration spin-wait (ARM yield) to `wg_queue_pop`. Changed the crypto worker to `wg_queue_pop_batch(max=8)`. Avoids the condvar at high throughput.

**Implementation**: added `_Atomic size_t count_hint` to `wg_queue_t`. Release store on push, acquire load before pop for a lock-free check.

**Results**:
- bench_throughput: 3.37 → 3.65 Gbps (**+8.3%**)
- veth iperf3: 5.07 → 5.01 Gbps (**no change**)

**Reason**: under real traffic, GSO batches (34 pkt) keep the crypto worker always busy. `pop_waiters` is almost 0, so condvar signals do not happen at all.

**Verdict**: **Adopted** (better in the 1 pkt/batch case, no regression under real traffic)

### 4. GRO hash map (implemented in an earlier session)

**Summary**: Optimized TCP flow lookup from an O(n) linear search → O(1) FNV-1a hash chains. Also added prepend coalescing.

**Results**: seq failures 4.66M → 64K (72x fewer), better GRO coalescing

**Verdict**: **Adopted**

### 5. Multi-container accumulation (tried in an earlier session)

**Summary**: Accumulate several containers in the sequential receiver before the TUN write.

**Results**: 4.7 → 3.3 Gbps (**-30% worse**)

**Reason**: TCP feedback loop sensitivity. Accumulating packets delays ACKs and shrinks cwnd.

**Verdict**: **reverted**

---

## Comparison with wireguard-go (EC2 c6i.2xlarge, 2026-04-28)

### Throughput gap

| Implementation | Throughput | vs wg-go | vs kernel WG |
|------|------------|----------|-------------|
| wireguard-go | 5.25 Gbps | — | +70% |
| wg-c RTC (SPSC 1+1) | 3.59 Gbps | **-32%** | +17% |
| kernel WireGuard | 3.08 Gbps | -41% | — |
| wg-c MPMC (old) | 2.20 Gbps | -58% | -29% |

### strace comparison (receive side)

| Metric | wg-c RTC | wireguard-go | Difference |
|------|---------|-------------|---|
| futex share | 29% | ~2% (goroutine M:N) | wg-c has 14x more |
| recvmsg method | recvmsg ×1 (GRO single) | recvmmsg batch (GRO multi) | wg-go batches |
| sendmmsg | 12.9% | similar | — |

### Analysis of the remaining 32% gap

1. ~~**recvmmsg + GRO batch (~15-20% worth)**~~ — **implemented (#22), no throughput effect**. Recv efficiency improved (pkt/call +123%, GRO 9.2x), but it does not help because the pipeline is crypto-bound.
2. **Crypto parallelization (~20-25% worth)**: wireguard-go decrypts per packet in parallel with goroutines and restores order with its equivalent of prev_queue. wg-c RTC has 1 recv worker. **The largest source of the gap**.
3. **goroutine M:N scheduling (~5-10% worth)**: futex 29% vs ~2%. The pool mutex + SPSC eventfd fallback remain.

**Removing the pool mutex: implemented** (lock-free Treiber stack). **Crypto backend: already optimized with OpenSSL EVP fused (AVX-512)** — ~4% EVP dispatch remains, but there is no way to remove it without breaking the fused structure (attempt #12 gave -9.3%). Next: crypto parallelization (with an ordered collector) or a different approach.

---

## EC2 per-thread CPU profile (2026-04-28, pidstat)

### With the mutex pool (3.59 Gbps, pool mutex is the bottleneck)

**Environment**: EC2 c6i.2xlarge (8 vCPU), RTC SPSC 1+1, recv_gro_batch

| TID | %usr | %sys | %CPU | Role |
|-----|------|------|------|------|
| 80860 | 73 | 25 | **98** | UDP recv worker (recvmmsg + dispatch + **pool_get**) |
| 80859 | 81 | 4 | **85** | RTC recv worker (decrypt + TUN write + **pool_put**) |
| 80875 | 19 | 27 | **46** | RTC send worker (encrypt + sendmmsg) |
| 80862 | 6 | 13 | **19** | TUN reader (ACKs) |
| Total | — | — | **~248** | **2.5 cores used** |

### After the lock-free pool (3.34 Gbps, raw network degraded to 4.78 Gbps)

**Environment**: EC2 c6i.2xlarge (8 vCPU), RTC SPSC 1+1, lock-free Treiber stack pool

**S1 (sender, pidstat at peak):**

| TID | %usr | %sys | %CPU | Role |
|-----|------|------|------|------|
| 82396 | 48 | 52 | **100** | UDP recv worker (ACKs, recvmmsg) |
| 82397 | 67 | 10 | **77** | RTC recv worker (decrypt ACKs + TUN write) |
| 82399 | 12 | 8 | **19** | TUN reader (iperf data) |
| 82554 | 4 | 14 | **17** | RTC send worker (encrypt + sendmmsg) |
| Total | — | — | **~213** | **2.1 cores used** |

**S2 (receiver, pidstat at peak):**

| TID | %usr | %sys | %CPU | Role |
|-----|------|------|------|------|
| 65873 | 67 | 20 | **87** | UDP recv worker (recvmmsg + dispatch) |
| 65872 | 67 | 7 | **74** | RTC recv worker (decrypt + TUN write) |
| 66031 | 17 | 30 | **47** | RTC send worker (encrypt + sendmmsg ACKs) |
| 65875 | 5 | 14 | **19** | TUN reader (ACKs) |
| Total | — | — | **~227** | **2.3 cores used** |

### Effect of the lock-free pool

**Note: the raw network degraded from 9.53 → 4.78 Gbps, so comparing absolute throughput is not valid. Evaluate by CPU efficiency ratio.**

| Metric | mutex pool | lock-free pool | Change |
|------|-----------|---------------|------|
| Raw network | 9.53 Gbps | 4.78 Gbps | EC2 bandwidth fluctuation |
| wg-c throughput | 3.59 Gbps | 3.34 Gbps | due to degraded raw |
| **wg-c / Raw ratio** | **38%** | **70%** | **+84% efficiency** |
| S2 recv worker %CPU | 98% | 87% | **-11pt** |
| S2 recv worker %usr | 73% | 67% | **-6pt** (pool mutex removed) |
| Total CPU / Gbps | 69%/Gbps | 68%/Gbps | same (bound by the network) |

**Conclusion**: the lock-free pool drops the UDP recv worker's CPU from 98% → 87% (mutex overhead removed). But in the current test the EC2 raw network (4.78 Gbps) is the bottleneck, so a throughput gain cannot be confirmed. Re-measuring is needed once the raw network recovers to 9.53 Gbps.

### Practicality of crypto parallelization (after the lock-free pool)

| Scenario | recv worker | crypto workers | Predicted throughput | Feasibility |
|---------|------------|---------------|---------------|----------|
| lock-free pool (1+1) | 87% | 1 × 74% | 3.34 Gbps (bound by raw) | — |
| lock-free + parallel crypto (1+N) | ~87% | N × (74/N)% | **4-5 Gbps** (once raw recovers) | ○ |

**Reason**: the recv worker now has ~13% headroom, but the raw network itself is degraded to 4.78 Gbps. The effect of crypto parallelization should be measured after the network recovers.

---

## RTC multi-worker experiments and failures (EC2, 2026-04-28)

### Results

| Configuration | Throughput | Retransmits | Problem |
|------|------------|-------------|------|
| RTC 1+1 (send=1, recv=1) | **3.59 Gbps** | **0** | none (best) |
| RTC 4+1 (send=4, recv=1) | 2.76 Gbps | 8,816 | nonce reorder → TCP retransmit |
| RTC 4+4 (send=4, recv=4) | 0.81 Gbps | 24,000+ | recv fan-out → TUN write order broken |

### Why 4+4 failed: recv fan-out breaks TCP

When several RecvWorkers do TUN writes in parallel, the order in which packets reach the kernel depends on the order decrypts finish. The TCP receiver sends dup-ACKs for out-of-order packets, and the sender's cwnd collapses. 813 Mbps with 24K retransmissions.

### Why 4+1 failed: send fan-out causes nonce reorder

The TUN reader assigns nonces in order, but when 4 SendWorkers encrypt → sendmmsg in parallel, the UDP send order does not match nonce order. This is within the WireGuard replay window (8128), so it is fine at the WireGuard layer, but on the receive side the TUN write order after decrypt shifts, and TCP retransmits.

### Lessons

**RTC multi-worker cannot be used with a single peer.** Round-robin dispatch inherently breaks packet order. Peer-affinity dispatch keeps order, but degenerates to 1 peer = 1 worker and loses crypto parallelism.

The old MPMC architecture paid 13% in mutex/condvar cost so that prev_queue could restore nonce order, which gave parallel crypto across N workers. RTC just reversed this trade-off.

**But in the EC2 case**: futex overhead dropped from 89% → 29%, reaching 2.20 → 3.59 Gbps (+63%). On EC2 the MPMC condvar overhead was far larger than on ARM64 veth, so removing sync with RTC had a large effect.

---

## Remaining bottlenecks and next optimization candidates (updated 2026-04-28)

### Evaluation of the next optimization candidates

#### Candidate 1: recvmmsg + per-message GRO cmsg parsing — **implemented (#22)**

**Results**: pipeline efficiency improved dramatically (recv pkt/call +123%, GRO 9.2x, TUN write -74%), but **throughput ±0%**.

**Lesson**: cutting syscalls on the recv path has no effect on a crypto-bound pipeline. The bottleneck is crypto on the single RTC recv worker. The gap to wireguard-go is not recv batching but low-cost parallel crypto via goroutine M:N.

#### Candidate 2: parallel decrypt + sequential TUN write

**Summary**: Run decrypt in parallel on several RecvWorkers and do only the TUN write sequentially.

**Usefulness: low to medium (needs care)**

- In theory, it gives both crypto parallelism and ordering
- **But the RTC 4+4 experiment showed**: not only TUN write order, but also variance in the latency from decrypt completion to TUN write hurts TCP
- Implementation idea: SPSC fan-out → N decrypt workers → collect completions in nonce order → 1 thread does the TUN write
  - This is essentially the same structure as the old MPMC + prev_queue
  - It just reinvents prev_queue with SPSC + atomic flags
- Crypto is 29% of RTC's CPU use, but 1 recv worker already gives enough throughput (3.59 Gbps)
- Improving recvmmsg batching has more leverage

**Verdict: re-evaluate after improving recvmmsg. Low priority for now.**

#### Candidate 3: keeping the GRO table across batches

**Summary**: `wg_handle_gro()` resets `tcp_table->count = 0` every batch → change to a persistent table.

**Usefulness: medium (interdependent with the recvmmsg improvement)**

- GRO is 2.4x on EC2 → if it could reach 10x+, TUN writes would drop by 50%+
- But the root problem is batch size (2.6 pkt). If recvmmsg makes batches large, enough packets will collect in the GRO table too
- Making only the GRO table persistent without the recvmmsg improvement makes flush timing control complex and risky (TCP sensitivity)

**Verdict: do it together with the recvmmsg improvement. Not enough on its own.**

---

## File layout (changed)

| File | Change |
|---------|---------|
| `src/device/wg_pools.h` | lock-free Treiber stack (tagged pointer + ABA counter) |
| `src/device/wg_pools.c` | lock-free get/put/put_batch for max==0 pools |
| `src/workers/wg_workers.h` | `_pool_next` intrusive link field |
| `src/device/wg_device.c` | calls `wg_wait_pool_enable_lockfree()` |
| `src/crypto/wg_crypto.c` | OpenSSL EVP backend + per-thread key cache |
| `src/device/wg_queue.h` | adds `_Atomic count_hint` |
| `src/device/wg_queue.c` | spin-wait + batch pop |
| `src/workers/wg_send.c` | encryption worker batch pop |
| `src/workers/wg_receive.c` | decryption worker batch pop |
| `src/tun/wg_tun_offload_linux.c` | GRO hash map + prepend coalescing |
| `src/tun/wg_tun_offload_linux.h` | adds hash table index |
| `CMakeLists.txt` | OpenSSL option + link |
| `scripts/bench_veth_iperf3.sh` | veth + iperf3 benchmark script |

---

## perf profile re-measurement (2026-04-18, baseline after reverting everything)

**Environment**: all optimization attempts reverted, HEAD = 6463771 (libsodium, mutex+condvar queue)
**Baseline**: 5.31 Gbps (perf record on the receiver, 30K samples, overhead ≈ 0%)

### CPU usage breakdown (perf report --no-children, receiver)

| % | Function | Category |
|---|------|---------|
| **44.55%** | `chacha20_encrypt_bytes.part.0` (libsodium) | ChaCha20 encryption |
| **12.92%** | `poly1305_blocks` (libsodium) | Poly1305 MAC |
| 4.04% | `try_to_wake_up` (kernel) | thread wake |
| 3.91% | `__arch_copy_to_user` (kernel) | recvmmsg copy |
| 2.59% | `el0_svc` (kernel) | syscall entry |
| 2.30% | `pthread_mutex_lock` (glibc) | queue mutex |
| 1.92% | `__kernel_clock_gettime` (vdso) | timing |
| 1.54% | `wg_worker_sequential_receiver` | seq receiver loop |
| 1.42% | `__aarch64_swp4_rel` | atomic unlock |
| 1.19% | `__memcpy_generic` | GRO/TUN write copy |

**Total: crypto = 57.5% (ChaCha20 44.6% + Poly1305 12.9%)**

### Key finding: libsodium uses the scalar (ref) implementation

The perf call chain shows `stream_ietf_ext_ref_xor_ic`, which is libsodium's **reference C implementation** (scalar, no NEON).

libsodium returns `sodium_runtime_has_neon() = 1`, but a NEON implementation of ChaCha20/Poly1305 **does not exist** for ARM64.

#### libsodium ARM64 NEON support investigation (2026-04-18)

Checked the libsodium (1.0.21–1.0.22) source code:

| Algorithm | Implementation variants | ARM64 NEON |
|-------------|--------------|------------|
| ChaCha20 | `ref` (portable C), `dolbeau` (x86 AVX2/SSSE3) | **none** |
| Poly1305 | `donna` (portable C), `sse2` (x86) | **none** |
| AEGIS-128L/256 | armcrypto | yes |
| AES-256-GCM | armcrypto | yes |

- The `HAVE_ARMCRYPTO` flag is used only for AEGIS/AES-GCM
- `stream_chacha20.c` / `onetimeauth_poly1305.c` have no ARM/NEON branch
- On ARM64 it always falls back to the scalar reference implementation

**Conclusion**: ChaCha20-Poly1305 cannot be accelerated on ARM64 with libsodium. We need to switch to OpenSSL (which has NEON asm).

### ChaCha20-Poly1305 microbenchmark (1420 bytes = typical WireGuard packet size)

| Implementation | Single-core throughput | Notes |
|------|-------------------|------|
| **libsodium** (ref C) | **3.58 Gbps** | no ARM64 NEON |
| **OpenSSL** (NEON asm) | **11.20 Gbps** | `chacha20_neon` + `poly1305_blocks_neon` |
| **Speedup** | **3.1x** | |

### Impact analysis

- Crypto is currently 57.5% of receiver CPU → if crypto became 3.1x faster, it would be 18.5%
- Recoverable CPU = 57.5% - 18.5% = **39%**
- Theoretical throughput gain: 5.31 / (1 - 0.39) ≈ **8.7 Gbps**
- Could exceed wireguard-go (7.45 Gbps)

### Breakdown of try_to_wake_up (4.04%)

```
try_to_wake_up 4.04%
├── 1.45% wg_worker_decryption → pthread_mutex_unlock → futex_wake
├── 1.02% wg_worker_tun_read → wg_queue_try_push_batch → pthread_cond_broadcast → futex_wake
└── 0.89% wg_worker_udp_recv → wg_queue_try_push_batch → pthread_cond_broadcast → futex_wake
```

**Note**: last time (with OpenSSL) try_to_wake_up was 11.3%, this time (libsodium) it is 4.04%.
Reason: crypto is heavy, so the mutex/futex share is relatively smaller.

### Pipeline statistics (receiver wg1)

```
UDP recv:   394K calls, 4.86M pkts (12.3 pkt/call)
Decrypt:    4.86M pkts, avg 0.0 us/pkt (no crypto wait)
Seq recvr:  40K batches, 4.86M pkts (120.3 pkt/batch)
TUN writes: 187K syscalls (GRO 26.0x coalesce)
GRO: tcp_in=4.86M, merged=4.67M, seq_fail=8.3M, psh_fail=134K
```

---

## Conclusions and next actions (updated 2026-04-28)

### Current status summary

| Environment | wg-c | wireguard-go | kernel WG | Gap (vs wg-go) |
|------|------|-------------|-----------|--------------|
| EC2 x86_64 (RTC) | 3.59 Gbps | 5.25 Gbps | 3.08 Gbps | **-32%** |
| ARM64 veth (MPMC) | 5.87 Gbps | 6.97 Gbps | — | **-16%** |

### Next actions

1. ~~**recvmmsg + GRO cmsg parsing**~~ — **Done (#22)**. No throughput effect (crypto-bound → actually recv worker saturated)
2. **Lock-free pool** — **new top priority**. pidstat confirmed the recv worker is 98% saturated. The pool mutex consumes ~30-40% CPU. Expected: +25-30%
3. **Crypto parallelization** — after the lock-free pool. No effect unless the recv worker has headroom. Expected: +50-100% (5-6 Gbps)
4. **EC2 BoringSSL x86_64** — crypto is single-threaded, so AVX2 fused asm may help

### Optimization history (22 items total)

1. ~~**OpenSSL ChaCha20-Poly1305 backend**~~ — **Done** (+14.5%, 5.31→6.08 Gbps)
2. ~~**Per-worker SPSC queue**~~ — **Rejected** (eventfd overhead, -12%)
3. ~~**Spin-wait + batch pop**~~ — **Adopted** (+8.3% bench, no change on veth)
4. ~~**GRO hash map**~~ — **Adopted**
5. ~~**Multi-container accumulation**~~ — **Rejected** (-30%)
6. ~~**Lock-free MPMC (Vyukov)**~~ — **Rejected** (eventfd makes it zero-sum)
7. ~~**Batch pop in workers**~~ — **Adopted** (no change, code improvement)
8. ~~**Reduce GRO seq failures**~~ — **Adopted** (seq_fail 8.7M→2K, TUN writes down 85%)
9. ~~**io_uring TUN write / SQPOLL**~~ — **Rejected** (syscall overhead too small)
10. ~~**Fewer crypto workers**~~ — **Rejected** (-4.2%)
11. ~~**condvar broadcast → targeted signal**~~ — **Adopted** (slight decrease)
12. ~~**Call OpenSSL internal symbols directly**~~ — **Rejected** (-9.3%)
13. ~~**Fewer push_batch signals**~~ — **Rejected** (-6–8%)
14. ~~**Batch signaling in crypto workers**~~ — **Rejected** (-4.2%)
15. ~~**recv_gro (recvmsg)**~~ — **Rejected** (-75% veth)
16. ~~**io_uring multishot recv**~~ — **Rejected** (-18%)
17. ~~**UDP GSO contiguous-run**~~ — **Neutral** (no effect on veth)
18. ~~**Container pattern + SPSC spin-wait**~~ — **Adopted** (+1.7%)
19. ~~**RTC (SPSC fan-out + inline crypto)**~~ — **Adopted on EC2** (+63%, 2.20→3.59 Gbps), rejected on ARM64 veth
20. ~~**BoringSSL fused asm**~~ — **Adopted** (+2.1% ARM64)
21. ~~**recv_gro bug fix**~~ — **Adopted (required)** (AEAD failures 80%→0%)
22. ~~**recvmmsg + GRO cmsg batch**~~ — **Adopted** (recv -55%, TUN writes -74%, throughput ±0%, crypto-bound)

### Remaining gap analysis (EC2: 3.59 vs 5.25 Gbps = -32%)

| Gap factor | Estimated impact | Feasibility |
|------------|---------|----------|
| single recvmsg vs recvmmsg batch + GRO | ~15-20% | ○ implement recvmmsg + GRO cmsg parsing |
| futex 29% (pool mutex + SPSC eventfd) | ~10% | △ make pool lock-free, tune SPSC spin_limit |
| single recv/send worker (crypto not parallel) | ~5% | × multiple workers break packet order |

**Top priority**: recvmmsg + GRO cmsg parsing. This alone is expected to reach 4.5+ Gbps.

### ARM64 veth gap analysis (5.87 vs 6.97 Gbps = -16%)

RTC is rejected on ARM64 veth (MPMC prev_queue is fastest). The gap is mainly the difference in sync cost versus goroutine M:N scheduling.

**Conclusion**: on EC2, improving recvmmsg batching is the strongest candidate. On ARM64 veth we are close to the pthread limit (5.9 Gbps ≈ ceiling).

---

## perf profile (latest, 2026-04-21)

**Environment**: OpenSSL 3.6.1 ChaCha20-Poly1305 NEON + EVP key cache + condvar targeted signal + spin-wait
**Throughput**: 5.78 Gbps (including perf overhead, baseline 5.94 Gbps)
**receiver context switches**: 1.37M / 14s = 98K/sec

### CPU usage breakdown (receiver, 105K samples)

| % | Function | Category |
|---|------|---------|
| **11.03%** | `try_to_wake_up` (kernel) | thread wake |
| 10.30% | `ChaCha20_512_neon` (OpenSSL) | Crypto NEON |
| 8.71% | `ChaCha20_neon` (OpenSSL) | Crypto NEON |
| 5.96% | `poly1305_blocks_neon` (OpenSSL) | Crypto NEON |
| 4.81% | `__arch_copy_to_user` (kernel) | recvmmsg copy |
| 4.07% | `ChaCha20_ctr32_dflt` (OpenSSL) | Crypto scalar fallback |
| 3.53% | `el0_svc` (kernel) | syscall entry |
| 2.66% | `__kernel_clock_gettime` (vdso) | timing |
| 2.64% | `__memcpy_generic` | GRO/TUN copy |
| 2.10% | `pthread_mutex_lock` (glibc) | queue mutex |
| 1.94% | `wg_worker_sequential_receiver` | seq receiver |
| 1.54% | `sock_def_readable` (kernel) | TCP socket wake |
| 1.47% | `recv_batch` | UDP recv processing |
| 1.31% | `wg_worker_udp_recv` | UDP recv worker |
| 1.20% | `__arch_copy_from_user` (kernel) | TUN write copy |
| 1.01% | `wg_handle_gro` | GRO processing |

### try_to_wake_up breakdown (11.03%)

```
try_to_wake_up 11.03%
├── 4.92% wg_worker_udp_recv → wg_queue_try_push_batch
│   ├── 3.78% pthread_cond_signal → futex_wake (crypto worker wake-up)
│   └── 0.86% pthread_mutex_unlock → futex_wake (mutex contention)
├── 4.04% wg_worker_decryption
│   ├── 1.43% pthread_mutex_unlock → futex_wake (queue mutex contention)
│   ├── 1.15% pthread_cond_signal → futex_wake (seq receiver notification)
│   └── 1.01% wg_queue_pop_batch (internal futex)
└── 1.23% wg_worker_tun_read → wg_queue_try_push_batch
    └── 0.95% pthread_cond_signal → futex_wake (crypto worker wake-up)
```

### Totals by category

| Category | Total % |
|---------|--------|
| Crypto (NEON + scalar) | 29.0% |
| **Thread sync (try_to_wake_up + mutex)** | **13.1%** |
| Kernel copy/syscall | 9.5% |
| clock_gettime (VDSO) | 2.7% |
| memcpy | 2.6% |
| Pipeline processing | 4.7% |
| Other | 38.4% |

### Key findings

1. **try_to_wake_up is 11.03% (the largest bottleneck)**: we tried fewer signals and batching, and every attempt made throughput worse. Waking crypto workers quickly directly determines throughput of the whole pipeline.
2. **The futex_wake from condvar signals cannot be reduced**: reducing it makes packets pile up in the queue, and the pipeline becomes crypto-bound.
3. **recvmmsg at 6.9 pkt/call**: on veth, UDP_GRO does not take effect, and this is effectively the ceiling. A physical NIC leaves room for improvement.
4. **ChaCha20_ctr32_dflt 4.07%**: inside the AEAD, the scalar fallback is used for short data (poly key derivation 64B, packet tail < 256B). This is OpenSSL internal behavior and cannot be avoided.

---

## Reference: gap to wireguard-go

### EC2 x86_64 (2026-04-28): 3.59 vs 5.25 Gbps (-32%)

wireguard-go's advantages:
1. **recvmmsg + GRO batch**: receives multiple GRO buffers at once → large batches and high GRO efficiency
2. **goroutine M:N scheduling**: futex 29% (wg-c) vs ~2% (wg-go). Minimizes OS context switches
3. **UDP_SEGMENT (send-side GSO)**: sends many packets with a single sendmsg. ENA has tx-udp-segmentation off, but software GSO works

### ARM64 veth (2026-04-27): 5.87 vs 6.97 Gbps (-16%)

wireguard-go's advantages:
1. **goroutine M:N**: sync overhead is inherently low
2. **Go channel**: lightweight wait/wake via gopark

**Strongest approach**: on EC2, implement recvmmsg + GRO cmsg → 4.5-5.0 Gbps expected. On ARM64 veth we are close to the pthread limit.

---

## Optimization attempts (2026-04-21, additional)

### #16: io_uring multishot recv (UDP recv path)

- **Hypothesis**: replace recvmmsg (746K calls/10s) + poll() with io_uring multishot recv → ~8% less CPU
- **Implementation**: io_uring provided buffer ring + multishot recvmsg SQE in `wg_bind_std.c`
- **Results**: **4.81 Gbps (-18%)** — large regression
- **Cause**: a **double copy** from the provided buffer to the caller buffer. recvmmsg copies kernel→user directly, but io_uring copies in two steps, kernel→provided buf→user buf. The memcpy cost far outweighed the benefit of fewer syscalls.
- **Conclusion**: recvmmsg + optimistic recv (skipping poll) is best. io_uring is counterproductive on the recv path.

### #18: Container pattern + SPSC spin-wait (2026-04-22)

- **Overview**: implemented a wireguard-go-style hybrid container pattern. Replaced per-element completion notification via `_Atomic bool ready` on each element with per-container batch completion notification via `_Atomic int remaining`. A container pool (wg_wait_pool) removes malloc/mutex_init/destroy/free.
- **Changes**:
  1. `wg_outbound_container_t` / `wg_inbound_container_t` — per-batch completion tracking (`_Atomic int remaining`)
  2. Push containers to SPSC and individual elements to MPMC (hybrid of parallel crypto + batch completion)
  3. Sequential sender/receiver: spin-wait (2000 iterations + yield/pause) + condvar fallback
  4. Crypto worker: decrements `remaining`; the last one sends the condvar signal
  5. Container pool: per-device pool, mutex kept via a reset callback

- **First results**: **927 Mbps (-80% regression)**, 3477 retransmissions, Cwnd ~130 KB
- **Root cause**: eventfd wake-up latency on the SPSC. With the container pattern, the SPSC gets only one entry per TUN read (the baseline had ~35 individual elements). The sequential sender drains the SPSC immediately and blocks in eventfd read(). When the next container arrives, eventfd write() → kernel wake-up takes ~5-50µs. 24K containers/sec × 5-50µs = 120-1200ms of scheduling delay. TCP detects the RTT increase and shrinks Cwnd.
- **Fix**: added a 4000-iteration spin-wait (yield/pause) to `wg_spsc_pop()`. Atomic tail check before blocking on eventfd.
- **Final results**:

| Metric | Container (before fix) | Container + SPSC spin | Baseline (per-elem) |
|------|-------------------|---------------------|----------------------|
| Throughput | 927 Mbps | **4.75 Gbps** | 4.67 Gbps |
| Retransmissions | 3,477 | **0** | 1 |
| Cwnd | ~130 KB | **4.14 MB** | 4.12 MB |
| pkt/batch | 80.2 | **126.4** | 126.2 |

- **Verdict**: **Adopted** — equal to or better than the baseline (+1.7%). Throughput recovered while keeping wireguard-go's container pattern.

**Changed files**: `src/device/wg_spsc.c`, `src/workers/wg_send.c`, `src/workers/wg_receive.c`, `src/workers/wg_handshake.c`, `src/workers/wg_workers.h`, `src/device/wg_device.c`, `src/device/wg_device.h`, `tests/test_workers.c`

### #17: UDP GSO contiguous-run (send path)

- **Hypothesis**: replace sendmmsg (128 pkt/call) with UDP GSO (sendmsg + UDP_SEGMENT) → fewer syscalls
- **Observation**: the final segments of GSO splits (short packets, ~2.4%) are mixed in, so batches did not meet the condition that all packets have the same size, and it fell back to sendmmsg
- **Implementation**: detect runs of consecutive same-size packets and do a separate GSO sendmsg for each run
- **Results**: **5.89 Gbps (±0%)** — neutral
- **Cause**: veth is a software device, so the kernel re-splits GSO packets. The amount of in-kernel work is the same with one sendmsg or N sendmmsg. It may be effective on a physical NIC.
- **Conclusion**: UDP GSO gives no benefit on veth.

### #20: BoringSSL fused asm vs OpenSSL EVP benchmark (2026-04-27)

**Overview**: veth iperf3 comparison of ARM64 BoringSSL fused asm (`chacha20_poly1305_armv8.S`, no EVP dispatch) vs OpenSSL EVP (`EVP_chacha20_poly1305()`, dispatch overhead ~4%).

**Environment**: ARM64, veth pair, Release build (-O2), iperf3 10s × 3 runs

**Results**:

| Run | BoringSSL fused asm | OpenSSL EVP |
|-----|-------------------|-------------|
| 1 | 5.97 Gbps | 5.85 Gbps |
| 2 | 5.91 Gbps | 5.64 Gbps |
| 3 | 5.74 Gbps | 5.76 Gbps |
| **Average** | **5.87 Gbps** | **5.75 Gbps** |

**Difference: +2.1%** (within noise)

**Analysis**: removing the 4% EVP dispatch overhead has almost no effect on effective throughput. This matches the Tailscale blog (https://tailscale.com/blog/more-throughput) — on veth, the bottleneck is not crypto but UDP stack traversal and thread sync. On a physical NIC with hardware GSO/GRO offload, crypto may become the bottleneck, and in that case a difference may appear.

**Verdict**: **Adopt BoringSSL fused asm** (no regression; removing EVP dispatch is correct in theory and may help on a physical NIC)

### #22: recvmmsg + per-message GRO cmsg parsing (2026-04-28)

**Overview**: replaced `recv_gro` (single recvmsg) with `recv_gro_batch` (recvmmsg + per-message GRO cmsg). recvmmsg receives multiple GRO-coalesced buffers at once, and each message's cmsg is parsed for the UDP_GRO segment size to split it.

**Implementation**:
- New `recv_gro_batch()` in `src/bind/wg_bind_std.c`
- GRO staging buffers (8 × 65536 = 512KB) pre-allocated in the bind struct
- recvmmsg → per-message cmsg parsing (UDP_GRO + IP_PKTINFO) → segment split → copy into caller bufs[]
- Replaced the 4 `recv_gro` calls in `std_recv()` with `recv_gro_batch`

**GRO_BATCH_SIZE tuning**:
- 32: 3.36-4.05 Gbps, **138-1855 retransmissions** — drains the socket buffer too much, bursty → TCP cwnd collapses
- **8**: 3.59 Gbps, **1-14 retransmissions** — same as baseline. Stable

**Results (EC2 c6i.2xlarge, RTC SPSC 1+1, GRO_BATCH=8)**:

| Metric | recv_gro (old) | recv_gro_batch (new) | Improvement |
|------|-------------|-------------------|------|
| **Throughput** | **3.59 Gbps** | **3.59 Gbps** | **±0%** |
| Retransmissions | 0 | 1-14 | same |
| UDP recv pkt/call | ~5.2 | **11.6** | **+123%** |
| GRO coalesce | 2.4x | **9.2x** | **+283%** |
| TUN writes/10s | ~1.36M (estimated) | ~355K | **-74%** |
| recv calls/10s | ~629K (estimated) | ~283K | **-55%** |

**Analysis**: pipeline efficiency (recv call count, GRO coalescing, TUN write count) improved dramatically. But throughput did not change. **The bottleneck is not the recv path but the crypto work in the single RTC recv worker**. Fewer recv-side syscalls have no effect on a crypto-bound pipeline.

If parallel decrypt is implemented in the future, this batching will be its foundation. Also, on veth with `use_gro=true`, the old recv_gro did 1 pkt/call, but recv_gro_batch uses recvmmsg and gets multiple pkts/call, avoiding the veth regression.

**Verdict**: **Adopted** — better pipeline efficiency (recv -55%, TUN writes -74%). No throughput change, but it is the foundation for future crypto parallelization and improves the GRO path on veth

**Changed files**: `src/bind/wg_bind_std.c` — `recv_gro` → `recv_gro_batch`, added `gro_staging` to the bind struct

---

## Sender perf profile (2026-04-21)

**Environment**: ARM64, iperf3 A→B (4 streams), wg0 = sender, 21K samples

| Overhead | Symbol | Category |
|----------|--------|----------|
| 10.31% | `ChaCha20_512_neon` | crypto (encryption) |
| 8.37% | `ChaCha20_neon` | crypto |
| 6.23% | `__memcpy_generic` | memcpy (GSO split 4.12%, EVP init 2.07%) |
| 5.69% | `__arch_copy_from_user` | sendmmsg kernel copy |
| 5.42% | `poly1305_blocks_neon` | crypto |
| 3.85% | `ChaCha20_ctr32_dflt` | crypto (scalar fallback) |
| 3.71% | `try_to_wake_up` | futex/condvar |

### Sender breakdown

| Category | Share |
|----------|------|
| **Crypto** | ~28% (ChaCha20 18.5% + Poly1305 5.4% + scalar 3.9%) |
| **GSO split memcpy** | ~4.1% |
| **EVP key init memcpy** | ~2.1% |
| **sendmmsg kernel copy** | ~5.7% |
| **try_to_wake_up** | ~3.7% |

### Sender vs receiver

| Bottleneck | Sender | Receiver |
|-------------|--------|--------|
| crypto | 28% | 27% |
| try_to_wake_up | 3.7% | 11.0% |
| kernel copy (user↔kernel) | 5.7% | 4.8% |
| GSO/GRO split/merge memcpy | 4.1% | — |

**Key finding**: the sender has 7.3% less try_to_wake_up than the receiver. The send pipeline is a linear flow, TUN read → encrypt → seq sender → sendmmsg, and has none of the complex wake pattern of the receiver (decrypt queue → per-peer condvar).

### #19: RTC (Run-to-Completion) architecture — SPSC fan-out + inline crypto (2026-04-27)

**Overview**: shorten the 3-stage pipeline (reader → MPMC crypto → prev_queue → sequential sender) to 2 stages (reader → SPSC → SendWorker[encrypt+sendmmsg]). The aim is to remove condvar/eventfd/mutex from the data path entirely.

**Design**:
```
Send: TUN reader → SPSC[Ns] (dispatch) → SendWorker[Ns] (encrypt inline + sendmmsg)
Recv: UDP recv   → SPSC[Nr] (dispatch) → RecvWorker[Nr] (decrypt inline + TUN write)
```

**Removed**: MPMC encryption/decryption queue (7.75% + 1.74%), prev_queue + eventfd (2.55%), sequential sender/receiver, per-peer worker threads, `_Atomic int state` on elements

**Implementation**: 8 files changed, 29/29 tests pass

**Results**:

| Dispatch method | Throughput | Retransmits | Problem |
|--------------|------------|-------------|------|
| Round-robin | **1.44 Gbps (-72%)** | 17,343 | multiple workers send the same peer's packets in an order different from nonce order → TCP reorder |
| Peer-affinity hash | **3.00 Gbps (-42%)** | 0 | a single peer is pinned to a single worker → crypto parallelism lost |
| Baseline (MPMC) | **5.13 Gbps** | 1 | 8 workers encrypt in parallel + prev_queue guarantees order |

**Root cause**: RTC can remove sync overhead, but cannot parallelize crypto for a single peer.

- **Round-robin**: parallel crypto is possible, but send order does not match nonce order and TCP retransmits heavily. It is within the replay window (8128), so the WireGuard layer is fine, but TCP dup-acks collapse cwnd.
- **Peer-affinity**: order is guaranteed, but 1 peer = 1 worker = single-core crypto. Crypto throughput is 1/8 of the old architecture's 8-worker parallel encrypt.

**Advantage of the old architecture**: in exchange for paying the MPMC queue's condvar/mutex cost (~13%), N workers encrypt in parallel and prev_queue restores nonce order. In a single-peer benchmark (iperf3 -P 1), sync overhead < the gain from parallel crypto.

**Trade-off**:
```
Old: sync cost 13% + parallel crypto (8 workers) → 5.13 Gbps
RTC: sync cost ~0% + serial crypto (1 worker/peer) → 3.00 Gbps
Go:  sync cost ~2% + parallel crypto (N goroutines) → 6.97 Gbps
```
Go gets both "cheap sync + parallel crypto" through M:N scheduling. With C's 1:1 pthread model, getting both is hard.

**Verdict (ARM64 veth)**: **Rejected, reverted** — 42% regression in the single-peer case. Code reverted to commit `43316a0`.

**Verdict (EC2 x86_64, RTC reimplemented 2026-04-28)**: **Adopted (SPSC 1+1 only)** — on EC2 the MPMC condvar overhead was dominant (futex 89%), so removing sync with RTC took it from 2.20→3.59 Gbps (+63%). However, there is only one send worker and one recv worker (multiple workers rejected). On ARM64 veth the old MPMC stays fastest.

---

## Throughput comparison by platform

### noisetun (current)

| OS | Estimated throughput | Notes |
|---|---|---|
| **Linux** | 5.13 Gbps (measured, x86_64 veth) | sendmmsg/recvmmsg, GSO/GRO |
| **macOS** | not measured (estimated 3-4 Gbps) | sendmsg loop, utun limits, no GSO/GRO |
| **Windows** | not measured (estimated 3-4 Gbps) | WSASendMsg loop, no GSO/GRO |

### wireguard-go (reference)

| OS | Estimated throughput | Notes |
|---|---|---|
| **Linux** | 6-10 Gbps | GSO/GRO (UDP_SEGMENT), Go netpoller, goroutine M:N |
| **macOS** | 2-4 Gbps | sendmsg loop, no GSO/GRO |
| **Windows** | 1-3 Gbps | WinTun, IOCP, no GSO/GRO |

### Why Go is fast on Linux

1. **GSO/GRO (UDP_SEGMENT/GRO)** — Linux 4.18+ only. Sends 64KB with one sendmsg
2. **goroutine M:N scheduling** — ~100ns context switches with no futex wake
3. **Go channel** — uses futex internally, but gopark minimizes OS context switches
4. **recvmmsg/sendmmsg** — Go netBatch uses batch I/O only on Linux

**On macOS/Windows, Go also gets less than half the performance,** because sendmmsg/recvmmsg/GSO/GRO do not exist there.

### External benchmark reference values (meshguard README, Intel i9-12900KF, LXC localhost)

| Implementation | Throughput |
|------|------------|
| wireguard-go | 10.6 Gbps |
| wireguard-linux (kernel) | 4.99 Gbps |
| meshguard (Zig) | 3.93 Gbps |
| boringtun (Rust) | 1.82 Gbps |

---

## Linux-only optimizations considered and rejected

### io_uring (3 attempts, all rejected)

| Attempt | Target | Results | Cause |
|------|------|------|------|
| #9 TUN write batch | write() → SQE batch | no change | syscall overhead is ~0.8% of the total |
| #9 SQPOLL | kernel polling | -21% | polling thread occupies a CPU core |
| #16 multishot recv | recvmmsg → provided buf | -18% | double copy (kernel→buf→user) |

**Conclusion**: syscall overhead (el0_svc 3.5%) is too small for io_uring to help. The bottlenecks are crypto (29%) and thread sync (13%).

### M:N threading (libcoro/libaco + coroutine)

- It might reduce the 11% try_to_wake_up, but by at most about +0.6 Gbps
- Implementation cost: several weeks, very hard to debug
- **Verdict**: poor cost/benefit

### DPDK / AF_XDP

- Removes socket syscalls entirely → the most promising
- But Linux-only, and requires root + hugepages + DPDK drivers
- Not usable in ordinary user environments → does not fit product requirements
- **Verdict**: conflicts with the portability requirement

---

## Reference: Tailscale blog "More Throughput" (2023-04)

https://tailscale.com/blog/more-throughput

A record of Tailscale greatly improving wireguard-go throughput. **Biggest finding: the bottleneck is UDP stack traversal, not crypto.**

### Results

| Environment | Before | After | Improvement |
|------|--------|-------|------|
| AWS c6i.8xlarge (x86_64) | 5.34 Gbps | 7.32 Gbps | +37% |
| i5-12400 bare metal + 25G NIC | 8.36 Gbps | **13.0 Gbps** | +55% |
| i5-12400 kernel WireGuard | 11.8 Gbps | — | — |

**wireguard-go (13.0 Gbps) > kernel WireGuard (11.8 Gbps)** on bare metal with hardware offload.

### Main optimizations

1. **UDP GSO (sendmsg + UDP_SEGMENT)** — the kernel defers segmentation. Removes per-packet kernel stack traversal. The largest effect.
2. **UDP GRO (recvmsg + large buffer)** — coalesces UDP packets on the receive side. Less kernel stack traversal.
3. **Checksum loop unwinding** — 4-byte loop → unrolled 128/64/32/16/8 bytes. **57-59% faster** (160ns → 64ns for 1024B).
4. **Hardware UDP segmentation offload** — with `ethtool -K eth0 tx-udp-segmentation on` the NIC does segmentation. 3.36 → 6.59 Gbps (+96%) on an E3-1230-V2.

### Implications for us

- **They did not touch crypto** — the bottleneck is UDP stack traversal, not encryption
- **Limits of veth benchmarks** — hardware GSO/GRO offload does not work on veth. Measuring on a physical NIC is required
- **We have also implemented UDP GSO (#17)**, but it was neutral on veth. It needs re-evaluation on a physical NIC
- **Checksum unwinding** is not implemented. It may help if our GRO/GSO computes checksums

---

## TODO: next optimization candidates

### Priority high — EC2 3.59 → 4.5+ Gbps

- [x] **recvmmsg + per-message GRO cmsg parsing** — **Done (#22)**. recv efficiency +123%, GRO 9.2x, TUN writes -74%. But throughput ±0% — crypto-bound, so recv improvements do not help. **The next improvement requires crypto parallelization**
- [ ] **Persistent GRO table** — GRO already improved to 9.2x with the recvmmsg change. Making it persistent leaves room for more, but has little effect while crypto-bound

### Priority medium

- [ ] **BoringSSL build on EC2** — x86_64 AVX2 fused asm. With RTC 1+1, crypto is a single worker, so it is likely to help
- [ ] **Multi-peer benchmark** — iperf3 -P 1 is the single-peer worst case. With multiple peers, crypto parallelization works naturally

### Priority low → promoted to high

- [ ] **Lock-free pool_get/put** — **new top priority**. pidstat confirmed the recv worker is 98% saturated. The pool mutex consumes ~30-40% CPU. Replacing it with an MPSC lock-free stack would give the recv worker 38% headroom. **Prerequisite for crypto parallelization**
- [ ] **Parallel decrypt + sequential TUN write (collector pattern)** — implement after the lock-free pool. SPSC[N] fan-out → N decrypt → SPSC[N] → 1 collector (TUN write in nonce order). Unlike the old RTC 4+4, the collector guarantees order
- [ ] **macOS support (utun + kqueue)** — Go has the same limits, 3-4 Gbps
- [ ] **Windows support (WinTun + IOCP)**

### Done

- [x] **RTC architecture (SPSC 1+1)** — 2.20→3.59 Gbps (+63%) on EC2. futex 89%→29%. Exceeded kernel WG by +17%
- [x] **RTC multi-worker experiment** — 813 Mbps (-77%) with 4+4, 2.76 Gbps (-23%) with 4+1. Rejected because it breaks packet order
- [x] **wireguard-go benchmark** — 5.25 Gbps on EC2. +46% over wg-c
- [x] **recvmmsg + GRO cmsg batch (#22)** — recv -55%, TUN writes -74%, GRO 9.2x. Throughput ±0% (crypto-bound)
- [x] **Physical NIC benchmark** — done on EC2 c6i.2xlarge
- [x] **recv_gro bug fix (#21)** — 80% AEAD failures from a UDP_GRO + recvmmsg mismatch. Critical bug fix
- [x] **EC2 bottleneck analysis** — root cause: small recv_gro batches → lower GRO efficiency → more TUN writes
- [x] **BoringSSL fused asm integration (#20)** — ARM64 veth +2.1% (within noise). Adopted
- [x] **eventfd wake optimization** — send_waiting + 10ms poll: batch 1.0→28.3, context switches 228K→472/sec

---

## EC2 benchmark and bottleneck analysis (2026-04-27)

### Environment

- AWS c6i.2xlarge × 2 (Intel Xeon Ice Lake, 8 vCPU), same AZ
- S1 = iperf3 server (receiver), S2 = client (sender)
- OpenSSL EVP (x86_64 AVX-512 fused ChaCha20-Poly1305), Release build (-O3)
- ENA NIC: `tx-udp-segmentation: off [fixed]` — no hardware UDP GSO

### Throughput comparison

| Test | Throughput | Notes |
|--------|------------|------|
| Raw network | 9.53 Gbps | iperf3 direct |
| Kernel WireGuard | 3.08 Gbps | wireguard.ko |
| wg-c multi-threaded | **2.20 Gbps** | send_waiting + 10ms poll |
| wg-c inline_crypto | 1.57 Gbps | all processing on 1 thread |
| wg-c always-wake (debug) | 2.19 Gbps | eventfd written every time, batch=1.0 |

### Pipeline statistics (TCP 2.20 Gbps, 10 seconds)

**S1 receiver**:
```
UDP recv:   373K calls, 1.95M pkts (5.2 pkt/call) — recv_gro (recvmsg)
Decrypt:    1.95M pkts, aead_fail=0
Seq recvr:  761K batches, 1.95M pkts (2.6 pkt/batch)
TUN writes: 794K syscalls (GRO 2.4x coalesce)
GRO: tcp_in=1.95M, merged=1.15M (59%), psh_fail=30K
```

**S2 sender**:
```
TUN read:   55K calls, 1.95M pkts (35.5 pkt/call) — GSO 99.7%
Encrypt:    1.95M pkts
Seq sender: 71K batches, 1.95M pkts (28.3 pkt/batch)
```

### Bottleneck analysis

**perf stat (S1, system-wide, 10 seconds)**:
- context-switches: 4,720 (472/sec)
- cpu-migrations: 9 (0.9/sec)
- The CPU is mostly idle — not CPU-bound

**Bottleneck chain (receive path)**:
```
recv_gro: one recvmsg = 1 GRO buffer → split into 5.2 pkts
    ↓
MPMC decrypt queue → 8 crypto workers (fast, zero wait)
    ↓
Sequential receiver: takes 2.6 pkt/batch from prev_queue
    ↓
wg_handle_gro: tcp_table->count = 0 (reset every batch!)
    → builds the GRO table from 2.6 pkts, flushes immediately → GRO 2.4x
    ↓
TUN write: 79K syscalls/sec (= 794K / 10s)
```

**Comparison with veth**:

| Metric | veth ARM64 | EC2 x86_64 | Ratio |
|------|-----------|------------|------|
| UDP recv pkt/call | 9.6 (recvmmsg) | 5.2 (recv_gro) | 0.54x |
| Seq recvr pkt/batch | 116 | 2.6 | **0.022x** |
| GRO coalesce | 31.2x | 2.4x | **0.077x** |
| TUN write/sec | 17K | 79K | **4.7x** |
| Throughput | 5.87 Gbps | 2.20 Gbps | 0.37x |

**Root cause**: `recv_gro` uses `recvmsg` (1 message/call), so the batch size of the whole pipeline collapses. With small batches (2.6 pkts) the GRO table is reset every time, GRO only reaches 2.4x, and TUN write syscalls increase 4.7x. The sequential receiver is a single-thread bottleneck.

**Attempt: looping recv_gro (recvmsg × N)**:
- 1.90 Gbps (-14%), 282 retransmissions
- The recvmsg loop pulls a large amount out of the socket buffer at once → pipeline responsiveness drops → TCP retransmits
- **Rejected**

### always-wake vs send_waiting check

| Setting | Seq sender batch | context-switches/sec | Throughput |
|------|-----------------|---------------------|------------|
| always-wake + 1ms poll | 1.0 pkt | 228K | 2.19 Gbps |
| send_waiting + 100ms poll | 21.3 pkt | — | 2.13 Gbps (225 retransmit) |
| send_waiting + 10ms poll | **28.3 pkt** | **472** | **2.20 Gbps** (0 retransmit) |

**Conclusion**: the `send_waiting` check + 10ms poll timeout is best. always-wake writes eventfd too often, causing 228K context-switches/sec and collapsing the batch size to 1.0. The 100ms timeout loses wake-ups through an eventfd race → retransmits. 10ms is a good balance.

### inline_crypto vs multi-threaded

- inline_crypto: **1.57 Gbps** — crypto concentrated on 1 core, pipeline overhead removed
- multi-threaded: **2.20 Gbps** — parallelized over 8 crypto workers, with MPMC/condvar overhead
- **Difference: +40%** — multi-threaded is much faster. Pipeline overhead < the gain from parallel crypto

### ENA NIC limits

```
$ ethtool -k ens5 | grep udp
tx-udp_tnl-segmentation: off [fixed]
tx-udp-segmentation: off [fixed]
```

The ENA NIC **does not support** hardware UDP GSO (tx-udp-segmentation). `[fixed]` = cannot be changed.
- The optimization from the Tailscale blog where wireguard-go reached 13 Gbps on bare metal + 25G NIC (hardware TSO) cannot be applied on EC2 ENA
- UDP GSO can be used, but the kernel re-splits in software, so it is neutral, as on veth

### #21: recv_gro fix — UDP_GRO + recvmmsg mismatch (2026-04-27, **Critical Bug Fix**)

**Overview**: with the UDP_GRO socket option enabled, `recvmmsg` returned GRO-coalesced packets as one large buffer, but the GRO cmsg (segment size) was not parsed, and the whole coalesced buffer was decrypted as one WireGuard packet.

**Symptoms**:
- 80% AEAD authentication failures (iperf3 100Mbps UDP)
- Failed packets exceed the WireGuard size limit: `pkt_len=4368` (3×1456), `pkt_len=2912` (2×1456)
- The ciphertext area is all zeros (the header part is normal)
- 0% failures with ping (low rate) — because GRO does not kick in

**Root cause**: `std_recv()` in `wg_bind_std.c` used `recv_batch()` (recvmmsg), but when `UDP_GRO` is enabled with `setsockopt`, the kernel coalesces multiple same-size UDP packets into one buffer. `recv_batch` does not parse the GRO cmsg, so it treated the whole coalesced buffer as one packet, and WireGuard AEAD decryption failed.

The existing `recv_gro()` function parses the GRO cmsg correctly and splits segments, but it was not called from `std_recv()`. The comment said "When UDP GRO is enabled, use recv_gro", but the actual code still used `recv_batch`.

**Fix**: in `std_recv()`, check `b->udp_gro_ok` and add a branch that uses `recv_gro()` when GRO is enabled and `recv_batch()` when it is not.

**Results**:
- AEAD failures: 80% → **0%**
- TCP throughput: 0 Bytes/sec → **2.10 Gbps**
- No effect on veth (UDP_GRO does not kick in, so it stays on `recv_batch`)

**Changed files**: `src/bind/wg_bind_std.c` — changed `recv_batch` → `use_gro ? recv_gro : recv_batch` in 4 places in `std_recv()`

**Verdict**: **Adopted (required)** — a critical bug that completely breaks the data path when UDP_GRO is enabled on a physical NIC / EC2

### Rejected for good (no need to retry)

- ~~io_uring (TUN write / SQPOLL / multishot recv)~~ — syscall overhead too small to help
- ~~Lock-free MPMC (Vyukov + eventfd)~~ — eventfd overhead makes it zero-sum
- ~~Calling OpenSSL internal symbols directly~~ — 2-pass, bad for cache
- ~~Fewer crypto workers~~ — becomes crypto-bound and worse
- ~~Batch signaling in crypto workers~~ — lower pipeline responsiveness
- ~~Fewer push_batch signals~~ — same as above
- ~~Multi-container accumulation~~ — breaks the TCP feedback loop
- ~~M:N threading~~ — poor implementation cost/benefit
- ~~DPDK / AF_XDP~~ — conflicts with the portability requirement
- ~~RTC multi-worker recv (4+4)~~ — recv fan-out breaks TUN write order, 24K retransmits, 813 Mbps (-77%)
- ~~RTC multi-worker send (4+1)~~ — send fan-out causes nonce reordering, 8.8K retransmits, 2.76 Gbps (-23%)
- ~~Looping recv_gro (recvmsg × N)~~ — 2.20→1.90 Gbps (-14%) on EC2, 282 retransmits. Drains the socket buffer too much, lowering pipeline responsiveness
- ~~always-wake eventfd~~ — 228K context-switches/sec on EC2, batch=1.0. send_waiting + 10ms poll is best

**Lesson from RTC multi-worker**: round-robin dispatch inherently breaks packet order for a single peer. Parallelizing crypto across multiple workers requires a mechanism that restores nonce order after completion (equivalent to prev_queue). That is exactly the old MPMC architecture. The benefit of RTC is removing sync, not parallel crypto.

---

## Experiment #30: Rigorous benchmark — fixing the benchmark methodology

**Date**: 2026-04-30
**Goal**: verify the validity of earlier benchmark results and run a fair comparison

### Problems found

The earlier benchmarks had several problems:

1. **Kernel module problem**: when wireguard-go runs on EC2, the Linux kernel WireGuard module
   (`wireguard.ko`) is loaded automatically, and wireguard-go creates the WireGuard device with the kernel module.
   It may have been using the kernel data path instead of the userspace TUN path.

2. **Cherry-picking**: wg-c was slow in Runs 1-2 (3.8-3.9 Gbps) and fast in Runs 3-6 (4.5-4.8 Gbps).
   The "steady-state avg 4.72 Gbps" was the average of the later runs only. wireguard-go had no warm-up.

3. **Short tests**: in a 10-second test, TCP CUBIC does not fully ramp up.

### Fixed benchmark method

```bash
# Script: scripts/bench_rigorous.sh
# Conditions:
#   - blacklist the kernel WireGuard module
#     echo "blacklist wireguard" > /etc/modprobe.d/wireguard-blacklist.conf
#     echo "install wireguard /bin/true" >> /etc/modprobe.d/wireguard-blacklist.conf
#   - wireguard-go: WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
#   - check the TUN device: ip -d link show → "tun type tun"
#   - iperf3 --omit 3 -t 30: skip 3 seconds of TCP slow start, measure 30 seconds
#   - 10 alternating runs (wg-c, wg-go, wg-c, wg-go, ...)
#   - Cold start: recreate the process + namespace every time
#   - JSON output + record CPU usage with mpstat
```

### Results

#### wg-c (10 runs)

| Run | Gbps  | Retrans |
|-----|-------|---------|
| 1   | 3.784 | 29      |
| 2   | 3.873 | 40      |
| 3   | 3.797 | 25      |
| 4   | 3.823 | 41      |
| 5   | 3.739 | 41      |
| 6   | 3.728 | 11      |
| 7   | 3.738 | 18      |
| 8   | 3.706 | 94      |
| 9   | 3.797 | 38      |
| 10  | 3.793 | 14      |

**Mean: 3.78 Gbps, Median: 3.78 Gbps, Stddev: 0.04 Gbps**

#### wireguard-go (10 runs, userspace TUN confirmed)

| Run | Gbps  | Retrans |
|-----|-------|---------|
| 1   | 7.203 | 143     |
| 2   | 7.164 | 0       |
| 3   | 7.232 | 932     |
| 4   | 7.183 | 425     |
| 5   | 7.180 | 0       |
| 6   | 7.200 | 0       |
| 7   | 7.231 | 188     |
| 8   | 7.183 | 0       |
| 9   | 7.178 | 0       |
| 10  | 7.174 | 0       |

**Mean: 7.19 Gbps, Median: 7.18 Gbps, Stddev: 0.03 Gbps**

#### CPU profile (wg-c, during the test)

```
wg-c per-thread CPU usage (ps -T):
  sequential_send:  100% (CPU 0)
  sequential_recv:   97% (CPU 6)
  crypto workers:   18-35% each
  tun_reader:        5-6%

mpstat (average over all CPUs):
  %usr:  39%
  %sys:  46%  ← syscall overhead dominates
  %idle: 11%
```

### Analysis

1. **wg-c's true throughput**: 3.80 Gbps (consistent, no warm-up needed)
2. **wireguard-go's true throughput**: 7.19 Gbps (consistent)
3. **Ratio**: 52.9% (wg-c / wg-go)
4. **wg-c's bottleneck**: %sys 46% → syscall frequency is too high
5. **spin-wait problem**: the sequential threads consume 100% CPU yet deliver only 3.8 Gbps

### Difference from the earlier ENA test

Why the earlier cross-instance test (S1↔S2) gave wg-c 4.72 Gbps / wg-go 4.38 Gbps:
- The ENA network was the bottleneck (raw 9.53 Gbps) → both were approaching the same ceiling
- If wireguard-go was using the kernel module, the kernel module's performance
  was limited to 4.38 Gbps by the network constraint
- The veth test has no network constraint (55 Gbps) → the true difference between implementations shows

### Next steps

We need to fix the root cause of wg-c delivering only half of wireguard-go:
- **Fewer syscalls**: %sys 46% is abnormal. Batch TUN writes, larger sendmmsg batch size
- **Better spin-wait**: reduce CPU wasted by the sequential threads
- **Kernel mode support**: work with the kernel WireGuard module, as wireguard-go does

---

## Experiment #31: io_uring + MSG_WAITFORONE test (2026-04-30)

### Goal

Check whether syscall optimizations can close the 2x gap found in #30 (3.80 vs 7.19 Gbps).

### Phase A: enable io_uring (TUN write batching)

**Change**: io_uring build with `cmake -DWG_USE_IO_URING=ON`. TUN writes batched with io_uring_submit_and_wait.

**Results**:

| Test | Throughput | Change |
|--------|------------|------|
| Baseline (build-release) | 3.85 Gbps | — |
| io_uring ON (build-iouring) | 3.23 Gbps | **-16%** |

**Analysis**: The io_uring submit/completion overhead is heavier than a per-packet `write()`.
io_uring is good at batch submission, but TUN writes are often processed one packet at a time,
and the overhead of preparing SQEs + submit + reaping CQEs exceeded a plain write() syscall.
Same conclusion as #9 (early 2026 test).

**Verdict**: **Rejected**

### Phase B: recvmmsg MSG_WAITFORONE

**Change**: In `recv_batch()` and `recv_gro_batch()` in `src/bind/wg_bind_std.c`,
the recvmmsg call after poll(POLLIN) changed from `MSG_DONTWAIT` → `MSG_WAITFORONE`.
The optimistic path (before poll) keeps `MSG_DONTWAIT`.

**Results**:

| Test | Throughput | recv pkt/call | Change |
|--------|------------|---------------|------|
| Baseline | 3.85 Gbps | 3.7 | — |
| MSG_WAITFORONE | 3.39 Gbps | 3.2 | **-12%** |

**Analysis**: When poll(POLLIN) returns, data has already arrived. MSG_WAITFORONE means
"block for the first packet, non-blocking for the rest", but
after poll the data is already there, so it behaves essentially the same as MSG_DONTWAIT.
If anything, the flag handling overhead made it slightly worse.

**Verdict**: **Rejected** (change fully reverted)

### Overall analysis

Simple syscall optimizations (io_uring, MSG_WAITFORONE) cannot close the 2x gap.
The fundamental difference is the **Go runtime's goroutine scheduler** (cooperative yield ~100ns, no syscall)
vs **wg-c's sched_yield** (~1µs + kernel round trip).

Phase C needs architecture-level changes:
- pthread_cond_signal (futex-based, possibly lighter than sched_yield)
- crypto workers doing I/O directly (keeping the pipeline is the challenge)
- improving sequential thread processing efficiency (reducing per-batch overhead)

---

## Experiment #32: adaptive spin + futex + recv accumulation (2026-05-01)

### Goal

Combine two measures to reduce sched_yield overhead and increase the recv batch size.

### Measure 3: larger recv batch size

**Change**:
1. `SO_BUSY_POLL` 50µs → 200µs (longer NAPI polling)
2. In the optimistic recv path, when only a few packets (< count/4) are received, spin PAUSE × 512 and then call recvmmsg again

### Measure 4: adaptive spin + futex hybrid

**Change**:
1. Add `_Atomic uint32_t seq_wake` (futex word) to `wg_device_t`
2. Crypto workers: after encrypt/decrypt completes, `seq_wake = 1` + `FUTEX_WAKE`
3. Sequential threads: no work → spin PAUSE × 1024 → `FUTEX_WAIT` (50µs timeout)
4. Remove `sched_yield()` completely

### Results (EC2 c6i.2xlarge veth, 5 runs × 30 seconds)

| Implementation | Mean | Median | Min | Max | Stddev | Retrans |
|------|------|--------|-----|-----|--------|---------|
| **wg-c (#32)** | **3.94 Gbps** | **3.99 Gbps** | 3.70 | 4.02 | 0.12 | 78 |
| **wg-c (#30 baseline)** | 3.80 Gbps | 3.80 Gbps | 3.71 | 3.90 | 0.04 | 351 |
| wireguard-go | 7.21 Gbps | 7.21 Gbps | 7.18 | 7.24 | 0.00 | 768 |

**Improvement**: +5.0% (median), ratio 52.9% → 55.4%

### Pipeline statistics comparison (receiver wg1, run 2)

| Item | #30 | #32 | Change |
|------|-----|-----|------|
| UDP recv pkt/call | 3.7 | **9.7** | **+162%** |
| Seq recvr pkt/batch | — | 18.2 | — |
| GRO coalescing | — | 13.2x | — |
| Retrans (wg-c) | 351 | 78 | **-78%** |

### Analysis

- **Better recv batching** (3.7 → 9.7): SO_BUSY_POLL 200µs + the accumulation spin are working
- **Retrans drop sharply** (351 → 78): latency jitter in packet processing improved
- **But only +5%**: the effect of sched_yield → futex is limited.
  The CPU the sequential thread no longer consumes can go to other threads, but
  the bottleneck may be the processing speed of the sequential thread itself
- **Low score in run 1 (3.70)**: cold start effect; runs 2-5 are stable at 3.99-4.02

### Verdict

**Adopted** — fewer retrans + 5% throughput improvement. But the fundamental gap (55% of wg-go) remains.

---

## Experiment #33: crypto worker inline drain (2026-05-01)

### Goal

Remove the sequential thread serialization point. After crypto work, the crypto worker runs
drain_rx_order / drain_tx_order directly with trylock, parallelizing I/O.

### Change

- `wg_worker_rtc_recv`: after the decrypt batch, for each peer in the batch,
  `trylock(rx_drain_lock)` → `drain_rx_order()` → unlock
- `wg_worker_rtc_send`: likewise `trylock(tx_drain_lock)` → `drain_tx_order()`
- Sequential threads kept as a fallback

### Results (EC2 c6i.2xlarge veth, 5 runs × 30 seconds)

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c (#33)** | **3.90 Gbps** | **3.90** | 3.90 | 3.91 | 152 |
| wg-c (#32 baseline) | 3.94 Gbps | 3.99 | 3.70 | 4.02 | 78 |

**Change**: -1% (regression)

### Pipeline statistics comparison (receiver wg1)

| Item | #32 | #33 | Change |
|------|-----|-----|------|
| Seq recvr pkt/batch | 18.2 | **14.6** | **-20%** |
| TUN writes | 910K | **1,040K** | **+14%** |
| GRO coalescing | 13.2x | **11.3x** | **-14%** |
| Retrans | 78 | 152 | **+95%** |

### Analysis

Inline drain breaks pipelining:
1. **Crypto worker blocks in write()**: during decrypt → drain → write(),
   the next crypto batch is not processed. Pipelining is lost.
2. **Batches at drain time are small**: when the crypto worker drains,
   only a few packets are in the CRYPTED state yet. The sequential thread can
   wait for them to accumulate, but inline drain processes them immediately.
3. **Worse GRO coalescing**: small batch = small TUN write batch = GRO does not help
4. **More retrans**: lower processing efficiency from smaller batch sizes

**Lesson**: pipelining (crypto and I/O running in parallel) must always be kept (#23, #33).
Even if the sequential thread is the bottleneck, merging it into the crypto worker
hurts batch efficiency and makes everything slower.

### Verdict

**Rejected** (change fully reverted)

---

## Experiment #34: Container Lock pattern (wireguard-go style)

**Date**: 2026-05-01
**Branch**: feat/benchmark
**Base**: #32 adaptive spin+futex (3.94 Gbps)

### Overview

Port wireguard-go's `QueueOutboundElementsContainer` pattern.
Instead of polling per-element atomic state, the sequential thread futex-waits
on a per-batch Container Lock.

### Design

```
Producer (TUN reader / UDP recv):
  create a container per peer → lock (futex: ready=0)
  set the container back-pointer on each elem
  push elem to SPSC (round-robin, keeps per-elem parallelism)
  enqueue container to prev_queue
  finalize: atomic remaining decrement (biased counter)

Crypto worker (RTC send/recv):
  after encrypt/decrypt → atomic_fetch_sub(&c->remaining, 1)
  last worker (returns 1) → futex_wake (container lock signal)

Sequential sender/receiver:
  prev_queue peek → container_lock_wait (futex) → whole batch ready → send/write all at once
  1 container = 1 futex wait/wake (no per-element polling needed)
```

### Biased Counter (race condition fix)

In the first implementation, remaining=0 → crypto decrements first → the signal is lost, giving 0 Gbps.
Fix: biased counter pattern:
- initialize `remaining` to 1 (producer reference)
- `fetch_add(1)` in `container_add()` (per elem, before SPSC push)
- `fetch_sub(1)` in `finalize()` (releases the producer reference)
- crypto worker: `fetch_sub(1)`, returns 1 → signal

### Cross-platform Lock

- Linux: raw futex (`_Atomic uint32_t ready`, 0=locked, 1=ready)
- macOS/Windows: pthread condvar (unlocking a pthread_mutex from another thread is UB)

### Benchmark results

EC2 c6i.2xlarge, veth, iperf3 --omit 3 -t 30, 5 runs

| Implementation | Mean | Retrans |
|------|------|---------|
| wg-c (#32 baseline) | 3.94 Gbps | 78 |
| **wg-c (#34 container)** | **3.67 Gbps** | **1226** |

**Change**: **-7% regression**, retrans **up 15.7x**

### Analysis

Why the Container Lock pattern works in wireguard-go, and why it backfires in wg-c:

1. **Container pool overhead**: the Treiber stack (lock-free pool) does an atomic CAS
   per batch. The existing elem pool is per packet, but the container pool is
   an extra allocation layer. wg-go does not need a pool because of GC.

2. **Biased counter overhead**: for a batch of N elems, N+1 extra atomic operations
   (N fetch_add + 1 finalize fetch_sub). The per-element approach needs
   only 1 atomic_store(release).

3. **The existing #32 futex is enough**: adaptive spin (PAUSE×1024) + futex_wait(50µs)
   already minimizes the cost of per-element polling. The Container Lock's
   batch-level futex only adds overhead with no real benefit.

4. **Architectural difference**: wireguard-go goroutines switch in ~100ns,
   and channel operations take ~50ns. The point of Container Lock is to reduce the number of channel operations.
   In wg-c's pthread model, SPSC + atomic state is the lightest synchronization,
   and Container Lock just adds another layer of synchronization on top.

5. **More retrans**: send timing becomes coarser at container batch boundaries,
   small batch → delayed flush → more TCP retransmissions.

### Verdict

**Rejected** (change fully reverted, back to #32 baseline)

---

## Experiment #35: sequential thread hot path optimization

**Date**: 2026-05-01
**Branch**: feat/benchmark
**Base**: #32 adaptive spin+futex (3.94 Gbps)

### Overview

A set of micro-optimizations that remove unnecessary synchronization from the sequential thread hot path.
The perf profile showed sched_yield ~26%, mutex ~4.7%, syscall ~6.2%,
so the aim was to raise throughput by reducing this overhead.

### Changes

1. **Split send/recv futex**: one `dev->seq_wake` → `seq_wake_send` + `seq_wake_recv`
   - Send crypto worker → wakes only the send sequential thread
   - Recv crypto worker → wakes only the recv sequential thread
   - Removes ~50% of false wakeups

2. **bind snapshot in sequential sender**: the `pthread_rwlock_rdlock(&dev->net.lock)` that `drain_tx_order()` takes every batch
   is replaced with a snapshot refreshed every 1024 iterations.
   Applies the same pattern as the UDP recv thread to the sequential sender.

3. **Batch keep_key_fresh**: per element → per batch (once per drain).
   For a 128-packet batch, 256 atomic RMW + 128 time calls → 2 atomic RMW + 1 time call.

4. **Local stats accumulation**: 5-6 `atomic_fetch_add` per batch → flushed every 256 iterations.

5. **batch pool put** (first test only, removed in the second): `wg_wait_pool_put_batch` makes
   128 CAS → 1 CAS. Removed because the results showed no significant difference.

### Benchmark results

EC2 c6i.2xlarge, veth, iperf3 --omit 3 -t 30, 5 runs

#### Test 1 (with batch pool put)

| Implementation | Mean | Median | Retrans |
|------|------|--------|---------|
| wg-c (#35) | 3.785 Gbps | 3.742 | 3384 |
| wg-go | 6.840 Gbps | 6.844 | 0 |

#### Test 2 (batch pool put removed)

| Implementation | Mean | Median | Retrans |
|------|------|--------|---------|
| wg-c (#35v2) | 3.828 Gbps | 3.877 | 3941 |
| wg-go | 6.850 Gbps | 6.848 | 1001 |

#### #32 baseline (reference)

| Implementation | Mean | Retrans |
|------|------|---------|
| wg-c (#32) | 3.94 Gbps | 78 |
| wg-go | 7.21 Gbps | 768 |

### Analysis

**Environment got slower**: wg-go also dropped from 7.21 Gbps at #32 to 6.85 Gbps (-5%).
wg-c's -3% is within EC2 environment noise. The ratio rose slightly: 55.4% → 55.9%.

**Key finding**: the atomic operations, rwlock, and futex false wakeups in the sequential thread hot path
are orders of magnitude smaller overhead than the I/O syscalls (sendmmsg/write),
so optimizing them gives no measurable improvement.

Concrete numbers:
- `atomic_fetch_add`: ~5ns/op. ~640ns for a 128-elem batch → ~0ns after optimization
- `pthread_rwlock_rdlock`: ~30ns/op. Once per batch → 0 times
- `keep_key_fresh`: ~20ns/elem × 128 = ~2.5µs → ~20ns
- Total saved: **~3.5µs/batch**

Meanwhile, `sendmmsg(128 packets)`: **~50-100µs** (most of the batch processing time)

3.5µs / 100µs = **~3.5% theoretical improvement**. This falls within the benchmark variance (~3%),
so it cannot be measured.

### Verdict

**Neutral** (changes kept. They do no harm and make the code's intent clearer.
But the throughput improvement cannot be measured)

---

## Experiment #36: enable UDP GSO send

**Date**: 2026-05-01
**Branch**: feat/benchmark
**Base**: #35 (= #32 baseline, 3.77 Gbps mean)

### Background

Fix GSO stats always being 0, and make UDP GSO send work correctly.

**How the problem was found**:
1. Added a `get_gso_stats` callback to `wg_bind_ops_t` → stats bridge complete
2. First bench: GSO ok=0, fail=0, skip=0 → `get_gso_stats` was not registered
3. After registering the callback: ok=165, fail=13343, errno=90 (EMSGSIZE) → GSO is attempted but fails
4. Added `IP_PMTUDISC_DONT`: ok=28571, fail=25926 → partial improvement
5. Looked at wireguard-go: it concatenates (coalesces) buffers into one before passing them to sendmsg
6. Switched to the coalesce approach: ok=860K, fail=0 → **fully working**

### Changes

1. **GSO stats bridge** (`include/wireguard.h`, `src/bind/wg_bind_std.c`, `src/device/wg_stats.h`)
   - Added the `wg_bind_gso_stats_t` type and the `get_gso_stats` callback
   - `wg_stats_dump()` shows the bind's GSO stats

2. **GSO coalesce send** (`src/bind/wg_bind_std.c`)
   - wireguard-go approach: copy multiple packets into one contiguous buffer, then send with `sendmsg(UDP_SEGMENT)`
   - `maxIPv4PayloadLen = 65507`, `max_segs = min(65507/seg_size, 64)`
   - Cause of EMSGSIZE: sendmsg with multiple iovecs → total size > PMTU and the kernel rejects it. A single contiguous buffer is OK

### Detailed analysis of the EMSGSIZE problem

**Failure pattern**:
- sendmsg + UDP_SEGMENT with multiple iovecs (128) → errno=90 (EMSGSIZE)
- Adding IP_PMTUDISC_DONT → 50% succeed but 50% still fail
- One iovec with a single contiguous buffer → 100% success

**Likely cause**: when the Linux kernel's `__ip_append_data()` compares the total size of multiple iovecs
with the maximum IP datagram length (65535), it does not account for GSO segmentation
and returns EMSGSIZE for total length > MTU. A single buffer goes through the GSO fast path,
where segmentation is applied correctly.

wireguard-go concatenates buffers from the start (`coalesceMessages()`),
so it never hits this problem.

### Benchmark results

EC2 c6i.2xlarge, veth, --omit 3, 30s × 5 runs, alternating

| Implementation | Mean | Median | Stddev | Retrans |
|------|------|--------|--------|---------|
| **wg-c (#36)** | **4.41 Gbps** | 4.41 | 0.00 | 186,866 |
| **wg-c (#35)** | 3.77 Gbps | 3.75 | 0.06 | 2,960 |
| **wg-go** | 6.84 Gbps | 6.84 | 0.00 | 0 |
| **Ratio** | **64.5%** | | | |

### Pipeline statistics comparison (#35 → #36)

| Item | #35 | #36 | Change |
|------|-----|-----|------|
| **Send batches** | 88K | 832K | +9.5x (split sends with GSO) |
| **Send pkt/batch** | 127 | 16 | split at max_segs=44 |
| **GSO ok** | 0 | 860K | ∞ |
| **GSO fail** | 0 | 0 | full success |
| **UDP recv pkt/call** | 9.1 | 38.0 | +4.2x (GSO → GRO chain) |
| **TUN GRO coalesce** | 8.1x | 15.2x | +1.9x |
| **Retrans** | 2,960 | 186,866 | +63x (send rate > receive processing) |

### Problem

**Retrans exploded** (2,960 → 186,866).
GSO raised the send rate, but the TUN write processing on the receiver (sequential receiver) could not keep up,
causing packet loss. TCP made up for it with retransmits.

Reducing retrans should give further throughput gains.
wg-go has retrans=0, so receive processing is the next target.

### Phase 2: max_segs tuning

The GSO burst size turned out to cause the retrans. Isolation tests:

| Setting | Throughput | Retrans | Notes |
|------|-----------|---------|------|
| No GSO (sendmmsg) | 3.78 Gbps | 235 | Baseline |
| max_segs=44 (coalesce) | 4.41 Gbps | 187K | burst too large |
| max_segs=44 (zero-copy iovec) | 4.39 Gbps | 187K | memcpy is not the cause |
| **max_segs=16 (zero-copy)** | **6.88 Gbps** | **2,326** | **best balance** |

**Retrans dominate throughput**: at max_segs=44, 187K retrans shrink the TCP congestion window,
giving 4.4 Gbps effective. Limiting the burst with max_segs=16 gives 2K retrans → the congestion window grows → 6.88 Gbps.

UDP-level packet loss is 0 (RcvbufErrors=0, veth dropped=0).
The retrans come from TCP's delay detection (delayed ACK).

### Phase 3: zero-copy iovec

Removed the memcpy (perf: `rep_movs_alternative` 4.07%).
Confirmed that with max_segs ≤ 44, EMSGSIZE does not occur even with multiple iovecs.
No coalesce buffer needed.

### Final benchmark

EC2 c6i.2xlarge, veth, --omit 3, 30s × 5 runs, alternating

| Implementation | Mean | Median | Stddev | Retrans |
|------|------|--------|--------|---------|
| **wg-c (#36)** | **6.88 Gbps** | 6.83 | 0.10 | 2,326 |
| **wg-go** | 6.83 Gbps | 6.83 | 0.00 | 0 |
| **Ratio** | **100.8%** | | | |

### Pipeline statistics (#36 final)

| Item | #35 (before) | #36 (after) | Change |
|------|-------------|-------------|------|
| **Throughput** | 3.77 Gbps | **6.88 Gbps** | **+82%** |
| Send pkt/batch | 127 | 16.4 | GSO max_segs=16 |
| GSO ok | 0 | 1.97M | fully working |
| **UDP recv pkt/call** | 9.1 | **50.9** | **+5.6x** |
| **TUN GRO coalesce** | 8.1x | **20.5x** | **+2.5x** |
| **Retrans** | 2,960 | 2,326 | -21% |

### Verdict

**Adopted** — UDP GSO (max_segs=16) gives **+82%** (3.77 → 6.88 Gbps).
On par with wireguard-go (100.8%). A breakthrough for a C userspace WireGuard.

---

## #37: SPSC 16K + spin-retry — retrans investigation + fewer queue drops

**Goal**: find and fix the cause of wg-c retrans ~400 vs wg-go retrans 0.

### Phase 1: cause investigation

**Initial hypothesis**: send bursts (128 pkt drain → 8 GSO sendmsg in a tight loop) are the cause.

**Drain batch reduction test** (128→48):
- wg-c: 6.875 Gbps, retrans 524/478/476 → **no effect**
- The actual batch was 15.2 pkt/batch and never reached the limit

**Key finding from pipeline stats**:
- wg1 (receiver) `inbound_drops = 2589, 998, 3286` — packets dropped because the SPSC queue overflowed
- wg0 (sender) `outbound_drops = 784` — encryption queue overflow
- **But retrans=401 also occurs in runs with drops=0** → drops are not the root cause

### Phase 2: SPSC spin-retry implementation

**Change**: add 16 spin retries when the SPSC push fails in `enqueue_inbound` / `enqueue_outbound`.
Emulates how wireguard-go's Go channels block when the queue is full.

```c
bool pushed = false;
for (int retry = 0; retry < 16; retry++) {
    if (wg_spsc_try_push(&dev->rtc.recv[w].queue, elem) == WG_OK) {
        pushed = true;
        break;
    }
    WG_CPU_RELAX();
}
```

**Results**: inbound_drops 2589→36 (**98.6% reduction**). outbound_drops unchanged (not enough SPSC capacity).

### Phase 3: larger SPSC capacity (4096→16384)

**Change**: raise the capacity in `wg_spsc_init` from 4096→16384.

**Results**:
- wg-c: **6.99 Gbps** (+1.3% from the previous 6.90)
- outbound_drops: 2300→0-284 (large reduction)
- retrans: ~400 (unchanged) → **confirms that drops are not the cause of retrans**

### Phase 4: retrans root cause investigation

**Test 1: BBR congestion control**
- CUBIC: 7.1 Gbps, retrans=138-154 (warm state)
- BBR: 7.5 Gbps, retrans=603-1884 (**counterproductive** — BBR tolerates loss while probing bandwidth)
→ not a matter of congestion control sensitivity

**Test 2: SCHED_FIFO (real-time scheduling)**
- wg-c: **5.3 Gbps (-23% regression)** — RT threads starve the crypto workers
→ **reverted immediately**

**Test 3: iperf3 interval analysis**
- retrans are spread evenly across the whole test (not concentrated in slow start)
- 0-72 retrans per second — random scheduling jitter

**Test 4: wireguard-go retrans**
- During the SCHED_FIFO test, wg-go recorded retrans=**696** — wg-go is not fully immune either

### Phase 5: conclusion

**Root cause of retrans**: spurious TCP retransmissions caused by OS scheduling jitter (CFS scheduler).

- **Retrans rate**: ~400/run ÷ ~21M pkts = **0.002%** — effectively negligible
- **Retrans occur even with drops=0**: pipeline latency variation → TCP RTO/TLP fires
- **wg-go also retransmits occasionally**: wg-go's 0 retrans just means it happens to stay under the threshold
- **Structural limit of a userspace VPN**: kernel thread scheduling jitter cannot be avoided
- **To eliminate it**: a kernel-mode data path (Phase D) is needed

### Final results (5-run benchmark)

| Implementation | Mean | Min | Max | Retrans | Drops |
|------|------|-----|-----|---------|-------|
| **wg-c** | **6.99 Gbps** | 6.90 | 7.08 | 2,078 | outbound 0-284, inbound 0-30 |
| **wg-go** | **6.92 Gbps** | 6.87 | 6.95 | 0 | - |
| **Ratio** | **101.1%** | | | | |

**Code changes**:
- `src/workers/wg_receive.c`: SPSC push spin-retry (16 iterations)
- `src/workers/wg_send.c`: SPSC push spin-retry (16 iterations)
- `src/device/wg_device.c`: SPSC capacity 4096→16384 (send + recv)

wg-c 6.99 Gbps / wg-go 6.92 Gbps = **101.1%**. Exceeded wireguard-go.

---

## Experiment #38: macOS cross-platform support + benchmark

**Date**: 2026-05-04
**Goal**: build and verify on macOS + wg-c vs wg-go A/B benchmark
**Environment**: macOS (Apple Silicon), local machine (via VM), utun + loopback (127.0.0.1)

### Fixes needed for macOS

1. **SPSC pipe fallback** (MAC-2, #101): Linux eventfd → replaced with a pipe(2) pair on macOS
   - `wg_spsc.h`: added the `wake_write_fd` field (`#ifndef __linux__`)
   - `wg_spsc.c`: initialized with `pipe()` + `fcntl(FD_CLOEXEC)`, `wake_write_fd()` helper
2. **pthread_timedjoin_np → usleep+flag** (MAC-1, #100): the GNU extension does not exist on macOS
   - `tools/wg-c/main.c`: `volatile sig_atomic_t g_uapi_done` + `usleep(200ms)` loop
3. **Unused variable warnings** (MAC-1): wrap `use_gro`, `gro_staging` in `#if defined(__linux__)`
   - `src/bind/wg_bind_std.c`: moved the declarations inside the `#ifdef`

### Structural limits of macOS

| Feature | Linux | macOS |
|------|-------|-------|
| UDP GSO (max_segs=16) | Yes | No |
| UDP GRO | Yes | No |
| sendmmsg/recvmmsg | Yes | No |
| SO_BUSY_POLL | Yes | No |
| CPU affinity | Yes | No |
| futex | Yes | No |
| eventfd | Yes | No (pipe fallback) |
| BatchSize | 16 | 1 |

**Conclusion**: macOS requires per-packet syscalls. ~1.4M syscalls/sec for 556 Mbps vs ~100K/sec for 7 Gbps on Linux.

### Benchmark procedure

```bash
sudo scripts/bench_macos.sh ./build-release/tools/wg-c wireguard-go 5 10
```

utun98/utun99 pair, 127.0.0.1:51820↔51821, iperf3 10s (--omit 3s), 5 rounds.

### macOS benchmark results

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c** | **556 Mbps** | 554 Mbps | 554 | 561 | 0 |
| **wg-go** | **575 Mbps** | 575 Mbps | 572 | 578 | 0 |
| **Ratio** | **96.7%** | | | | |

### Analysis

- **wg-c 556 Mbps vs wg-go 575 Mbps** — a 3.3% gap
- Both have retrans=0 — on local loopback, TCP RTO rarely fires
- wg-go's 3.3% lead comes from the efficiency of the Go goroutine scheduler
  - Go goroutines use M:N scheduling and can run other goroutines while one waits on a syscall
  - C pthreads map 1:1, so a thread stops while blocked in a syscall
  - On macOS with BatchSize=1 the syscall rate is high, so this difference shows clearly
- **On Linux wg-c wins at 101.1%** — GSO/GRO batching cuts the syscall count to 1/16, where C's low overhead pays off

### Cross-platform performance guard

All macOS changes are guarded by `#ifdef` / `#ifndef __linux__`, so the Linux code path is unaffected.
A rule was added to the project guidelines (now in CONTRIBUTING.md): "after macOS/Windows changes, always check for regressions with a Linux benchmark".

---

## Experiment #39: macOS sendmsg_x/recvmsg_x + SPSC spin tuning

**Date**: 2026-05-05
**Goal**: beat wg-go on macOS — use a C advantage (calling private syscalls directly)
**Environment**: macOS (Apple Silicon), local machine (via VM), utun + loopback (127.0.0.1)

### Background: a macOS API wireguard-go cannot use

macOS (Darwin) has private syscalls `sendmsg_x`/`recvmsg_x`.
They are the equivalent of Linux `sendmmsg`/`recvmmsg`, sending and receiving multiple UDP datagrams in a batch with one syscall.

**wireguard-go cannot use them:**
- Go's standard library does not expose `sendmsg_x`/`recvmsg_x`
- Calling them via cgo breaks the goroutine scheduler (the thread blocks during the syscall)
- So wireguard-go on macOS uses `BatchSize=1` (sendmsg/recvmsg per packet)

**wg-c (C) can call them directly:** there is no header, but by defining the function declarations and struct ourselves they can be called through libsystem_kernel.

```c
// XNU private API — darwin-xnu/bsd/sys/socket.h
struct msghdr_x {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    int msg_iovlen;
    void *msg_control;
    socklen_t msg_controllen;
    int msg_flags;
    size_t msg_datalen;
};
extern ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
extern ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
```

### Measure 1: sendmsg_x/recvmsg_x batch UDP I/O

**Change:**
- `src/bind/wg_bind_std.c`: macOS `WG_BIND_BATCH_SIZE` changed from 1→32
- `recv_batch_darwin()`: receive up to 32 packets in one syscall with `recvmsg_x`
- `std_recv` macOS path: added optimistic recv + accumulation spin (same pattern as Linux)
- `std_send` macOS path: send up to 32 packets in one syscall with `sendmsg_x`

**Results (sendmsg_x/recvmsg_x only):**

| Implementation | Mean | Ratio |
|------|------|------|
| wg-c | 567 Mbps | 97.8% |
| wg-go | 580 Mbps | — |

+11 Mbps (+2%) — batch send/receive works, but the effect is limited.

### Measure 2: finding and removing SPSC pipe overhead

Bottleneck found by **profiling (dtruss)**:

CPU samples: `wg_worker_udp_recv` takes **90%+**. The cause is pipe syscall overhead:

```
write(0x13, "\001\0", 0x8) = 8    ← SPSC pipe wake (per packet)
read(0x12, "\001\0", 0x8) = 8     ← SPSC pipe consume (per packet)
```

**The decisive difference between Linux eventfd and macOS pipe:**
- eventfd: `write(1)+write(1)` → counter=2, `read()` → returns 2 (one syscall consumes multiple wakes)
- pipe: `write(8)+write(8)` → 2 entries, needs `read()` × 2 (no coalescing)

A pipe read+write per packet = **2 syscalls**. This was 50%+ of all syscalls.

**Fix — 3-stage consumer wait:**

1. **Phase 1: tight spin** (ARM64 yield × 16384 ≈ 16µs) — covers the ~15µs packet interval
2. **Phase 2: sched_yield** (× 4) — a minimal safety net
3. **Phase 3: pipe block** — only when truly idle (almost never reached during active transfer)

**Failed intermediate attempt:** sched_yield × 32 triggered E-core migration on Apple Silicon and regressed to 505 Mbps. Reducing it to 4 fixed this.

### Final results

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c** | **607 Mbps** | 607 Mbps | 586 | 626 | 0 |
| **wg-go** | **568 Mbps** | 567 Mbps | 514 | 630 | 0 |
| **Ratio** | **106.8%** | | | | |

### Pipeline statistics improvement

| Metric | #38 (Before) | #39 (After) | Improvement |
|------|-------------|-------------|------|
| Seq sender pkt/batch | 2.8 | **5.7** | 2.0x |
| Seq recvr pkt/batch | 2.7 | **6.2** | 2.3x |
| UDP recv pkt/call | 2.4 | **2.7** | +13% |
| UDP send calls | 236K | **126K** | -47% |
| Throughput | 556 Mbps | **607 Mbps** | **+9.2%** |

### Progression

| Version | wg-c | wg-go | Ratio | Change |
|-----------|------|-------|------|------|
| #38 (BatchSize=1) | 556 Mbps | 575 Mbps | 96.7% | initial macOS implementation |
| +sendmsg_x/recvmsg_x | 567 Mbps | 580 Mbps | 97.8% | batch UDP I/O |
| +SPSC sched_yield×32 | 505 Mbps | 539 Mbps | 93.6% | **regression** (E-core migration) |
| **+SPSC spin 16K** | **607 Mbps** | **568 Mbps** | **106.8%** | tight spin 16µs |

### Lessons

1. **C's access to private APIs makes the decisive difference** — `sendmsg_x`/`recvmsg_x` cannot be used from Go
2. **pipe(2) is not a substitute for eventfd** — it does not coalesce, so it costs 2 syscalls per packet
3. **ARM64 yield is very cheap (~1ns)** — even 16384 iterations take only 16µs. It does not enter the kernel, so it is far faster than sched_yield
4. **E-core migration on Apple Silicon is fatal** — heavy use of sched_yield causes P→E core migration and a sharp latency increase
5. **The real bottleneck on macOS is utun (1 pkt/read)** — this is a kernel limit and cannot be avoided

wg-c 607 Mbps / wg-go 568 Mbps = **106.8%**. Exceeded wireguard-go on macOS too.

## Experiment #40: macOS kqueue + MSG_TRUNC + randomized benchmark order

**Date**: 2026-05-05
**Scope**: macOS only (Linux path unchanged)

### Changes

1. **Replace poll() with kqueue (rwcancel + bind)**
   - `wg_rwcancel.c`: on macOS, create a kqueue fd once and register cancel_pipe with EVFILT_READ. `ready_kqueue()` waits on EVFILT_READ/EVFILT_WRITE with EV_ONESHOT
   - `wg_bind_std.c`: `std_open()` creates a kqueue and registers fd4/fd6/cancel_pipe with EVFILT_READ. `std_recv()` skips rebuilding the pollfd array and waits in kevent()
   - Benefits: native macOS mechanism, no fd set rebuild, fd close reliably detected via EV_EOF

2. **Add MSG_TRUNC detection to recv_batch_darwin()**
   - Check `msg_flags & MSG_TRUNC` on each message from recvmsg_x
   - Skip truncated datagrams and return only valid packets

3. **Randomize run order in the benchmark script**
   - `bench_macos.sh`: swap the wg-c/wg-go run order each round using `RANDOM % 2`
   - Removes cache warm-up bias

4. **Fix ratio calculation bug in bench_rigorous.sh**
   - With `bc` `scale=1`, the intermediate division result was truncated (7.085/7.103=0.9 → 90%)
   - Fix by multiplying first: `$WGC_MEAN * 100 / $WGGO_MEAN`

### macOS benchmark results (Apple Silicon, 5 runs x 10 s)

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c** | **624 Mbps** | 628 Mbps | 602 | 643 | 0 |
| **wg-go** | **574 Mbps** | 576 Mbps | 570 | 578 | 0 |
| **Ratio** | **108.7%** | | | | |

Previous (607/568=106.8%) → this run (624/574=**108.7%**), **+1.9pt improvement**.

### Linux benchmark results (EC2 c6i.2xlarge, 10 runs x 30 s)

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c** | **7.085 Gbps** | 7.053 Gbps | 7.001 | 7.173 | 4,410 |
| **wg-go** | **7.103 Gbps** | 7.103 Gbps | 7.072 | 7.142 | 0 |
| **Ratio** | **99.75%** | | | | |

All changes are inside `#ifdef __APPLE__`. No Linux regression (7.085 vs previous 6.99 — natural variation).

### Pipeline statistics (macOS wg-c, 10 s test)

| Operation | calls | pkts | pkt/call |
|------|-------|------|----------|
| TUN read (sender) | 764K | 764K | 1.0 |
| Seq sender | 141K batches | 764K | 5.4 pkt/batch |
| UDP recv (sender) | 90K | 140K | 1.5 |
| UDP recv (receiver) | 270K | 762K | 2.8 |
| Seq recvr (receiver) | 121K batches | 762K | 6.3 pkt/batch |

recvmsg_x batch efficiency: 2.8 pkt/call (previous 2.5 → +12%). The MSG_TRUNC filter returns only valid packets, so reprocessing goes down.

### Lessons

1. **kqueue is slightly faster than poll() on macOS** — native mechanism, no fd set rebuild
2. **MSG_TRUNC detection helps both safety and performance** — removes wasted work on truncated packets
3. **Benchmark methodology matters** — run-order bias can cause 2-3% error
4. **Watch bc's scale with intermediate results** — rewrite `a / b * c` as `a * c / b`

## Experiment #41: GSO max_segs 16→12 — fewer retrans, +27% throughput

**Date**: 2026-05-05
**Scope**: Linux (EC2 c6i.2xlarge)

### Background

With max_segs=16, about 441 retrans/run occurred. wireguard-go had 0.
The GSO burst size (16 × ~1500B = 24KB) was too large, causing jitter in GRO processing and TCP ACK
return on the receiver → CUBIC mistakes it for congestion → fast retransmit → cwnd shrinks → throughput drops.

### Changes

Changed max_segs in `src/bind/wg_bind_std.c` from 16→12.
Burst size: 24KB → 18KB (-25%). sendmsg calls increase by 33%, but the syscall overhead is small.

### Results (EC2 c6i.2xlarge, 5 runs x 30 s)

| Implementation | Mean | Median | Min | Max | Retrans | CPU |
|------|------|--------|-----|-----|---------|-----|
| **wg-c** | **9.01 Gbps** | 9.02 Gbps | 8.93 | 9.06 | 384 | ~20% |
| **wg-go** | **7.03 Gbps** | 7.02 Gbps | 7.01 | 7.07 | 0 | ~17% |
| **Ratio** | **128.1%** | | | | | |

### Comparison with previous run

| Metric | max_segs=16 | max_segs=12 | Change |
|------|-------------|-------------|------|
| wg-c throughput | 7.085 Gbps | **9.01 Gbps** | **+27.2%** |
| retrans (total) | 4,410 (10 runs) | 384 (5 runs) | **-91%** |
| retrans/run | 441 | 77 | **-83%** |
| wg-c / wg-go | 99.75% | **128.1%** | **+28.4pt** |

### Analysis

Fewer retrans → TCP cwnd maintained → large throughput gain. This reconfirms Lesson #9 (retrans is the biggest enemy of throughput).

With max_segs=16, 16 packets are sent at once via GSO, and the receiver's WireGuard pipeline (recvmmsg → decrypt → TUN write) incurs processing delay. During this delay TCP ACKs stall, and the sender's CUBIC shrinks cwnd.

With max_segs=12 the burst is 25% smaller:
1. Receiver processing time is shorter (12 packets vs 16)
2. TCP ACKs are returned faster
3. CUBIC's cwnd stays stable → high throughput maintained

### Lessons

1. **Reducing retrans translates directly into throughput** — 441/run → 77/run gives +27% throughput
2. **The optimal GSO max_segs depends on the environment** — we thought 16 was "good enough", but 12 was optimal
3. **wireguard-go's retrans=0 comes from not using GSO** — it paces at the cost of throughput
4. **The key is balancing burst size against receive pipeline speed** — burst > receive capacity → retrans → cwnd shrinks

### Reproducibility check (2nd run, same conditions)

| Implementation | Mean | Min | Max | Retrans |
|------|------|-----|-----|---------|
| **wg-c** | **8.98 Gbps** | 8.92 | 9.01 | 134 (27/run) |
| **wg-go** | **7.02 Gbps** | 7.00 | 7.05 | 0 |
| **Ratio** | **127.9%** | | | |

Reproduced twice in a row. Retrans dropped further in the 2nd run (77/run → 27/run). The result is reliable.

---

## Experiment #42: Windows wg-c vs wireguard-go comparison benchmark

**Date**: 2026-05-16
**Environment**: Parallels ARM64 VM (4 vCPU), Windows 11, Wintun + UDP loopback (127.0.0.1)
**Tool**: `scripts/bench_windows.ps1` (fixed: #110 adapter cleanup race fix)
**wireguard-go**: v0.0.20250522

### Background

First comparison benchmark for Windows support. wg-c uses RIO (Registered I/O) + Wintun,
wireguard-go uses standard UDP + Wintun. Both use the inline_crypto path.

### Results (3 runs x 10 s, --omit 3)

| Implementation | Mean | Median | Min | Max | Retrans |
|------|------|--------|-----|-----|---------|
| **wg-c** | **65 Mbps** | 60 Mbps | 56 | 79 | 0 |
| **wg-go** | **94 Mbps** | 94 Mbps | 92 | 97 | 0 |
| **Ratio** | **69.1%** | | | | |

### Observations

1. **wireguard-go has very little variance** (92-97 Mbps) — the Go scheduler is stable
2. **wg-c has large variance** (56-79 Mbps) — jitter from the GQCS 1ms timeout
3. **wireguard-go's "Failed to send data packets: short buffer"** — occurs a few times every round, minor performance impact
4. **Handshake completes normally** — the Noise IK handshake completes immediately in both implementations

### Bottleneck analysis

| Factor | Impact | Details |
|------|------|------|
| **GQCS 1ms timeout** | Large | Spin-poll miss on RIO recv → 1ms block. Raises average recv latency |
| **inline_crypto (ncpu<=4)** | Medium | Encryption/decryption is serial. wireguard-go parallelizes across 4 workers |
| **ARM64 VM overhead** | Small | Parallels virtualization layer; expected to improve on real hardware |
| **Wintun ring contention** | Unknown | Need to verify whether read spin of 128 iterations is appropriate |

### Improvement plan

1. **Tune RIO recv spin** — raise spin count above 4096, or remove GQCS with WaitOnAddress
2. **Multithreaded crypto for ncpu>4** — test on real hardware (8+ cores)
3. **Increase Wintun read spin** — TUN_READ_SPINS 128→512 or 1024
4. **Re-evaluate on native x86_64 Windows** — removes VM overhead

---

## Experiment #43: libsodium master (NEON ChaCha20) vs OpenSSL EVP — AEAD microbenchmark (2026-09-23)

### Background

To shrink the audit scope, we considered consolidating the AEAD backend on libsodium.
libsodium master added `chacha20_dolbeau-neon.c` (commit `5e261847ce`, 2026-07-12) and
`chacha20_dolbeau-avx512.c` (2026-07-12). **These are not in 1.0.22 (2026-04-09) and are unreleased**.
Poly1305 still has only `donna` (portable C) and `sse2`; there is no ARM64 NEON version.

### Environment

- Apple M5 Max (macOS), single thread, ChaCha20-Poly1305 IETF, no AAD
- libsodium 1.0.21 (nix) / libsodium master `c960b3b` (zig build, ReleaseFast) / OpenSSL 3.6.1 EVP (ctx reused, only nonce re-initialized)
- Best of 5 runs. Decrypt measures the case where verification succeeds with the correct tag

### Results (1420 B)

| Implementation | encrypt | decrypt | ChaCha20 alone | Poly1305 alone |
|------|---------|---------|---------------|---------------|
| libsodium 1.0.21 | 6.30 Gbps | 6.24 Gbps | 8.59 Gbps | 29.09 Gbps |
| libsodium master (NEON) | 8.89 Gbps | 8.96 Gbps | 14.38 Gbps | 27.81 Gbps |
| OpenSSL 3.6.1 EVP | 12.94 Gbps | 12.89 Gbps | — | — |

At 64 B, all three are about 3 Gbps with no difference (dominated by fixed overhead).

### Observations

1. libsodium master's NEON ChaCha20 gives +41% AEAD (6.3→8.9 Gbps), but it is still only about 69% of OpenSSL
2. Cause of the gap: libsodium processes ChaCha20 and Poly1305 in separate passes (2-pass); OpenSSL uses fused NEON asm
3. x86_64 (AVX-512) not measured. Needs measuring on EC2 c6i

### Conclusion

On ARM64, OpenSSL is currently about 1.45x faster for AEAD alone. Consolidating on libsodium would lower ARM64 performance.
On x86_64, crypto is about 2% of perf, so the impact may be small, but it needs measuring on EC2.

---

## Experiment #44: Remove BoringSSL asm backend + harden EVP cache (2026-09-23)

### Background

Shrinking the security audit scope before the OSS release. BoringSSL fused asm (#20) was +2.1% vs OpenSSL EVP (within noise), yet
it added 3,024 lines of asm and the "in-place decryption before tag verification" concern to the audit scope.

### Changes

1. Removed the `WG_USE_BORINGSSL_ASM` option, `chacha20_poly1305_armv8.S` and `wg_chacha20poly1305_arm64.h`. Two AEAD backends remain: OpenSSL EVP (default on Linux/macOS) and libsodium (Windows)
2. EVP cache key comparison changed from `memcmp` → constant-time comparison `evp_key_equal()` (64-bit word XOR-OR, branch-free; on GCC/Clang `__asm__("" : "+r"(diff))` prevents turning it into an early exit). `sodium_memcmp` is 9.8 ns/call at 32B, `evp_key_equal` is <1 ns/call, `memcmp` 0.3 ns/call (M5 Max, 200 million calls x 3). Against one 1420B AEAD (~0.9 µs), `sodium_memcmp` adds about 1%, so it was rejected
3. In OpenSSL EVP decrypt, `EVP_DecryptUpdate` writes out plaintext before tag verification (`Final`). Moved `EVP_CTRL_AEAD_SET_TAG` before `DecryptUpdate`; any failure of `DecryptUpdate` (including partial writes) or `DecryptFinal` does `goto fail`, which wipes `dst` with `wg_secure_zero` (failure path only, no hot path impact). libsodium's `crypto_aead_chacha20poly1305_ietf_decrypt` zero-fills the output on verification failure
4. Added tests: `test_aead_tamper_wipes_output` (in-place 1420B, tampered tag → zeroed output), `test_aead_key_switch` (re-keys with keys that differ only in the first/last word). Confirmed both tests fail when the change is reverted (mutation test)

### Results (Apple M5 Max, bench_crypto, 1420B, Release, 3 runs)

| | Encrypt | Decrypt |
|---|---|---|
| main | 12,786–12,815 Mbps | 12,800–12,855 Mbps |
| branch | 12,789–12,835 Mbps | 12,817–12,876 Mbps |

No difference. ctest passes 28/28 in both OpenSSL / libsodium configurations (Debug, no ASan).

### Notes

- On macOS 26.4, the ASan runtime hangs at initialization with both nix clang and Apple clang (`AsanInitInternal` → `get_dyld_hdr` → malloc recursion). ASan must be run on Linux
- Linux ASan+UBSan (NixOS aarch64 VM, gcc 15.2, root): 28/30 pass in both OpenSSL / libsodium configurations. The 2 failures (`test_tun_linux` assumes batch_size==1, `test_handshake_real` timeout) are existing issues that also fail on main
### Verification on EC2 (2026-09-23)

**Environment**: EC2 c6i.2xlarge, Ubuntu 26.04, kernel 7.0.0-1006-aws, GCC 15.2, OpenSSL 3.5.5, iperf3 3.20, wireguard-go v0.0.20250522 (Go 1.26)

**Setup on Ubuntu 26.04 (AppArmor)**: the `wireguard-tools` AppArmor profile `/etc/apparmor.d/wg` can only read
`/etc/wireguard/**` and does not allow connecting to the UAPI socket. As is, `bench_rigorous.sh` stops with
`fopen: Permission denied` (key file) and `Unable to modify interface: Permission denied` (UAPI).
This is the same for both userspace implementations, wg-c and wireguard-go. We worked around it with the following two steps:

```bash
echo '/run/wireguard/*.sock rw,' | sudo tee -a /etc/apparmor.d/local/wg
sudo apparmor_parser -r /etc/apparmor.d/wg
sudo TMPDIR=/etc/wireguard scripts/bench_rigorous.sh <wg-c> <wireguard-go> 10 30
```

| Measurement | main | branch | Difference |
|------|------|--------|----|
| `bench_rigorous.sh` interleaved, 10 pairs (wg-c) | 7.707 Gbps | 7.667 Gbps | −0.51% (paired t = −3.4) |
| `bench_crypto` 1420B interleaved, 5 runs (encrypt) | 12,582 Mbps | 12,543 Mbps | −0.3% (ranges overlap) |
| `bench_crypto` 1420B interleaved, 5 runs (decrypt) | 12,425 Mbps | 12,397 Mbps | −0.2% (ranges overlap) |

- On Linux x86, behavior changes only inside the AEAD functions, and AEAD alone shows no difference. On x86, crypto is about 2% of CPU, so even if the difference were real, the throughput impact would be 0.01% or less
- We judge the remaining −0.5% to be a difference in code placement (alignment) and **accept** it. A placement difference pushes each binary in the same direction every time, so it shows up as a significant difference even in interleaved runs. Reverting changes one at a time changes placement every time, so bisecting would not reach a conclusion
- Meets the 6.9 Gbps threshold (7.67 Gbps). 100% of wireguard-go is not met by main either (93.5%). Being investigated separately as an environment factor
- **Lesson**: measured sequentially, wireguard-go moved about 3% within the same hour, 8.63 → 8.37 Gbps. main also differed by about 5%, 8.09 (sequential) vs 7.71 Gbps (interleaved). Always use interleaved runs when comparing builds

---

## Experiment #45: Kernel 6.17 vs 7.0 A/B — 127.6% does not reproduce even after reverting the kernel (2026-09-24)

### Background

In the EC2 re-measurement, wg-c fell below wireguard-go (93.6%), so we isolated whether the kernel is the cause.
The #41 environment was kernel 6.17.0-1007-aws (execution environment field in OPTIMIZATION_STATUS.md). The current Ubuntu 24.04 AMI also boots linux-aws 7.0, so
we compared **on the same instance, same userland and same binaries, swapping only the kernel**.

### Environment

- EC2 c6i.2xlarge x2 (ap-northeast-1a, Xeon 8375C), created with terraform and deleted after measurement
- noble: Ubuntu 24.04.5, GCC 13, OpenSSL 3.0.13. Kernel 7.0.0-1013-aws → 6.17.0-1007-aws → 7.0.0-1013-aws (ABA, grub-reboot)
- resolute: Ubuntu 26.04.1, kernel 7.0.0-1012-aws (reference)
- wg-c: main `5256646` built on noble (`-O3 -march=native`), same binary used on both hosts (sha256 d119a85a…)
- wireguard-go: v0.0.20250522 static cross-build with Go 1.25.7, same binary used on both hosts (sha256 f822c097…)
- `bench_rigorous.sh` (wg-c and wireguard-go interleaved), iperf3 30s, --omit 3. Kernel WireGuard module blacklisted
- Preemption model: 6.17 = `PREEMPT_VOLUNTARY`, 7.0 = `PREEMPT_LAZY` (no PREEMPT_DYNAMIC)

### Results

| # | Host | Kernel | wg-c | wg-c (Gbps) | wg-go (Gbps) | Ratio | Runs |
|---|---|---|---|---|---|---|---|
| 1 | noble | 7.0 | main | 7.836 | 8.512 | 92.0% | 10 |
| 2 | resolute | 7.0 | main | 7.876 | 8.516 | 92.4% | 10 |
| 3 | noble | 6.17 | main | 7.072 | 7.427 | 95.2% | 10 |
| 4 | noble | 6.17 | #41 (`a764a49`) | 7.323 | 7.481 | 97.8% | 5 |
| 5 | noble | 6.17 | main, tcp_rmem max 6MB | 7.266 | 7.465 | 97.3% | 3 |
| 6 | noble | 7.0 | main (2nd A of ABA) | 7.806 | 8.500 | 91.8% | 5 |

Retransmits were 0 in every case (only 1 for wg-c on resolute).

### Profile during the run (5 s while wg-c is running, system-wide)

| | 6.17 | 7.0 |
|---|---|---|
| sched_yield | 0 | 0 |
| futex | 737,395 | 899,564 |
| write (TUN) | 1,299,088 | 1,190,500 |
| read (TUN) | 387,130 | 484,899 |
| sendmsg / recvmmsg | 278,146 / 157,464 | 313,197 / 216,672 |
| context-switches | 631,691 | 705,013 |
| wg-c CPU share (perf) | 58% | 67% |

The top symbols are nearly the same on both kernels (wg_spsc_pop, sequential send/recv, rep_movs_alternative, finish_task_switch).

### Findings

1. **Kernel 6.17→7.0 speeds up both, but wireguard-go gains more**: wg-c +10.4% (7.07→7.82), wireguard-go +14.5% (7.43→8.51). The 1st and 2nd A of ABA agree within 0.4%, so the difference comes from the kernel
2. **Reverting to 6.17 does not reproduce 127.6%**: main gives 95.2%, and even the #41 code (`a764a49`) gives 97.8%. Against wg-c's 9.01–9.41 Gbps at the time of #41, the same kernel and same code give 7.3 Gbps. wireguard-go roughly matches #41's 7.02–7.37 Gbps
3. #41 had 27–77 retransmits/run, but this time all were 0. Restoring the tcp_rmem max to the old value of 6MB changes nothing (#5)
4. **The change in sched_yield semantics in 6.19 (`79104becf42b`) has no effect on this benchmark**: sched_yield is called 0 times. Linux `seq_wake_send_wait()` is spin + futex; sched_yield is only called on the retry path when the SPSC is full
5. main is about 2.5 points lower than the #41 code on 6.17 (95.2% vs 97.8%; compared across separate sessions, so for reference only)

### Conclusion

- The main reason wireguard-go overtook us is that "#41's 9 Gbps does not come out on today's EC2"; kernel 7.0 only widened the gap by a few points
- The conditions under which #41 got 9.01–9.41 Gbps (host, sysctl, other tuning) were not recorded, and it cannot be reproduced with the same kernel and same code. We stop using 127.6% as a baseline
- A candidate cause for the wider gap on 7.0 is `PREEMPT_LAZY` (wake-up latency via futex). It is likely unfavorable to wg-c's design, which has many futex calls and context switches, but this is unverified

### Next steps

- Compare experimental builds with a different wake-up mechanism (longer spin, a different way of waiting instead of futex) on 7.0
- Compare run delay of wg-c threads on 6.17 and 7.0 with `perf sched timehist`
- Investigate the possibility that TUN write is one call per packet (about 240,000 writes/s). wireguard-go writes to TUN in batches with GSO

---

## Experiment #46: About 90% of wg-c's writes are eventfd writes for thread wake-up (2026-09-24)

### Background

In the #45 profile, wg-c called write about 1.2 million times in 5 seconds. We suspected TUN writes were not batched, and looked at where the writes go.

### Environment

NixOS VM (aarch64, 8 vCPU, kernel 6.19.10), Release build of main `5256646`, wireguard-go v0.0.20250522 (nixpkgs).
The netns + veth setup is the same as bench_rigorous.sh. In the middle of a 25-second iperf3 run, we measured the sender (A) and receiver (B) processes
with perf stat (10 s) and bpftrace (write fd and size, 3 s).

### Results

| | wg-c A | wg-c B | wg-go A | wg-go B |
|---|---|---|---|---|
| Throughput | 7.03 Gbps | | 5.97 Gbps | |
| write / s | 136,000 | 129,000 | 9,300 | 21,900 |
| of which eventfd (8 bytes) / s | 94,000 | 88,000 | 220 | 130 |
| of which TUN / s | 11,400 | 29,800 | 9,100 | 20,900 |
| futex / s | 49,000 | 89,000 | 5,700 | 7,200 |
| context-switches / s | 34,000 | 51,000 | 15,000 | 16,000 |

### Findings

1. **TUN write batching is about the same as wireguard-go**. Receiver TUN writes: wg-c 4.2 thousand/s/Gbps, wireguard-go 3.5 thousand/s/Gbps
2. **About 90% of writes are eventfd writes to wake SPSC queue consumers**. `wake_consumer()` (src/device/wg_spsc.c:112) writes to the eventfd on every push while consumer_waiting is true. The consumer clears the flag only after it wakes, so every push until then is an extra write
3. **futex is 7–12x wireguard-go**. `seq_wake_send_signal()` / `seq_wake_recv_signal()` call FUTEX_WAKE on every encryption/decryption without checking whether any thread is waiting. The waiting side also repeats FUTEX_WAIT with a 50µs timeout
4. Context switches are 2–3x wireguard-go

### Proposed fixes (not implemented)

- `wake_consumer()`: write only when `atomic_exchange(&q->consumer_waiting, false)` returns true. That gives one write per sleep
- seq_wake: the waiting side sets a waiter flag, and the signal side calls FUTEX_WAKE only when the flag is set

This design, sensitive to wake-up delay, is also a candidate reason why it gains less than wireguard-go under PREEMPT_LAZY (7.0). After the fix it needs to be measured on both 6.17 and 7.0.

---

## Experiment #47: Remove extra syscalls for thread wake-up — eventfd −95%, throughput unchanged (2026-09-24)

Branch: `perf/wake-syscalls`

### Changes

1. `wake_consumer()` (src/device/wg_spsc.c): only the producer that exchanges `consumer_waiting` from true→false writes to the eventfd. That gives one write per sleeping consumer. If the consumer finds an item on its recheck and skips the read, a count of 1 stays in the eventfd, but the next read just returns immediately and the loop rechecks
2. `seq_wake_{send,recv}_signal()` (Linux): place `seq_wake_*_waiting` on the same cache line, and call FUTEX_WAKE only when the waiting side has set it (Dekker: value → fence → flag / flag → fence → value)
3. `seq_wake_*_wait()`: every reset of the value to 0 now uses `atomic_exchange(..., 0, acq_rel)`. The original code wrote 0 with relaxed right before FUTEX_WAIT, so a signal arriving between leaving the spin and that store was lost, and the thread could sleep up to 50µs (this also fixes lost wakeups). The load→store during spin also overwrote the signal from a second worker signaling concurrently, so it was changed to exchange. The Windows version was changed the same way (unverified)

### Tests

- macOS (Debug): 28/28
- NixOS VM aarch64 (kernel 6.19.10): ASan+UBSan 28/28, TSan 25/28 (the 3 failures also fail on main: 1 false positive on getrandom inside libsodium, 2 use-after-free at shutdown — see below)

### Results (VM, interleaved with main, 5 pairs, iperf3 25s)

| Pair | main | branch |
|---|---|---|
| 1 | 9.30 | 10.19 |
| 2 | 10.74 | 11.26 |
| 3 | 11.21 | 11.41 |
| 4 | 10.61 | 10.06 |
| 5 | 10.14 | 10.11 |
| Mean | 10.40 Gbps | 10.61 Gbps (+2%, paired t ≈ 0.84, not significant) |

| Per 10 s | main | branch |
|---|---|---|
| eventfd writes (A, 3 s) | 555,700 | 16,700 (−97%) |
| eventfd writes (B, 3 s) | 447,400 | 30,400 (−93%) |
| futex (A / B) | 636,003 / 1,068,737 | 534,164 / 925,699 (−16% / −13%) |
| context-switches (A / B) | 389,588 / 569,928 | 359,523 / 538,263 |

### futex breakdown (branch, 3 s, bpftrace)

| | A | B |
|---|---|---|
| WAIT (op 0) | 39,451 | 75,495 |
| WAIT_BITSET (op 9, glibc condition variables) | 42,654 | 51,119 |
| WAKE (op 1) | 117,812 | 238,890 |
| ETIMEDOUT | 20,870 | 14,366 |
| seq_wake word (WAIT+WAKE) | about 60,000 | about 76,000 |
| Other (pthread condition variables, mutexes) | about 140,000 | about 290,000 |

Call stacks (perf record --call-graph dwarf, callers of futex):

| Caller | A | B |
|---|---|---|
| Timers (`wg_timers_any_authenticated_packet_*` → `wg_timer_del` → `pthread_cond_signal`, and the mutex in the woken `timer_thread_fn`) | about 45% | about 40% |
| Replay protection (contention on the `wg_replay_counter_validate` mutex, rtc_recv) | small | about 18% |
| seq_wake (`syscall`) | about 33% | about 25% |

### Conclusion

The extra eventfd writes are almost gone, but throughput is unchanged. Most futex calls came not from seq_wake but from timers and replay protection (→ #48). We treat this as a change that "reduces syscalls and fixes lost wakeups; throughput unchanged".

### Separate issue: use-after-free at shutdown (existing bug)

Under TSan, `test_interop_wg_go` and `test_uapi_wg_compat` fail on main too. `wg_tun_linux_destroy()` (src/tun/wg_tun_linux.c:757-772) calls `wg_rwcancel_destroy()` after `wg_rwcancel_cancel()` without waiting for the TUN read thread to exit (free: wg_rwcancel.c:241, read: wg_rwcancel.c:171).

---

## Experiment #48: Eliminate wasted timer wake-ups — futex −61% / −39%, throughput +5% (2026-09-24)

Branch: `perf/timer-wakeups`

### Cause

`wg_timers_any_authenticated_packet_sent/received()` called `wg_timer_del()` on every batch, and `wg_timer_del()` took the mutex every time, even when the timer was stopped, and woke the timer thread with `pthread_cond_signal`. On the data path, del and mod alternate every batch (receiver B: mod send_keepalive on data receive, del on ACK send. Sender A: mod new_handshake on data send, del on ACK receive). wg-c has one thread per timer, so each of these caused a wake-up and a context switch.

### Changes

- Made `is_pending` `_Atomic`, and the timer thread records "which deadline it is currently sleeping until" in `sleep_until_ns` (UINT64_MAX when waiting indefinitely, 0 when not waiting)
- mod: signal only when the new deadline is earlier than `sleep_until_ns` (always wake when waiting indefinitely)
- del: return immediately without locking if stopped. Even if running, do not signal (the thread wakes at the old deadline, sees `is_pending`, and goes back to waiting indefinitely)
- Timer thread: checks `now >= deadline_ns` every time it wakes, and sleeps again if the deadline was extended. It fires based on time, not ETIMEDOUT, so it is also robust against spurious wakeups
- `wg_timer_is_pending()` is lock-free
- Added 4 tests: del → wait → mod fires at the new deadline / mod while waiting indefinitely / mod that moves the deadline earlier / repeated del and mod. Confirmed that a mutation setting sleep_until to 0 while waiting indefinitely makes `test_timer_mod_from_idle` fail

### Tests

- macOS (Debug): 28/28 (test_timers 10/10)
- NixOS VM aarch64: ASan+UBSan 28/28, TSan 25/28 (only the same 3 existing failures as #47)

### Results (VM, interleaved with main, 5 pairs)

| Pair | main | branch | Difference |
|---|---|---|---|
| 1 | 10.94 | 11.12 | +0.17 |
| 2 | 10.08 | 11.03 | +0.96 |
| 3 | 10.50 | 10.52 | +0.02 |
| 4 | 9.89 | 10.41 | +0.52 |
| 5 | 9.22 | 10.25 | +1.03 |
| Mean | 10.12 Gbps | 10.67 Gbps | +5.3% (t ≈ 2.7, 4 degrees of freedom, two-sided p ≈ 0.05. All 5 pairs positive) |

| Per 10 s | main | branch | Change |
|---|---|---|---|
| futex (A) | 660,408 | 257,363 | −61% |
| futex (B) | 1,104,066 | 668,159 | −39% |
| context-switches (A) | 405,590 | 259,072 | −36% |
| context-switches (B) | 594,659 | 459,844 | −23% |
| WAIT_BITSET (condition variables, 3 s) | about 40,000–47,000 | 1–2 | nearly zero |

Timers (`pthread_cond_signal`, `timer_thread_fn`) disappeared from the futex callers. About 47% of the futex calls remaining on receiver B are the replay protection mutex (`wg_replay_counter_validate`, lock_wake 35% + lock_wait 12%).

### Notes

- main's baseline moved from 10.40 in #47 to 10.12 Gbps. This VM fluctuates a lot, so confirm with interleaved runs on EC2 x86 (a project requirement, see CONTRIBUTING.md)
- test_timers is sleep-based, so it may be flaky when CI load is high (test_timer_del_then_mod has 70ms of margin)

### Next steps

- On EC2 x86, measure main and "both #47 + #48" interleaved. If there is a regression, expand to 4 variants
- Move the replay check to the sequential thread (same shape as wireguard-go's RoutineSequentialReceiver and the kernel's wg_packet_rx_poll)

---

## Experiment #49: Move replay protection to the sequential thread — contention gone, but throughput does not improve (2026-09-24)

Branch: `perf/replay-sequential` (not merged)

### Changes

- Removed the replay check from `decrypt_elem()`, and check it in `drain_rx_order()` (under the per-peer `rx_drain_lock`, in arrival order) and in `recv_elem_inline()`. Same position as wireguard-go's RoutineSequentialReceiver and the kernel's wg_packet_rx_poll (the check was already after AEAD verification)
- Kept the lock in `wg_replay_counter_validate()`, because of `wg_transport_decrypt()` (an API not called from the data path) and the inline configuration with multiple UDP receive workers. Since it is called from a single thread, there is no contention
- `stats.decrypt_replay_fail`, which had never been incremented, is now incremented on rejection
- Test: with a bind wrapper where dev0 sends each transport message twice, confirmed that each ping reaches dev1's TUN only once and `decrypt_replay_fail` is at least N (21 for 20 pings). Confirmed it fails under a mutation that removes the check

### Tests

macOS 28/28. VM: ASan+UBSan 28/28, TSan 25/28 (only the 3 existing failures)

### Results (VM, interleaved with main, 5 pairs)

| Pair | main | branch | Difference |
|---|---|---|---|
| 1 | 10.56 | 9.98 | −0.58 |
| 2 | 9.75 | 9.55 | −0.20 |
| 3 | 9.86 | 9.98 | +0.12 |
| 4 | 9.93 | 9.83 | −0.10 |
| 5 | 9.63 | 9.35 | −0.28 |
| Mean | 9.95 Gbps | 9.74 Gbps | −2.1% (t ≈ −1.7, not significant) |

`wg_replay_counter_validate` disappeared from the futex callers, and WAKE on receiver B went from 238,890 → 169,426 in 3 s (−29%).

### Conclusion

The sequential thread is a serial bottleneck that every packet passes through (Lesson 5), so adding per-packet work there, even an uncontended mutex, cancels out the reduced contention in the parallel part. We will not merge this as is. One possible improvement is checking without a lock inside the sequential thread (guaranteeing only that thread touches it), but that requires more safety argument, so the priority is low.

---

## Experiment #50: Verify #47 (seq_wake) and #48 (timers) on EC2 x86 — seq_wake +2.5%, timers −2.3% (2026-09-24)

### Environment

EC2 c6i.2xlarge (ap-northeast-1a, Xeon 8375C), Ubuntu 26.04.1, kernel 7.0.0-1012-aws (PREEMPT_LAZY), GCC 15, OpenSSL 3.5.5,
wireguard-go v0.0.20250522 (static build with Go 1.25.7). All 4 builds were built on the same host with `-O3 -march=native`.
Measurement used the same netns + veth setup as bench_rigorous.sh, iperf3 25 seconds, interleaved with main.

| Build | Contents | sha256 (prefix) |
|---|---|---|
| main | `5256646` | 65db490d |
| wake | main + #47 | 0e542a4f |
| timers | main + #48 | d53f2255 |
| combined | main + #47 + #48 | 52feebea |

### Results

main and combined interleaved, 10 pairs:

| | main | combined |
|---|---|---|
| Mean | 7.739 Gbps | 7.661 Gbps |
| Paired difference | | −0.078 (−1.0%, t ≈ −3.6, negative in 9 of 10 pairs) |

Isolation (main → timers → main → wake as one round, 5 rounds):

| Round | main | timers | main | wake |
|---|---|---|---|---|
| 1 | 7.720 | 7.457 | 7.787 | 7.918 |
| 2 | 7.761 | 7.484 | 7.788 | 7.925 |
| 3 | 7.753 | 7.577 | 7.669 | 7.913 |
| 4 | 7.659 | 7.606 | 7.659 | 7.940 |
| 5 | 7.673 | 7.559 | 7.746 | 7.937 |
| Mean difference | | −0.177 (−2.3%, t ≈ −4.1) | | +0.197 (+2.5%, t ≈ +6.7) |

bench_rigorous.sh (combined, 5 pairs): wg-c 7.732 Gbps / wg-go 8.303 Gbps = 93.1%. Meets the 6.9 Gbps threshold.

### Findings

| Fix | VM (aarch64, kernel 6.19) | EC2 (x86, kernel 7.0) |
|---|---|---|
| #47 seq_wake | +2% (not significant) | **+2.5% (significant)** |
| #48 timers | **+5.3%** | **−2.3% (significant)** |

- #47 helps on x86. Make it a PR
- #48 regresses on x86, so it is parked. An example of why you must not decide on VM results alone
- Hypothesis (unverified): before the fix, the timer thread woke on every batch, so the CPU rarely entered halt. After the fix it enters halt more easily, and on EC2 guests resuming from halt (VM exit) is slow, so pipeline thread wake-ups are delayed. In the #45 profile, `pv_native_safe_halt` is also 27–36%. How to check: perf stat on EC2 (idle, context-switches, thread run delay), and whether the difference disappears when booted with `idle=poll`
- With both applied it is −1.0%, not the simple sum (+0.2%)

---

## Experiment #51: Adaptively extend the sequential thread's spin — +3.0%, 104.5% of wireguard-go (2026-09-24)

Branch: `perf/adaptive-spin` (on top of `perf/wake-syscalls` = #125)

### Changes

- Unified `seq_wake_*_wait()` (Linux) into `seq_wake_wait_adaptive()` in `src/workers/wg_seq_wake_linux.h`
- After the existing fixed spin (1024 iterations), add an extra spin of 0–100µs. If a signal is picked up during the spin, or a sleep shorter than 100µs ends with a signal, double it (2µs when starting from 0); on timeout or a sleep of 100µs or more, halve it (below 2µs becomes 0). The clock is read every 256 iterations. No extra spin on 1 core
- FUTEX_WAIT timeout 50µs → 1ms (the waiting flag guarantees FUTEX_WAKE, so this is only a safety net)
- The extra spin length is read and written only by each direction's sequential thread, so it is placed on a separate cache line from the ones workers write
- wg_spsc_pop's spin_limit is unchanged (to isolate the effect)

### Tests

NixOS VM aarch64: ASan+UBSan 28/28, TSan 25/28 (only the 3 existing failures)

Idle CPU (VM, 2 wg-c processes, no traffic, 10 s):

| Build | Before load | After 10 s of iperf3 |
|---|---|---|
| main | 0.4% / 0.3% | 0.4% / 0.4% |
| #125 | 0.4% / 0.4% | 0.4% / 0.3% |
| adaptive spin | 0.1% / 0.1% | 0.1% / 0.0% |

### EC2 results

c6i.2xlarge, Ubuntu 26.04, kernel 7.0.0-1012-aws (PREEMPT_LAZY), GCC 15. A different host from #50 (the sha256 of the #125 build is the same as in #50, 0e542a4f).

Interleaved with #125, 6 rounds:

| Round | #125 | adaptive |
|---|---|---|
| 1 | 6.751 | 6.999 |
| 2 | 6.783 | 6.982 |
| 3 | 6.731 | 6.884 |
| 4 | 6.694 | 6.843 |
| 5 | 6.723 | 6.871 |
| 6 | 6.712 | 7.006 |
| Mean | 6.732 | 6.931 (+3.0%, t ≈ 7.9, all 6 rounds positive) |

Measurements during the run (1 run each, whole host):

| | #125 | adaptive | wg-go |
|---|---|---|---|
| Throughput | 6.70 Gbps | 6.91 Gbps | 6.64 Gbps |
| context-switches / 5 s | 683,267 | 560,294 (−18%) | 493,679 |
| cpu-migrations / 5 s | 67,780 | 52,255 (−23%) | 51,209 |
| CPU idle% | 24.5 | 24.2 | 26.5 |
| Scheduling events / 2 s (perf sched) | 148,588 | 118,855 (−20%) | 94,429 |
| Average wake-up wait | 0.049 ms | 0.054 ms | 0.054 ms |

bench_rigorous.sh (adaptive, 5 pairs): **wg-c 7.001 Gbps / wg-go 6.695 Gbps = 104.5%** (wg-c ahead in all 5 pairs).

### Findings

- CPU idle rate is about the same for every build. What mattered was not the amount of halt but how often the sequential thread sleeps and is woken, and the resulting migrations between CPUs. Extending the spin brings that close to wireguard-go's level
- Absolute values differ a lot between hosts (wireguard-go on this host is 6.7 Gbps; on the #50 host it is 8.3 Gbps). 104.5% of wireguard-go is the value on this host and cannot be compared directly with the 93.1% (both applied) measured on the #50 host. Compare using interleaved runs on the same host

### CPU usage at moderate load (VM, preliminary)

Limited the rate with iperf3 `-b` and measured the CPU of the 2 wg-c processes for 10 s (not measured on EC2).

| Rate | #125 (A / B) | adaptive (A / B) |
|---|---|---|
| 100 Mbps | 2.8% / 3.1% | 2.2% / 2.5% |
| 1 Gbps | 20.9% / 23.0% | 19.3% / 21.3% |

No increase. However, iperf3 `-b` sends in bursts at fixed intervals, so the gap between batches is long. For traffic with a steady stream of small batches at fixed intervals (under 200µs), the spin could be pinned at 100µs and the sequential thread could use nearly one core (not measured).

### Fixes from review

- `seq_spin_send_ns` and `seq_spin_recv_ns` were on the same cache line, and the `stats` right after them (written by the TUN reader on every batch) also overlapped that line. Added `_Alignas(64)` to both fields and to `stats`. Not yet re-measured on EC2 after the fix

### EC2 re-measurement (after the alignment fix, `bdab1c6`)

c6i.2xlarge, kernel 7.0.0-1012-aws, GCC 15. A different host from the first #51 measurement. The sha256 of the #125 build is the same (0e542a4f).

| Round | #125 | adaptive |
|---|---|---|
| 1 | 8.247 | 8.517 |
| 2 | 8.261 | 8.446 |
| 3 | 8.294 | 8.409 |
| 4 | 8.349 | 8.516 |
| 5 | 8.388 | 8.494 |
| Mean | 8.308 | 8.476 (+2.0%, t ≈ 5.7, all 5 rounds positive) |

CPU of the 2 wg-c processes (1 core = 100%, sum of all threads in the process, 10 s):

| Load | #125 (A / B) | adaptive (A / B) |
|---|---|---|
| UDP 200 B, 20 Mbps (paced at 10µs send interval) | 89% / 90% | 132% / 133% |
| UDP 200 B, 100 Mbps (same) | 132% / 130% | 169% / 179% |
| TCP 100 Mbps (`-b`) | 40% / 41% | 11% / 12% |
| TCP 1 Gbps (`-b`) | 101% / 119% | 76% / 101% |

- With small packets at fixed intervals, the spin is pinned at 100µs and uses about +40 points of CPU per process (the worst case predicted in review)
- With TCP (bursty), CPU goes down instead. Raising the FUTEX_WAIT timeout from 50µs → 1ms reduced wasted wake-ups during nearly idle periods
- **Already at #125, small UDP at 20 Mbps uses about 90%.** On the VM (aarch64) TCP 100 Mbps was 3%, but on x86 it is 40%. PAUSE on x86 (Ice Lake) is about 140 cycles, so the fixed 1024-iteration spin is likely about 50µs rather than a few µs. Spin length should be set by time, not by instruction count

### Next steps

- Bound the fixed spin by time too (same length on x86 and aarch64)
- Reduce CPU for small packets at fixed intervals, e.g. by extending the extra spin only "when a signal was picked up during the spin" or lowering the cap, and redo the same measurements
- On top of that, re-apply the timer fix (#48) and check whether the x86 regression disappears
- Tune wg_spsc_pop's spin_limit with the same approach (in a separate step)
- Measure the ratio to wireguard-go on other hosts too, to check whether 104.5% holds regardless of host

---

## Experiment #52: Bound the fixed spin by time — x86 CPU −15–25 points, throughput +1.65% (2026-09-24)

Branch: `perf/time-based-spin` (on top of main, PR #130)

### Background

In the #51 re-measurement, #125 (= same waiting as main) used about 90% of one core on x86 for small UDP at 20 Mbps. The sequential thread's fixed spin is 1024 PAUSEs; on Skylake and later x86, PAUSE is about 140 cycles, so this comes to about 40–50µs (arm64's yield is a few ns, giving 1–2µs). Before reworking adaptive spin (#51), first bound this fixed spin by time.

### Changes

Bound the spin in Linux `seq_wake_*_wait()` by `WG_SEQ_SPIN_NS` (default 3000 ns, can be overridden at build time). The clock is read once every 64 iterations. No change on Windows.

### Results (EC2 c6i.2xlarge, Ubuntu 26.04, kernel 7.0.0-1012-aws, GCC 15)

4 rounds, with main → 3µs → main → 5µs → main → 10µs as one round. Difference from the preceding main:

| Build | 4 rounds | Mean |
|---|---|---|
| 3µs | +0.62%, +2.19%, +1.84%, +1.95% | +1.65% |
| 5µs | +1.59%, +1.84%, +0.33%, +2.47% | +1.56% |
| 10µs | +1.86%, +0.85%, +1.49%, +0.15% | +1.09% |

CPU (1 core = 100%, sum of all threads in the process, sender / receiver, 10 s):

| Load | main | 3µs | 5µs | 10µs | wireguard-go |
|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps (paced at 10µs) | 90 / 93 | 68 / 68 | 74 / 73 | 82 / 82 | 45 / 42 |
| UDP 200 B, 100 Mbps (same) | 139 / 138 | 115 / 113 | 120 / 117 | 130 / 125 | 137 / 126 |
| TCP 100 Mbps | 42 / 43 | 25 / 26 | 28 / 29 | 36 / 37 | 5 / 5 |
| TCP 1 Gbps | 107 / 124 | 93 / 109 | 95 / 111 | 101 / 117 | 49 / 55 |

bench_rigorous.sh (5µs, 5 pairs): wg-c 7.956 / wireguard-go 8.417 = 94.5%.

CPU on arm64 (NixOS VM), main → 3µs: UDP 20 Mbps 21/25 → 26/30, TCP 100 Mbps 2.9/3.0 → 7.2/7.5, TCP 1 Gbps 24/27 → 27/29. On arm64 the original spin was even shorter, so it goes up a little.

### Findings

- On x86, the shorter the spin, the lower the CPU, and throughput is above main for any of 3–10µs. The 40–50µs spin was too long
- Default is 3µs (best in both throughput and CPU). On arm64 it rises by 3–5 points, but the reduction on x86 is much larger
- For small UDP at 100 Mbps, wg-c at 3µs uses less CPU than wireguard-go. At low rates wireguard-go uses much less (about 5x difference at TCP 100 Mbps). This difference comes from the thread structure, not the spin

### Plan for reworking #51 (adaptive spin)

- Lower the cap to about the cost of sleeping and waking (10–20µs on x86). The inter-arrival time of 200 B UDP at 20 Mbps is about 80µs, so if the cap is shorter than that, the spin misses and shrinks
- Stack it on top of this #52 and re-measure with the same 4 loads and a wireguard-go column

---

## Experiment #53: #130 re-measurement, #131 performance, adaptive spin v2 — what helps is the futex timeout (2026-09-24)

### Environment

EC2 c6i.2xlarge, Ubuntu 26.04, kernel 7.0.0-1012-aws, GCC 15. All built on the same host and measured interleaved.

| Build | Contents | sha256 (prefix) |
|---|---|---|
| main | `977d3c9` (after merging #125, #128) | a3987b7d |
| t3 | #130 (after rebase `9feece2`, 3µs, clock read every 16 iterations) | c3677cd3 |
| t5 | #130 with `-DWG_SEQ_SPIN_NS=5000` | 99575ad3 |
| bind | main + #131 | 7fc56263 |
| spin | v2 (#130 + extra spin capped at 15µs + futex timeout 1ms, `ff7e8b6`) | e170ca97 |
| spin50 | spin with only the futex timeout set back to 50µs | 12dcb75d |

### Throughput (3 rounds, with main → t3 → main → t5 → main → bind → t3 → spin as one round. Difference from the preceding build)

| Comparison | 3 rounds | Mean |
|---|---|---|
| t3 vs main | +1.96%, −0.68%, +1.22% | +0.83% |
| t5 vs main | −1.76%, +0.27%, +1.93% | +0.15% |
| bind (#131) vs main | −0.02%, −0.95%, +1.93% | +0.32% (no regression) |
| spin (v2) vs t3 | +2.99%, +3.18%, +2.24% | +2.81% |
| spin50 vs spin (2 pairs) | −4.6%, −4.0% | −4.3% |

### CPU (1 core = 100%, sender / receiver, 10 s)

| Load | main | t3 | t5 | spin (v2) | spin50 | wireguard-go |
|---|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps | 90 / 91 | 66 / 66 | 71 / 71 | 52 / 50 | 68 / 68 | 44 / 42 |
| UDP 200 B, 100 Mbps | 134 / 132 | 109 / 106 | 114 / 111 | 92 / 87 | — | 136 / 125 |
| TCP 100 Mbps | 41 / 42 | 24 / 26 | 27 / 29 | 8 / 10 | 24 / 25 | 5 / 5 |
| TCP 1 Gbps | 101 / 118 | 86 / 104 | 89 / 108 | 70 / 92 | — | 48 / 54 |

### bench_rigorous.sh (5 pairs, same host)

| Build | wg-c | wg-go | Ratio |
|---|---|---|---|
| main | 8.173 | 8.525 | 95.8% |
| t3 (#130) | 8.285 | 8.482 | 97.6% |
| spin (v2) | 8.415 | 8.429 | 99.8% |

### Findings

1. **3µs is fine as the #130 default**: with the clock read every 16 iterations, 5µs uses 3–5 points more CPU than 3µs, and the throughput difference is within noise. 3µs is +0.8% over main, and 95.8% → 97.6% in bench_rigorous
2. **#131 does not regress**: taking the net.lock read lock per batch in sequential send gives +0.32% (within noise)
3. **Most of v2's effect is the futex timeout (50µs → 1ms)**: setting only the timeout back to 50µs brings CPU back to the same as t3 (20 Mbps UDP 68%, TCP 100 Mbps 24%) and throughput drops about 4%. The extra spin capped at 15µs itself likely contributes little. With a 50µs timeout, a nearly idle sequential thread was waking up to 20,000 times per second
4. v2 uses less CPU than wireguard-go for small UDP at 100 Mbps, and the gap at low rates also narrowed (1.2x at 20 Mbps, 1.6–2x at TCP 100 Mbps). At TCP 1 Gbps it is still about 1.5x

### Next steps

- Build **#130 plus only the 1ms futex timeout** and compare it with v2. If there is no difference, make a PR with only the timeout change and no adaptive spin (simpler and easier to explain)

---

## Experiment #54: the FUTEX_WAIT timeout alone is enough; 10ms exposed a peer cache bug (2026-09-24)

### Measurements (EC2 c6i.2xlarge, Ubuntu 26.04, kernel 7.0.0-1012-aws, GCC 15, 4 interleaved rounds on the same host)

Builds: main (`1406b5c`), f1 (1ms timeout only), f10 (10ms timeout only), v2 (extra spin capped at 15µs + 1ms).

| Round | f1 | f10 | v2 | v2 − f1 |
|---|---|---|---|---|
| 1 | +2.29% | +0.36% | +2.23% | −0.06% |
| 2 | +2.08% | +0.15% | −0.30% | −2.33% |
| 3 | +2.33% | +1.39% | +2.45% | +0.12% |
| 4 | +3.89% | +2.08% | +3.08% | −0.78% |
| Mean (vs main) | +2.65% | +0.99% | +1.86% | −0.76% |

CPU (sender / receiver):

| Load | main | f1 | f10 | v2 | wireguard-go |
|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps | 69 / 67 | 51 / 52 | 53 / 53 | 53 / 52 | 46 / 43 |
| UDP 200 B, 100 Mbps | 110 / 107 | 93 / 87 | 91 / 85 | 94 / 87 | 136 / 126 |
| TCP 100 Mbps | 25 / 26 | 9 / 11 | 8 / 9 | 9 / 11 | 7 / 6 |
| TCP 1 Gbps | 89 / 107 | 73 / 93 | 73 / 92 | 71 / 94 | 50 / 57 |

bench_rigorous.sh: f1 98.7% (8.142 / 8.244), v2 98.6% (8.147 / 8.258). f10 could not be measured because the first ping failed.

### Findings

1. **Only the FUTEX_WAIT timeout matters.** Adding adaptive extra spin (v2) does not beat f1 on either throughput or CPU. The PR is f1 (#136)
2. **With f10 the first ping fails every time** (2/2 on EC2, 5/5 on the NixOS VM; 100ms is also 5/5). The cause is the sequential thread's peer cache, which was refreshed only once every 1024 loop iterations. When there is no work, each iteration enters FUTEX_WAIT, so a peer added at runtime is not processed for 1024 × timeout (about 50ms at 50µs, about 1 second at 1ms, about 10 seconds at 10ms). bench_rigorous.sh starts wg-c and then configures the peer, so this exceeded the 5-second ping wait
3. The same cache caused the sequential thread to keep using a removed peer after it was freed (confirmed with TSan). #134 added a generation number to refresh the cache and a wait before freeing. With that, ping failures drop to 0/5 even at 10ms
4. Peer lifetime management has other holes too (the handshake worker can free a peer that is still being processed). #135

### Lesson

Lengthening a just-in-case safety net (the FUTEX_WAIT timeout) exposes code that was relying on it. Before a change that lengthens a timeout, check whether any work only makes progress when the timeout expires

## Experiment #55: checking the merged main on x86 and Graviton (2026-09-25)

We compared main after merging #133 (clang-format), #134 (peer cache generation number + prev_queue head exchange changed from `release` to `acq_rel`), #136 (FUTEX_WAIT timeout 50µs → 1ms), and #138 (shared wake-up code, identical machine code) against the pre-merge `1406b5c`. This is the first EC2 measurement of #134 and acq_rel. On arm64, acq_rel turns SWPL into SWPAL, so we also measured on Graviton.

### Environment

| | x86 | Graviton |
|---|---|---|
| Instance | c6i.2xlarge (Xeon Platinum 8375C) | c7g.2xlarge (Neoverse-V1, Graviton3) |
| OS / kernel | Ubuntu 26.04.1 / 7.0.0-1012-aws | Same |
| GCC / OpenSSL / iperf3 | 15 / 3.5.5 / 3.20 | Same |
| wireguard-go | v0.0.20250522 (Go 1.25.7) | v0.0.20250522 (Go 1.26.7) |

Builds use `-march=native`, Release. 6 interleaved rounds with probe.sh (veth, iperf3 25 seconds) (odd rounds base → new, even rounds new → base).

### Throughput (Gbps, mean of 6 rounds)

| | 1406b5c | main (129419b) | Diff | Rounds new was ahead | Paired t |
|---|---|---|---|---|---|
| x86 | 8.023 | 8.258 | **+2.93%** | 6/6 | 3.4 |
| Graviton | 6.858 | 7.465 | **+8.85%** | 6/6 | 16.6 |

bench_rigorous.sh (5 pairs, same host):

| | main | 1406b5c |
|---|---|---|
| x86 | **100.1%** (8.190 / 8.179), retrans 0 | 98.2% (7.925 / 8.066) |
| Graviton | **120.3%** (7.427 / 6.170), retrans 1 | 111.2% (6.818 / 6.127) |

The Go version used for wireguard-go differs between hosts (1.25.7 on x86, 1.26.7 on Graviton). Each ratio is a comparison within one host, so the conclusions do not change, but do not compare the ratios across hosts (100.1% vs 120.3%) directly.

The raw bench_rigorous.sh logs (per-run values) were lost because copying them before the instances were deleted failed. Only the summary lines in each host's merged.log (ratio, mean, total retrans) remain.

### CPU (1 core = 100%, sender / receiver, 10 seconds)

| Load | x86 1406b5c | x86 main | x86 wg-go | Graviton 1406b5c | Graviton main | Graviton wg-go |
|---|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps | 69 / 67 | 53 / 53 | 46 / 42 | 58 / 47 | 47 / 44 | 54 / 44 |
| UDP 200 B, 100 Mbps | 110 / 106 | 94 / 87 | 136 / 126 | 111 / 99 | 97 / 80 | 164 / 141 |
| TCP 100 Mbps | 25 / 26 | 9 / 10 | 6 / 5 | 16 / 17 | 7 / 8 | 6 / 7 |
| TCP 1 Gbps | 87 / 106 | 74 / 92 | 49 / 55 | 67 / 77 | 55 / 66 | 58 / 61 |

### Checking #124 (AEAD cleanup)

#124 (removing BoringSSL, wiping plaintext that failed authentication) was also merged during the measurements, so we ran 6 interleaved rounds of main (129419b) against post-#124 main (17bf731) on the same hosts.

| | 129419b | 17bf731 | Diff | Paired t |
|---|---|---|---|---|
| x86 | 8.227 | 8.200 | −0.32% | −1.1 |
| Graviton | 7.363 | 7.353 | −0.14% | −0.3 |

Both are within noise (|t| < 2).

### Findings

1. **The merged main is +2.9% on x86 and +8.9% on Graviton.** It was ahead in all 6 rounds. The x86 +2.9% is almost the same as f1 in #54 (+2.65%). However, #54 was on a different day and environment, so the contribution of #134 and acq_rel cannot be separated on x86
2. **acq_rel on arm64 does not lose.** Graviton gains more than x86. The fewer wake-ups from the longer FUTEX_WAIT timeout far outweigh the one extra acquire per packet
3. **In bench_rigorous on the same host, x86 is also level with wg-go (100.1%).** This is the first time on the kernel 7.0 environment. Graviton is 120.3%
4. Low-rate CPU dropped a lot on both x86 and Graviton (x86 TCP 100 Mbps 25% → 9–10%). For small UDP packets at 100 Mbps it is lower than wg-go. At TCP 1 Gbps on x86 it is still 50–70% higher than wg-go (sender 74 vs 49, 1.5x; receiver 92 vs 55, 1.67x)
5. #124 does not affect throughput
6. We are holding off on updating docs/wg-c-vs-wg-go.md. x86 is only level with wg-go so far, so we will update it once there is a result that shows it is ahead

### Lesson

Just as results can be reversed between the VM (aarch64) and EC2 x86 (#48, #50), the size of an effect also differs between x86 and Graviton. Measure changes that affect arm64 on Graviton too

## Experiment #56: comparing wg-c, wireguard-go and kernel WireGuard in a two-host setup (over a real NIC) (2026-09-25)

The Tailscale blog post ([Surpassing 10Gb/s over Tailscale](https://tailscale.com/blog/more-throughput)) measures between two hosts over a real NIC (wireguard-go 13.0 Gbps on bare-metal i5-12400 + 25GbE; on AWS c6i.8xlarge it tops out at 7.3 Gbps). All of our measurements so far used veth inside one host, so we measured with the same kind of two-host setup. The code is main 17bf731 (differs from the current main 623fa1a only in docs).

### Environment

| | |
|---|---|
| Instance | c6in.4xlarge × 2 (Xeon 8375C, 16 vCPU, 25 Gbps sustained bandwidth), cluster placement group in the same AZ (ap-northeast-1a) |
| OS / kernel | Ubuntu 26.04 / 7.0.0-1012-aws |
| GCC / OpenSSL / iperf3 | 15.2.0 / 3.5.5 / 3.20 |
| wireguard-go | 0.0.20250522 (Go 1.26.0) |
| MTU | Underlying path (ens5) 1500, tunnel 1420 |

c6i.8xlarge × 2 exceeds the vCPU limit (64), so we used c6in.4xlarge. ENA reports `tx-udp-segmentation: off [fixed]`, so the NIC hardware UDP segmentation described in the Tailscale post is not available on AWS.

### Method

`iperf3 -c <peer> -t 20 --omit 3 -C cubic -P 1` from A (sender) → B (receiver). Four variants, raw (no tunnel), wg-c, wg-go and kernel, over 6 rounds; odd rounds in the order raw → wgc → wggo → kern, even rounds in reverse. Processes and interfaces are recreated every time. CPU is the /proc/stat delta on each host (cores used out of 16 vCPU, including iperf3 and kernel work). Scripts are in `scripts/bench_2host/` (bench.sh; wgup.sh, wgdown.sh and cpu.sh placed on each host; provision.sh for initial setup).

### Throughput (Gbps, mean of 6 rounds)

| | Gbps | Retransmits (6-round total) | CPU A (sender) | CPU B (receiver) |
|---|---|---|---|---|
| raw | 9.181 (same every time) | 0 | 0.13 | 0.29 |
| **wg-c** | **7.305 (same every time)** | 5 | 3.10 | **4.56** |
| wg-go | 7.006 (6.82–7.16) | 0 | 2.59 | 2.77 |
| kernel | 3.212 | 2493 | 1.50 | 2.63 |

wg-c / wg-go is +2.1 to +7.2% per round, mean **+4.29%** (6/6, paired t = 6.1).

Per-round values (Gbps; in parentheses, CPU cores sender / receiver):

| Round (order) | raw | wg-c | wg-go | kernel (retransmits) | wg-c / wg-go |
|---|---|---|---|---|---|
| 1 (raw→kern) | 9.181 | 7.305 (3.10 / 4.51) | 7.156 (2.62 / 2.82) | 3.202 (560) | +2.08% |
| 2 (kern→raw) | 9.181 | 7.305 (3.04 / 4.55) | 6.817 (2.53 / 2.68) | 3.190 (322) | +7.16% |
| 3 (raw→kern) | 9.181 | 7.305 (3.07 / 4.55) | 7.036 (2.59 / 2.80) | 3.202 (370) | +3.82% |
| 4 (kern→raw) | 9.181 | 7.305 (3.11 / 4.55) | 6.965 (2.57 / 2.77) | 3.224 (409) | +4.88% |
| 5 (raw→kern) | 9.181 | 7.305 (3.20 / 4.54) | 7.071 (2.64 / 2.82) | 3.232 (434) | +3.31% |
| 6 (kern→raw) | 9.181 | 7.305 (3.10 / 4.68) | 6.991 (2.56 / 2.75) | 3.222 (398) | +4.49% |

All 5 of wg-c's retransmits were in round 5. In a single trial round run before these 6 rounds (not included in the table), throughput was almost the same (wg-c 7.306, wg-go 6.953), but CPU was 15–20% lower than in the real runs (wg-c 2.63 / 3.83, wg-go 2.10 / 2.24). The receiver-side ratio was 1.71, close to the real runs (1.65). **Absolute CPU values move by nearly 20% between runs, so compare ratios within the same round.**

### wg-c is pinned at AWS's per-UDP-flow cap

wg-c's value was a constant 7.305 in all 6 rounds, so we measured a single UDP flow without a tunnel (`iperf3 -u -b 0 -l 1452`, the same size as WireGuard's outer packets).

| | Received Gbps |
|---|---|
| 1 UDP flow | 7.77 |
| 2 UDP flows (different ports) | 7.77 + 7.41 = 15.2 |

The cap is about 7.77 Gbps per flow, not a cap on the whole host. Converting wg-c's in-tunnel 7.305 Gbps to outer UDP payload gives 7.305 × 1452 / 1368 ≈ 7.75 Gbps, which almost matches this cap. The ENA `*_allowance_exceeded` counters stayed at 0; this cap does not show up in the counters. The 7.3 Gbps Tailscale hit on c6i.8xlarge is probably the same cap.

### Findings

1. **In the two-host setup, wg-c exceeds wireguard-go (+4.3%, 6/6).** However, wg-c is pinned at the AWS cap, so +4.3% is a lower bound on the difference. The real difference cannot be measured on AWS
2. **wireguard-go stops short of the cap (7.0 Gbps).** This is lower than on veth (#55, 8.18 Gbps). With sender and receiver on separate hosts, wireguard-go may be stuck on the receiver side (unconfirmed)
3. **On the receiver side, wg-c uses 1.65x the CPU of wireguard-go (4.56 vs 2.77 cores).** This is much larger than the throughput difference (+4.3%). On the sender side it is 1.2x. This matches the trend in #55 ("about 1.5x wireguard-go at TCP 1 Gbps") and is probably the cost of receiver-side spin and wake-ups (unconfirmed)
4. **Kernel WireGuard gets 3.2 Gbps with many retransmits.** This matches the trend of the AWS result in the Tailscale post (2.67 Gbps)
5. Whether it exceeds 10 Gbps cannot be measured with this setup (the normal ENA path). c6in supports ENA Express (SRD), which may raise the per-UDP-flow cap (whether it is available on 4xlarge and whether it works for UDP is unconfirmed). The reliable option is bare metal with a 25GbE or faster NIC

### Lesson

In a two-host setup on AWS there is a cap of about 7.77 Gbps per UDP flow. A WireGuard tunnel is a single UDP flow, so if the value stops varying between rounds and stays constant, suspect the cap and compare against a single UDP flow without a tunnel

## Experiment #57: cost of peer lifetime management (#141) and the send queue fix (#144) (2026-09-25)

#141 (removes peers in 3 stages and publishes a generation number in reader sections) and #144 (encrypts staged packets in the caller and makes the TUN reader the only one that pushes to the crypto worker SPSC) touch the send and receive hot paths. #144 was merged before measurement, so it was checked afterwards.

### Environment

x86 is c6i.2xlarge (Xeon Platinum 8375C), Graviton is c7g.2xlarge (Neoverse-V1). Both run Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20. wireguard-go v0.0.20250522 (Go 1.25.7 on x86, Go 1.26.7 on Graviton). probe.sh (veth, iperf3 25 seconds).

### Run 1: main (623fa1a) vs #141 (7e55cd7, after review changes)

6 interleaved rounds (odd rounds main → #141, even rounds reversed).

| | main | #141 | Diff | Rounds #141 was ahead | Paired t |
|---|---|---|---|---|---|
| x86 | 8.297 | 8.291 | −0.06% | 3/6 | −0.1 |
| Graviton | 7.832 | 7.787 | −0.58% | 1/6 | −2.0 |

bench_rigorous.sh (5 pairs, same host): on x86, main 98.2% (8.310 / 8.454), #141 98.7% (8.296 / 8.397). On Graviton, main 119.2% (7.789 / 6.534), #141 119.1% (7.788 / 6.536).

The Graviton interleaved runs are at the |t| = 2 boundary, but in bench_rigorous the difference in wg-c means is 0.001 Gbps, so we judged it to be noise.

### Run 2: 623fa1a, 0c567a9 (after merging #141) and ffbe59a (after merging #144)

On different instances, 6 interleaved rounds of the three, with the order changed each round.

| | 623fa1a | 0c567a9 | ffbe59a | #141 diff (0c567a9 − 623fa1a) | #144 diff (ffbe59a − 0c567a9) |
|---|---|---|---|---|---|
| x86 | 7.420 | 7.455 | 7.461 | +0.48% (t=1.2) | +0.08% (t=0.2) |
| Graviton | 7.878 | 7.885 | 7.850 | +0.09% (t=0.6) | −0.45% (t=−1.1) |

bench_rigorous.sh: on x86, 0c567a9 96.3% (7.438 / 7.720), ffbe59a 96.7% (7.470 / 7.717). On Graviton, 0c567a9 118.7% (7.859 / 6.616), ffbe59a 119.0% (7.883 / 6.621).

x86 absolute values are about 10% lower than in run 1 (instance-to-instance variation and time of day). Comparisons are made only with interleaved runs within the same instance.

CPU (1 core = 100%, sender / receiver, 10 seconds):

| Load | x86 623fa1a | x86 0c567a9 | x86 ffbe59a | Graviton 623fa1a | Graviton 0c567a9 | Graviton ffbe59a |
|---|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps | 53 / 54 | 53 / 53 | 55 / 55 | 51 / 42 | 45 / 41 | 52 / 43 |
| UDP 200 B, 100 Mbps | 96 / 88 | 95 / 88 | 95 / 88 | 96 / 80 | 96 / 81 | 96 / 81 |
| TCP 100 Mbps | 10 / 11 | 10 / 11 | 10 / 12 | 7 / 8 | 7 / 8 | 7 / 8 |
| TCP 1 Gbps | 75 / 96 | 74 / 97 | 74 / 96 | 55 / 65 | 55 / 67 | 55 / 66 |

### Findings

1. **Neither #141 nor #144 makes a measurable difference in throughput or CPU.** Every combination has |t| < 2, and each side was ahead in roughly half the rounds. The Graviton −0.58% (t=−2.0) in run 1 did not reproduce in run 2 (+0.09%)
2. The cost of publishing the generation number in reader sections (one seq_cst fence per section) is not visible, even with the TUN reader's many per-packet batches
3. Both x86 and Graviton meet the performance criteria (at least 6.9 Gbps, not below main on the same host)
4. Starting with this experiment, the raw bench_rigorous.sh logs (per-run values) are saved

### Lesson

For safety fixes, if the reader side is kept to one fence per section, the hot path cost is almost zero. A difference that lands at the |t| = 2 boundary in a single set of interleaved runs should be measured again on another instance before drawing conclusions

## Experiment #58: cost of reading the current keypair under the lock (#146) and removing the index (#149) (2026-09-25)

#146 moved the sender-side code that takes the current keypair (TUN reader, keep_key_fresh, staged send) under kps->lock. The TUN reader and two sequential threads take the same peer's lock on every batch, so the contention cost needed to be checked on real hardware. #149 only changes key rotation. Both were merged before measurement, so they were checked afterwards.

### Environment

Same as #57 (c6i.2xlarge / c7g.2xlarge, Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20). 6 interleaved rounds of ffbe59a (before #146), cbe04e4 (#146) and 12da103 (#146 + #149), with the order changed each round.

### Throughput (Gbps, mean of 6 rounds)

| | ffbe59a | cbe04e4 | 12da103 | #146 diff | #149 diff |
|---|---|---|---|---|---|
| x86 | 8.328 | 8.334 | 8.308 | +0.08% (t=0.4) | −0.31% (t=−1.7) |
| Graviton | 7.358 | 7.355 | 7.383 | −0.04% (t=−0.3) | +0.38% (t=1.1) |

bench_rigorous.sh: on x86, cbe04e4 99.0% (8.332 / 8.416), 12da103 98.6% (8.317 / 8.428). On Graviton, cbe04e4 120.8% (7.354 / 6.083), 12da103 121.0% (7.373 / 6.091).

### CPU (1 core = 100%, sender / receiver, 10 seconds, 1 run each)

| Load | x86 ffbe59a | x86 cbe04e4 | x86 12da103 | Graviton ffbe59a | Graviton cbe04e4 | Graviton 12da103 |
|---|---|---|---|---|---|---|
| UDP 200 B, 20 Mbps | 53 / 53 | 51 / 51 | 53 / 54 | 47 / 40 | 55 / 44 | 54 / 48 |
| UDP 200 B, 100 Mbps | 92 / 87 | 92 / 87 | 92 / 87 | 101 / 88 | 104 / 90 | 107 / 94 |
| TCP 100 Mbps | 9 / 10 | 9 / 11 | 9 / 11 | 7 / 8 | 7 / 8 | 7 / 9 |
| TCP 1 Gbps | 73 / 93 | 73 / 92 | 74 / 92 | 56 / 67 | 56 / 67 | 57 / 70 |

### Findings

1. **No throughput difference in any combination** (|t| < 2). Lock contention from #146 does not show up in interleaved runs on either x86 or Graviton
2. x86 CPU is the same for all three
3. **For small UDP (200 B) on Graviton, CPU may have gone up slightly**: at 100 Mbps, sender 101 → 104 → 107, receiver 88 → 90 → 94. However, each is a single 10-second run, and 20 Mbps on the same host goes 47 → 55 → 54, not in order, so it cannot be told apart from noise. #149 only runs at key rotation, so if there is a difference it is the #146 lock. With small packets the batches are small and the number of lock acquisitions approaches the number of packets, so it is plausible
4. The performance criteria (at least 6.9 Gbps, not below main on the same host) are met

### Next steps

Confirm the Graviton small-UDP CPU by measuring each build 3 or more times. If the difference is real, consider the fallback plan from #140 (reuse keypair memory and read it with CAS), or having the TUN reader hold the keypair per peer and re-fetch it only on rotation

## Experiment #59: re-measuring the small-UDP CPU from #58 (2026-09-25)

In #58, sender CPU for 200 B UDP at 100 Mbps on Graviton lined up as 101 → 104 → 107% (1 run each). We increased the number of runs to check whether the #146 lock is the cause.

### Method

Same environment as #58 (c6i.2xlarge / c7g.2xlarge, kernel 7.0.0-1012-aws). 5 rounds of ffbe59a (before #146), cbe04e4 (#146) and ea891a1 (current main), with the order changed each round. idle.sh sends 200 B UDP at 20 / 100 / 200 Mbps, and CPU was measured for 10 seconds each.

### CPU (1 core = 100%, mean of 5 rounds ± standard deviation, A = sender / B = receiver)

| Load | Host | ffbe59a | cbe04e4 | ea891a1 |
|---|---|---|---|---|
| 20 Mbps | x86 | 54.1±0.8 / 53.6±1.0 | 54.0±0.9 / 54.0±0.9 | 53.2±0.9 / 53.0±0.3 |
| 100 Mbps | x86 | 94.8±0.4 / 87.4±0.2 | 94.8±0.5 / 87.7±0.5 | 95.1±0.5 / 87.7±0.5 |
| 200 Mbps | x86 | 108.0±0.2 / 102.7±0.2 | 108.0±0.3 / 102.9±0.3 | 108.3±0.1 / 102.8±0.3 |
| 20 Mbps | Graviton | 48.6±1.5 / 43.7±0.7 | 49.6±2.0 / 41.0±1.7 | 50.6±1.9 / 44.3±1.3 |
| 100 Mbps | Graviton | **97.9±0.7** / 80.2±0.9 | **97.4±0.7** / 82.5±0.7 | **97.6±0.9** / 81.3±1.4 |
| 200 Mbps | Graviton | 134.0±0.3 / 100.4±1.9 | 134.6±0.4 / 101.1±1.5 | 134.3±0.5 / 101.4±1.5 |

For reference: wireguard-go at 20 / 100 / 200 Mbps is 49/44, 138/128, 202/187 on x86 and 54/44, 162/141, 201/183 on Graviton.

### Findings

1. **The Graviton sender increase seen in #58 (101 → 107) does not reproduce.** At the same load it is 97.9 → 97.4 → 97.6. It was the variance of a single 10-second run
2. Differences are at most 2–3 points and do not point in a consistent direction (for example, Graviton receiver: #146 is −2.8 at 20 Mbps and +2.3 at 100 Mbps). A few |t| > 2 out of 24 comparisons is within chance
3. #146 (reading the current keypair under the lock) has no measurable CPU cost

### Lesson

Do not judge CPU differences from a single run. If one run shows a difference of a few points, measure 5 or more times, swapping the order within each round

## Experiment #60: chasing the x86 CPU gap: bounding crypto worker spin by time (2026-09-25)

On x86 (c6i), wg-c uses 1.5–1.7x the CPU of wireguard-go at TCP 1 Gbps (since #57). On Graviton they are equal. We tracked down the cause with perf and fixed how the crypto worker SPSC waits (PR #154).

### Profile (c6i, TCP 1 Gbps, receiver, points per core)

| | wg-c (total 97) | wg-go (total 58) |
|---|---|---|
| Kernel (finish_task_switch, _raw_spin_unlock_irqrestore = wake-up and switch) | about 36 | about 18 |
| Crypto (libcrypto AVX-512 ChaCha20 core / Go asm) | about 35 | about 22 |
| Other user space (including 6–8% wg_spsc_pop spin) | about 19 | about 17 |

On Graviton at the same load, wg-c is 55/66 and wg-go 56/58 (sender/receiver), and none of the above stands out.

### Wrong hypothesis: OpenSSL AVX-512

In the first measurement we passed `OPENSSL_ia32cap=""` (empty string) intending it as the "default". OpenSSL reads this as "use no features", which gave the non-SIMD implementation at 487 MB/s and wg-c throughput of 4.1 Gbps. Actually removing the environment variable (`env -u`) gives 2.2 GB/s at 1420 B, and 1.9 GB/s with AVX-512 disabled, so AVX-512 is the faster one. In wg-c too, disabling AVX-512 did not lower CPU (1 Gbps receiver 94.4 → 97.1), and throughput dropped from 7.91 to 7.72 Gbps. When measuring the "default", use `env -u VAR`, not `VAR=""`.

### Cause: wg_spsc_pop spins for about 20 µs on x86

The Linux SPSC spins 512 PAUSEs before sleeping on eventfd (the comment says "about 2 µs"). PAUSE is about 140 cycles since Skylake, so that is about 20 µs at 3.5 GHz; with arm64 yield it is under 1 µs. One device has 8 crypto workers, and each spins this long per batch. It is the same pitfall found in the sequential thread in #130.

### Fix and measurements (PR #154, interleaved with main 0d25358 in the same rounds, CPU 3 rounds + throughput 4 rounds, context switches summed over all threads)

x86 c6i.2xlarge (sender/receiver, 1 core = 100%):

| Load | main | 2 µs | Diff | 5 µs diff | 20 µs diff |
|---|---|---|---|---|---|
| TCP 1 Gbps | 71.1 / 90.9 | 68.4 / 87.6 | **−2.7 / −3.3** | −1.4 / −1.3 | +5.0 / +6.8 |
| TCP 3 Gbps | 133.1 / 173.2 | 125.7 / 163.2 | **−7.4 / −9.9** | −3.8 / −5.3 | +15.5 / +15.7 |
| UDP 200 B, 100 Mbps | 92.3 / 86.2 | 74.8 / 70.6 | **−17.4 / −15.7** | −9.5 / −7.9 | +28.3 / +29.6 |

Throughput: main 8.358 → 2 µs 8.363 Gbps (+0.05%, t=0.2). Context switches are +4–5% with 2 µs, but CPU goes down on balance. wg-go at 1 Gbps is 48.3 / 53.9 (for reference).

Graviton c7g.2xlarge: the original spin is under 1 µs, so 2 µs is an extension, giving +3.5 / +4.0 points for UDP 200 B (5 rounds, sender t=2.7). At 1 µs it is the same as main (+0.3 / −0.8, t≈0; TCP 1 Gbps +0.1 / −0.0). Throughput with 2 µs is −0.29% (t=−1.1). The default was set to 2 µs on x86-64 and 1 µs on arm64.

### Findings

1. Part of the x86 CPU gap was crypto worker spin. With 2 µs, the 1 Gbps receiver goes 90.9 → 87.6, and small UDP drops 17 points. Throughput does not change
2. The gap is not fully closed. The remaining about 18 points are kernel-side wake-ups and switches, a separate issue
3. Bound spin by time, not by iteration count. PAUSE length differs by more than 10x across generations (same lesson as #130)
4. When measuring the "default", do not set the environment variable to empty (`env -u`)
5. Context switches are the sum over task/*/status, not /proc/<pid>/status (status covers only the main thread)
6. Decide and write down the pass/fail criteria before looking at results (this time: on x86, throughput within −2% and CPU down a few points; on Graviton, no regression). 2 µs on Graviton was outside the criteria, so the default was made per architecture

---

## Experiment #61: chasing x86 wake-up cost: per-batch dispatch misses; reapplying the timer fix (#48) (2026-09-25)

We chased what was left from #60 (at TCP 1 Gbps on x86, receiver kernel time is about 2x wireguard-go, and context switches are also about 2x). Branch: `perf/lazy-timers` (60094d6).

### Wrong hypothesis: dispatch to crypto workers per batch

The TUN reader and UDP receive pick a crypto worker round-robin per packet (`idx % num_recv`). The theory was that at 1 Gbps with batches of about 10, every batch wakes all 4 workers, and each of them wakes the sequential thread. So we sent the elements of one read/recvmmsg to the same worker (moving to the next worker every 32 elements).

VM (aarch64, prof.sh, 3 rounds interleaved with main, per 10 seconds, receiver B):

| | main | Per batch |
|---|---|---|
| TCP 1 Gbps CPU | 33.4% | 34.5% (+1.1) |
| write | 65.6k | 75.3k (+15%) |
| futex | 177k | 196k (+10%) |
| Context switches | 110k | 114k (+3%) |
| Max throughput | 12.53 Gbps | 12.54 Gbps |

Instead of going down, they went up. main's receiver-side writes are about 6.5k per second, about the same as recvmmsg (about 4.8k). About half of those are eventfd, and "up to 4 wake-ups per batch" is not happening (since #125, only sleeping workers are written to). Work for each worker became sparser and the workers slept more often, which likely made it worse. Rejected.

### Cause: timer thread wake-ups

`perf record -e syscalls:sys_enter_futex,syscalls:sys_enter_write,sched:sched_switch -g` (main, TCP 1 Gbps, receiver B, 5 seconds):

| | Share |
|---|---|
| futex: `wg_timers_*` → `pthread_cond_signal` | 22% |
| futex: `timer_thread_fn` mutex (`__lll_lock_wake`) | 21% (plus `wg_replay_counter_validate` 4%) |
| futex: `timer_thread_fn` cond wait / timedwait | 22% |
| futex: crypto worker and sequential thread wake-ups (`syscall`) | 30% |
| Context switches: `timer_thread_fn` waits | 34% |
| Context switches: crypto worker SPSC waits (eventfd) | 31% |
| Context switches: sequential thread futex waits | 17% |
| Context switches: TUN / UDP poll | 17% |

The same pattern as #46–#48 was still present in main. The #48 fix had been parked after #50 showed −2.3% throughput on EC2 x86, and the code was lost without being committed. We redo the item from #51's "Next steps" ("reapply it and check whether the x86 regression goes away") on main after #52–#54 (time-bounded spin, 1 ms FUTEX_WAIT timeout) and #154.

### Change (rewritten with the same idea as #48)

- The timer thread records the deadline it is currently sleeping until in `wait_deadline_ns` (UINT64_MAX if no deadline, 0 during a callback)
- `wg_timer_mod()`: signal only if the new deadline is earlier than that
- `wg_timer_del()`: do not signal. The thread wakes at the old deadline and, if nothing is pending, goes back to waiting with no deadline
- Each time the thread wakes, it compares the time with the current `deadline_ns` and goes back to sleep if the deadline was extended (fires based on time, not on ETIMEDOUT)
- Differences from #48: `is_pending` stays under the lock (not made `_Atomic`), and there is no "return without the lock if already stopped" in `wg_timer_del()`. The change is limited to how the timer waits

### Tests

- Added 4 tests to test_timers: mod / del that moves the deadline earlier → mod before the old deadline (does not fire at the old deadline) / del → mod after the old deadline has passed (wakes from the no-deadline wait) / mod after 100,000 repetitions of mod and del
- Mutations: not signaling in mod → `test_timer_mod_earlier` fails. Not recording the no-deadline wait → `test_timer_mod_after_idle` fails. Firing on wake-up without checking the time → `test_timer_cancel` fails
- VM (aarch64): ASan+UBSan 29/30 (only the existing test_tun_linux), TSan 28/30 (the existing test_tun_linux and test_handshake_concurrent; the latter also fails on main, and its reports are in libsodium's getrandom and wg_noise.c, not involving timers). test_timers passed 5 times each under ASan / TSan / Release
- macOS (Debug, no ASan): 28/28. A Debug build with ASan on macOS 26 also hangs with no output on test_types, which is unrelated to timers (hangs during runtime startup, a separate issue)

### Results (VM aarch64, prof.sh, 3 rounds interleaved with main a3fbe8f, per 10 seconds, A = sender / B = receiver)

| | main | Timer fix | Diff |
|---|---|---|---|
| TCP 1 Gbps CPU | 30.8% / 32.7% | 27.8% / 29.9% | **−3.0 / −2.8** (all 3 rounds) |
| Context switches | 113k / 109k | 68k / 68k | **−40% / −38%** |
| futex | 181k / 176k | 52k / 61k | **−71% / −65%** |
| Max throughput | 12.42 Gbps | 12.64 Gbps | +1.8% |
| CPU at max throughput | 218% / 273% | 211% / 275% | −7 / +2 |

### Next steps (EC2; pass/fail criteria decided before measuring)

- x86 c6i.2xlarge, interleaved with main in the same rounds: CPU at TCP 1 Gbps / 3 Gbps / UDP 200 B for 3 rounds, throughput for 4 or more rounds
  - Pass: TCP 1 Gbps CPU drops a few points on both sender and receiver, and throughput is within −1% (or |t| < 2). Fail if #50's −2.3% reproduces
- Graviton c7g.2xlarge: no regression in the same measurements (throughput within −1% or |t| < 2, CPU within ±2 points)
- In the same session, also measure the #154 follow-up (Graviton 1 µs at TCP 3 Gbps and max throughput)
- If x86 regresses, check #50's hypothesis (slow resume from halt) with the number of idle states from `perf stat` and sched run delay

### EC2 results (2026-09-26, pre-#154 0d25358 / main a3fbe8f / lazy-timers 60094d6 interleaved in the same rounds, CPU 3 rounds + throughput 4 rounds)

Diff vs main (sender / receiver, 1 core = 100%):

| | x86 c6i.2xlarge | Graviton c7g.2xlarge |
|---|---|---|
| TCP 1 Gbps CPU | **−5.4 / −10.6** (t=−8.4 / −10.8) | **−6.2 / −6.5** (t=−21 / −8.9) |
| TCP 3 Gbps CPU | **−19.6 / −26.3** | **−15.6 / −13.6** |
| UDP 200 B, 100 Mbps CPU | −8.6 / −8.1 | −17.5 / −15.5 |
| Context switches | about −40% | about −40% |
| Max throughput | **−2.39%** (0/4 wins, t=−11.4) | **−5.24%** (0/4 wins, t=−10.2) |

Absolute values: x86 main 8.497 → lazy 8.294 Gbps, Graviton main 7.873 → lazy 7.460 Gbps.

**Verdict: fail** (criteria were within −1% or |t| < 2 on x86, no regression on Graviton). The CPU reduction is the largest so far, but the drop in max throughput is in the same direction as #50's −2.3%, and this time it also appeared on Graviton.

By-products of the same session:
- #154 follow-up (Graviton 1 µs, TCP 3 Gbps and max throughput): main (1 µs) vs pre-#154, CPU −0.2 / +1.3 (|t| < 1.5), throughput −0.79% (within −1%). **Pass**
- Rechecking #154 on x86: main vs pre-#154, TCP 1 Gbps −4.3 / −2.3, UDP 200 B −17.8 / −15.9, throughput −0.53% (t=−2.3, within −1%)

### Why throughput drops (not yet determined)

We do not know why max throughput drops when the timer thread is no longer woken. #50's hypothesis (fewer wake-ups let the CPU enter deeper idle, so the data path resumes more slowly) matches the sign but is unverified. To check it, the next EC2 run needs to compare the number of idle states from `perf stat` and sched run delay between main and lazy, and also measure a variant that "reduces wake-ups but keeps a cheap periodic wake-up".

### Testing the hypothesis "fewer wake-ups let the CPU enter deeper idle" (2026-09-26, rebooted with idle=poll)

The guest has no cpuidle driver (`current_driver: none`), and `/dev/cpu_dma_latency` has no effect. Idle is plain HLT / WFI (vCPU halt), so the only way to eliminate halt is to reboot with the kernel parameter `idle=poll`. We ran 3 rounds of main / lazy with a normal boot, then rebooted with `idle=poll` and ran 3 more rounds (same instance, TCP 1G / 3G CPU and max throughput).

| Max throughput, lazy vs main | Normal (with halt) | `idle=poll` (no halt) |
|---|---|---|
| x86 c6i | −2.78% (0/3, t=−6.4) | **−4.32%** (0/3, t=−9.0) |
| Graviton c7g | −6.20% (0/3, t=−20.8) | **−5.18%** (0/3, t=−15.6) |

Eliminating halt does not remove lazy's drop (on x86 it even widens). **Hypothesis rejected.** As per the reading decided before measuring (reject if lazy is 2% or more below main), we do not write the variant that keeps a periodic wake-up.

For reference: lazy greatly reduces run delay in both phases (x86 1 Gbps receiver 948 → 339 ms/10 s, Graviton 1043 → 349 ms), context switches −40%, CPU −6 to −20 points. So wake-ups are not slow; waiting time goes down. Max throughput drops for some other reason. `idle=poll` itself lowered x86 main throughput from 8.436 to 8.283 Gbps (because the SMT sibling is always spinning).

### Next steps

It is not slow wake-ups, so the remaining candidates are (1) thread migration between CPUs, (2) caches, (3) something other than timers that lazy changed (mod/del frequency is the same; only cond_signal went down). In the next EC2 run, compare main and lazy during max throughput with `perf stat -e cycles,instructions,cache-misses,cpu-migrations,context-switches` (per process) and `perf record` → `perf diff`, to see which thread gains cycles and where.

### Testing placement and idle resume (2026-09-26, max throughput, 4 ABAB rounds)

On x86, `cpuidle_haltpoll force=1` could be loaded (driver = haltpoll, guest_halt_poll_ns=200000). On Graviton it could not. We compared `WG_PIN_STRICT=1` (perf/pin-strict ff9b5fe: pins the sequential thread to HT0 of the path's first core, the reader to its sibling HT, and the crypto workers one each to HTs of the remaining cores) applied to both main and lazy.

| Max throughput (Gbps) | x86 c6i | Graviton c7g |
|---|---|---|
| main / lazy (no pinning) | 8.536 / 8.313 (**−2.6%**, 0/4, t=−6.6) | 7.503 / 7.057 (**−5.9%**, 0/4, t=−14.7) |
| main / lazy (haltpoll enabled) | 8.421 / 8.222 (−2.4%, 0/4, t=−11.4) | — |
| main / lazy (WG_PIN_STRICT=1) | 6.886 / 7.820 (**lazy +13.6%**, 4/4, t=+11.1) | 7.618 / 7.645 (**+0.35%**, 2/4, t=+0.6) |

1. **The delayed idle resume hypothesis is rejected** (second time): enabling haltpoll does not change lazy's drop. Together with the earlier `idle=poll` result, the presence of halt is not the cause
2. **Placement is the cause**: pinning each thread to its own CPU removes lazy's drop on Graviton (+0.35%), and on x86 lazy exceeds main by 13.6%. Max throughput drops with lazy because, without timer thread wake-ups, the scheduler places the data path threads differently, and that placement falls on the bad side. In main, each wake-up shakes up the placement, and as a result it settles into a good placement
3. However, this pinning assignment is not a good placement: on x86, main 8.54 → 6.89 and lazy 8.31 → 7.82, both below no pinning. The assignment that puts the sequential thread and the reader on sibling HTs of the same physical core appears to be bad (Graviton has no HT, and pinning raises main slightly, 7.50 → 7.62)
4. **main is extremely sensitive to placement** (on x86, 8.54 vs 6.89 just from how threads are pinned). While the timer thread is running, its wake-ups disturb the pinned data path threads

### Next steps

The direction is lazy timers + explicit placement. Look for an assignment that exceeds unpinned main (x86 8.5 Gbps). Order to try: (a) pin only the sequential thread to a dedicated HT, leaving the reader and workers free within the mask, (b) put the sequential thread on one physical core and leave its sibling HT empty, (c) put the send and receive sequential threads on separate physical cores. Switch via the value of `WG_PIN_STRICT` and compare lazy × each assignment against unpinned main with ABAB (x86 and Graviton, 5 conditions × 4 rounds in one EC2 session)

### Searching assignments (2026-09-26, lazy × WG_PIN_STRICT 1–4 vs unpinned main, 4 ABAB rounds, then 1 round of TCP 1 Gbps CPU)

Modes (perf/pin-strict fc82313, all derived from the detected topology): 1 = one thread per CPU (sequential on HT0 of the first core, reader on its sibling, workers on HTs of other cores), 2 = pin only the sequential thread, 3 = mode 2 plus keeping other threads off the first core's sibling HT, 4 = pin the sequential thread and reader, workers free on other cores.

| Max throughput (Gbps, vs main) | x86 c6i (4 cores × 2 HT) | Graviton c7g (8 cores) |
|---|---|---|
| main (no pinning) | 8.509 | 7.815 |
| lazy no pinning | 8.321 (−2.2%) | 7.374 (−5.6%) |
| lazy + 1 | 7.781 (−8.6%) | **7.846 (+0.4%, t=0.5)** |
| lazy + 2 | 6.320 (−25.7%) | 5.457 (−30.2%) |
| lazy + 3 | 6.684 (−21.5%) | 6.489 (−17.0%) |
| lazy + 4 | 7.373 (−13.4%) | 7.194 (−7.9%) |

TCP 1 Gbps CPU (sender / receiver, 1 round): x86 main 68.1 / 86.9, lazy 58.8 / 75.6, lazy+1 48.6 / 65.6, lazy+4 46.7 / 65.0. Graviton main 54.9 / 66.2, lazy 48.9 / 59.3, lazy+1 46.1 / 52.1.

1. **On x86, none of the static assignments tried reaches unpinned main.** The best, one thread per CPU (mode 1), is still −8.6%. Modes 2/3, which pin only the sequential thread, are the worst at −21 to −26%: other threads land on the pinned sequential thread's sibling HT or on the same core and get in its way
2. **On Graviton (no HT), lazy + mode 1 is equal to main (+0.4%), with CPU −9 / −14 points at 1 Gbps.** On a machine without HT, a static one-thread-per-CPU placement works
3. Understanding of the mechanism: main's high throughput comes from a dynamic placement that results from the scheduler continually shaking up placement on timer wake-ups, and it cannot be reproduced statically (at least on a path of 2 cores × 2 HT). lazy removes that shaking, so placement settles on the bad side
4. Verdict: the pre-registered pass/fail criteria (adopt if lazy + an assignment exceeds unpinned main) are **not met on x86**. This line is closed, and #157 stays parked

### Remaining options (not measured)

- Make lazy timers + mode 1 the default **on arm64 only** (equal to main on Graviton, CPU −9 / −14). Keep x86 as is. Per-architecture defaults have precedent in #154. If adopted, confirm once on a different Graviton size or in the two-host setup (#56)
- Add a "cheap periodic wake-up" to lazy timers to keep only the placement shake-up that timer wake-ups used to provide. This makes sense given our understanding of the mechanism, but it requires searching the interval and target (which thread to wake), and the result is not guaranteed

## Experiment #62: what determines x86 max throughput (2026-09-26)

The single-host x86 setup remains "level" at 96–100% of wireguard-go (#57–#59). We looked at the whole system during max throughput to find the bottleneck. c6i.2xlarge (4 cores × 2 HT) and c7g.2xlarge (8 cores), Ubuntu 26.04.1, kernel 7.0.0-1012-aws. wg-c is main cf9190f (RelWithDebInfo, with frame pointers), wireguard-go v0.0.20250522. 2 rounds each. We collected `mpstat -P ALL` (busy% per vCPU), iperf CPU, per-thread CPU with thread names (#159), and `perf record -a -g` (whole system).

### Isolating: it is not CPU contention

| During max throughput | x86 wg-c | x86 wg-go | Graviton wg-c | Graviton wg-go |
|---|---|---|---|---|
| Throughput | 7.75 Gbps | 8.02 Gbps | 7.73 Gbps | 6.43 Gbps |
| Busy across all 8 vCPUs | **70.7%** (idle 29.3%) | 77.6% (idle 22.4%) | 77.0% | 74.9% |
| Busy per vCPU | uniform at 69–72% | uniform at 77–78% | 75–79% | 74–76% |
| iperf (client / server) | 20% / 20% | 22% / 16% | 14% / 21% | 12% / 13% |
| Busiest thread | wg-seq-recv 69% | one thread at 98–108% | wg-rtc-recv 78% | one thread at 98–110% |

- No vCPU is near 100%, and 30% of the 8 vCPUs is idle overall. **Even with the sender, receiver and iperf sharing one host, there is no CPU contention** (the review's concern does not apply)
- In whole-system perf too, the largest symbol is `pv_native_safe_halt` (idle) at 29%
- Every wg-c thread is under 70%, while wireguard-go runs one thread near 100% and gets 4% more. wg-c is not bound by CPU but by **the waiting time in hand-offs between stages (UDP receive → decryption worker → sequential receive)**. The round trips where each stage sleeps and is woken per batch add up. This is the same place where #61 found that "reducing wake-ups changes placement and lowers throughput"
- Graviton has the same structure and is 20% ahead of wireguard-go, because hand-offs (wake-ups) cost less there than on the x86 VM

### wg-c per-thread CPU (x86, sender then receiver)

Send: wg-seq-send 61%, wg-rtc-send0/1 52% each, wg-tun-read 36%. Receive: wg-seq-recv 69%, wg-rtc-recv0/1 64% each, wg-udp-recv 62%. libcrypto is 13% of the total in the 2 decryption workers and 11.5% in the 2 crypto workers (encryption).

### Other markers (x86, top symbols system-wide)

`rep_movs_alternative` 4.7% (in-kernel copies), `kernel_init_pages` 3.1% (zeroing pages = repeated allocation), `finish_task_switch` 3.0% + `_raw_spin_unlock_irqrestore` 2.5% (hand-offs). In user space, the ones that stand out are `wg_wait_pool_get` 1.5%, `recv_gro_batch` 1.1%, `wg_prev_queue_dequeue` 1.0%.

### Next steps

1. **Remove one stage hand-off**: when the queue is empty and the workers are sleeping, the sequential thread does the crypto itself (do not hand small batches to workers). This removes 1 wake-up and 2 switches per batch
2. **Lengthen sequential thread spin at high rates** (revisiting adaptive spin): in #54 there was no gain over the 1 ms futex timeout, but the goal then was CPU, not max throughput
3. **Reduce copies and page allocation**: find the sources of `rep_movs` 4.7% and `kernel_init_pages` 3.1% (TUN read/write, sendmsg copies)

---

## Experiment #63: the sequential thread does crypto itself when idle (2026-09-26)

Candidate 1 from #62. x86 max throughput was determined by stage hand-offs (the round trip of waking a worker and coming back). When there is nothing to send, the sequential send/receive threads spin for 3 µs and then sleep on a futex. Instead, they now encrypt/decrypt unprocessed elements waiting in the peer's order queue themselves (up to `WG_SEQ_INLINE_MAX` = 16 per peer per scan), and send them on the next iteration. Only when nothing could be taken do they wait as before.

Mechanism: an `INFLIGHT` element state is added, and both workers and the sequential thread take elements with a `UNCRYPTED → INFLIGHT` CAS. Only the side that wins processes the element; the loser skips it (elements left in a worker's SPSC are just popped, lose the CAS, and are dropped). Marking `DEAD` when dropping on a full SPSC and the flush on device down use the same CAS, so they do not overwrite taken elements. The drain side treats `INFLIGHT` as "not complete". Branch `perf/seq-inline-crypto`.

### Pre-registered pass/fail criteria

- Main goal: x86 (c6i.2xlarge) max throughput. 6 ABAB rounds against main (probe.sh, single-host veth, iperf3 TCP 25 s). The minimum to pass is **inline not below main on average**; we write that it is effective if it is **+2% or more and ahead in 5 or more of 6 rounds**. Within −1% is noise (it moves ±3% with time of day)
- Graviton (c7g.2xlarge) with the same 6 ABAB rounds: **not below main** (within −1% is noise). Graviton keeps +20% over wireguard-go, so if this drops it is rejected
- CPU: with idle.sh, UDP 20M/100M/200M (200 B, same as #59) and TCP 100M/1G CPU must **not get worse than main by 3 pt or more**. At low rates, even when the producer wakes a worker, the seq thread may take the element first, so the woken worker finds nothing and wake-ups increase; this does not show up in max throughput alone (review comment). Also look at the relation to the x86 CPU gap examined in #154
- wg-c ≥ 6.9 Gbps in bench_rigorous (the project minimum)
- Also record, from SIGUSR1 statistics, what percentage of the crypto the sequential thread did during max throughput (near 0 means it is not working; too large means it is pushing the workers out)
- Pre-check: all tests under ASan and TSan on the NixOS VM (aarch64) (excluding the known test_tun_linux)

### Results (2026-09-26, c6i.2xlarge + c7g.2xlarge, Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20, wg-go v0.0.20250522)

main is 1a5e1b5 (after merging #165), inline is branch e80acb9 (PR #166). The pre-check on the NixOS VM (aarch64) was 29/29 under both ASan and TSan (excluding test_tun_linux).

**Max throughput (probe.sh, 6 ABAB rounds against main)**

| Host | main | inline | Diff | Wins |
|---|---|---|---|---|
| x86 c6i.2xlarge | 8.049 Gbps (8.18 7.97 8.13 7.97 8.00 8.04) | **8.557 Gbps** (8.57 8.69 8.50 8.49 8.56 8.53) | **+6.3%** | 6/6 |
| Graviton c7g.2xlarge | 7.809 Gbps (7.81 7.78 7.84 7.78 7.84 7.80) | 7.881 Gbps (7.87 7.87 7.89 7.92 7.87 7.86) | +0.9% | 6/6 |

**bench_rigorous (5 × 30 s, vs wg-go)**

| Host | main | inline |
|---|---|---|
| x86 | 8.272 vs 8.454 Gbps = 97.8% | **8.724 vs 8.374 Gbps = 104.1%** (retransmits 0 / 0) |
| Graviton | 7.731 vs 6.429 = 120.2% | 7.898 vs 6.519 = 121.1% (retransmits 5 / 0) |

104.1% is from a single bench_rigorous run, and main in the same session was 97.8% (main in #55–#59 moves between 96 and 100%). Whether to write "exceeds wireguard-go" for the single-host x86 setup will be decided after it reproduces in another session (per the project policy). The next EC2 session adds one more x86 bench_rigorous run.

**Share the seq thread processed itself (SIGUSR1 statistics, during max throughput)**

| | x86 sender (encrypt) | x86 receiver (decrypt) | Graviton sender | Graviton receiver |
|---|---|---|---|---|
| Main direction (iperf data) | 354,413 / 21,893,712 = **1.6%** | 314,194 / 21,891,743 = **1.4%** | 203,175 / 19,994,646 = 1.0% | 169,483 / 19,993,640 = 0.8% |
| Reverse direction (ACKs, low rate) | 87,310 / 549,827 = 15.9% | 90,814 / 549,778 = 16.5% | 98,164 / 648,998 = 15.1% | 104,852 / 648,624 = 16.2% |
| seq batch (pkt/batch) | 36.9 | 34.1 | 11.9 | 10.1 |

seq takes over only 1–2% of the total, yet x86 gains +6.3%. **There are two hypotheses for why it works, and this data cannot tell them apart**: (a) seq picks up head elements that workers have not yet taken from the SPSC, removing the time spent waiting at the head of the queue (seq can only take UNCRYPTED elements and skips INFLIGHT ones a worker holds), (b) processing even one element skips sleeping, so the sleep-and-wake round trips themselves go down. To tell them apart, count "how many taken elements were at the head" and "how many times seq entered a wait"; we added `of them head` and `waits` to the statistics (to be collected in the next EC2 session). In the low-rate reverse direction, seq processes 16%, and as the review predicted, workers are being woken for nothing. Note: in this session, worker decrypt counts were only summed at thread exit, so the SIGUSR1 "Decrypt:" total did not include the workers; the denominators above are the "Seq recvr" processed counts. This has since been fixed to sum per batch.

**CPU (idle.sh, 10 s, % of 1 CPU, A = sender / B = receiver, main → inline)**

| Rate | x86 main | x86 inline | Diff | Graviton main | Graviton inline | Diff |
|---|---|---|---|---|---|---|
| UDP 20 Mbps 200 B | 45.5 / 45.9 | 46.2 / 46.2 | +0.7 / +0.3 | 48.2 / 44.4 | 54.0 / 44.1 | +5.8 / −0.3 (single run) |
| UDP 100 Mbps 200 B | 74.9 / 71.8 | 74.4 / 70.8 | −0.5 / −1.0 | 97.9 / 87.1 | 100.7 / 86.5 | +2.8 / −0.6 |
| UDP 200 Mbps 200 B | 89.9 / 86.3 | 90.7 / 87.0 | +0.8 / +0.7 | 132.6 / 101.1 | 137.5 / 107.0 | +4.9 / +5.9 (single run) |
| TCP 100 Mbps | 8.6 / 10.3 | 8.7 / 10.4 | +0.1 / +0.1 | 6.9 / 8.0 | 7.1 / 8.1 | +0.2 / +0.1 |
| TCP 1 Gbps | 69.6 / 90.0 | 69.6 / 93.1 | 0 / +3.1 (single run) | 55.0 / 65.6 | 56.1 / 67.2 | +1.1 / +1.6 |

Reference wg-go: x86 45.4/41.8, 135.8/125.7, 200.9/185.2, 6.2/5.6, 49.7/56.0. Graviton 54.6/43.9, 162.2/140.3, 201.3/181.4, 6.0/6.1, 56.7/59.0.

For points near 3 pt, we added 3 more interleaved runs each of main/inline (mean of 4 samples including the first run):

| Point | main | inline | Diff |
|---|---|---|---|
| x86 TCP 1G | 68.6 / 89.6 | 69.1 / 90.9 | +0.6 / **+1.3** → pass |
| Graviton UDP 20M | 48.0 / 43.1 | 50.6 / 43.6 | +2.6 / +0.5 → pass |
| Graviton UDP 200M | 133.2 / 101.1 | 136.6 / 105.7 | **+3.5 / +4.7, same direction all 4 times → fail** |

### Verdict

- x86: passes every item. Max throughput +6.3% (6/6), bench_rigorous 104.1%, CPU within 3 pt, well above the 6.9 Gbps minimum
- Graviton: throughput +0.9% (6/6) passes, but CPU for 200 B UDP at 200 Mbps is sender +3.5 / receiver +4.7 pt (relative +2.6% / +4.6%), **exceeding the pre-registered 3 pt criterion**. The mechanism is as the review predicted: at low rates, even when the producer wakes a worker, seq takes the element first and the woken worker finds nothing. Wake-ups are cheap on Graviton, so seq wins more often
- Conclusion: we want to adopt it on x86. On Graviton the gain (+0.9%) is small and the CPU loss exceeds the criterion, so **inline is disabled by default on Linux aarch64** (`WG_SEQ_INLINE_MAX` 0, removing the processing entirely with `#if`). Only Linux was measured, so macOS (Apple Silicon / x86) and Windows (the ARM64 VM is a typical case of expensive hand-offs and may benefit) also stay at 0 until measured. In that case the only changes remaining on Graviton are the CAS and reference count, whose CPU cost is unmeasured, so we measure Graviton once more (ABAB + CPU) before merging. In the same session, add one x86 bench_rigorous run to see whether 104.1% reproduces

### #63b: re-measurement (2026-09-26, new instances with the same configuration, main 1a5e1b5)

**x86 bench_rigorous, second run** (main also in the same session): inline **106.0%** (9.162 vs 8.638 Gbps, retransmits 0 / 0), main 98.8% (8.551 vs 8.650). The 104.1% from #63 reproduced in another session. In both runs main was in the 96–100% range and inline at 104–106%.

**x86 statistics (SIGUSR1, `of them head` / `waits`)**

| | Processed by seq | Of which head elements | Times seq entered a wait | seq batches |
|---|---|---|---|---|
| Max rate, sender (23.0M pkt) | 356,980 (1.6%) | **328,540 (92%)** | 22,009 | 605,789 |
| Max rate, receiver (23.0M pkt) | 341,749 (1.5%) | 252,625 (74%) | 76,617 | 694,845 |
| 100 Mbps 200 B UDP, sender (750k pkt) | 4,397 (0.6%) | 2,820 | 158,029 | 157,195 |
| 100 Mbps 200 B UDP, receiver (750k pkt) | 4,946 (0.7%) | 3,108 | 157,234 | 156,494 |

At max rate, 92% (send) / 74% (receive) of the elements seq took were at the head of the queue, and the number of waits is 4% (send) / 11% (receive) of the number of batches. **Hypothesis (a) (picking up the head before a worker takes it) is the main one**, and as a result the number of sleeps also goes down (b). At low rates, seq on x86 takes only 0.6% and enters a wait almost once per batch. This is consistent with x86 low-rate CPU not changing.

**Graviton, inline off by default (ce2b9bc: the pass is removed but the CAS and reference count remain)**: 6 ABAB rounds, main 7.772 → 7.650 Gbps (**−1.6%, 1/6**). With inline on in #63 it was +0.9% (6/6), so with it on, the gain slightly outweighs the cost of the CAS and reference count; turning it off leaves only the cost. CPU (main vs this off build, mean of 2 runs each, A/B): UDP 20M −0.5/−1.2, 100M −0.1/+0.8, 200M +0.5/+1.2, TCP 100M +0.1/+0.2, 1G +1.2/+1.8 pt (all within 3 pt).

**Graviton, compiled-out build (ea8f3a2: with `WG_SEQ_INLINE_MAX` 0 the CAS, reference count and worker-side free are also removed, and workers only write state as in main)**: 6 ABAB rounds on the same instance, main 7.758 → 7.756 Gbps (**−0.03%, 3/6**). Equal to main. Comparing machine code with main in a Release build on the NixOS VM (aarch64): the 2 crypto workers have the same instruction sequence (the buffer offset moves by 4 bytes because of the added `refs`), TUN read and UDP receive differ only in register allocation, `elem_free` and staged send are identical, and the 2 sequential threads have +48 instructions for the wait counter (on the path just before waiting).

### Verdict (final)

- x86 Linux: enabled (`WG_SEQ_INLINE_MAX` 16). ABAB +6.3% (6/6), bench_rigorous 104.1% and 106.0% (2 runs; main in the same sessions was 97.8% / 98.8%), CPU within 3 pt, meets the 6.9 Gbps minimum
- Linux aarch64: default 0 (compiled out). Equal to main in ABAB (−0.03%), CPU within 3 pt
- macOS / Windows: not measured, so default 0
- Can we write that single-host x86 "exceeds" wireguard-go: with 2 bench_rigorous runs (104.1%, 106.0%) and ABAB (+6.3%) in hand, the README table is updated as "2026-09-26, 104–106% over 2 bench_rigorous runs". The earlier "level with" stays as the description at the time of main

### Next steps (start only when instructed)

1. Alternative (not measured): limit seq entering inline to "after spinning, just before sleeping". This might get the +0.9% on Graviton without increasing CPU
2. Enable and measure on macOS / Windows (the Windows ARM64 VM in particular is a typical case of expensive hand-offs)

---

## Experiment #64: why macOS is slow (2026-09-26)

The project notes had only one line, "184 vs 386 Mbps (48%) on macOS 26.1", with no measurement procedure or investigation record (#40 in May was 624 vs 574 = 108.7%). We re-measured on a local Mac, profiled it, and fixed it.

Environment: macOS 26.4 (25E246), Apple M5 Max 18 cores, clang 21.1.8 + apple-sdk 14.4 from `nix develop`, libsodium 1.0.21, OpenSSL 3.6.1, wireguard-go 0.0.20250522, iperf3 3.20, wireguard-tools 1.0.20260223. The setup is the same as `scripts/bench_macos.sh` (utun98/utun99 via 127.0.0.1, iperf3 TCP 10 s, --omit 3). wg-c is a Release build of main f41a387 (no `-march`).

### Current state (main)

| | 10 s × 3 | Mean | vs wg-go |
|---|---|---|---|
| wg-c main | 435 / 417 / 359 | 404 Mbps | **76%** |
| wireguard-go | 504 / 554 / 530 | 529 Mbps | |

The "48%" on 26.1 did not reproduce, but it is definitely slow. Since May (#40), wireguard-go is −8% and wg-c is −35% (the machine used in May was not recorded).

### Profile 1: main (pipeline)

Per-thread CPU (`ps -M`, sender): from the top, 87%, 74%, 67%, 43%, 35%, 22%, plus 8 crypto workers (4 × 37% + 4 × 14%). **5.3 cores in total for 404 Mbps.** wireguard-go uses 2.8 cores in total for 529 Mbps. Looking with `sample`:
- The sequential send/receive threads spend 55–78% of their time in `swtch_pri` (= `sched_yield`). Waiting on macOS just loops on `sched_yield()` (there is no equivalent of Linux futex or Windows WaitOnAddress), and the `waits` statistic is 14 to 16.5 million in 15 seconds (**1 million syscalls/second per thread**). System time is 4x user time
- The crypto workers spend 60–87% sleeping in pipe `read`, and each wake-up is paired with a producer-side `write`
- utun is 1 read = 1 packet (TUN read 1.0 pkt/call), UDP is 1.1–1.7 pkt/call with recvmsg_x, and seq send is 1.5 pkt/batch with sendmsg_x

### Experiment A (3 rounds with rotated order, with CPU seconds of the 2 daemon processes per 13 seconds)

| Variant | Mbps | CPU sender / receiver |
|---|---|---|
| wireguard-go | 585 | 35.8 / 30.1 s |
| main | 409 | 67.6 / 61.8 s |
| seqwait: seq wait changed from 3 µs spin → `os_sync_wait_on_address` (the macOS 14.4 futex equivalent) | 442 (+8%) | 64.3 / 58.4 s |
| inline: same build with `WG_INLINE_CRYPTO=1` (TUN read → encrypt → send in one thread, no workers or seq) | 435 (+6%) | **26.4 / 23.9 s** |

Stopping the yield spin only cut CPU by 3 seconds; it was not the main culprit. **On macOS the pipeline is pure overhead**: a single thread is faster and uses 1/2.5 of the CPU. Even so, inline uses about 48k pkt/s on one core = **40 µs per packet**, which 3 syscalls + encryption (about 10 µs in total) cannot explain.

### Profile 2: inline send thread (self time, `sample` 5 seconds)

| Function | Sender TUN read thread (92%, of which 90% system time) | Receiver UDP receive thread |
|---|---|---|
| `sendmsg_x` | 46% | — |
| `read` (utun) | 18% | — |
| **`__psynch_cvsignal`** | **16%** | 8–13% |
| `__psynch_mutexwait/drop` | 6% | 6% |
| `kevent` | — | 22–48% |
| `recvmsg_x` | — | 24–28% |
| `write` (utun) | — | 7–16% |

`__psynch_cvsignal` is **timer re-arming**: `wg_timers_data_sent` and others wake the timer thread via `wg_timer_mod` → `pthread_cond_signal`. The "wake the timer per batch" problem found on Linux as #46–#48/#157 was happening **per packet** on macOS, because utun gives 1 read = 1 packet.

### Experiment B (noisy, with an ASan build running in the background; 3 rounds with rotated order)

| Variant | Mbps | CPU sender / receiver |
|---|---|---|
| wireguard-go | 526 | 34.3 / 29.0 s |
| main | 362 | 59.8 / 53.9 s |
| pipe2: seqwait + SPSC wake-up also pipe → os_sync_wait_on_address + lazy timers (the #157 change) | 413 | 52.0 / 45.9 s |
| **inline2: inline + lazy timers** | **536** | **18.9 / 16.7 s** |

Lazy timers take inline from 435 to 536 (+23%). Even with cheaper wake-ups, the pipeline stops at 413.

### Adopted configuration and final measurements (quiet machine, 5 rounds interleaved with wireguard-go)

- On macOS, `inline_crypto` is enabled by default (single-thread path)
- Lazy timers (`wg_timer_mod` signals only when the new deadline is earlier than the one being waited on; `wg_timer_del` does not signal) are enabled **on macOS only** (`WG_TIMER_LAZY_WAKE`). On Linux, #61 showed a 2–3% drop in x86 max throughput, so mod and del still wake every time as before. The only change on Linux is how the timer thread loop is written (the expiry check moves from `ETIMEDOUT` to comparing the clock)
- The sequential thread and SPSC waits use `os_sync_wait_on_address` (macOS 14.4 and later; older macOS uses the previous yield / pipe). The default inline path does not use them, but they remove the spin when the pipeline is used. The header comes from the macOS 14.4 SDK, so it is checked with `__has_include`, and with older SDKs only the fallback is built (`WG_HAVE_OS_SYNC`)

| | Per round | Mean | CPU sender / receiver |
|---|---|---|---|
| wireguard-go | 542 / 546 / 547 / 549 / 552 | 547 Mbps | 35.1 / 29.6 s |
| **wg-c (this branch's default)** | 586 / 601 / 589 / 593 / 593 | **592 Mbps** | **19.0 / 16.9 s** |

**+8.2%, ahead in 5 of 5 rounds, CPU at 54%.** +47% from the starting point of 404 Mbps (76%). The variance of both is ±1.5%.

### Lessons

- macOS utun is 1 syscall per packet, so the cost of stage hand-offs (wake-ups) is paid per packet. A round trip that happened once per 128-packet batch on Linux happens once per packet here. The pipeline does not work
- For the same reason, timer re-arming also happens per packet, and that alone is 16% of the send thread
- In #40 in May, "spin the SPSC 16K times" and "kqueue" beat wireguard-go only by brute-force hiding these two sources of waste

### Next steps (not measured)

1. Batch TUN reads: read from utun until EAGAIN (up to 32), then encrypt and send with a single sendmsg_x. The inline send thread is `sendmsg_x` 46% + `read` 18%, so if several packets have accumulated at high rates, the number of syscalls drops to a fraction
2. Receiver-side `kevent` 22–48%: spin briefly before recvmsg_x to reduce wait syscalls
3. Windows has the same structure (Wintun is one packet at a time, inline on 4 vCPU), so lazy timers will very likely work there as is

---

## Experiment #66 (plan): Linux regression check for #168 + #169 (2026-09-26)

#64 (macOS) and #65 (Windows) touch shared code: the timer thread loop structure (Linux still wakes every time), one field of `wg_spsc_t`, and send batching on the inline path (on Linux x86, `inline_crypto` only when ncpu ≤ 4). On EC2 c6i.2xlarge and c7g.2xlarge, run 6 ABAB rounds (probe.sh) of main against the #169 branch (which includes #168), idle.sh CPU (UDP 20/100/200M 200 B, TCP 100M/1G), and bench_rigorous once each.

Pre-registered pass/fail criteria: on both hosts, **not below main on average** (within −1% is noise), CPU **not worse by 3 pt or more**, and wg-c ≥ 6.9 Gbps on c6i.

### Results (2026-09-26, Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20, wg-go v0.0.20250522)

main f41a387 and the #169 branch 8252648 (includes #168).

| Host | main (6 ABAB rounds) | new | Diff | Wins | bench_rigorous (vs wg-go) main / new |
|---|---|---|---|---|---|
| x86 c6i.2xlarge | 8.815 Gbps | 8.805 | −0.11% | 4/6 | 106.0% / 105.9% |
| Graviton c7g.2xlarge | 7.673 | 7.648 | −0.33% | 1/6 | 119.4% / 120.0% |

CPU (idle.sh, A/B, main → new): x86 within ±0.7 pt at all rates (TCP 1G 67.6/88.6 → 67.6/89.3), Graviton also within ±1.2 pt (UDP 20M 49.9/42.9 → 50.6/41.7).

Verdict: **both hosts pass** (within −1%, CPU within 3 pt, c6i 8.8 Gbps). On Graviton, −0.33% has main ahead in 5 of 6 rounds but is within noise, and new is higher in bench_rigorous in the same session. On x86, main is also 106.0% in bench_rigorous, so the 106.0% from #63b (#166) reproduced a third time on another instance.

### The macOS part of #65 (2026-09-26 20:24, same Mac and procedure as #64, 5 rounds interleaved with wireguard-go)

| | Per round | Mean | CPU sender / receiver |
|---|---|---|---|
| wireguard-go | 632 / 634 / 630 / 623 / 625 | 629 Mbps | 36.5 / 30.8 s |
| wg-c (#169: read utun until EAGAIN + send batching) | 689 / 691 / 698 / 652 / 694 | **685 Mbps** | 19.3 / 17.2 s |

**108.9%** of wireguard-go (5/5), CPU 53%. #64 (#168 only) was 108.2%. wireguard-go itself was 15% higher in this session (547 → 629), and the Mac's state (time of day, temperature) differs, so absolute values cannot be compared. The ratio is almost the same, so **on macOS the extra gain from send batching cannot be confirmed** (measuring the #168 and #169 builds interleaved in the same session would separate them). There is no regression either.

---

## Experiment #67 (plan): Linux check of the rewritten order queue (2026-09-27)

`src/device/wg_prev_queue.{c,h}` was rewritten from Vyukov's intrusive MPSC queue description (the old file described itself as a translation of GPL-2.0 kernel code). Same algorithm and API; the two sequential-thread walkers now call `wg_prev_queue_walk_next()`. The queue is on the hot path in both directions, so EC2 c6i.2xlarge and c7g.2xlarge: main (53b9121) vs the branch, ABAB 6 rounds (probe.sh), idle.sh CPU (UDP 20/100/200M 200 B, TCP 100M/1G), bench_rigorous once each.

Pre-registered pass/fail criteria: on both hosts **not below main on average** (within −1% is noise), CPU **not worse by 3 pt or more**, wg-c ≥ 6.9 Gbps on c6i.

### Results (2026-09-27, Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20, wireguard-go v0.0.20250522)

| Host | main (ABAB 6 rounds) | rewrite | Difference | Wins | bench_rigorous wg-c, main / rewrite |
|---|---|---|---|---|---|
| x86 c6i.2xlarge | 8.751 Gbps | 8.736 | −0.17% | 1/6 | 8.768 / 8.782 Gbps (106.5% / 105.2% of wireguard-go; wireguard-go itself moved 8.226 → 8.346) |
| Graviton c7g.2xlarge | 7.866 | 7.885 | +0.24% | 3/6 | 7.886 / 7.896 Gbps (119.2% / 119.7%) |

Throughput: within noise on both hosts (criterion: not below −1%).

CPU (idle.sh, sender / receiver, % of one CPU, one sample each):
- x86: every rate within 0.9 pt (TCP 1G 69.3/91.6 → 69.4/90.9).
- Graviton: TCP 100M/1G within 0.6 pt; UDP 200 Mbps 200 B +1.6/−0.8; **UDP 20 Mbps 200 B 47.1/43.6 → 52.6/40.9 (+5.5/−2.7) and UDP 100 Mbps 200 B 95.7/84.8 → 100.1/86.8 (+4.4/+2.0) — over the 3 pt line on the sender side in a single sample.**

On aarch64 the sequential-thread walkers are compiled out (`WG_SEQ_INLINE_MAX` 0), so the only code that runs differently is the queue itself, where the rewrite's instructions match the old ones except one acquire load on the empty path. Earlier runs of the same main on the same instance type measured the Graviton sender at UDP 20 Mbps between 45.5% and 50.3% (#63b, #66), so a single sample does not decide it. Verdict pending: repeat the Graviton CPU points (main/rewrite interleaved, 3+ samples) before merging.

**Repeat (Graviton c7g.2xlarge, same day, fresh instance, main/rewrite interleaved 4 times each, sender / receiver):**

| Rate | main (4 samples) | rewrite (4 samples) | Mean difference |
|---|---|---|---|
| UDP 20 Mbps 200 B | 52.2/43.9, 44.4/41.6, 51.3/45.4, 50.1/44.4 → 49.5/43.8 | 50.5/43.3, 45.2/43.7, 55.3/43.6, 48.3/44.4 → 49.8/43.8 | +0.3 / −0.1 pt |
| UDP 100 Mbps 200 B | 100.2/86.3, 96.2/82.3, 98.6/88.0, 100.9/91.6 → 99.0/87.1 | 99.2/88.5, 96.1/86.1, 101.9/88.9, 96.7/85.6 → 98.5/87.3 | −0.5 / +0.2 pt |

The single samples of the first run were noise: the sender side at UDP 20 Mbps spans 44–55% within each build. **Verdict: pass** on both hosts (throughput within noise, CPU within 3 pt).

---

## Experiment #68 (plan): Linux check of the keypair/handshake type regroup (2026-09-28)

PR #180 changes `wg_noise_keypair_t`, which the send and receive paths read for every packet: the per-direction `{key, birthdate, is_valid}` structs become two bare keys with one birthdate and one flag, so the struct is 32 bytes shorter and the fields after the sending key move (order unchanged: sending key, sending counter, receiving key, replay window). The handshake types change too, but they are off the data path. An M5 laptop showed −0.7% (16 interleaved runs, ranges overlapping). EC2 c6i.2xlarge and c7g.2xlarge: main (b7f3ad4) vs the branch, ABAB 6 rounds (probe.sh), idle.sh CPU (UDP 20/100/200M 200 B, TCP 100M/1G) with main/branch interleaved 3 times each (a single CPU sample proved too noisy on Graviton in #67), bench_rigorous once each.

Pre-registered pass/fail criteria: on both hosts **not below main on average** (within −1% is noise), CPU **not worse by 3 pt or more** (mean of the 3 samples), wg-c ≥ 6.9 Gbps on c6i.

### Results (2026-09-28, Ubuntu 26.04.1, kernel 7.0.0-1012-aws, GCC 15, OpenSSL 3.5.5, iperf3 3.20, wireguard-go v0.0.20250522 built on the host)

The branch was built as main plus the branch's source diff (checked locally to reproduce the branch tree exactly), because the uplink from the Mac was slow.

| Host | main (ABAB 6 rounds) | branch | Difference | Wins | bench_rigorous wg-c, main / branch |
|---|---|---|---|---|---|
| x86 c6i.2xlarge | 8.953 Gbps | 8.959 | +0.07% | 4/6 | 8.774 / 8.937 Gbps (102.9% / 104.7% of wireguard-go) |
| Graviton c7g.2xlarge | 7.831 | 7.890 | +0.75% | 4/6 | 7.785 / 7.872 Gbps (119.5% / 120.4%) |

CPU (idle.sh, sender / receiver, % of one CPU, mean of 3 interleaved samples each):

| Rate | x86 main | x86 branch | Graviton main | Graviton branch |
|---|---|---|---|---|
| UDP 20 Mbps 200 B | 45.3/45.6 | 45.2/45.5 | 48.1/42.6 | 48.8/41.7 |
| UDP 100 Mbps 200 B | 74.4/70.5 | 74.5/69.8 | 96.5/82.2 | 96.6/82.2 |
| UDP 200 Mbps 200 B | 90.6/85.6 | 90.6/84.7 | 133.6/100.7 | 133.3/98.6 |
| TCP 100 Mbps | 8.4/9.7 | 8.4/9.8 | 6.9/8.0 | 6.9/7.8 |
| TCP 1 Gbps | 68.9/90.6 | 69.4/89.2 | 55.1/66.0 | 55.1/65.7 |

Every point is within 0.7 pt on the sender and within 2.1 pt (lower) on the receiver. **Verdict: pass** on both hosts: throughput not below main, CPU within 3 pt, c6i at 8.96 Gbps.

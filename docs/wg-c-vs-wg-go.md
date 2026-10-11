# wg-c vs wireguard-go: Technical Comparison and Performance Analysis

**Last updated**: 2026-09-26

> **Note**: The 127.6% Linux figure from #41 (2026-05) did not reproduce on the same instance type with the same code and kernel (performance-analysis.md #45) and is not used as a baseline. The Linux numbers below are the current same-host results (#63, #63b).

wg-c is a full userspace WireGuard implementation in C,
developed with the goal of exceeding wireguard-go (in Go, the official reference implementation) in performance.
This document records the technical differences between the two implementations and the reasons for the performance gap.

---

## Benchmark results summary

### Linux — EC2 c6i.2xlarge (Intel Xeon 8375C, 8 vCPU)

| Implementation | Mean | Retrans | CPU |
|------|------|---------|-----|
| **wg-c** | **8.72 / 9.16 Gbps** | 0 | |
| wireguard-go | 8.37 / 8.64 Gbps | 0 | |
| **Ratio** | **104.1% / 106.0%** (two runs) | | |

Conditions: veth pair on one host, `scripts/bench_rigorous.sh` (iperf3 --omit 3, 30 s × 5), Ubuntu 26.04.1, kernel 7.0.0-1012-aws, wireguard-go v0.0.20250522, kernel WireGuard module blacklisted (2026-09-26, performance-analysis.md #63 and #63b). The same runs measured the previous code at 97.8% / 98.8%.

### macOS — Apple Silicon (local machine)

| Implementation | Mean | CPU (13 s, sender / receiver) |
|------|------|---|
| **wg-c** | **592 Mbps** | 19.0 / 16.9 s |
| wireguard-go 0.0.20250522 | 547 Mbps | 35.1 / 29.6 s |
| **Ratio** | **108.2%** (5 of 5 rounds) | CPU 54% |

Conditions: macOS 26.4, Apple M5 Max, utun + loopback (127.0.0.1), iperf3 --omit 3, 10 s × 5 interleaved rounds (2026-09-26, performance-analysis.md #64).

**wg-c exceeds wireguard-go on both platforms.** On macOS, unlike Linux, the default is the single-thread path (TUN read → encrypt → send in one thread).

---

## Architectural differences

### Pipeline structure

Both implementations have the same basic pipeline:

```
[TUN read] → [encrypt] → [UDP send]   (send path)
[UDP recv] → [decrypt] → [TUN write]  (receive path)
```

| Design element | wg-c (C) | wireguard-go (Go) |
|----------|----------|-------------------|
| Thread model | pthread (1:1) | goroutine (M:N) |
| Queue | Lock-free SPSC ring buffer | Go channel |
| Memory management | Treiber stack pool + posix_memalign(64) | sync.Pool + GC |
| Encryption | OpenSSL EVP (AVX-512/NEON) or libsodium | Go crypto/cipher |
| Packet buffers | Fixed allocation, no GC | GC-managed, runtime overhead |

### Thread layout

**wg-c:**
- TUN read thread × 1
- Crypto worker × N (ncpu/2 - 2, auto-scaling)
- Sequential sender × 1
- Sequential receiver × 1
- UDP recv thread × 1

**wireguard-go:**
- A similar layout based on goroutines
- The Go runtime schedules goroutines with M:N mapping
- Other goroutines can run during a syscall

---

## Linux: why wg-c wins

When these techniques landed (#37), wg-c was at **101.1%** on Linux (6.99 vs. 6.92 Gbps). The gap came from:

### 1. UDP GSO (Generic Segmentation Offload)

The biggest source of improvement (+82%). A `UDP_SEGMENT` cmsg is attached to sendmsg,
passing up to 16 packets to the kernel in one syscall.

```c
// wg-c: sendmsg + UDP_SEGMENT cmsg
struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
cm->cmsg_level = SOL_UDP;
cm->cmsg_type  = UDP_SEGMENT;       // = 103
*(uint16_t *)CMSG_DATA(cm) = seg_size;
sendmsg(fd, &msg, 0);  // scatter-gather iovec, zero-copy
```

wireguard-go uses the same GSO, but building the iovec in Go has runtime overhead.

### 2. UDP GRO (Generic Receive Offload) + recvmmsg batching

On the receive side, the kernel coalesces same-size UDP packets with UDP GRO.
recvmmsg fetches up to 8 messages in one syscall, and the GRO segment size is read from
each message's cmsg to split them.

```
pkt/call: 3.7 → 50+ (GRO 20x coalesce)
```

### 3. CPU affinity + HT-aware topology

Parses `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list` to
identify HyperThreading pairs. The send side and receive side are placed on different physical cores.

```
Core 0 (HT 0,4): sequential_send + crypto_worker_0
Core 1 (HT 1,5): sequential_recv + crypto_worker_1
```

### 4. Adaptive spin + futex

The sequential threads use a two-stage wait: PAUSE × 1024 spin → futex_wait (50µs timeout).
More efficient than eventfd/epoll (-23% regression) or sched_yield.

### 5. Low overhead of C

- No GC → no latency jitter
- Direct function calls (no vtable/interface dispatch)
- Cache-line alignment with posix_memalign(64)
- CPU 14.4% vs. 16.7% for Go

---

## macOS: why wg-c wins

When these techniques landed (#39, 2026-05), wg-c was at **106.8%** on macOS (607 vs. 568 Mbps).
The deciding factors are a private API that Go cannot use, and eliminating pipe overhead.

### 1. sendmsg_x / recvmsg_x (Darwin private syscall)

**This is the biggest differentiator. wireguard-go cannot use it at all.**

macOS (Darwin XNU) has private syscalls called `sendmsg_x`/`recvmsg_x`.
They are the equivalent of Linux `sendmmsg`/`recvmmsg`, batching multiple UDP datagrams in one syscall.

```c
// wg-c: send up to 32 packets in 1 syscall
struct msghdr_x msgs[32];
// ... setup msgs ...
ssize_t sent = sendmsg_x(fd, msgs, count, 0);
```

**Why wireguard-go cannot use it:**
- Go's standard library (`net.UDPConn`) does not expose `sendmsg_x`
- Calling it via cgo breaks the goroutine scheduler (the thread blocks during the syscall and the M:N mapping stops working)
- So wireguard-go forces `BatchSize=1` on macOS:

```go
// wireguard-go/conn/bind_std.go
func (s *StdNetBind) BatchSize() int {
    if runtime.GOOS == "linux" || runtime.GOOS == "android" {
        return IdealBatchSize  // 128
    }
    return 1  // macOS ends up here — no batching
}
```

**Result:** wg-c **cuts UDP syscalls by 47%** (send calls: 236K → 126K).

### 2. SPSC tight spin (eliminating pipe overhead)

pipe(2), used on macOS instead of eventfd, has a fatal problem:

| Feature | Linux eventfd | macOS pipe |
|------|--------------|------------|
| write coalescing | write(1)+write(1) → counter=2, read()→2 | write(8)+write(8) → 2 entries, needs read()×2 |
| syscalls/wake | 1 (read resets the counter) | 2 (read and write map 1:1) |
| overhead/packet | nearly zero (absorbed by spin) | **~500K+ syscalls/sec** |

dtruss profiling showed that **50%+ of all syscalls are pipe read/write**.

**Solution: three-stage consumer wait:**

```
Phase 1: ARM64 yield × 16384 (≈ 16µs) — covers the inter-packet interval
Phase 2: sched_yield × 4 — safety net
Phase 3: pipe block — only when idle (almost never reached during active transfer)
```

The ARM64 `yield` instruction takes ~1ns and does not enter the kernel. Even 16384 of them take 16µs,
fully covering the inter-packet interval (~15µs at 67K pkt/sec).

**Note:** sched_yield × 32 triggered P→E core migration on Apple Silicon and
regressed to 505 Mbps. Reducing it to 4 fixed this.

### 3. Improved batch efficiency

| Metric | Before | After | Improvement |
|------|--------|-------|------|
| Seq sender pkt/batch | 2.8 | 5.7 | 2.0x |
| Seq recvr pkt/batch | 2.7 | 6.2 | 2.3x |
| UDP recv pkt/call | 2.4 | 2.7 | +13% |

---

## Structural limits of macOS

The following Linux features are not available on macOS:

| Feature | Linux | macOS | Impact |
|------|-------|-------|------|
| UDP GSO (UDP_SEGMENT) | 16 segs/syscall | not available | 16x send syscalls |
| UDP GRO | 50+ pkt/recv | not available | no receive coalescing |
| sendmmsg/recvmmsg | 128 pkt/syscall | **sendmsg_x/recvmsg_x** (32 pkt) | only wg-c can use it |
| SO_BUSY_POLL | NAPI polling | not available | receive latency |
| CPU affinity | pthread_setaffinity | not available | thread placement |
| futex | two-stage wait | not available (sched_yield fallback) | synchronization efficiency |
| eventfd | coalescing counter | pipe (non-coalescing) | **the biggest penalty** |
| TUN batch | writev/readv available | 1 pkt/read (utun limit) | cannot be avoided |

**The real bottleneck on macOS is utun's 1 pkt/read.** This is a kernel limit that cannot be avoided, and as a consequence
stage hand-offs (worker wake-ups, timer resets) happen per packet. What #64 found:
the Linux-oriented pipeline is slower than a single thread on macOS and uses 2.5x the CPU, and the timer's
`pthread_cond_signal` alone took 16% of the send thread. Making the single-thread path the default and
not waking the timer on timer resets (lazy) puts wg-c 8% ahead of wg-go at half the CPU.
The replacement for futex is `os_sync_wait_on_address` from macOS 14.4.

---

## Common: essential differences between C and Go

| Property | C (wg-c) | Go (wireguard-go) |
|------|----------|-------------------|
| Private API access | called directly via extern declarations | requires cgo, fits poorly with goroutines |
| Memory layout | posix_memalign, cache-line control | GC-managed, movable |
| Thread control | pthread affinity, futex | goroutine M:N (delegated to the OS) |
| Syscall overhead | direct syscalls | Go runtime wrapper + goroutine parking |
| Encryption | OpenSSL AVX-512 / platform-native | Go crypto (with assembly) |
| GC pause | none | ~µs-ms jitter |

**Go's M:N scheduler has an advantage with high-frequency syscalls on macOS** (other goroutines run during a syscall),
but C comes out ahead with private APIs and direct hardware control.

---

## Outlook

### Room for further macOS optimization

- **Batch TUN reads**: read from utun until EAGAIN, then encrypt and send with a single sendmsg_x (targets `sendmsg_x` 46% + `read` 18% in the send thread)
- Reduce `kevent` on the receive side (22–48%) with a short spin before recvmsg_x
- If the macOS utun limit is lifted, a large improvement can be expected

### Kernel mode (Phase D)

Like wireguard-go, work with the `wireguard.ko` kernel module.
In kernel mode the data path is handled in the kernel,
so userspace overhead is eliminated entirely.
Linux kernel WireGuard is 7.19 Gbps (= the userspace ceiling).

### Windows — Windows 11 ARM64 (Parallels VM, 4 vCPU), Wintun + loopback

| Implementation | Mean | Min | Max |
|------|------|-----|-----|
| **wg-c** | **488 Mbps** | 481 | 497 |
| wireguard-go 0.0.20250522 | 499 Mbps | 487 | 518 |
| **Ratio** | **98% (on par, ranges overlap)** | | |

Conditions: Wintun + UDP loopback (127.0.0.1), iperf3 --omit 3, 10 s × 3 runs (2026-09-26, performance-analysis.md #65). On the same VM, wg-c before the improvements gave 184 Mbps (37%).

Windows was slow for the same structural reason as macOS. Wintun handed over 15.7 packets per read,
but the inline path called `RIOSendEx` one packet at a time (send 1.0 pkt/batch), and RIO receive also handled one completion per call.
In addition, every timer reset woke the timer thread per packet. Three fixes:
1. **Lazy timers** (shared with macOS; Linux not affected) — 184 → 274–376 Mbps
2. **Send batching**: one TUN batch becomes one `bind.send`. RIO queues all but the last with `RIO_MSG_DEFER` and commits once
3. **Batched receive dequeue**: up to 32 completions at once with `RIODequeueCompletion`

The threads run at 55–70% and are not saturated; the rest is waiting time. Remaining room:
- Writes to Wintun are one packet at a time
- Measurement on real x64 hardware (only an ARM64 VM has been measured)

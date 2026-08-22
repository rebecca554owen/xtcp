# Performance

> Language: **English** | [中文](PERFORMANCE_CN.md)

Every number in this document was produced by a command shown here, on the
hardware and software versions listed below, during one session. Raw
outputs were captured and are quoted verbatim in the result tables. Nothing
is projected, averaged across machines, or carried over from older runs.
Chinese version: [PERFORMANCE_CN.md](PERFORMANCE_CN.md).

## 1. Test environments

### Environment A — Windows host (all `bench_*` numbers)

| Item | Value |
|---|---|
| CPU | AMD Ryzen 9 7945HX, 16 cores / 32 threads (Zen 4), base clock 2.5 GHz |
| RAM | 63.2 GB |
| OS | Windows 11 Enterprise, build 26200 |
| Power plan | Vendor performance profile ("Beast mode") |
| Compiler | MSVC 14.39.33519 (Visual Studio 2022 Enterprise) |
| Build system | CMake 3.22.1, build type `Release` |
| Relevant flags | Default (`XTCP_CHECKSUM_VALIDATE` off for throughput benches) |

### Environment B — WSL2 guest (all TUN `interop_*` numbers)

| Item | Value |
|---|---|
| Host | Same physical machine as Environment A |
| Guest OS | Ubuntu 24.04.3 LTS |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| CPU/memory visible to guest | 32 vCPUs / 30 GB (WSL2 VM allocation) |
| Compiler | GCC 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), `-O2` Release |
| TUN device | `/dev/net/tun`, samples executed as root |

### Environment C — QEMU emulation (functional verification only)

aarch64 cross-build with GCC 13 (`aarch64-linux-gnu-g++`), fully static,
executed under `qemu-aarch64` user-mode emulation on the same host. QEMU
single-core emulation distorts wall-clock pacing, so **no performance
numbers are taken from this environment**; it exists to prove the code is
correct on ARM64 (237/237 tests pass there).

## 2. What each benchmark measures

| Benchmark | Measures | Does NOT measure |
|---|---|---|
| `bench_throughput` | One `XtcpStack` pair wired back-to-back through in-memory backends inside one process: TCP processing cost only | NIC, kernel network stack, real network |
| `bench_multi_thread` | N threads injecting segments into N distinct flows of one stack: RX-side concurrency behavior under synthetic load | End-to-end application throughput |
| `bench_syn_rate` | Connection establishment rate (SYN → ESTABLISHED → teardown), single process | Handshake under packet loss |
| `bench_conns` | Cost of sweeping an idle vs recently-active connection table | Memory footprint per connection |
| `interop_perf` | One-way bulk transfer between the kernel and XTCP through a real TUN device | Multi-flow aggregate |
| `interop_latency` | RTT distribution of 2000 sequential 1 KB echo round trips through TUN | First-packet latency, connection setup latency |
| `interop_fair` | Bandwidth share of 4 concurrent flows shaped by `tbf 20mbit` + `netem delay 40ms` on the TUN path | Fairness without shaping |

## 3. Results

### 3.1 Loopback throughput (`bench_throughput`, Environment A)

Command shape: `bench_throughput <total_bytes> <chunk_bytes> <qdisc> <quickack> [cc]`.
Three rounds per configuration; all rounds are shown.

| Configuration | Round 1 | Round 2 | Round 3 | Best | Best kpps |
|---|---|---|---|---|---|
| 64 MB, 1460 B chunks, KCC | 24 624.86 | 24 216.44 | 24 503.81 | **24 624.86** | 3 162.6 |
| 256 MB, 1460 B chunks, KCC | 25 532.07 | 22 212.09 | 25 127.18 | **25 532.07** | 3 279.0 |
| 64 MB, 1460 B chunks, Reno | 23 972.17 | 23 057.91 | 23 055.83 | **23 972.17** | 3 078.7 |
| 128 MB, 65 536 B chunks, KCC | 23 741.69 | 12 096.58 | 19 627.57 | **23 741.69** | 3 124.6 |
| 64 MB, 64 B chunks, KCC | 1 257.63 | 1 129.59 | 1 274.92 | **1 274.92** | 3 731.6 |

Reading these rows:

- The MSS-sized path sustains ~24–25 Gbps in-process on this host. This is
  the stack's own ceiling here: no NIC, no kernel networking involved.
- KCC versus Reno differs by ~2.7 % at this scale; both saturate the same
  loopback path.
- The 65 536-byte-chunk row shows the largest spread (12.1–23.7 Gbps).
  Large writes amplify scheduler noise on a laptop CPU (see §5).
- 64-byte writes are packet-rate bound: ~3.7 Mpps regardless of bandwidth,
  i.e. per-segment fixed cost dominates.

### 3.2 RX worker scaling (`bench_multi_thread`, Environment A)

Each worker injects 200 000 segments into its own flow; workers run
concurrently against one stack.

| Workers | Segments total | Wall time | Aggregate | kpps |
|---|---|---|---|---|
| 1 | 200 000 | 0.017 s | 135.18 Gbps | 11 573.6 |
| 8 | 1 600 000 | 0.189 s | 98.92 Gbps | 8 469.3 |

Eight workers aggregate *below* one worker. This is a measured property of
the current implementation under synthetic injection, not a law: per-worker
flows hash to different shards, so the run exercises cross-shard parallelism
plus shared ingress paths. Treat multi-core claims accordingly (§5).

### 3.3 Connection handling (`bench_syn_rate`, `bench_conns`, Environment A)

```
bench_syn_rate: 200000 conns in 0.353s = 566149 conns/s (completed=200000)
bench_conns:    10000 conns, 2000 rounds, 0.02 us/round, 0.0 ns/conn/round (idle)
bench_conns:    10000 conns, 500 rounds, 3481.35 us/round, 348.1 ns/conn/round (dirty)
```

Idle sweep is O(1) per round (timer-wheel fast path); the dirty sweep pays
per-connection work proportional to active state.

### 3.4 RTT latency over TUN (`interop_latency`, Environment B)

2000 sequential echo round trips, 1 KB payload, kernel client ↔ XTCP server
through `/dev/net/tun`. Two independent executions:

| Run | mean | p50 | p95 | p99 | jitter (σ) | failures |
|---|---|---|---|---|---|---|
| 1 | 205.8 µs | 204.0 µs | 233.5 µs | 266.9 µs | 21.1 µs | 0 |
| 2 | 195.6 µs | 193.6 µs | 219.6 µs | 259.8 µs | 17.2 µs | 0 |

This includes two TUN device crossings and the kernel client's own socket
path per round; it is not a pure stack-latency figure.

### 3.5 Bulk throughput over TUN (`interop_perf`, Environment B)

16 MB one-way transfer, kernel sender ↔ XTCP receiver via TUN:

| Run | XTCP over TUN | Kernel loopback baseline (same command) |
|---|---|---|
| 1 | 1 806.42 Mbps | 30 932.36 Mbps |
| 2 | 1 791.84 Mbps | 21 148.88 Mbps |

The baseline row is the kernel's own loopback throughput printed by the
same sample for calibration. XTCP-over-TUN reaches ~1.8 Gbps and is bound
by the TUN character-device copy path, not by TCP processing: the in-process
number for the same machine is ~25 Gbps (§3.1).

### 3.6 Fairness (`interop_fair`, Environment B)

Four concurrent flows shaped by `tbf 20mbit` + `netem delay 40ms` on the
TUN path, each transferring 2 097 152 bytes:

```
[fairness] flows=4 total_mbps=18.9
flow[0] 4.78 Mbps (25.3%)   flow[1] 4.75 Mbps (25.1%)
flow[2] 4.71 Mbps (24.9%)   flow[3] 4.67 Mbps (24.7%)
Jain index = 0.9999 ; all flows completed
```

## 4. Verification context

Performance means nothing if correctness is conditional, so the gates that
held while these numbers were taken:

- Full deterministic suite: every registered test passes on Windows MSVC
  Release (`ctest`; 237/237 with the optional lwIP differential target,
  236/236 without).
- Same suite, aarch64 static cross-build: 237/237 under `qemu-aarch64`
  (three sequential batches of 80/80/77, zero failures).
- CI on the exact source revision: ASan+UBSan suites green on Linux
  (clang++ and g++) and Windows MSVC.

## 5. Threats to validity

Stated before you cite these numbers anywhere:

1. **Laptop hardware.** Environment A is a mobile Zen 4 part under a vendor
   performance profile. Thermal states move individual rounds by tens of
   percent (visible in §3.1); "best of 3" is reported precisely because of
   that, and every round is published.
2. **In-process loopback is not a network.** `bench_throughput` excludes
   NIC, DMA, kernel stack, and interrupts entirely. It bounds what the
   library itself costs; it does not predict deployed throughput.
3. **WSL2 is virtualized.** TUN numbers include the hypervisor's device
   model. Absolute latencies (§3.4) would differ on bare-metal Linux; the
   *comparison* against the kernel-loopback baseline on the same guest is
   the meaningful part.
4. **Synthetic injection ≠ application load.** §3.2 drives pre-built
   segments at the RX path. Real workloads interleave syscalls, timers, and
   user callbacks.
5. **Single-run fairness/latency samples.** §3.4–3.6 report two runs where
   marked, single runs otherwise. They demonstrate behavior and reproducibility
   at order-of-magnitude level, not statistical rigor.
6. **No DPDK/EFVI backend exists yet**, so line-rate claims beyond the TUN
   path cannot be made at all.

## 6. Reproducing

```bash
# Environment A (Windows, MSVC Release)
cmake -B build -G "Visual Studio 17 2022" -A x64 \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build --config Release
build\Release\bench_throughput.exe 67108864 1460 0 1        # §3.1 row 1
build\Release\bench_multi_thread.exe                        # §3.2
build\Release\bench_syn_rate.exe 200000                     # §3.3
build\Release\bench_conns.exe 10000 2000                    # §3.3 idle
build\Release\bench_conns.exe 10000 500 dirty               # §3.3 dirty

# Environment B (WSL2, root for /dev/net/tun)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DXTCP_BUILD_SAMPLES=ON
cmake --build build -j$(nproc)
sudo ./build/interop_latency     # §3.4
sudo ./build/interop_perf        # §3.5
sudo ./build/interop_fair        # §3.6
```

Raw outputs corresponding to every table above were captured from the runs
this document reports; re-running should land within the published spreads
on comparable hardware.

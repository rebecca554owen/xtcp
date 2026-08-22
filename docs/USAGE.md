# Usage

> Language: **English** | [中文](USAGE_CN.md)

This is the task-oriented guide to using XTCP: building it, wiring a stack
into your process, the full callback and configuration surface, queueing,
and plugins. Concepts and internals live in
[ARCHITECTURE.md](ARCHITECTURE.md); measured numbers live in
[PERFORMANCE.md](PERFORMANCE.md). Chinese version:
[USAGE_CN.md](USAGE_CN.md).

## 1. Building and linking

XTCP builds as a static library (`xtcp_static`) plus optional test,
benchmark, sample, and plugin targets.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build -j$(nproc)          # Windows: cmake --build build --config Release
ctest --test-dir build                  # Windows: ctest --test-dir build -C Release
```

CMake options (defaults from `CMakeLists.txt`):

| Option | Default | Effect |
|---|---|---|
| `XTCP_BUILD_TESTS` | `ON` | The deterministic test suite (236 targets; +1 with `XTCP_BUILD_LWIP`) |
| `XTCP_BUILD_BENCH` | `OFF` | `bench_throughput`, `bench_multi_thread`, `bench_syn_rate`, `bench_conns`, `bench_multi_data`, `bench_thread_e2e` |
| `XTCP_BUILD_SAMPLES` | `OFF` | `echo` plus TUN-based `interop_*` samples. Interop samples require UNIX (they open `/dev/net/tun`) |
| `XTCP_BUILD_CC_PLUGINS` | `ON` | Links built-in congestion controls (KCC/BBRv1/CUBIC/Reno) into the static library |
| `XTCP_BUILD_PLUGINS` | `OFF` | Example out-of-tree plugin as a shared library |
| `XTCP_BUILD_LWIP` | `OFF` | Builds vendored lwIP for symmetric differential testing |
| `XTCP_CHECKSUM_VALIDATE` | `OFF` | Verify IPv4/TCP checksums on receive (SIMD-accelerated). Enable for hostile-input deployments |
| `XTCP_SANITIZE` | `OFF` | ASan/UBSan on Linux; CRT leak detection on MSVC |

Your target links `xtcp_static` and adds `include/`. One public header
covers most uses: `#include <xtcp/core/stack.h>`.

## 2. Core concepts

Four things determine how you use the library:

1. **One `XtcpStack` per network identity.** Construct it with an NDI
   backend; it terminates TCP for the addresses that backend delivers.
2. **You pump.** Packets enter via `OnPacket`; time advances via
   `PollAckTimers` (delayed ACKs, RTO, persist, keepalive). Call both from
   your thread(s); there are no hidden workers.
3. **Connection ids are opaque handles** that also encode the owning shard;
   store them, route them across threads, pass them to every per-connection
   call.
4. **Callbacks run outside internal locks**, so calling back into the stack
   from a handler is legal.

## 3. Getting started: two stacks in one process

The smallest complete program wires two stacks back-to-back through
in-memory backends (full source: `samples/echo.cpp`):

```cpp
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

xtcp::buf::InitPools();                       // once per process, before use

xtcp::ndi::ManualBackend server_backend, client_backend;
xtcp::XtcpStack server_stack(&server_backend);
xtcp::XtcpStack client_stack(&client_backend);

// Each backend's Tx becomes the peer's Rx. Copy into a pooled buffer —
// the Packet view is only valid during the handler.
server_backend.SetRxHandler([&](xtcp::ndi::Packet&& p) {
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
    if (buf.IsEmpty()) return;                // pool exhausted: drop
    std::memcpy(buf.Data(), p.data, p.len);
    buf.SetLen(p.len);
    server_stack.OnPacket(std::move(buf));
});
// client_backend -> client_stack: same shape.

// Server side: listen, accept, echo.
xtcp::core::Endpoint laddr{};                 // 10.0.0.2:8080
laddr.family = 4;
laddr.addr[0] = 0x0A000002;
laddr.port    = 8080;
server_stack.Listen(laddr);
server_stack.SetAcceptHandler(
    [](UInt64 id, const xtcp::core::Endpoint& remote,
       const xtcp::core::Endpoint& local) { return true; /* admit */ });
server_stack.SetRecvHandler([&](UInt64 id, const Byte* data, UInt32 len) {
    server_stack.Send(id, data, len);         // echo
});

// Client side: connect, send, observe state.
client_stack.SetStateHandler([&](UInt64, xtcp::core::TcpState st) {
    if (st == xtcp::core::TcpState::kEstablished) { /* ready */ }
});
xtcp::core::Endpoint raddr{};                 // peer 10.0.0.2:8080
raddr.family = 4;
raddr.addr[0] = 0x0A000002;
raddr.port    = 8080;
const UInt64 conn = client_stack.Connect(clocal, raddr);   // 0 == failure
if (conn) {
    client_stack.Send(conn, payload, size);   // legal before Established too
    client_stack.Close(conn);                 // active close (FIN)
}

// Pump loop (your thread): deliver Tx of each backend into the peer,
// then advance timers.
while (running) {
    Byte out[65536];
    while (auto n = client_backend.PollTx(out))
        server_backend.Inject(out, n, 0x0800);
    while (auto n = server_backend.PollTx(out))
        client_backend.Inject(out, n, 0x0800);
    server_stack.PollAckTimers();
    client_stack.PollAckTimers();
}
xtcp::buf::ShutdownPools();                   // once per process, after all stacks die
```

With a real NIC-shaped backend (TUN on Linux), the same program talks to
the kernel's own TCP: see the `interop_*` samples.

## 4. API reference by task

### Connection lifecycle

| Task | Call |
|---|---|
| Passive open | `bool Listen(const Endpoint&)` |
| Admit/refuse an incoming connection | `SetAcceptHandler` returning `true`/`false` |
| Active open | `UInt64 Connect(const Endpoint& local, const Endpoint& remote)` — returns id, `0` on failure |
| Send bytes | `bool Send(UInt64 conn, const Byte*, UInt32)` — queues within the send quota; `false` means refused (closed or over quota) |
| Receive bytes | `SetRecvHandler(conn_id, data, len)` — in-order stream |
| Urgent pointer | `SetUrgentHandler(conn_id)` |
| State transitions | `SetStateHandler(conn_id, TcpState)` |
| Active/passive close | `Close(UInt64 conn)` |
| Stop listening | `bool StopListen(const Endpoint&)` — true only if a listener was removed |

### Queries

```cpp
xtcp::core::Endpoint local, remote;
stack.GetLocalEndpoint(conn, local);   // getsockname equivalent; ephemeral port filled in
stack.GetRemoteEndpoint(conn, remote); // getpeername equivalent

UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup_acks, fast_rec, front_seq, snd_una;
UInt16 lp, rp; UInt64 rto_deadline;
stack.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                rto_deadline, dup_acks, fast_rec, front_seq, snd_una, lp, rp);
```

### Stack-wide configuration

| Call | Meaning |
|---|---|
| `SetSyncookieThreshold(n)` | Outstanding half-open connections above which SYN cookies engage |
| `SetDefaultCongestionControl(name)` | CC used by new listeners/connections (`""` reverts to Reno baseline) |
| `SetDefaultEcn(bool)` | Default RFC 3168 negotiation state |
| `SetDefaultNoSack(bool)` | Suppress SACK-permitted by default (see options table) |
| `SetTxQdisc(qdisc*)` | Mount/unmount the egress qdisc (see §7) |

## 5. NDI backends

A backend implements three things: `Tx` (emit one complete IP packet),
`SetRxHandler` (deliver received packets), and `Caps` (capabilities such as
checksum offload). The in-memory `ManualBackend` in
`include/xtcp/ndi/manual.h` is the reference implementation and what the
tests and benchmarks drive. A concrete Linux TUN driver ships as sample
code (`samples/tun2socks/tun_ndi.cpp`) rather than as part of the library —
the library is driver-agnostic by design. DPDK and OpenOnload (EFVI)
backends are reserved interfaces; they do not exist yet.

## 6. Congestion control

Built-in algorithms register when `XTCP_BUILD_CC_PLUGINS=ON` (default):
KCC (default), Reno, CUBIC, BBRv1.

```cpp
xtcp::cc::RegisterKcc();      // normally implicit via the build option
xtcp::cc::RegisterBbrv1();
xtcp::cc::RegisterCubic();
stack.SetDefaultCongestionControl("bbr");   // name-based selection
```

Selection is per-listener; changing algorithms affects new connections and
leaves live ones untouched. Porting another kernel algorithm follows
[CC_PORTING.md](CC_PORTING.md): copy the ops-table shape, replace kernel
types with `XtcpConnCc*`.

## 7. Queueing disciplines

FQ is the default egress discipline (kernel `sch_fq` semantics: per-flow
queues plus pacing). Built-ins: `RegisterFqDefault()`,
`RegisterFqCoDel()` (per-flow FIFO + CoDel AQM), `RegisterCake()`
(per-flow DRR + Cobalt AQM), plus TBF.

```cpp
xtcp::qdisc::RegisterFqDefault();                       // idempotent
xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", &params);
stack.SetTxQdisc(q);                                    // mount
stack.SetTxQdisc(nullptr);                              // unmount: direct emission
```

Hot-swapping a qdisc drains old queues naturally instead of dropping live
flows. Closing connections reclaim their queued segments through
`remove_flow`, keeping transmit accounting exact. Custom disciplines
register via `xtcp::qdisc::RegisterQdisc`; `tests/test_fifo.cpp` is the
minimal worked example.

## 8. Per-connection options

Linux `setsockopt`-style ids (`include/xtcp/options/options.h`):

```cpp
Int32 v = 1;
stack.SetOption(conn, xtcp::options::kTcpNodelay, &v, sizeof(v));
```

| Id | Name | Semantics |
|---|---|---|
| 1 | `kTcpNodelay` | Disable Nagle |
| 2 | `kTcpMaxseg` | MSS clamp |
| 3 | `kTcpCork` | Accepted, **no-op in v1** |
| 4/5/6 | `kTcpKeepidle/Keepintvl/Keepcnt` | Keepalive tuning |
| 7 | `kTcpSynCnt` | SYN retry count |
| 9 | `kTcpDeferAccept` | Delay accept until data arrives |
| 12 | `kTcpQuickack` | Disable delayed ACK temporarily |
| 18 | `kTcpUserTimeout` | Abort when unacknowledged too long |
| 23 / 30 | `kTcpFastopen` / `kTcpFastopenConnect` | Server cookies / client TFO |
| 64 | `kTcpEcn` | RFC 3168 negotiation |
| 65 | `kTcpNoSackPermitted` | Suppress SACK-permitted on SYN: connection runs SACK-less (RACK off, RFC 5827 Early Retransmit covers small losses) — parity with `sysctl net.ipv4.tcp_sack=0` |

## 9. mimt channels

For in-process streams (VPN user-plane, forward proxies, traffic audit),
mimt exposes TCP-like flows without synthesizing packets. Reads complete
with fill-to-want semantics: consecutive queued chunks drain into your
buffer, and a short read happens only when the queue is empty — one
accepted read gets exactly one completion. See ARCHITECTURE §11 for the
exact contract and its rationale.

## 10. Benchmarks

```bash
./bench_throughput <total_bytes> <chunk> [qdisc_mode] [quickack] [cc] [sleep_us]
# JSON lines per round + best-of summary.
#   qdisc_mode: 0 none, 1 fq+pacing, 2 fq, -1 null-qdisc
#   cc: kcc (default) | reno | cubic | bbr
#   sleep_us: pause between pump rounds. Rate-based CCs (BBR/CUBIC) need
#             real time between rounds; the zero-delay busy loop
#             underestimates them. Loss-based KCC/Reno do not.
./bench_multi_thread            # RX injection, 1 vs 8 workers
./bench_syn_rate [conns]        # establishment rate
./bench_conns [conns] [rounds] [idle|dirty]
```

Methodology and published results: [PERFORMANCE.md](PERFORMANCE.md).

## 11. Troubleshooting

- **No traffic flows**: confirm your pump loop calls both `OnPacket`
  (ingress) and `PollAckTimers` (timers). A stack nobody pumps never
  retransmits nor ACKs.
- **`Connect` returns 0**: local endpoint collision or backend not wired
  bidirectionally.
- **Send returns false immediately**: the send quota (64 KiB default) is
  full or the connection is gone; check `ConnStats`.
- **Throughput far below published numbers with BBR/CUBIC in
  `bench_throughput`**: pass `sleep_us > 0`; the zero-delay loop starves
  rate-based algorithms (§10).

# XTCP CC Porting Guide

> Language: **English** | [中文](CC_PORTING_CN.md)

How to port a Linux kernel congestion control module (e.g. `tcp_bbr.c`,
`tcp_cubic.c`, `tcp_kcc.c`) into XTCP with logic and constants unchanged.

## 1. The hook table

XTCP's `XtcpCongestionOps` (include/xtcp/cc/cc.h) mirrors Linux
`struct tcp_congestion_ops` field for field:

| Kernel field | XTCP field | Notes |
|---|---|---|
| `.name` | `name` | Algorithm name (`cc=<name>` selects it) |
| `.init` | `init` | Called at connection creation |
| `.release` | `release` | Called at connection destruction |
| `.ssthresh` | `ssthresh` | Slow-start threshold |
| `.cong_avoid` | `cong_avoid` | Classic cwnd computation |
| `.set_state` | `set_state` | CA state transitions |
| `.cwnd_event` | `cwnd_event` | CA events (loss, ECN, ACK...) |
| `.pkts_acked` | `pkts_acked` | ACK samples (RTT/delivered) |
| `.undo_cwnd` | `undo_cwnd` | Recovery undo |
| `.cong_control` | `cong_control` | New-style direct pacing/cwnd control (BBR/KCC) |
| `.reinit_ssthresh` | `reinit_ssthresh` | ssthresh reinit |

## 2. Field equivalents

Kernel `tcp_sock` fields used by CC code map onto `XtcpConnCc` with the
same names and semantics: `snd_cwnd`, `snd_ssthresh`, `pacing_rate`,
`delivered`, `delivered_mstamp`, `lost`, `lsndtime`, `srtt_us`, `mdev_us`,
`mss`, `rtt_min_us`, `rcv_wnd`, `snd_wnd`, `inflight`, `app_limited`.
Algorithm private state goes into `ca_priv` (owned by the algorithm).

## 3. Porting steps

```mermaid
flowchart LR
    A[Copy kernel source into plugins/] --> B[Replace sk type with XtcpConnCc]
    B --> C[ca_priv private state + init/release]
    C --> D[Replace kernel helpers one by one]
    D --> E[Package XtcpCongestionOps + register]
    E --> F[Extract pure-computation core as C reference]
    F --> G[Differential-drive verification <=1% tolerance]
```

1. Copy the kernel source file into `plugins/`.
2. Replace `struct sock *sk` with `XtcpConnCc *sk`.
3. Replace `inet_csk_ca(sk)`/`tcp_sk(sk)` private-state access with
   `static_cast<BbrState*>(sk->ca_priv)` (allocate on `init`).
4. Replace kernel helpers:
   - `tp->snd_cwnd` -> `sk->snd_cwnd`
   - `tcp_sk(sk)->srtt_us` -> `sk->srtt_us`
   - `tcp_mss_to_mtu` -> `sk->mss`
   - `tcp_snd_wnd` -> `sk->snd_wnd`
   - `tcp_reno_ssthresh` -> `ssthresh = cwnd/2`
5. Wrap the hooks in a `const XtcpCongestionOps` table and register:
   `RegisterCongestionControl(ops)`.
6. Add a `RegisterXxx()` function and call it at stack startup.
7. Fidelity: extract the pure computation core as a C reference
   (`plugins/ref/`) and run the differential driver (`tests/ref_driver`
   pattern in test_cc_bbr.cpp) over a deterministic ACK sequence.

## 4. Fidelity contract

- Algorithm constants are copied verbatim from the kernel source.
- Decision logic is unchanged; only kernel dependencies are replaced.
- Differential testing compares cwnd/pacing/mode per sample against the
  extracted reference core (1% tolerance).
- Sample `plugins/cc_cubic.cpp` demonstrates a full classic-path port;
  `plugins/cc_bbrv1.cpp` demonstrates the cong_control path.

## 5. Units convention

XTCP CC uses one shared convention (both the reference core and ports):
- `bw` samples: bytes/sec * `UNIT` (1,000,000), computed as
  `delivered * UNIT / interval_us`.
- `bdp`/cwnd outputs: packets (`bdp_bytes / mss + 1`).
- `pacing_rate`: bytes/sec.

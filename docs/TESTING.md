# Testing

> Language: **English** | [中文](TESTING_CN.md)

How the suite is organized, why it is deterministic, what has been verified
on which platform, and how to extend it. Chinese version:
[TESTING_CN.md](TESTING_CN.md).

## 1. Suite organization

236 registered test executables in the default configuration (a 237th, the lwIP differential target, appears when `XTCP_BUILD_LWIP=ON`), each an independent program built from
`tests/*.cpp` and executed by CTest. Naming maps to area:

| Prefix family | Covers |
|---|---|
| `test_tcp_fsm`, `test_seq*`, `test_state_*` | RFC 793 machine: handshake, teardown, wraparound, transitions |
| `test_sack*`, `test_dsack`, `test_rack`, `test_tlp`, `test_early_retx`, `test_fastrec*`, `test_eifel`, `test_prr`-related, `test_loss_recovery`, `test_rto_recovery` | Loss recovery pipeline |
| `test_cc_*` | Congestion-control selection, registration, per-algorithm behavior |
| `test_qdisc*`, `test_fq`, `test_fifo`, `test_cake`, `test_fq_codel`, `test_pacing*` | Egress queueing and pacing |
| `test_mimt*` | In-process channels incl. the fill-to-want read contract |
| `test_tfo*`, `test_md5*`, `test_ecn*`, `test_keepalive*`, `test_window*`, `test_wscale*`, `test_nagle`, `test_urgent`, `test_user_timeout`, `test_persist*` | Options and feature surface |
| `test_syncookie*`, `test_rst_*`, `test_challenge*`, `test_icmp_spoof`, `test_cookie_*` | Defense paths |
| `test_frag*`, `test_frag6`, `test_ipv6_*`, `test_ip` | IP layer v4/v6, fragmentation |
| `test_gso*`, `test_tso*`, `test_gro_rx`, `test_zc_*`, `test_checksum_simd` | Data-path features |
| `test_shard`, `test_scale*`, `test_lock_stress`, `test_conn_churn*`, `test_thread_*`, `test_async*`, `test_combo_stress`, `test_mixed_load` | Concurrency and stress |
| `test_e2e`, `test_full_stack`, `test_diff_harness`, `test_lwip_interop` | End-to-end and differential layers |

Each binary asserts its own pass/fail and exits nonzero on failure; CTest
aggregates. Several suites additionally assert buffer-pool and quota balance
at exit, so leaks surface as assertion failures even without sanitizers.

## 2. Determinism model

The stack's timers are driven by whoever calls `PollAckTimers`. Tests
exploit this: instead of sleeping until an RTO fires, they advance virtual
time deterministically. Consequences:

- The suite is reproducible: same inputs, same results, no flaky waits by
  design.
- Wall-clock pacing is *not* covered by that part of the suite. Paths where
  real time matters (pacing-driven egress, rate-based CC) are exercised by
  benchmarks and TUN samples instead, with relaxed deadlines in tests when
  emulation forces it.

## 3. Differential layer

`tests/harness/diff_harness.h` drives a TCP implementation through scripted
scenarios and records a normalized event stream; two implementations can be
compared event-for-event. With `XTCP_BUILD_LWIP=ON`, vendored lwIP is driven
through the same scenarios (`test_lwip_interop`). Without lwIP, the harness
still runs against XTCP itself (`test_diff_harness`) so the machinery stays
exercised.

## 4. Verification record

What was actually executed, on which tree revision:

| Check | Platform/toolchain | Result |
|---|---|---|
| Full suite via CTest | Windows 11, MSVC 14.39, Release | all registered pass: 237/237 with the optional lwIP target, 236/236 without (189 s / 277 s wall) |
| Full suite, static cross-build | aarch64 GCC 13 under qemu-aarch64 | 237/237 pass (batches 80+80+77, zero failures) |
| ASan+UBSan full suite ×2 compilers | Linux CI (clang++, g++) | green at source revision `e9d5922` |
| MSVC full suite | Windows CI | green at source revision `e9d5922` |

Known platform caveats, stated rather than hidden:

- Under QEMU single-core emulation, timing-sensitive tests run with relaxed
  deadlines; correctness results are unaffected, wall-clock numbers are not
  meaningful there.
- The lwIP differential targets are conditional on vendored sources; CI now
  enables them on every job (XTCP_BUILD_LWIP=ON), local default builds
  remain opt-in.

## 5. Adding a test

1. Create `tests/test_<area>_<behavior>.cpp`; copy the skeleton of the
   closest existing test (assertion helpers, pool init/shutdown).
2. Register it in `CMakeLists.txt` next to its area siblings.
3. Prefer deterministic timer advancement over sleeps; if you must use real
   time, gate the deadline generously so QEMU runs stay valid.
4. If the test pins behavior that contradicts an RFC or a documented
   contract, fix the code or document the deviation — do not weaken the
   assertion to make it pass.

## 6. Debugging playbook notes

Two practices that repeatedly paid off in this codebase, recorded here so
they survive:

- Print-based probes change timing and can hide races entirely. The working
  approach is a zero-perturbation in-memory ring buffer dumped at process
  exit.
- When a failure reproduces only under ARM/QEMU, bisect by feature first
  (disable pacing → passes?), then vary rates to distinguish timing windows
  from logic errors. The mimt fill-to-want deadlock was found exactly this
  way after x86 runs masked it.

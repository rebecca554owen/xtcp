# XTCP Goals and Expectations (GOALS)

> Language: **English** | [中文](GOALS_CN.md)

> This file defines the solution-level goals and expectations (decision
> layer): what to build, the acceptance criteria, and the technical route.
> Implementation-level details are specified in `docs/ARCHITECTURE.md`.
> All expectations were confirmed by the user. Chinese version:
> `docs/GOALS_CN.md`.

---

## 1. Positioning

XTCP is a C++17 userspace TCP/IP protocol stack whose first principles are
**high performance + high pluggability** (performance comparable to
DPDK/f-stack; a unified plugin mechanism crosses every extension point).

**Primary integration**: userspace VPN products — replacing bundled
lwIP-based virtual network stacks.
**Ecosystem**: DPDK / OpenOnload (EFVI) reserved.
**Deliverables**: static library + benchmarks + test suite; dynamic plugin
support.

## 2. Goals and Acceptance Criteria

| # | Goal | Acceptance (measurable) |
|---|---|---|
| G1 | Ultra-high throughput | Single core >= 10 Gbps (measured 17-21 Gbps loopback); multi-core scaling to 100 Gbps class (measured 118 Gbps / 8 threads RX); lwIP/kernel comparisons |
| G2 | Protocol module hot-plug | Runtime load/unload **without interrupting existing connections**; new/old coexistence + natural drain |
| G3 | Multi-core parallelism | Flow sharding with dynamic placement + hot migration; avoids single-core saturation; scaling benchmarks. *(status: flow sharding is live; hot migration designed but not wired into production — see ARCHITECTURE §placement)* |
| G4 | Strict quality gates | All tests pass; **zero memory leaks** (ASan/LSan, per-test-cycle assertions); **zero crashes** (fuzz + sanitizers) |
| G5 | Multi-platform | Linux + Windows + Android NDK build/run, CMake, C++17 (headers includeable by openppp2); ARM NEON vectorized checksum for Android performance |
| G6 | High pluggability | One plugin mechanism across all extension points (congestion control, protocol, NDI backends, scheduling policy); unified register/drain/ABI |
| G7 | Kernel CC portability | CC hooks isomorphic to `tcp_congestion_ops`; porting a kernel CC into xtcp replaces only `struct sock*` + kernel helpers; **zero algorithm changes** (verified with an unshipped sample) |
| G8 | Zero copy | **Zero memcpy on the hot data plane**: rx delivery borrows the pool block (pointer-to-callback), TX transfers ownership; the intentional copies (borrowed-inject fallback, MIMT delivery, per-segment GSO) are pinned by the copy-count table in the buf audit and the DMA/offload test matrix (`test_zc_rxpath`, `test_tx_backpressure`, `test_gro_rx`, `test_tso_tx`) |
| G9 | TSO/GSO | Software GSO segmentation deferred to the tx boundary; TSO hardware passthrough (NDI capability bits); GSO byte-identical to per-segment sending |
| G10 | FQ AQM (pluggable) | Pluggable qdisc algorithms; default Linux FQ (sch_fq semantics: per-flow queues, DRR, internal pacing); kernel `tc fq` comparison tests *(not implemented - documented future item)* |
| G11 | Strict performance testing | Statistical rigor (warmup/steady-state/>=5 rounds/95% CI), controlled environment, load matrix, impairment simulation, reproducible results |
| G12 | RFC compliance & interop | RFC 793/1122/791/8200/5681/2018/7323/6298/5961/1071/1624 etc.; **Linux/Windows kernel stacks must fully recognize and interop with xtcp** (bidirectional) |
| G13 | Audit mode (MIMT proxy) | One listening port per family (IPv4/IPv6); all destination flows converge; **TCP streams delivered to the user as async Proactor callbacks** (AsyncRead/AsyncWrite/AsyncClose); transparent to the peer. tun2socks sample delivered |
| G14 | Kernel-compat control plane + dual-layer API | Layer 1: kernel-compat options (TCP_NODELAY/TCP_FASTOPEN/sysctl tcp_*); Layer 2: **Proactor-only async API** (no built-in coroutines; **callbacks guaranteed async — never synchronous reentry**, with one documented exception: AsyncClose on an already-closed flow completes inline, mimt.h). Modern tech: SYN Cookies (RFC 4987), TCP Fast Open (RFC 7413), ECN (RFC 3168), NODELAY |
| G15 | Industrial style + bilingual docs | Style rigorously aligned with openppp2 `ppp/`; **English comments; docs bilingual** (`doc.md` + `doc_CN.md`) |

## 3. Technical Route (decisions)

| Decision | Conclusion |
|---|---|
| Language/build | C++17 + CMake |
| API layers | Kernel-compat layer (same-name options) + Proactor async layer (no sync form; async-dispatch guarantee) |
| Parallelism | A2 dynamic placement + migratable shards (zero-lock data plane, least-loaded placement, hot migration, lock-free cross-shard queues) |
| Hot-plug semantics | New/old coexistence + natural drain |
| Plugin ABI | C++ ABI direct (documented risk + mitigation) |
| NDI backend | Abstraction + manual packet I/O; TAP/TUN abstraction only; DPDK/EFVI reserved |
| Protocol scope (v1) | Dual-stack IPv4 + IPv6 full TCP (state machine/retransmit/congestion control/fragmentation); UDP/ICMP later |
| Congestion control | **Default KCC**; Reno (`cc=reno`, RFC 5681) via `SetDefaultCongestionControl("")`; BBRv1/CUBIC selectable via `SetCongestionControl`/`SetDefaultCongestionControl`; kernel-isomorphic hooks |
| qdisc | Pluggable; default Linux FQ (sch_fq semantics); fq_codel and cake also built in |
| Zero copy | Ref-counted buffer pools + IOV chains; GSO zero-copy segmentation |
| Testing | Unit + lwIP differential + CC fidelity differential + FQ comparison *(future item)* + replay + interop + fuzz + sanitizers + strict benchmarks, CI both platforms |
| Docs | English-first with `_CN.md` Simplified Chinese counterparts; behavioral changes update both |

## 4. Reference Assets (behavioral authority)

| Asset | Location | Use |
|---|---|---|
| lwIP | upstream lwIP sources (incl. custom port layer) | Differential reference (xtcp replaces it) |
| KCC kernel | reference KCC kernel implementation | KCC port cross-check |
| BBRv1 kernel | Linux kernel `tcp_bbr.c` | BBRv1 port reference |
| KCC userspace (primary) | reference userspace KCC implementation (`UcpCongestionControl`) | KCC port main reference |
| UCP protocol | reference UCP RFC document | SACK/NAK/FEC, NetworkSimulator |
| Kernel fq | Linux `net/sched/sch_fq.c` | FQ behavior reference |

## 5. Milestones

- **M1** skeleton + NDI + manual backend + single-core minimal TCP + unit tests
- **M2** dual-stack full TCP + differential + interop + RFC checklist
- **M3** multi-core sharding + dynamic placement + hot migration + scaling bench
- **M4** plugin system + hot-plug drain + benchmark targets + full docs
- **M5** CC ports (KCC default + BBRv1 + CUBIC, kernel-isomorphic hooks) + FQ AQM + GSO

## 6. Non-Goals (YAGNI, v1)

- UDP/ICMP userspace stacks (routing-only support; state machines later)
- DPDK / EFVI data-plane backends (no hardware; NDI interface only)
- TAP/TUN concrete drivers (abstraction only, user-provided)

## 7. Key Risks and Mitigations

| Risk | Mitigation |
|---|---|
| C++ ABI fragility (plugins) | ABI contract docs, version check, load self-test, fail-safe fallback |
| Hash skew on a single core | Dynamic placement + hot migration |
| Migration loss/inconsistency | Pause-serialize-restore protocol + differential tests |
| CC port divergence | Pure-core extraction + per-sample fidelity differential (kernel + UCP references) |
| 100 Gbps without DPDK hardware | Manual-backend benchmarks first; NDI DPDK reserved; real-scenario (openppp2) validation |
| Dual-stack effort | Unified address-family abstraction, layer-by-layer, per-family test matrix |
| RFC deviation (kernel stack rejects xtcp) | RFC-to-case mapping (TEST_PLAN §6 RFC coverage table), bidirectional interop matrix as hard gate |

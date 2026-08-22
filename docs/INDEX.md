# Documentation Index

> Language: **English** | [中文](INDEX_CN.md)

Every document exists in English and in Chinese (`_CN` suffix). Both
versions carry identical technical content; the English version is the
editing master.

## Reading order by intent

**Evaluating XTCP for a product**

1. [README](../README.md) — positioning, support matrix, measured results,
   known limitations
2. [PERFORMANCE](PERFORMANCE.md) — how every number was produced;
   environments, raw outputs, interpretation, limitations
3. [ARCHITECTURE](ARCHITECTURE.md) — whether the layering and threading
   model fits your integration

**Integrating the library**

4. [BUILDING](BUILDING.md) — toolchain matrix, per-platform recipes,
   sanitizers, cross-compilation, QEMU verification lab
5. [USAGE](USAGE.md) — API walkthrough: lifecycle, callbacks, options,
   qdisc selection, mimt channels, plugin authoring
6. [CC_PORTING](CC_PORTING.md) — bringing a kernel congestion-control
   algorithm into the plugin interface

**Contributing code**

7. [TESTING](TESTING.md) — suite organization, determinism model, how to
   add a test, what CI enforces
8. [CODING_STYLE](CODING_STYLE.md) — conventions enforced in review
9. [GOALS](GOALS.md) — project goals and acceptance criteria that changes
   are judged against

## Document map

| Document | English | Chinese | Content |
|---|---|---|---|
| Overview | [README.md](../README.md) | [README_CN.md](../README_CN.md) | Positioning, protocol support, measured performance summary, limitations, quick start |
| Index | INDEX.md | INDEX_CN.md | This page |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) | [ARCHITECTURE_CN.md](ARCHITECTURE_CN.md) | Layers, packet path, sharding, buffers, TCP FSM, CC/qdisc plugins, mimt, locking rules |
| Performance | [PERFORMANCE.md](PERFORMANCE.md) | [PERFORMANCE_CN.md](PERFORMANCE_CN.md) | Methodology, environments, raw benchmark outputs, interpretation, limitations |
| Building | [BUILDING.md](BUILDING.md) | [BUILDING_CN.md](BUILDING_CN.md) | Platform/toolchain matrix, MSVC/GCC/Clang/NDK recipes, ASan/UBSan, QEMU lab |
| Usage | [USAGE.md](USAGE.md) | [USAGE_CN.md](USAGE_CN.md) | Getting started, API reference by task, options table, qdisc usage, plugins |
| Testing | [TESTING.md](TESTING.md) | [TESTING_CN.md](TESTING_CN.md) | Suite map, virtual-clock determinism, verification records (MSVC/QEMU/sanitizers) |
| Goals | [GOALS.md](GOALS.md) | [GOALS_CN.md](GOALS_CN.md) | Solution-level goals and measurable acceptance criteria |
| Coding style | [CODING_STYLE.md](CODING_STYLE.md) | [CODING_STYLE_CN.md](CODING_STYLE_CN.md) | Mandatory code conventions |
| CC porting | [CC_PORTING.md](CC_PORTING.md) | [CC_PORTING_CN.md](CC_PORTING_CN.md) | Kernel `tcp_congestion_ops` porting guide |

## Source-tree orientation

```
include/xtcp/     public headers (stack.h is the entry point)
src/core/         TCP FSM, IP, sharding, timers, buffers
src/options/      Linux-style setsockopt option layer
src/qdisc/        FQ / fq_codel / cake / TBF queueing disciplines
src/cc/           KCC, Reno, CUBIC, BBRv1 congestion controls
include/xtcp/ndi/ backend interfaces (manual, tun, tap)
plugins/ref/      reference CC cores used for differential testing
tests/            237-test deterministic suite (+ harness/)
samples/          interop samples (TUN-based, Linux) and echo demo
bench/            micro-benchmarks cited by PERFORMANCE.md
```

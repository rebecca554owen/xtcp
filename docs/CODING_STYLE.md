# XTCP Coding Style

> Language: **English** | [中文](CODING_STYLE_CN.md)

> Mandatory project-wide style. Industrial-grade discipline. Chinese version: `CODING_STYLE_CN.md`.

## 1. Language and Standard

- **C++17 strictly** — no C++20 features. Enforced project-wide.
- No RTTI/exception requirements beyond C++17 defaults; exceptions only at API boundary of the async layer (error surfaced via callbacks, never thrown across Proactor dispatch).

## 2. Naming

| Category | Style |
|---|---|
| Types, functions | `PascalCase` |
| Private fields | trailing `_` (e.g. `server_`) |
| Constants | `k` prefix (e.g. `kMaxPendingLines`) |
| Macros | `UPPER_SNAKE_CASE` |
| Namespaces | `lowercase` (`xtcp`, `xtcp::core`, `xtcp::qdisc`) |
| Static file-local constants | `UPPER_SNAKE_CASE` (e.g. `VNETSTACK_SYNC_ACK_STATE_CLOSED`) |

## 3. Mandatory Macros (do not use raw equivalents)

| Use this | Not this |
|---|---|
| `NULLPTR` | `nullptr` or `NULL` |
| `elif` | `else if` |
| Constants-on-left: `if (0 == x)` | `if (x == 0)` |

## 4. Type Aliases (global fixed-width typedefs)

- Fixed-width aliases are GLOBAL typedefs (not namespaced): `Byte`, `Int16/Int32/Int64`, `UInt16/UInt32/UInt64`, `SByte`, `Double`, `Single`, `Boolean`, `Char` — use them unqualified everywhere (the codebase never writes `xtcp::Byte`-style qualified names; they do not resolve).
- There are NO `xtcp::string` / `xtcp::vector<T>` / `xtcp::map<K,V>` aliases — use the standard library types directly (`std::string`, `std::vector`, `std::unordered_map`).
- All defined in the master header `include/xtcp/stdafx.h` — read it before adding types. Typedef blocks are column-aligned like openppp2 `ppp/stdafx.h`.

## 5. Memory

- No raw `new`/`delete` in runtime paths. Use `xtcp::Malloc` / `xtcp::Mfree` (defined in stdafx.h).
- The hot data plane is zero-copy / pool-based: `BufRef` ref-counted pools; no runtime malloc in the hot path.
- (There is no `xtcp::allocator<T>` / jemalloc integration — allocations go through `xtcp::Malloc` / the pool allocators.)

## 6. Platform Guards (use repo macros, never raw compiler symbols)

- The master header defines the macro pairs `_WIN32`/`WIN32`, `_LINUX`/`LINUX`, `_MACOS`/`MACOS` (that is the full pairing table — `_ANDROID`/`_HARMONYOS`/`_IPHONE` are not defined here) plus the architecture gates `XTCP_X86` / `XTCP_ARM` / `XTCP_RISCV`.
- Never add `#ifdef __linux__` or `#ifdef _MSC_VER` in shared `include/`/`src/core/` files. Every SIMD/CPU-specific path must be gated by `XTCP_X86` (never the compiler vendor alone — `_MSC_VER` also fires on ARM64 MSVC, `__GNUC__` also fires on ARM GCC/Clang).
- Platform-specific code belongs in `src/platform/linux/`, `src/platform/windows/`, etc.

## 7. Error Handling

Every failure branch must detect the failure and return the documented sentinel (0 conn id, `false`, `NULLPTR`). Return-value contracts are documented on each public API in stack.h/tcp.h — keep them in sync when behavior changes (a silently-returning-only-sentinel branch that skips cleanup is a bug).

## 8. Concurrency

- Cross-thread lifecycle flags: `std::atomic<bool>` with `compare_exchange_strong(memory_order_acq_rel)`.
- Data plane: zero-lock per-shard run-to-completion; cross-shard via lock-free queues only.
- Async API: Proactor callbacks dispatched via per-shard event queues; **completion callbacks are NEVER invoked synchronously on the initiator's stack** (no reentry). No coroutines built-in; users may wrap with their own (e.g. Boost.Asio spawn/yield).
- Never block the IO/dispatch thread.

## 9. Comments (all English)

- All code comments in English.
- Public APIs: English Doxygen `@brief`, `@param`, `@return`.
- File headers: `@file`, `@brief` (e.g. `@file fq.cpp` / `@brief FQ scheduler (sch_fq semantics)`).

## 10. Documentation (English + Simplified Chinese)

- Docs ship bilingual: `<name>.md` (English) + `<name>_CN.md` (Simplified Chinese), kept in sync.
- **Behavioral changes must update BOTH the English and `_CN.md` Chinese docs.**
- Docs are authored in English first, Chinese as the parallel translation (aligned with openppp2 `docs/` EN + `_CN.md` convention).

## 11. File Layout

- `#pragma once` first in headers.
- File top: `#include` block, then `@file`/`@brief` Doxygen block (or `@file`/`@brief` right after includes, mirroring openppp2 ordering).
- Local typedef shortcuts at the top of translation units (`typedef xtcp::net::IPEndPoint IPEndPoint;`) — file-local, not exported.
- Grouped `static constexpr` constants with a `@brief` comment per group.

## 12. Testing (xtcp-specific, beyond openppp2)

- TDD: failing test → minimal implementation → pass → commit.
- No test may depend on wall-clock timing (deterministic virtual clock for network sims).
- Zero memory leaks (ASan/LSan; leak assertions per test cycle); zero crashes (fuzz + sanitizers).

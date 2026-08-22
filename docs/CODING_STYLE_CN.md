# XTCP 编码规范

> 语言：[English](CODING_STYLE.md) | **中文**

> 项目级强制规范。工业级水准。英文版：`CODING_STYLE.md`。

## 1. 语言与标准

- **严格 C++17**——禁用 C++20 特性，项目级强制执行
- 异常仅在异步层 API 边界使用（错误经回调呈现，绝不允许跨 Proactor 派发抛出）

## 2. 命名

| 类别 | 风格 |
|---|---|
| 类型、函数 | `PascalCase` |
| 私有字段 | 尾随 `_`（如 `server_`） |
| 常量 | `k` 前缀（如 `kMaxPendingLines`） |
| 宏 | `UPPER_SNAKE_CASE` |
| 命名空间 | `lowercase`（`xtcp`、`xtcp::core`、`xtcp::qdisc`） |
| 文件级静态常量 | `UPPER_SNAKE_CASE`（如 `VNETSTACK_SYNC_ACK_STATE_CLOSED`） |

## 3. 强制宏（禁止使用原始等价物）

| 使用 | 禁用 |
|---|---|
| `NULLPTR` | `nullptr` 或 `NULL` |
| `elif` | `else if` |
| 常数在左：`if (0 == x)` | `if (x == 0)` |

## 4. 类型别名（全局定宽 typedef）

- 定宽别名是**全局 typedef**（不在命名空间内）：`Byte`、`Int16/Int32/Int64`、`UInt16/UInt32/UInt64`、`SByte`、`Double`、`Single`、`Boolean`、`Char` — 全仓一律非限定使用（代码从不写 `xtcp::Byte` 式限定名；它们无法解析）
- 不存在 `xtcp::string` / `xtcp::vector<T>` / `xtcp::map<K,V>` 别名 — 直接用标准库类型（`std::string`、`std::vector`、`std::unordered_map`）
- 全部定义于总头文件 `include/xtcp/stdafx.h`——新增类型前先读它；typedef 块列对齐（同 openppp2 `ppp/stdafx.h`）

## 5. 内存

- 运行路径禁止裸 `new`/`delete`，使用 `xtcp::Malloc` / `xtcp::Mfree`（stdafx.h 定义）
- 热数据面零拷贝/池化：`BufRef` 引用计数缓冲池；热路径无运行时 malloc
- （无 `xtcp::allocator<T>` / jemalloc 集成 — 分配走 `xtcp::Malloc` / 池分配器）

## 6. 平台宏（使用仓库宏，禁止原始编译器符号）

- 总头文件定义宏对 `_WIN32`/`WIN32`、`_LINUX`/`LINUX`、`_MACOS`/`MACOS`（这就是完整配对表 — `_ANDROID`/`_HARMONYOS`/`_IPHONE` 未定义），另有架构门 `XTCP_X86` / `XTCP_ARM` / `XTCP_RISCV`
- 共享 `include/`、`src/core/` 文件禁止 `#ifdef __linux__` 或 `#ifdef _MSC_VER`；每个 SIMD/CPU 专属路径必须按 `XTCP_X86` 门控（绝不能只用编译器厂商判断 — `_MSC_VER` 在 ARM64 MSVC 也会命中，`__GNUC__` 在 ARM GCC/Clang 也会命中）
- 平台代码归入 `src/platform/linux/`、`src/platform/windows/` 等

## 7. 错误处理

每个失败分支必须检测失败并按各公共 API 在 stack.h/tcp.h 文档化的返回契约返回哨兵（0 conn id、`false`、`NULLPTR`）。行为变化时保持契约注释同步（静默只返回哨兵却跳过清理的分支是 bug）。

## 8. 并发

- 跨线程生命周期标志：`std::atomic<bool>` + `compare_exchange_strong(memory_order_acq_rel)`
- 数据面：每 shard 零锁 run-to-completion；跨核仅无锁队列
- 异步 API：Proactor 回调经每 shard 事件队列派发；**完成回调绝不在发起者栈上同步调用（禁止重入）**；不内置协程，用户可自行包装（如 Boost.Asio spawn/yield）
- 禁止阻塞 IO/派发线程

## 9. 注释（全英语）

- 所有代码注释一律英语
- 公开 API：英文 Doxygen `@brief`、`@param`、`@return`
- 文件头：`@file`、`@brief`（如 `@file fq.cpp` / `@brief FQ scheduler (sch_fq semantics)`）

## 10. 文档（英语 + 简体中文双语）

- 文档成对交付：`<name>.md`（英语）+ `<name>_CN.md`（简体中文），保持同步
- **行为变更必须同步更新英文与 `_CN.md` 中文两份文档**
- 先写英文，中文为平行翻译（对齐 openppp2 `docs/` EN + `_CN.md` 惯例）

## 11. 文件布局

- 头文件首行 `#pragma once`
- 文件顶部：`#include` 块，然后 `@file`/`@brief` Doxygen 块（顺序镜像 openppp2）
- 翻译单元顶部放局部 typedef 简写（`typedef xtcp::net::IPEndPoint IPEndPoint;`）——文件局部，不导出
- 分组 `static constexpr` 常量 + 每组一个 `@brief` 注释

## 12. 测试（xtcp 特有，超越 openppp2）

- TDD：失败测试 → 最小实现 → 通过 → 提交
- 测试不得依赖墙钟时序（网络仿真用确定性虚拟时钟）
- 零内存泄漏（ASan/LSan，每测试循环泄漏断言）；零崩溃（fuzz + sanitizer）

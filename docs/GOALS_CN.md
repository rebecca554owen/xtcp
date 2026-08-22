# XTCP 方案目标与预期（GOALS）

> 语言：[English](GOALS.md) | **中文**

> 本文件是 xtcp 项目的**方案层目标与预期**（决策层），定义"要什么、验收标准是什么、技术路线是什么"。具体实现架构细节（字段级接口、内部结构）在实现阶段于 `docs/ARCHITECTURE_CN.md` 细化。所有预期经用户逐项确认。

---

## 1. 项目定位

xtcp 是一个 C++17 用户态 TCP/IP 协议栈，**高性能 + 高度插件可扩展**是第一性架构原则（对标 DPDK/f-stack 的性能，插件化横切所有扩展点）。

**首要集成场景**：用户态 VPN 产品——**替换其内置的基于 lwIP 的虚拟网络栈**。
**生态兼顾**：DPDK / OpenOnload（EFVI）生态预留。
**交付形态**：静态库 + 基准程序 + 测试体系；支持动态库插件。

## 2. 核心目标与验收标准

| # | 目标 | 验收标准（可度量） |
|---|---|---|
| G1 | 超高吞吐 | 单核 ≥ 10Gbps（回环实测 17-21 Gbps）；多核扩展至 **100Gbps 级**（8 线程 RX 实测 118 Gbps）；lwIP/内核栈对照 |
| G2 | 协议模块热插拔 | 运行时动态加载/卸载，**不中断现有连接**；新旧共存+自然排空（drain） |
| G3 | 多核并行 | 多核流分片，动态放置 + 热点迁移，避免单核被海量流打爆；多核扩展性基准 |
| G4 | 严格质量门槛 | 测试全量通过；**零内存泄漏**（ASan/LSan/每测试循环断言）；**零崩溃**（fuzz+sanitizer） |
| G5 | 多平台 | Linux + Windows + Android NDK 均可构建运行，CMake，C++17（头文件可被 openppp2 直接包含）；ARM NEON 向量化校验和提升 Android 性能 |
| G6 | 高度插件可扩展 | 统一插件机制横切所有扩展点（拥塞控制、协议处理、NDI 后端、调度策略等），注册/drain/ABI 一套机制 |
| G7 | 内核 CC 可移植性 | CC 挂钩与内核 `tcp_congestion_ops` 同构；第三方照移植指南把内核 CC 接入 xtcp，仅替换 `struct sock*` 与内核辅助函数，算法逻辑与常数**零改动**（以未内置算法样例验证） |
| G8 | 零拷贝 | 数据面热路径**零 memcpy**：rx 投递借用池块（指针直达回调），TX 所有权转移；有意的拷贝（借用注入回退、MIMT 交付、逐段 GSO）由 buf 审计中的拷贝计数表与 DMA/卸载测试矩阵钉定（`test_zc_rxpath`、`test_tx_backpressure`、`test_gro_rx`、`test_tso_tx`） |
| G9 | TSO/GSO | 软件 GSO 分段延迟到 tx 边界；TSO 硬件直通（NDI 能力位）；GSO 与逐段发送逐字节一致 |
| G10 | FQ AQM（可插拔） | **qdisc 算法可插拔**：默认实现与 Linux 内核 FQ 行为一致的队列管理（per-flow 队列+DRR+pacing，sch_fq 语义），BBR/KCC 正确运行前提；qdisc 算法挂钩接口（内核 `Qdisc_ops` 同构风格）支持运行时注册/替换新算法（如 fq_codel、cake、自定义）；与内核 `tc fq` 对照测试（未实现，记录在册的后续项） |
| G11 | 严格性能测试 | 统计严谨（预热/稳态/≥5 轮/95% CI）、受控环境（CPU pinning/performance governor）、负载矩阵、网络损伤仿真、结果可复现（配置驱动+CI 存原始结果） |
| G12 | RFC 标准合规与互操作 | 协议实现**大量按 RFC 标准**进行（RFC 793/1122/791/8200/5681/2018/7323/6298/5961/1071/1624 等），**Linux/Windows 内核 TCP/IP 协议栈必须能完整识别并与 xtcp 互通**——双向互操作验收：xtcp 主动连接内核栈、内核栈主动连接 xtcp，覆盖选项协商（窗口缩放/SACK/时间戳）、零窗口、快重传、Keepalive、分段等场景 |
| G13 | 审计模式（MIMT 代理） | **每地址族一个监听端口**（IPv4/IPv6 各一）：用户启用 MIMT 模式时仅需监听该 TCP 端口，所有访问任意目的（如 google.com:443）的连接流都汇合到此端口；**xtcp 将已建立的 TCP 连接流以异步 Proactor 回调模式交付用户（AsyncRead/AsyncWrite/AsyncClose），用户自行控制读写**；连接方视角流量完全正常（对端无感）。架构上数据面**不得假设直连**。交付 tun2socks 示例程序展示利用方式；不内置代理服务端协议 |
| G14 | 内核同构控制面 + 双层 API | **API 双层设计**：①**内核兼容层**——参数命名与设置规范复刻 Linux 内核（setsockopt 风格 TCP_NODELAY/TCP_FASTOPEN/TCP_KEEPIDLE 等 + sysctl 风格 tcp_syncookies/tcp_fastopen/tcp_ecn 等），同名词义一一对应，C++ 封装更清晰简洁，用户从内核习惯迁移零成本；②**全异步层**——**仅提供 Proactor API**（回调完成通知；**默认不提供协程支持**，用户可自行用协程包装）；**铁律：回调保证异步调用（绝不在发起者栈上同步重入）**（唯一文档化例外：对已关闭流发出的 AsyncClose 会内联完成其处理器，见 mimt.h），用户挂协程不会栈破坏/重入弄死。支持现代技术：**SYN Cookies（RFC 4987）、TCP Fast Open（RFC 7413 客户端+服务端）、ECN（RFC 3168，tcp_ecn 布尔使能，窗口削减经 CC ssthresh 钩子）、NODELAY** |
| G15 | 工业级风格 + 双语文档 | **编码风格严谨对齐 openppp2 `ppp/` 内规范**（完整规范见 `docs/CODING_STYLE.md` + `docs/CODING_STYLE_CN.md` 双语）：C++17 严格；PascalCase 类型/函数、私有字段 trailing `_`、常量 `k` 前缀、宏 `UPPER_SNAKE_CASE`、`lowercase` 命名空间；强制宏 `NULLPTR`/`elif`/常数在左；全局定宽类型别名 `Byte`/`UInt32` 等（master header `include/xtcp/stdafx.h`，typedef 列对齐）；无裸 new/delete（`xtcp::Malloc/Mfree`）；平台宏 `_WIN32/_LINUX` 配对（禁 `#ifdef __linux__`）；错误处理按公共 API 文档化返回契约返回哨兵；`compare_exchange_strong(acq_rel)`；**注释全英语**；**文档全英语 + 简体中文双语**（`doc.md` + `doc_CN.md` 成对，行为变更同步双语文档）；公开 API 英文 Doxygen（@brief/@param/@return）；文件头 `@file`/`@brief` |

## 3. 技术路线（方案层决策）

| 决策点 | 结论 |
|---|---|
| 语言/构建 | C++17 + CMake（openppp2 为 C++17 严格标准，兼容头文件包含） |
| API 双层策略 | ①内核兼容层：与内核同名同义（TCP_NODELAY/tcp_syncookies 等），C++ 简洁封装；②全异步层：Proactor 回调/协程，同步形态不提供；文档明确两层定位与映射 |
| 并行模型 | **A2 动态放置 + 可迁移分区**：每核 shard 零锁数据面（流表/定时器/内存池），新流放最空闲核，热点连接可迁移，跨核仅无锁队列 |
| 热插拔语义 | 新旧共存 + 自然排空（drain）：新连接用新模块，旧连接排空后卸载；不中断现有连接 |
| 插件 ABI | C++ ABI 直连（用户选定；记录跨编译器风险，文档化 ABI 契约 + 版本校验 + 失败回退） |
| 数据面后端（NDI） | 抽象接口 + 手动以太网/IP 报文输入输出；TAP/TUN 仅抽象（具体实现交使用者，提供开发文档）；DPDK/EFVI 预留接口 |
| 协议范围（v1） | 双栈：IPv4 + IPv6 完整 TCP（状态机/重传/拥塞控制/分片重组）；UDP/ICMP 后续版本 |
| RFC 合规 | 实现按 RFC 标准（793/1122/791/8200/5681/2018/7323/6298/5961/1071/1624 等）；每个协议任务以 RFC 清单为验收标准之一 |
| 拥塞控制 | **默认 KCC**；经 `SetDefaultCongestionControl("")` 回到 Reno（`cc=reno`，RFC 5681）；BBRv1/CUBIC 可经 `SetCongestionControl`/`SetDefaultCongestionControl` 选择；挂钩框架与内核 `tcp_congestion_ops` 同构 |
| MIMT 审计模式 | **每地址族一个 MIMT 监听端口**（IPv4/IPv6 各一）；所有目的流汇合于此；xtcp 以**异步 Proactor 回调**交付已建立的 TCP 连接流（AsyncRead/AsyncWrite/AsyncClose，用户自行控制读写）；连接方视角流量正常（对端无感）；适用 VPN/正向代理/流量审计；交付 tun2socks 示例程序 |
| FQ AQM | **qdisc 算法可插拔**：默认 Linux FQ（sch_fq 语义：per-flow 队列、DRR、内部 pacing）；fq_codel 与 cake 也已内建；qdisc 挂钩接口（内核 Qdisc_ops 同构）支持新算法注册/替换（fq_codel/cake/自定义） |
| 零拷贝 | 引用计数包缓冲池 + IOV 描述符链，热路径无整包复制；GSO 分段零拷贝 |
| 测试体系 | 全量：单元 + lwIP 差分对照 + CC 保真差分（双参照：内核纯核心 + UCP 用户态）+ FQ 对照 + pcap 回放 + 对传 + fuzz + Sanitizer + 严格基准，CI 双平台跑 |
| 性能测试 | 严格方法学：受控环境、统计严谨、负载矩阵、损伤仿真、公平性、资源指标、结果可复现 |

## 4. 参照与借鉴资产（行为权威）

| 资产 | 位置 | 用途 |
|---|---|---|
| lwIP | 上游 lwIP 源码（含定制端口层） | 差分对照参照（xtcp 即替换它） |
| KCC 内核版 | 参照 KCC 内核实现 | KCC 移植参照（交叉校验） |
| BBRv1 内核版 | Linux 内核 `tcp_bbr.c` | BBRv1 移植参照 |
| KCC 用户态（首选参照） | 参照用户态 KCC 实现（`UcpCongestionControl`，UCP 协议 RFC UCP-1） | KCC 移植主参照（纯用户态 C++，单线程模型契合） |
| UCP 协议 | 参照 UCP RFC 文档 | 借鉴：SACK/NAK/FEC 恢复、NetworkSimulator 确定性测试、性能文档 |
| 内核 fq | Linux `net/sched/sch_fq.c` | FQ AQM 行为参照 |

## 5. 里程碑（方案层划分）

- **M1** 骨架 + NDI + 手动后端 + 单核 TCP 最小状态机 + 单元测试
- **M2** 双栈完整 TCP（重传/拥塞控制/分片重组）+ 差分对照 + 对传 + **双平台互操作测试（G12）** + RFC 清单落实
- **M3** 多核分片 + 动态放置 + 热点迁移 + 扩展性基准
- **M4** 插件系统 + 热插拔 drain + 基准达标（100Gbps 级）+ 文档全量
- **M5** CC 插件（KCC 默认 + BBRv1 对照 + CUBIC 样例，内核同构挂钩）+ FQ AQM（可与 M2/M3 并行推进）

## 6. 非目标（YAGNI，v1 不做）

- UDP/ICMP 用户态协议栈（仅路由层支持，状态机后续版本）
- DPDK / EFVI-Onload 数据面后端实现（无硬件环境，仅预留 NDI 接口）
- TAP/TUN 具体驱动实现（仅抽象，交使用者）

## 7. 关键风险与对策（方案层）

| 风险 | 对策 |
|---|---|
| C++ ABI 跨编译器脆弱（插件） | ABI 契约文档、版本校验、加载自检、失败回退不中断 |
| 哈希偏斜压单核 | 动态放置 + 热点迁移兜底 |
| 迁移丢包/状态不一致 | 暂停-序列化-恢复协议 + 差分测试覆盖迁移路径 |
| CC 移植行为偏差 | 纯计算核心提取 + 逐样本保真差分（内核 + UCP 双参照） |
| 100Gbps 无 DPDK 硬件验证 | 手动后端基准先行，NDI 预留 DPDK；真实场景（openppp2）回测 |
| 双栈工作量 | 地址族抽象统一，逐层实现，测试矩阵分族 |
| RFC 合规偏差导致内核栈"认不到" | RFC 条款→用例映射表（TEST_PLAN §6 RFC 覆盖表）逐条验收；双平台互操作测试矩阵（G12）为硬性门槛 |
| 内核/Winsock 行为差异 | 互操作场景矩阵显式覆盖双平台差异（如 Winsock 默认缓冲、Linux 窗口缩放默认开启） |

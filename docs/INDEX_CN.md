# 文档索引

> 语言：[English](INDEX.md) | **中文**

每份文档均有英文版与中文版（`_CN` 后缀）。两版技术内容完全一致；英文版
为编辑主版本。

## 按意图选择阅读顺序

**评估 XTCP 是否适合产品**

1. [README](../README_CN.md) — 定位、协议支持、实测结果摘要、已知局限
2. [PERFORMANCE](PERFORMANCE_CN.md) — 每个数字如何产生：环境、原始输出、
   解读、局限
3. [ARCHITECTURE](ARCHITECTURE_CN.md) — 分层与线程模型是否匹配你的集成
   方式

**集成该库**

4. [BUILDING](BUILDING_CN.md) — 工具链矩阵、各平台配方、sanitizer、交叉
   编译、QEMU 验证环境
5. [USAGE](USAGE_CN.md) — API 走读：生命周期、回调、选项、qdisc 选择、
   mimt 通道、插件编写
6. [CC_PORTING](CC_PORTING_CN.md) — 把内核拥塞控制算法移植进插件接口

**参与代码贡献**

7. [TESTING](TESTING_CN.md) — 套件组织、确定性模型、如何新增测试、CI
   强制项
8. [CODING_STYLE](CODING_STYLE_CN.md) — 评审强制执行的代码规范
9. [GOALS](GOALS_CN.md) — 项目目标与可度量的验收标准

## 文档地图

| 文档 | 英文 | 中文 | 内容 |
|---|---|---|---|
| 总览 | [README.md](../README.md) | [README_CN.md](../README_CN.md) | 定位、协议支持、实测性能摘要、局限、快速上手 |
| 索引 | [INDEX.md](INDEX.md) | INDEX_CN.md | 本页 |
| 架构 | [ARCHITECTURE.md](ARCHITECTURE.md) | [ARCHITECTURE_CN.md](ARCHITECTURE_CN.md) | 分层、报文路径、分片、缓冲、TCP FSM、CC/qdisc 插件、mimt、加锁规则 |
| 性能 | [PERFORMANCE.md](PERFORMANCE.md) | [PERFORMANCE_CN.md](PERFORMANCE_CN.md) | 方法学、环境、原始基准输出、解读、局限 |
| 构建 | [BUILDING.md](BUILDING.md) | [BUILDING_CN.md](BUILDING_CN.md) | 平台/工具链矩阵、MSVC/GCC/Clang/NDK 配方、ASan/UBSan、QEMU 环境 |
| 用法 | [USAGE.md](USAGE.md) | [USAGE_CN.md](USAGE_CN.md) | 上手指南、按任务组织的 API 参考、选项表、qdisc 用法、插件 |
| 测试 | [TESTING.md](TESTING.md) | [TESTING_CN.md](TESTING_CN.md) | 套件地图、虚拟时钟确定性、验证记录（MSVC/QEMU/sanitizer） |
| 目标 | [GOALS.md](GOALS.md) | [GOALS_CN.md](GOALS_CN.md) | 方案级目标与可度量验收标准 |
| 代码规范 | [CODING_STYLE.md](CODING_STYLE.md) | [CODING_STYLE_CN.md](CODING_STYLE_CN.md) | 强制代码规范 |
| CC 移植 | [CC_PORTING.md](CC_PORTING.md) | [CC_PORTING_CN.md](CC_PORTING_CN.md) | 内核 `tcp_congestion_ops` 移植指南 |

## 源码树导览

```
include/xtcp/     公共头文件（stack.h 是入口）
src/core/         TCP FSM、IP、分片、定时器、缓冲
src/options/      Linux 风格 setsockopt 选项层
src/qdisc/        FQ / fq_codel / cake / TBF 队列规则
src/cc/           KCC、Reno、CUBIC、BBRv1 拥塞控制
include/xtcp/ndi/ 后端接口（manual、tun、tap）
plugins/ref/      用于差分测试的参考 CC 核心
tests/            237 项确定性测试套件（含 harness/）
samples/          互操作样例（基于 TUN，Linux）与 echo 演示
bench/            PERFORMANCE.md 引用的微基准
```

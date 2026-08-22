# 测试

> 语言：[English](TESTING.md) | **中文**

套件如何组织、为何确定性、在哪些平台验证过什么、以及如何扩展。英文主
版本：[TESTING.md](TESTING.md)。

## 1. 套件组织

默认配置注册 236 个测试可执行文件（第 237 个为 lwIP 差分目标，`XTCP_BUILD_LWIP=ON` 时出现），各自独立成程序，由 `tests/*.cpp` 构建并经 CTest
执行。命名对应领域：

| 前缀族 | 覆盖 |
|---|---|
| `test_tcp_fsm`、`test_seq*`、`test_state_*` | RFC 793 状态机：握手、拆除、序号回绕、状态迁移 |
| `test_sack*`、`test_dsack`、`test_rack`、`test_tlp`、`test_early_retx`、`test_fastrec*`、`test_eifel`、PRR 相关、`test_loss_recovery`、`test_rto_recovery` | 丢包恢复流水线 |
| `test_cc_*` | 拥塞控制选择、注册、各算法行为 |
| `test_qdisc*`、`test_fq`、`test_fifo`、`test_cake`、`test_fq_codel`、`test_pacing*` | 出向队列与 pacing |
| `test_mimt*` | 进程内通道，含 fill-to-want 读契约 |
| `test_tfo*`、`test_md5*`、`test_ecn*`、`test_keepalive*`、`test_window*`、`test_wscale*`、`test_nagle`、`test_urgent`、`test_user_timeout`、`test_persist*` | 选项与特性面 |
| `test_syncookie*`、`test_rst_*`、`test_challenge*`、`test_icmp_spoof`、`test_cookie_*` | 防御路径 |
| `test_frag*`、`test_frag6`、`test_ipv6_*`、`test_ip` | IP 层 v4/v6 与分片 |
| `test_gso*`、`test_tso*`、`test_gro_rx`、`test_zc_*`、`test_checksum_simd` | 数据面特性 |
| `test_shard`、`test_scale*`、`test_lock_stress`、`test_conn_churn*`、`test_thread_*`、`test_async*`、`test_combo_stress`、`test_mixed_load` | 并发与压力 |
| `test_e2e`、`test_full_stack`、`test_diff_harness`、`test_lwip_interop` | 端到端与差分层 |

每个二进制自行断言通过/失败并以非零码退出；CTest 汇总。多个套件还在退出
时断言缓冲池与配额平衡，因此即使没有 sanitizer，泄漏也会以断言失败的形式
暴露。

## 2. 确定性模型

栈的定时器由调用 `PollAckTimers` 的人驱动。测试利用了这一点：不等 RTO
真实到期，而是确定性地推进虚拟时间。推论：

- 套件可复现：相同输入、相同结果，设计上不存在抖动等待。
- 墙钟节奏不被该部分覆盖。真实时间起作用的路径（pacing 出向、速率型 CC）
  改由基准与 TUN 样例锻炼；仿真逼不得已时测试放宽截止时间。

## 3. 差分层

`tests/harness/diff_harness.h` 以脚本化场景驱动 TCP 实现并记录归一化事件
流；两个实现可以逐事件对比。`XTCP_BUILD_LWIP=ON` 时，vendored lwIP 走同样
的场景（`test_lwip_interop`）。没有 lwIP 时，harness 仍对 XTCP 自身运行
（`test_diff_harness`），机制保持被锻炼。

## 4. 验证记录

实际执行过什么、在哪棵树版本上：

| 检查 | 平台/工具链 | 结果 |
|---|---|---|
| CTest 全量套件 | Windows 11，MSVC 14.39，Release | 注册项全部通过：含可选 lwIP 目标 237/237，不含 236/236（墙钟 189 秒 / 277 秒） |
| 全量套件，静态交叉构建 | aarch64 GCC 13 under qemu-aarch64 | 237/237 通过（80+80+77 三批，零失败） |
| ASan+UBSan 全量 ×2 编译器 | Linux CI（clang++、g++） | 源码版本 `e9d5922` 全绿 |
| MSVC 全量套件 | Windows CI | 源码版本 `e9d5922` 全绿 |

已知平台注意事项，如实陈述而非隐藏：

- QEMU 单核仿真下，时序敏感测试以放宽的截止时间运行；正确性结论不受
  影响，但那里的墙钟数字不具意义。
- lwIP 差分目标以 vendored 源码存在为条件；CI 已在全部作业开启（XTCP_BUILD_LWIP=ON），本地默认构建仍为可选。

## 5. 新增测试

1. 创建 `tests/test_<领域>_<行为>.cpp`；从最接近的现有测试复制骨架
   （断言辅助、池 init/shutdown）。
2. 在 `CMakeLists.txt` 中按领域相邻位置注册。
3. 优先用确定性定时器推进而非 sleep；必须用真实时间时，把截止时间放宽，
   保证 QEMU 运行仍然有效。
4. 若测试钉住的行为与 RFC 或文档契约矛盾：修代码或记录偏差——不要为了
   通过而削弱断言。

## 6. 调试打法备忘

两条在本代码库中反复奏效的实践，记录在此防止失传：

- 打印探针会改变时序，甚至完全掩盖竞争。有效做法是零扰动的进程内环形
  缓冲，进程退出时倾倒。
- 只在 ARM/QEMU 下复现的失败：先按特性二分（关 pacing → 通过？），再变
  速率区分时序窗口与逻辑错误。mimt fill-to-want 死锁正是这样发现的——
  x86 运行把它掩盖了很久。

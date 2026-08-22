# 性能

> 语言：[English](PERFORMANCE.md) | **中文**

本文档中的每一个数字都由文中展示的命令、在下列硬件与软件版本上、于同一
工作时段内产生。原始输出已留存，并在结果表中逐字引用。没有任何数字是
推算的、跨机器平均的、或沿用旧运行的。英文主版本：
[PERFORMANCE.md](PERFORMANCE.md)。

## 1. 测试环境

### 环境 A —— Windows 主机（全部 `bench_*` 数字）

| 项目 | 值 |
|---|---|
| CPU | AMD Ryzen 9 7945HX，16 核 / 32 线程（Zen 4），基础频率 2.5 GHz |
| 内存 | 63.2 GB |
| 操作系统 | Windows 11 企业版，build 26200 |
| 电源计划 | 厂商性能档（"野兽模式"） |
| 编译器 | MSVC 14.39.33519（Visual Studio 2022 Enterprise） |
| 构建系统 | CMake 3.22.1，构建类型 `Release` |
| 相关开关 | 默认（吞吐基准关闭 `XTCP_CHECKSUM_VALIDATE`） |

### 环境 B —— WSL2 客户机（全部 TUN `interop_*` 数字）

| 项目 | 值 |
|---|---|
| 宿主 | 与环境 A 同一台物理机 |
| 客户机系统 | Ubuntu 24.04.3 LTS |
| 内核 | 6.18.33.2-microsoft-standard-WSL2 |
| 客户机可见 CPU/内存 | 32 vCPU / 30 GB（WSL2 VM 分配） |
| 编译器 | GCC 13.3.0（Ubuntu 13.3.0-6ubuntu2~24.04.1），`-O2` Release |
| TUN 设备 | `/dev/net/tun`，样例以 root 执行 |

### 环境 C —— QEMU 仿真（仅用于功能验证）

GCC 13（`aarch64-linux-gnu-g++`）aarch64 交叉构建、全静态链接，在同一
主机上以 `qemu-aarch64` 用户态仿真执行。QEMU 单核仿真会扭曲墙钟节奏，
因此**本环境不产生任何性能数字**；它的作用是证明代码在 ARM64 上正确
（237/237 测试通过）。

## 2. 每个基准测什么

| 基准 | 测量对象 | 不测量 |
|---|---|---|
| `bench_throughput` | 一对 `XtcpStack` 经进程内内存后端背靠背相连：纯 TCP 处理成本 | 网卡、内核网络栈、真实网络 |
| `bench_multi_thread` | N 线程向一个栈的 N 条不同流注入段：合成负载下的 RX 侧并发行为 | 端到端应用吞吐 |
| `bench_syn_rate` | 连接建立速率（SYN → ESTABLISHED → 拆除），单进程 | 有丢包时的握手 |
| `bench_conns` | 扫描空闲表与近期活跃表的成本 | 每连接内存占用 |
| `interop_perf` | 内核与 XTCP 经真实 TUN 设备的单向批量传输 | 多流聚合 |
| `interop_latency` | 经 TUN 的 2000 次顺序 1 KB echo 往返延迟分布 | 首包延迟、建连延迟 |
| `interop_fair` | `tbf 20mbit` + `netem delay 40ms` 整形下 4 并发流的带宽占比 | 无整形时的公平性 |

## 3. 结果

### 3.1 环回吞吐（`bench_throughput`，环境 A）

命令形态：`bench_throughput <total_bytes> <chunk_bytes> <qdisc> <quickack> [cc]`。
每配置三轮；所有轮次均列出。

| 配置 | 第 1 轮 | 第 2 轮 | 第 3 轮 | 最优 | 最优 kpps |
|---|---|---|---|---|---|
| 64 MB，1460 B 块，KCC | 24 624.86 | 24 216.44 | 24 503.81 | **24 624.86** | 3 162.6 |
| 256 MB，1460 B 块，KCC | 25 532.07 | 22 212.09 | 25 127.18 | **25 532.07** | 3 279.0 |
| 64 MB，1460 B 块，Reno | 23 972.17 | 23 057.91 | 23 055.83 | **23 972.17** | 3 078.7 |
| 128 MB，65 536 B 块，KCC | 23 741.69 | 12 096.58 | 19 627.57 | **23 741.69** | 3 124.6 |
| 64 MB，64 B 块，KCC | 1 257.63 | 1 129.59 | 1 274.92 | **1 274.92** | 3 731.6 |

如何读这些行：

- MSS 大小路径在本主机进程内维持约 24–25 Gbps。这就是栈自身在此处的
  上限：不涉及网卡、不涉及内核网络。
- KCC 与 Reno 在此规模相差约 2.7 %；两者打满同一条环回路径。
- 65 536 字节大块一行波动最大（12.1–23.7 Gbps）。大写入放大了笔记本
  CPU 的调度噪声（见 §5）。
- 64 字节写入受包速率限制：无论带宽多少约 3.7 Mpps，即每段固定成本
  占主导。

### 3.2 RX worker 扩展性（`bench_multi_thread`，环境 A）

每个 worker 向自己的流注入 200 000 段；worker 并发作用于同一个栈。

| Workers | 总段数 | 墙钟时间 | 聚合 | kpps |
|---|---|---|---|---|
| 1 | 200 000 | 0.017 s | 135.18 Gbps | 11 573.6 |
| 8 | 1 600 000 | 0.189 s | 98.92 Gbps | 8 469.3 |

八个 worker 的聚合*低于*单 worker。这是当前实现在合成注入下的实测性质，
不是定律：各 worker 的流哈希到不同分片，该运行同时锻炼跨分片并行与共享
入口路径。引用多核结论时请据此措辞（§5）。

### 3.3 连接处理（`bench_syn_rate`、`bench_conns`，环境 A）

```
bench_syn_rate: 200000 conns in 0.353s = 566149 conns/s (completed=200000)
bench_conns:    10000 conns, 2000 rounds, 0.02 us/round, 0.0 ns/conn/round (idle)
bench_conns:    10000 conns, 500 rounds, 3481.35 us/round, 348.1 ns/conn/round (dirty)
```

空闲扫描每轮 O(1)（定时器轮快速路径）；dirty 扫描按活跃状态支付每连接
成本。

### 3.4 TUN 往返延迟（`interop_latency`，环境 B）

2000 次顺序 echo 往返，1 KB 载荷，内核客户端 ↔ XTCP 服务端经
`/dev/net/tun`。两次独立执行：

| 轮次 | mean | p50 | p95 | p99 | 抖动 (σ) | 失败 |
|---|---|---|---|---|---|---|
| 1 | 205.8 µs | 204.0 µs | 233.5 µs | 266.9 µs | 21.1 µs | 0 |
| 2 | 195.6 µs | 193.6 µs | 219.6 µs | 259.8 µs | 17.2 µs | 0 |

其中包含每轮两次 TUN 设备穿越与内核客户端自身的 socket 路径；这不是纯
栈内延迟数字。

### 3.5 TUN 批量吞吐（`interop_perf`，环境 B）

16 MB 单向传输，内核发送端 ↔ XTCP 接收端经 TUN：

| 轮次 | XTCP over TUN | 内核环回基线（同命令） |
|---|---|---|
| 1 | 1 806.42 Mbps | 30 932.36 Mbps |
| 2 | 1 791.84 Mbps | 21 148.88 Mbps |

基线行是同一样例打印的内核自身环回吞吐，用于标定。XTCP-over-TUN 达到
约 1.8 Gbps，瓶颈在 TUN 字符设备拷贝路径而非 TCP 处理：同一台机器的
进程内数字约为 25 Gbps（§3.1）。

### 3.6 公平性（`interop_fair`，环境 B）

TUN 路径上 `tbf 20mbit` + `netem delay 40ms` 整形下的四条并发流，各传
2 097 152 字节：

```
[fairness] flows=4 total_mbps=18.9
flow[0] 4.78 Mbps (25.3%)   flow[1] 4.75 Mbps (25.1%)
flow[2] 4.71 Mbps (24.9%)   flow[3] 4.67 Mbps (24.7%)
Jain index = 0.9999 ; all flows completed
```

## 4. 验证背景

正确性是有条件的时性能毫无意义，因此列出产生这些数字时成立的质量门：

- 全量确定性套件：Windows MSVC Release 注册项全部通过（`ctest`；含可选
  lwIP 差分目标 237/237，不含 236/236）。
- 同一套件 aarch64 静态交叉构建：`qemu-aarch64` 下 237/237 通过
  （80/80/77 三批顺序执行，零失败）。
- 精确源码版本的 CI：Linux（clang++ 与 g++）ASan+UBSan 与 Windows MSVC
  全绿。

## 5. 有效性威胁

在你引用这些数字之前先读这里：

1. **笔记本硬件。** 环境 A 是厂商性能档下的移动版 Zen 4。热状态会让单轮
   波动数十个百分点（§3.1 可见）；正因如此才报告"三轮最优"，且每一轮都
   公布。
2. **进程内环回不是网络。** `bench_throughput` 完全排除了网卡、DMA、内核
   栈与中断。它界定的是库自身的成本；不能外推为部署吞吐。
3. **WSL2 是虚拟化的。** TUN 数字包含 hypervisor 的设备模型。裸机 Linux
   上的绝对延迟（§3.4）会不同；有意义的是同一客户机上与内核环回基线的
   *对比*。
4. **合成注入 ≠ 应用负载。** §3.2 把预构造的段灌入 RX 路径。真实负载会
   交织系统调用、定时器与用户回调。
5. **单次公平性/延迟样本。** §3.4–3.6 中标注处报告了两轮，其余为单轮。
   它们证明的是数量级层面的行为与可复现性，不是统计严格性。
6. **尚无 DPDK/EFVI 后端**，因此 TUN 路径之外的线速声明根本无从谈起。

## 6. 复现

```bash
# 环境 A（Windows，MSVC Release）
cmake -B build -G "Visual Studio 17 2022" -A x64 \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build --config Release
build\Release\bench_throughput.exe 67108864 1460 0 1        # §3.1 第 1 行
build\Release\bench_multi_thread.exe                        # §3.2
build\Release\bench_syn_rate.exe 200000                     # §3.3
build\Release\bench_conns.exe 10000 2000                    # §3.3 idle
build\Release\bench_conns.exe 10000 500 dirty               # §3.3 dirty

# 环境 B（WSL2，root 以使用 /dev/net/tun）
cmake -B build -DCMAKE_BUILD_TYPE=Release -DXTCP_BUILD_SAMPLES=ON
cmake --build build -j$(nproc)
sudo ./build/interop_latency     # §3.4
sudo ./build/interop_perf        # §3.5
sudo ./build/interop_fair        # §3.6
```

上文每张表对应的原始输出都来自本文所报告的运行；在相近硬件上重跑应落在
已公布的波动范围内。

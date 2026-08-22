# 用法

> 语言：[English](USAGE.md) | **中文**

本文是面向任务的 XTCP 使用指南：构建、把栈接入你的进程、完整的回调与
配置面、队列规则与插件。概念与内部机制见
[ARCHITECTURE_CN.md](ARCHITECTURE_CN.md)；实测数字见
[PERFORMANCE_CN.md](PERFORMANCE_CN.md)。英文主版本：
[USAGE.md](USAGE.md)。

## 1. 构建与链接

XTCP 构建为静态库（`xtcp_static`），外加可选的测试、基准、样例与插件
目标。

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DXTCP_BUILD_TESTS=ON -DXTCP_BUILD_BENCH=ON
cmake --build build -j$(nproc)          # Windows: cmake --build build --config Release
ctest --test-dir build                  # Windows: ctest --test-dir build -C Release
```

CMake 选项（默认值来自 `CMakeLists.txt`）：

| 选项 | 默认 | 作用 |
|---|---|---|
| `XTCP_BUILD_TESTS` | `ON` | 确定性测试套件（236 项目标；开 `XTCP_BUILD_LWIP` 后 +1） |
| `XTCP_BUILD_BENCH` | `OFF` | `bench_throughput`、`bench_multi_thread`、`bench_syn_rate`、`bench_conns`、`bench_multi_data`、`bench_thread_e2e` |
| `XTCP_BUILD_SAMPLES` | `OFF` | `echo` 与基于 TUN 的 `interop_*` 样例。互操作样例需要 UNIX（打开 `/dev/net/tun`） |
| `XTCP_BUILD_CC_PLUGINS` | `ON` | 把内置拥塞控制（KCC/BBRv1/CUBIC/Reno）链入静态库 |
| `XTCP_BUILD_PLUGINS` | `OFF` | 树外示例插件（动态库） |
| `XTCP_BUILD_LWIP` | `OFF` | 构建内置 lwIP 用于对称差分测试 |
| `XTCP_CHECKSUM_VALIDATE` | `OFF` | 收包校验 IPv4/TCP 校验和（SIMD 加速）。敌意输入部署建议开启 |
| `XTCP_SANITIZE` | `OFF` | Linux 下 ASan/UBSan；MSVC 下 CRT 泄漏检测 |

你的目标链接 `xtcp_static` 并添加 `include/`。多数场景一个公共头即可：
`#include <xtcp/core/stack.h>`。

## 2. 核心概念

四件事决定你如何使用这个库：

1. **每个网络身份一个 `XtcpStack`。** 以 NDI 后端构造；它终结该后端投递
   的地址上的 TCP。
2. **泵由你来驱动。** 报文经 `OnPacket` 进入；时间经 `PollAckTimers`
   推进（延迟 ACK、RTO、persist、keepalive）。从你的线程调用两者；
   库里没有隐藏的工作线程。
3. **连接 id 是不透明句柄**，同时编码了所属分片；保存它、跨线程传递它，
   每个按连接的调用都用它。
4. **回调在内部锁之外运行**，因此在 handler 里回调进栈是合法的。

## 3. 上手：同进程双栈

最小的完整程序把两个栈经内存后端背靠背相连（完整源码：
`samples/echo.cpp`）：

```cpp
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

xtcp::buf::InitPools();                       // 每进程一次，使用前

xtcp::ndi::ManualBackend server_backend, client_backend;
xtcp::XtcpStack server_stack(&server_backend);
xtcp::XtcpStack client_stack(&client_backend);

// 每个后端的 Tx 成为对端的 Rx。拷入池化缓冲——Packet 视图只在 handler
// 执行期间有效。
server_backend.SetRxHandler([&](xtcp::ndi::Packet&& p) {
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
    if (buf.IsEmpty()) return;                // 池耗尽：丢弃
    std::memcpy(buf.Data(), p.data, p.len);
    buf.SetLen(p.len);
    server_stack.OnPacket(std::move(buf));
});
// client_backend -> client_stack：同形。

// 服务端：监听、接受、回显。
xtcp::core::Endpoint laddr{};                 // 10.0.0.2:8080
laddr.family = 4;
laddr.addr[0] = 0x0A000002;
laddr.port    = 8080;
server_stack.Listen(laddr);
server_stack.SetAcceptHandler(
    [](UInt64 id, const xtcp::core::Endpoint& remote,
       const xtcp::core::Endpoint& local) { return true; /* 接纳 */ });
server_stack.SetRecvHandler([&](UInt64 id, const Byte* data, UInt32 len) {
    server_stack.Send(id, data, len);         // 回显
});

// 客户端：连接、发送、观察状态。
client_stack.SetStateHandler([&](UInt64, xtcp::core::TcpState st) {
    if (st == xtcp::core::TcpState::kEstablished) { /* 就绪 */ }
});
xtcp::core::Endpoint raddr{};                 // 对端 10.0.0.2:8080
raddr.family = 4;
raddr.addr[0] = 0x0A000002;
raddr.port    = 8080;
const UInt64 conn = client_stack.Connect(clocal, raddr);   // 0 == 失败
if (conn) {
    client_stack.Send(conn, payload, size);   // Established 之前也合法
    client_stack.Close(conn);                 // 主动关闭（FIN）
}

// 泵循环（你的线程）：把各后端的 Tx 交给对端，然后推进定时器。
while (running) {
    Byte out[65536];
    while (auto n = client_backend.PollTx(out))
        server_backend.Inject(out, n, 0x0800);
    while (auto n = server_backend.PollTx(out))
        client_backend.Inject(out, n, 0x0800);
    server_stack.PollAckTimers();
    client_stack.PollAckTimers();
}
xtcp::buf::ShutdownPools();                   // 每进程一次，所有栈消亡后
```

换成真实网卡形态的后端（Linux 上的 TUN），同一程序就能与内核自身的 TCP
对话：见 `interop_*` 样例。

## 4. 按任务组织的 API 参考

### 连接生命周期

| 任务 | 调用 |
|---|---|
| 被动打开 | `bool Listen(const Endpoint&)` |
| 接纳/拒绝入连接 | `SetAcceptHandler` 返回 `true`/`false` |
| 主动打开 | `UInt64 Connect(const Endpoint& local, const Endpoint& remote)` —— 返回 id，失败为 `0` |
| 发送字节 | `bool Send(UInt64 conn, const Byte*, UInt32)` —— 在发送配额内排队；`false` 表示被拒（已关闭或超配额） |
| 接收字节 | `SetRecvHandler(conn_id, data, len)` —— 按序字节流 |
| 紧急指针 | `SetUrgentHandler(conn_id)` |
| 状态迁移 | `SetStateHandler(conn_id, TcpState)` |
| 主动/被动关闭 | `Close(UInt64 conn)` |
| 停止监听 | `bool StopListen(const Endpoint&)` —— 仅当确实移除了监听器才返回 true |

### 查询

```cpp
xtcp::core::Endpoint local, remote;
stack.GetLocalEndpoint(conn, local);   // getsockname 等价；临时端口会填好
stack.GetRemoteEndpoint(conn, remote); // getpeername 等价

UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup_acks, fast_rec, front_seq, snd_una;
UInt16 lp, rp; UInt64 rto_deadline;
stack.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                rto_deadline, dup_acks, fast_rec, front_seq, snd_una, lp, rp);
```

### 栈级配置

| 调用 | 含义 |
|---|---|
| `SetSyncookieThreshold(n)` | 半开连接超过该数即启用 SYN cookies |
| `SetDefaultCongestionControl(name)` | 新监听器/新连接使用的 CC（`""` 回到 Reno 基线） |
| `SetDefaultEcn(bool)` | RFC 3168 协商默认态 |
| `SetDefaultNoSack(bool)` | 默认抑制 SACK-permitted（见选项表） |
| `SetTxQdisc(qdisc*)` | 挂载/卸载出向 qdisc（见 §7） |

## 5. NDI 后端

后端实现三件事：`Tx`（发出一个完整 IP 包）、`SetRxHandler`（投递收到的
包）、`Caps`（校验和卸载等能力声明）。`include/xtcp/ndi/manual.h` 的进程内
`ManualBackend` 是参考实现，测试与基准都驱动它。具体的 Linux TUN 驱动以
样例代码交付（`samples/tun2socks/tun_ndi.cpp`）而非库的一部分——库在设计上
与驱动无关。DPDK 与 OpenOnload（EFVI）后端为预留接口，尚未存在。

## 6. 拥塞控制

`XTCP_BUILD_CC_PLUGINS=ON`（默认）时内置算法自动注册：KCC（默认）、Reno、
CUBIC、BBRv1。

```cpp
xtcp::cc::RegisterKcc();      // 构建选项开启时通常隐式完成
xtcp::cc::RegisterBbrv1();
xtcp::cc::RegisterCubic();
stack.SetDefaultCongestionControl("bbr");   // 按名选择
```

选择按监听器生效；切换算法只影响新连接，存量连接不受触碰。移植其他内核
算法遵循 [CC_PORTING_CN.md](CC_PORTING_CN.md)：照抄 ops 表形态，把内核类型
替换为 `XtcpConnCc*`。

## 7. 队列规则

FQ 是默认出向规则（内核 `sch_fq` 语义：每流队列 + pacing）。内置：
`RegisterFqDefault()`、`RegisterFqCoDel()`（每流 FIFO + CoDel AQM）、
`RegisterCake()`（每流 DRR + Cobalt AQM），另有 TBF。

```cpp
xtcp::qdisc::RegisterFqDefault();                       // 幂等
xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", &params);
stack.SetTxQdisc(q);                                    // 挂载
stack.SetTxQdisc(nullptr);                              // 卸载：直接发送
```

热切换 qdisc 时旧队列自然排空，不丢弃存量流。关闭的连接经 `remove_flow`
回收其排队段，使发送记账保持精确。自定义规则经
`xtcp::qdisc::RegisterQdisc` 注册；`tests/test_fifo.cpp` 是最小完整示例。

## 8. 每连接选项

Linux `setsockopt` 风格 id（`include/xtcp/options/options.h`）：

```cpp
Int32 v = 1;
stack.SetOption(conn, xtcp::options::kTcpNodelay, &v, sizeof(v));
```

| Id | 名称 | 语义 |
|---|---|---|
| 1 | `kTcpNodelay` | 关闭 Nagle |
| 2 | `kTcpMaxseg` | MSS 钳制 |
| 3 | `kTcpCork` | 接受但 **v1 为空操作** |
| 4/5/6 | `kTcpKeepidle/Keepintvl/Keepcnt` | keepalive 调参 |
| 7 | `kTcpSynCnt` | SYN 重试次数 |
| 9 | `kTcpDeferAccept` | 有数据前推迟 accept |
| 12 | `kTcpQuickack` | 暂时禁用延迟 ACK |
| 18 | `kTcpUserTimeout` | 过久未确认即中止 |
| 23 / 30 | `kTcpFastopen` / `kTcpFastopenConnect` | 服务端 cookie / 客户端 TFO |
| 64 | `kTcpEcn` | RFC 3168 协商 |
| 65 | `kTcpNoSackPermitted` | SYN 上抑制 SACK-permitted：该连接无 SACK 运行（RACK 关闭，小损失由 RFC 5827 Early Retransmit 覆盖）——对齐 `sysctl net.ipv4.tcp_sack=0` |

## 9. mimt 通道

对进程内流（VPN 用户面、正向代理、流量审计），mimt 无需合成报文即可暴露
类 TCP 流。读操作以 fill-to-want 语义完成：连续排空已排队 chunk 到你的
缓冲，只有队列为空才允许短读——一个被接受的读恰好对应一次完成。精确契约
及其理由见 ARCHITECTURE_CN §11。

## 10. 基准

```bash
./bench_throughput <total_bytes> <chunk> [qdisc_mode] [quickack] [cc] [sleep_us]
# 每轮 JSON 行 + 最优汇总。
#   qdisc_mode: 0 无, 1 fq+pacing, 2 fq, -1 null-qdisc
#   cc: kcc（默认）| reno | cubic | bbr
#   sleep_us: 泵轮次间停顿。速率型 CC（BBR/CUBIC）需要轮间真实时间；
#             零延迟忙环会低估它们。丢包型 KCC/Reno 不受影响。
./bench_multi_thread            # RX 注入，1 vs 8 worker
./bench_syn_rate [conns]        # 建连速率
./bench_conns [conns] [rounds] [idle|dirty]
```

方法学与已公布结果：[PERFORMANCE_CN.md](PERFORMANCE_CN.md)。

## 11. 故障排查

- **完全没有流量**：确认泵循环同时调用了 `OnPacket`（入口）与
  `PollAckTimers`（定时器）。没人泵的栈既不会重传也不会 ACK。
- **`Connect` 返回 0**：本地端点冲突，或后端没有双向接线。
- **Send 立即返回 false**：发送配额（默认 64 KiB）已满或连接已不存在；
  查 `ConnStats`。
- **BBR/CUBIC 在 `bench_throughput` 中远低于公布数字**：传
  `sleep_us > 0`；零延迟循环会让速率型算法吃不饱（§10）。

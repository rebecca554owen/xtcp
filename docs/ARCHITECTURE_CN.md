# 架构

> 语言：[English](ARCHITECTURE.md) | **中文**

本文描述 XTCP 的实际构造：分层、线程、数据路径、状态机、插件接口与加锁
规则。文中每一条陈述都对应 `src/` 与 `include/xtcp/` 中的代码；凡设计选择
有代价之处，代价一并写明。英文主版本：[ARCHITECTURE.md](ARCHITECTURE.md)。

## 1. 系统总览

XTCP 是进程内库，不是守护进程。一个 `XtcpStack` 实例持有一组固定分片；
每个分片独占哈希到它的全部流的可变状态。数据路径上没有共享连接表，也没有
共享锁。

```mermaid
flowchart TB
    subgraph APP["应用进程"]
        direction TB
        TH["应用线程<br/>Connect / Send / Close / 回调"]
        subgraph STACK["XtcpStack"]
            direction TB
            SH0["分片 0<br/>流表 · 定时器 · 内存池 · 1 把锁"]
            SH1["分片 1<br/>流表 · 定时器 · 内存池 · 1 把锁"]
            SHN["...<br/>共 kShardCount = 8 个"]
            IP["IP 层 v4 / v6<br/>分片重组 · 路由钩子"]
            TXQ["qdisc 层<br/>FQ（默认）· fq_codel · cake · TBF"]
        end
        NDI["NDI 后端<br/>manual（进程内）· TUN · TAP"]
    end
    TH <-->|"回调 + 调用"| STACK
    SH0 --> IP
    SH1 --> IP
    SHN --> IP
    IP --> TXQ --> NDI
    NDI -->|OnPacket| IP
```

各层职责边界：

| 层 | 拥有 | 不拥有 |
|---|---|---|
| NDI 后端 | 与外部世界的报文收发 | 任何协议状态 |
| qdisc | 出向排序、pacing 速率、AQM 丢弃 | 流控制块 |
| IP | 地址、分片/重组、TTL、校验和 | TCP 状态 |
| 分片 | 其流的流表、定时器、缓冲池 | 其他分片的流 |
| TCP 连接 | 序号空间、窗口、重传队列、CC 状态 | 相邻连接 |

## 2. 线程模型

默认配置下 XTCP 不自行产生数据面线程。应用以一或多个线程驱动栈：

- **调用线程**执行 `Connect`、`Send`、`Close`、`Listen`。这些调用可并发；
  每次调用获取目标分片的锁。
- **泵线程**经 `OnPacket` 送入报文，并调用 `PollAckTimers` 推进时间
  （延迟 ACK、RTO、persist、keepalive）。单线程即可泵全部；多线程可并发
  泵不同分片，因为分片之间不共享锁。
- 异步 API（`include/xtcp/async.h`）为每个栈增加一个事件循环，用
  `async_mutex` 串行化完成事件；它是可选的。

必须言明的推论：吞吐取决于调用方的泵送。PERFORMANCE.md 的基准都在紧循环
中驱动栈——那些数字背后没有任何隐藏的工作线程。

## 3. 分片与连接标识

连接在创建时定一次位，之后永不迁移：

```mermaid
flowchart LR
    K["流键<br/>(src ip, src port, dst ip, dst port)"] --> H1["scheduler_hash::HashFlowKey"]
    H1 --> H2["MurmurHash3 fmix64 终结器<br/>（雪崩化，避免连续端口<br/>塌缩到同一分片）"]
    H2 --> M["% kShardCount (= 8)"]
    M --> S["分片索引"]
```

`Connect` 返回的 64 位连接 id 在最高字节编码了分片号：
`(conn_id >> 56) % kShardCount` 无需任何查找即可还原分片。这使得回调分发
为 O(1)，也让多线程应用仅凭 id 就能路由工作。

哈希终结器为何必要：顺序分配的临时端口产生的键只在低位不同。不做雪崩
混合时，这些位在 `% 8` 下消失，几乎所有流都会落到分片 0。fmix64 终结器
把它们打散；`tests/test_scale_shard_balance.cpp` 断言顺序端口扰动下的分布
保持在界内。

## 4. 接收路径

```mermaid
sequenceDiagram
    participant NET as NDI 后端
    participant ST as XtcpStack
    participant IP as IP 层
    participant SH as 分片（按哈希）
    participant TC as TcpConn
    participant APP as 应用回调

    NET->>ST: OnPacket(BufRef)
    ST->>ST: 解码链路/Ethertype，长度校验
    ST->>IP: IPv4/IPv6 输入
    IP->>IP: 头部检查，必要时分片重组
    IP->>SH: 按四元组哈希分流
    SH->>TC: 查流表（单把分片锁）
    alt 流存在
        TC->>TC: RFC 793 段处理：<br/>序号检查、PAWS、ACK 处理、<br/>乱序入队或按序交付
        TC->>APP: RecvHandler(id, data, len)
        TC-->>SH: ACK / dupack 决策
    else 无流
        SH->>SH: 监听套接字匹配、SYN cookie 检查、<br/>或 RST 策略
    end
    SH-->>NET: 出向入队（见 §5）
```

由该结构直接得到的性质：

- 一个报文恰好触碰一把分片锁，一次。
- 乱序段缓存在接收配额内（每连接默认 64 KiB），按序交付；超限即丢弃，
  由重传恢复，绝不无界增长。
- 校验和按需验证：`XTCP_CHECKSUM_VALIDATE=ON` 时启用 SIMD 加速
  （x86 用 SSSE3/AVX2，ARM64 用 NEON，运行时探测）；后端已保证完整性时
  （manual 后端）跳过。

## 5. 发送路径

```mermaid
sequenceDiagram
    participant APP as 应用线程
    participant TC as TcpConn
    participant Q as qdisc（按监听器）
    participant NET as NDI 后端

    APP->>TC: Send(id, data, len)
    TC->>TC: 按 MSS 分段（或 GSO 大段），<br/>拷入池化缓冲，追加重传队列
    TC->>Q: enqueue(packet, flow_id)
    Q->>Q: FQ 记账：每流队列、丢弃策略
    loop 到期的 paced 报文
        APP->>Q: dequeue(now) -> next_pacing 截止时间
        Q-->>TC: BufRef packet
        TC->>NET: Tx 下沉（后端写 TUN / 对端 Inject）
    end
    Note over TC,Q: pacing 速率来自 CC；<br/>qdisc 按流强制执行
```

设计要点：

- 分段发生在入队之前，因此重传队列保存的正是需要重发的内容。GSO 风格的
  大块发送按 MSS 边界切分；TSO 路径在后端可卸载时推迟切分。
- qdisc 属于监听器且可热切换：fq → cake 的切换立即作用于新流量，旧队列
  自然排空而非丢弃存量流。
- 每流 pacing 速率由拥塞控制写入，由 qdisc 的
  `dequeue(now, next_pacing)` 契约强制执行；栈从不空转等待 pacing 截止。

## 6. 缓冲管理

所有载荷以 `BufRef` 句柄移动：指向池化 slab 的引用计数视图。拷贝只发生
在定义好的边界上（后端入口、用户 `Send`），内部阶段之间零拷贝。

```mermaid
stateDiagram-v2
    [*] --> Pooled: slab 分配
    Pooled --> Acquired: BufRef Acquire(len)
    Acquired --> Cloned: Clone() 引用计数+1
    Cloned --> Acquired: 释放一个引用
    Acquired --> Released: 最后一次 Release()
    Released --> Pooled: 归还分片池
    Pooled --> [*]: ShutdownPools()
```

实现强制的规则：

- 每个分片从自己的池分配；跨分片交接传递句柄，缓冲可以比来源分片活得久，
  但始终记在持有它的连接账上。
- 每连接配额限定内存：默认发送缓冲 64 KiB、乱序缓冲 64 KiB
  （`kDefaultSndBuf = 65536`），即每条存活连接最坏约 129 KiB 加固定块开销。
- 池耗尽是硬信号：`Acquire` 返回空句柄，报文被丢弃。栈宁可丢包也不扩容，
  这正是洪泛下内存上限依然成立的原因。

## 7. TCP 状态机

```mermaid
stateDiagram-v2
    [*] --> Listen : Listen()
    Listen --> SynRcvd : SYN -> SYN-ACK
    SynRcvd --> Established : ACK
    Listen --> Listen : 洪泛时签发 SYN cookie
    [*] --> SynSent : Connect()
    SynSent --> Established : SYN-ACK -> ACK
    SynSent --> Closed : RST / 重试耗尽
    Established --> FinWait1 : 主动 Close()（FIN）
    FinWait1 --> FinWait2 : FIN 的 ACK
    FinWait1 --> Closing : 收到 FIN
    FinWait2 --> TimeWait : 收到 FIN
    Closing --> TimeWait : FIN 的 ACK
    TimeWait --> Closed : 2MSL 定时器
    Established --> CloseWait : 被动关闭（收到 FIN）
    CloseWait --> LastAck : Close()（发出 FIN）
    LastAck --> Closed : FIN 的 ACK
    Established --> Closed : 任一侧 RST
```

教科书状态机之外的健壮性：

- RFC 5961 对盲 RST/SYN 攻击回应 challenge ACK；窗口外的 RST 被应答而
  不是被执行。
- SYN-RCVD 上捎带的数据被接受；客户端侧在 `Established` 之前排队的数据
  在握手完成后立即发出（完整客户端语义）。
- 序号回绕全程用串行算术处理；数据与 RST 边界的回绕均有专项测试。

## 8. 丢包恢复流水线

每个 ACK 之后按固定次序运行丢包判定：

```mermaid
flowchart TB
    A["ACK 处理完成"] --> B{"重复 ACK？"}
    B -- 是 --> C["计数 dupacks；<br/>达 3 触发快速重传<br/>（RFC 6582 形态）"]
    B -- 否 --> D{"RACK：最近一次重传<br/>可证已丢失？（RFC 8985）"}
    D -- 是 --> E["标记 >= lost seq 的段"]
    C --> F{"处于恢复态？"}
    E --> F
    D -- 否 --> G{"TLP 探测到期？(RFC 8985)<br/>2*SRTT 无 ACK"}
    G -- 是 --> H["发送一个探测段"]
    G -- 否 --> I{"Early Retransmit<br/>(RFC 5827)：在途很少时<br/>降低 dupthresh"}
    F -- 进入恢复 --> J["PRR (RFC 6937)：cwnd<br/>朝 ssthresh 平滑升降<br/>而非盲目减半"]
    F -- 判定为伪重传 --> K["D-SACK undo (RFC 2883)<br/>+ Eifel (RFC 3522) 还原 cwnd"]
    J --> L["重传被标记的段，<br/>从重传队列零拷贝克隆"]
    K --> L
```

重传队列存的是 `BufRef` 句柄，重传克隆引用而不拷贝字节。伪重传检测有两条
独立信号（D-SACK 反馈与 Eifel 时间戳检查），任一都可触发 cwnd 还原。

## 9. 拥塞控制插件

CC 算法通过与 Linux 内核 `tcp_congestion_ops` 同形的操作表接入，移植工作
直接从内核源码出发并保持其结构：

```mermaid
classDiagram
    class XtcpCongestionOps {
        +const char* name
        +init(sk)
        +release(sk)
        +ssthresh(sk) UInt32
        +cong_avoid(sk, ack, acked)
        +set_state(sk, new_state)
        +cwnd_event(sk, ev)
        +pkts_acked(sk, sample)
        +undo_cwnd(sk) UInt32
        +cong_control(sk, rate_sample)
        +reinit_ssthresh(sk) UInt32
    }
    class KCC
    class Reno
    class Cubic
    class BBRv1
    XtcpCongestionOps <|.. KCC : 默认
    XtcpCongestionOps <|.. Reno
    XtcpCongestionOps <|.. Cubic
    XtcpCongestionOps <|.. BBRv1
```

注册显式且即时生效：`RegisterCongestionControl(ops)` 使算法可按名选用；
仍有连接使用时拒绝注销。选择按监听器生效，切换算法只影响新连接，不触碰
存量连接。`RateSample` 向 BBRv1 这类带宽时延积算法提供与内核相同的信息。

## 10. 队列规则插件

```mermaid
classDiagram
    class XtcpQdiscOps {
        +const char* name
        +init(q, params) int
        +destroy(q)
        +enqueue(q, flow_id, packet) int
        +dequeue(q, now, next_pacing) BufRef
        +has_backlog(q) bool
        +change(q, params) int
        +reset(q)
        +set_pacing_rate(q, flow_id, bps) int
        +get_pacing_rate(q, flow_id) UInt64
        +remove_flow(q, flow_id) int
    }
    class FQ
    class FqCodel
    class Cake
    class TBF
    XtcpQdiscOps <|.. FQ
    XtcpQdiscOps <|.. FqCodel
    XtcpQdiscOps <|.. Cake
    XtcpQdiscOps <|.. TBF
```

`dequeue(now, next_pacing)` 契约是集成的核心：qdisc 可以在 pacing 时间未到
时拒交报文，并报告下次可发时刻。栈视该截止时间为权威并据此安排下一次
轮询。`remove_flow` 让关闭中的连接确定性地回收排队段（返回的被丢弃段数
进入 tx 记账），这使关闭期清理精确而非泄漏。

## 11. mimt 通道

mimt（"multiplexed in-memory transport"，进程内多路传输）在同一进程的
组件间暴露类 TCP 流，不合成报文：读写直接在流对象之间移动缓冲。

```mermaid
sequenceDiagram
    participant W as 写线程
    participant WF as MimtFlow（写侧）
    participant RF as MimtFlow（读侧）
    participant R as 读线程

    W->>WF: Write(buf, len)
    WF->>RF: chunk 移入 rx 队列
    RF-->>R: AsyncRead 完成
    Note over RF,R: fill-to-want 语义：<br/>连续排空 chunk 直到<br/>want 字节或队列空；<br/>只有队列空才允许短读
    R->>RF: Read 返回 n < want
    RF-->>R: 重新挂起；下一次 Write 将其完成
    W->>WF: Close()
    WF->>RF: EOF 在排队字节之后传播
    RF-->>R: 挂起的读以 0 完成（EOF）
```

fill-to-want 规则的存在理由：部分完成若消费掉挂起的读，会让等待全长后才
重新挂起的调用方死锁（这是差分 ARM 测试发现的真实死锁；见 TESTING.md）。
一个被接受的读恰好对应一次完成。

## 12. 加锁规则

锁共三类。以下获取次序是全局的，代码中不存在其他次序。

```mermaid
flowchart LR
    SL["分片锁"] --> AM["async_mutex<br/>（仅异步 API 使用）"]
    SL --> FL["flow sync_<br/>（每连接）"]
```

- **分片锁**：保护流表与分片级记账。持有区间短且有界。
- **flow `sync_`**：保护单连接可变状态。在分片锁之后获取，绝不在其前。
- **`async_mutex`**：串行化异步 API 的完成投递。在分片锁之后获取，绝不
  在其前。

无死锁论证：上图无环，且 `src/` 中所有多锁路径都按所列次序获取（已审计；
并发路径的压力测试见 TESTING.md）。回调在所有锁之外运行：handler 被调用
时分片锁已释放，因此用户代码回调进栈不会死锁。

## 13. 设计决策及其代价

| 决策 | 收益 | 代价 |
|---|---|---|
| 固定 8 分片，创建时定位 | 无迁移竞争；凭 id O(1) 分发 | 哈希偏斜即负载偏斜；用雪崩哈希缓解，测试断言 |
| 每分片单锁 | 推理简单，数据面无锁序问题 | 同一分片多线程时争用；RX 扩展数字中可见 |
| 全程零拷贝 `BufRef` | 重传与跨分片交接免拷贝 | 需要句柄纪律；池耗尽意味着丢弃而非增长 |
| 内核同形插件表 | 移植贴近参考源码 | 接口略宽于严格所需 |
| 虚拟时钟确定性测试 | CI 可复现；时序 bug 只可能藏在实时路径 | 实时行为需另行测量（PERFORMANCE.md） |
| 过载时丢弃而非增长 | 每连接内存硬上限 | 极端过载下吞吐退化而非延迟退化 |

## 14. 有意缺席的部分

- 尚无 DPDK/EFVI 后端：接口预留，实现未写。现有后端为 manual（进程内）、
  TUN、TAP。
- 无 UDP、无 socket-fd 仿真、无 POSIX 兼容层。
- `TCP_CORK` 可解析接受但 v1 中不改变任何行为。
- 流的分片间热迁移已有设计（GOALS.md），尚未接入生产路径。

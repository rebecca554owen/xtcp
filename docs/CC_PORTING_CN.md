# XTCP 内核 CC 移植指南

> 语言：[English](CC_PORTING.md) | **中文**

> 中文版。英文：`docs/CC_PORTING.md`。

如何把 Linux 内核拥塞控制模块（如 `tcp_bbr.c`、`tcp_cubic.c`、`tcp_kcc.c`）移植进 XTCP，且算法逻辑与常数零改动。

## 1. 挂钩表

XTCP 的 `XtcpCongestionOps`（include/xtcp/cc/cc.h）与 Linux `struct tcp_congestion_ops` 逐字段镜像：

| 内核字段 | XTCP 字段 | 说明 |
|---|---|---|
| `.name` | `name` | 算法名（`cc=<name>` 选择） |
| `.init` | `init` | 连接创建时 |
| `.release` | `release` | 连接销毁时 |
| `.ssthresh` | `ssthresh` | 慢启动阈值 |
| `.cong_avoid` | `cong_avoid` | 经典 cwnd 计算 |
| `.set_state` | `set_state` | CA 状态转换 |
| `.cwnd_event` | `cwnd_event` | CA 事件（丢包/ECN/ACK...） |
| `.pkts_acked` | `pkts_acked` | ACK 采样（RTT/delivered） |
| `.undo_cwnd` | `undo_cwnd` | 恢复撤销 |
| `.cong_control` | `cong_control` | 新式直接 pacing/cwnd 控制（BBR/KCC） |
| `.reinit_ssthresh` | `reinit_ssthresh` | ssthresh 重初始化 |

## 2. 字段等价

内核 CC 使用的 `tcp_sock` 字段映射到 `XtcpConnCc`（同名同语义）：`snd_cwnd`、`snd_ssthresh`、`pacing_rate`、`delivered`、`delivered_mstamp`、`lost`、`lsndtime`、`srtt_us`、`mdev_us`、`mss`、`rtt_min_us`、`rcv_wnd`、`snd_wnd`、`inflight`、`app_limited`。算法私有状态放 `ca_priv`（算法拥有）。

## 3. 移植步骤

```mermaid
flowchart LR
    A[复制内核源文件到 plugins/] --> B[sk 类型替换为 XtcpConnCc]
    B --> C[ca_priv 私有状态 + init/release]
    C --> D[内核 helper 逐项替换]
    D --> E[打包 XtcpCongestionOps + 注册]
    E --> F[提取纯计算核心为 C 参考]
    F --> G[差分驱动验证 ≤1% 容差]
```

1. 复制内核源文件到 `plugins/`。
2. 把 `struct sock *sk` 换成 `XtcpConnCc *sk`。
3. 把 `inet_csk_ca(sk)`/`tcp_sk(sk)` 私有状态访问换成 `static_cast<BbrState*>(sk->ca_priv)`（在 `init` 分配）。
4. 替换内核辅助：`tp->snd_cwnd`→`sk->snd_cwnd`；`tcp_sk(sk)->srtt_us`→`sk->srtt_us`；`tcp_mss_to_mtu`→`sk->mss`；`tcp_snd_wnd`→`sk->snd_wnd`；`tcp_reno_ssthresh`→`ssthresh = cwnd/2`。
5. 包装成 `const XtcpCongestionOps` 表并注册：`RegisterCongestionControl(ops)`。
6. 添加 `RegisterXxx()` 并在栈启动时调用。
7. 保真：把纯计算核心提取为 C 参照（`plugins/ref/`），用差分驱动（test_cc_bbr.cpp 的模式）跑确定性 ACK 序列比对。

## 4. 保真契约

- 算法常数逐字取自内核源码。
- 决策逻辑不变；只替换内核依赖。
- 差分测试逐样本比对 cwnd/pacing/mode（1% 容差）。
- `plugins/cc_cubic.cpp` 演示经典路径移植；`plugins/cc_bbrv1.cpp` 演示 cong_control 路径。

## 5. 单位约定

XTCP CC 使用统一约定（参照核心与移植版一致）：
- `bw` 样本：字节/秒 × `UNIT`（1,000,000），按 `delivered * UNIT / interval_us` 计算。
- `bdp`/cwnd 输出：包数（`bdp_bytes / mss + 1`）。
- `pacing_rate`：字节/秒。

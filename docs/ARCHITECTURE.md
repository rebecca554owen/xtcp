# Architecture

> Language: **English** | [中文](ARCHITECTURE_CN.md)

This document describes how XTCP is actually built: layers, threading,
data paths, state machines, plugin interfaces, and locking rules. Every
statement here maps to code in `src/` and `include/xtcp/`; where a design
choice has a cost, the cost is stated. Chinese version:
[ARCHITECTURE_CN.md](ARCHITECTURE_CN.md).

## 1. System overview

XTCP is an in-process library, not a daemon. One `XtcpStack` instance owns
a fixed set of shards; each shard owns all mutable state for the flows
hashed onto it. There is no shared connection table and no shared lock on
the data path.

```mermaid
flowchart TB
    subgraph APP["Application process"]
        direction TB
        TH["Application threads<br/>Connect / Send / Close / callbacks"]
        subgraph STACK["XtcpStack"]
            direction TB
            SH0["Shard 0<br/>flow table · timers · pools · 1 lock"]
            SH1["Shard 1<br/>flow table · timers · pools · 1 lock"]
            SHN["...<br/>kShardCount = 8 total"]
            IP["IP layer v4 / v6<br/>fragment reassembly · routing hooks"]
            TXQ["qdisc layer<br/>FQ (default) · fq_codel · cake · TBF"]
        end
        NDI["NDI backend<br/>manual (in-memory) · TUN · TAP"]
    end
    TH <-->|"callbacks + calls"| STACK
    SH0 --> IP
    SH1 --> IP
    SHN --> IP
    IP --> TXQ --> NDI
    NDI -->|OnPacket| IP
```

Layer responsibilities:

| Layer | Owns | Does not own |
|---|---|---|
| NDI backend | Packet I/O with the outside world | Any protocol state |
| qdisc | Egress ordering, pacing rate, AQM drops | Flow control blocks |
| IP | Addresses, fragmentation/reassembly, TTL, checksums | TCP state |
| Shard | Flow table, timers, buffer pools for its flows | Other shards' flows |
| TCP connection | Sequence space, windows, retransmit queue, CC state | Neighbor connections |

## 2. Threading model

XTCP does not spawn data-path threads of its own in the default
configuration. The application drives the stack from one or more threads:

- **Caller threads** invoke `Connect`, `Send`, `Close`, `Listen`. These are
  safe to call concurrently; each call takes the destination shard's lock.
- **Pump threads** deliver packets via `OnPacket` and advance time by
  calling `PollAckTimers` (delayed ACKs, RTO, persist, keepalive). A single
  thread can pump everything; multiple threads may pump different shards
  concurrently because shards do not share locks.
- The async API (`include/xtcp/async.h`) adds an event loop per stack that
  serializes completions through an `async_mutex`; it is optional.

Consequence worth stating: throughput depends on the caller pumping. The
benchmarks in PERFORMANCE.md drive the stack in tight loops; there is no
hidden worker thread producing those numbers.

## 3. Sharding and connection identity

A connection is placed once, at creation, and never migrates:

```mermaid
flowchart LR
    K["Flow key<br/>(src ip, src port, dst ip, dst port)"] --> H1["scheduler_hash::HashFlowKey"]
    H1 --> H2["MurmurHash3 fmix64 finalizer<br/>(avalanche so sequential ports<br/>do not collapse onto one shard)"]
    H2 --> M["% kShardCount (= 8)"]
    M --> S["Shard index"]
```

The 64-bit connection id returned by `Connect` encodes the shard in its
top byte: `(conn_id >> 56) % kShardCount` recovers the shard without any
lookup. This makes handler dispatch O(1) and lets a multi-threaded
application route work by id alone.

Why the hash finalizer matters: ephemeral ports allocated sequentially
produce keys that differ only in low bits. Without avalanche mixing, those
bits vanish under `% 8` and nearly every flow lands on shard 0. The fmix64
finalizer spreads them; `tests/test_scale_shard_balance.cpp` asserts the
distribution stays within bounds under sequential-port churn.

## 4. Receive path

```mermaid
sequenceDiagram
    participant NET as NDI backend
    participant ST as XtcpStack
    participant IP as IP layer
    participant SH as Shard (hashed)
    participant TC as TcpConn
    participant APP as Application callback

    NET->>ST: OnPacket(BufRef)
    ST->>ST: decode link/Ethertype, validate length
    ST->>IP: IPv4/IPv6 input
    IP->>IP: header checks, reassembly if fragmented
    IP->>SH: demux by 4-tuple hash
    SH->>TC: lookup flow table (single shard lock)
    alt flow exists
        TC->>TC: RFC 793 segment processing:<br/>seq checks, PAWS, ACK processing,<br/>OOO queue insert or in-order accept
        TC->>APP: RecvHandler(id, data, len)
        TC-->>SH: ACK / dupack decision
    else no flow
        SH->>SH: listen socket match, SYN cookie check,<br/>or RST policy
    end
    SH-->>NET: egress queued (see §5)
```

Properties that follow from this structure:

- A packet touches exactly one shard lock, once.
- Out-of-order segments are buffered up to the receive quota (default
  64 KiB per connection) and delivered in order; excess is dropped and
  recovered by retransmission, never by unbounded growth.
- Checksums are validated lazily: SIMD-accelerated (SSSE3/AVX2 on x86,
  NEON on ARM64, runtime-detected) when `XTCP_CHECKSUM_VALIDATE=ON`,
  skipped when the backend already guarantees integrity (manual backend).

## 5. Transmit path

```mermaid
sequenceDiagram
    participant APP as Application thread
    participant TC as TcpConn
    participant Q as qdisc (per listener)
    participant NET as NDI backend

    APP->>TC: Send(id, data, len)
    TC->>TC: segmentation to MSS (or GSO super-segment),<br/>copy into pooled buffers, append retransmit queue
    TC->>Q: enqueue(packet, flow_id)
    Q->>Q: FQ bookkeeping: per-flow queue, drop policy
    loop while paced packet is due
        APP->>Q: dequeue(now) -> next_pacing deadline
        Q-->>TC: BufRef packet
        TC->>NET: Tx sink (backend writes to TUN / peer Inject)
    end
    Note over TC,Q: pacing rate comes from CC.<br/>qdisc enforces it per flow
```

Design points:

- Segmentation happens before enqueue, so the retransmit queue holds
  exactly what must be re-sent. GSO-style large sends are split at MSS
  boundaries; the TSO path defers splitting to the backend when it can
  offload.
- The qdisc is per-listener and hot-swappable: changing fq → cake affects
  new traffic immediately and drains old queues naturally instead of
  dropping live flows.
- Per-flow pacing rates are written by congestion control and enforced by
  the qdisc's `dequeue(now, next_pacing)` contract; the stack never spins
  waiting for a pacing deadline.

## 6. Buffer management

All payload moves inside `BufRef` handles: reference-counted views into
pooled slabs. Copies happen at defined boundaries (backend ingress, user
`Send`), never between internal stages.

```mermaid
stateDiagram-v2
    [*] --> Pooled: slab allocated
    Pooled --> Acquired: BufRef Acquire(len)
    Acquired --> Cloned: Clone() refcount + 1
    Cloned --> Acquired: release one reference
    Acquired --> Released: last Release()
    Released --> Pooled: returned to shard pool
    Pooled --> [*]: ShutdownPools()
```

Rules the implementation enforces:

- Each shard allocates from its own pool; cross-shard handoff transfers a
  handle, so a buffer can outlive its originating shard but is accounted
  against the connection that holds it.
- Per-connection quotas bound memory: send buffer 64 KiB and out-of-order
  buffer 64 KiB by default (`kDefaultSndBuf = 65536`), i.e. roughly 129 KiB
  worst-case per live connection plus fixed block overhead.
- Pool exhaustion is a hard signal: `Acquire` returns an empty handle and
  the packet is dropped. The stack prefers dropping over growing, which is
  what makes the memory ceiling hold under flood.

## 7. TCP state machine

```mermaid
stateDiagram-v2
    [*] --> Listen : Listen()
    Listen --> SynRcvd : SYN -> SYN-ACK
    SynRcvd --> Established : ACK
    Listen --> Listen : SYN cookie issued under flood
    [*] --> SynSent : Connect()
    SynSent --> Established : SYN-ACK -> ACK
    SynSent --> Closed : RST / retries exhausted
    Established --> FinWait1 : active Close() (FIN)
    FinWait1 --> FinWait2 : ACK of FIN
    FinWait1 --> Closing : FIN received
    FinWait2 --> TimeWait : FIN received
    Closing --> TimeWait : ACK of FIN
    TimeWait --> Closed : 2MSL timer
    Established --> CloseWait : passive close (FIN received)
    CloseWait --> LastAck : Close() (FIN sent)
    LastAck --> Closed : ACK of FIN
    Established --> Closed : RST either side
```

Hardening beyond the textbook machine:

- RFC 5961 challenge ACKs for blind RST/SYN attacks; out-of-window RSTs
  are answered, not obeyed.
- Data arriving on SYN-RCVD is accepted (piggybacked payloads), and data
  queued before `Established` on the client side is transmitted once the
  handshake completes (full client semantics).
- Sequence-number wraparound is handled by serial arithmetic throughout;
  dedicated tests cover wrap at both data and RST boundaries.

## 8. Loss recovery pipeline

Loss detection runs as ordered decision points after each ACK:

```mermaid
flowchart TB
    A["ACK processed"] --> B{"duplicate ACK?"}
    B -- yes --> C["count dupacks,<br/>3 -> fast retransmit<br/>(RFC 6582 shape)"]
    B -- no --> D{"RACK: was the most recent<br/>retransmission provably lost?<br/>(RFC 8985)"}
    D -- yes --> E["mark skbs >= lost seq"]
    C --> F{"in recovery?"}
    E --> F
    D -- no --> G{"TLP probe due? (RFC 8985)<br/>no ACK in 2*SRTT"}
    G -- yes --> H["send one probe segment"]
    G -- no --> I{"Early Retransmit<br/>(RFC 5827): few in-flight,<br/>dupack threshold lowered"}
    F -- entering --> J["PRR (RFC 6937): pace cwnd<br/>down/up toward ssthresh<br/>instead of halving blindly"]
    F -- spurious detected --> K["D-SACK undo (RFC 2883)<br/>+ Eifel (RFC 3522) restore cwnd"]
    J --> L["retransmit marked segments,<br/>zero-copy clones from retransmit queue"]
    K --> L
```

The retransmit queue stores `BufRef` handles, so retransmission clones a
reference instead of copying bytes. Spurious-retransmission detection runs
on two independent signals (D-SACK feedback and the Eifel timestamp
check); either can trigger cwnd restoration.

## 9. Congestion-control plugins

CC algorithms plug in through an operations table shaped like the Linux
kernel's `tcp_congestion_ops`, so a port starts from the kernel source and
keeps its structure:

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
    XtcpCongestionOps <|.. KCC : default
    XtcpCongestionOps <|.. Reno
    XtcpCongestionOps <|.. Cubic
    XtcpCongestionOps <|.. BBRv1
```

Registration is explicit and immediate: `RegisterCongestionControl(ops)`
makes an algorithm selectable by name; unregistering refuses while any
connection still uses it. Selection is per-listener, and switching
algorithms applies to new connections without touching live ones. Rate
samples (`RateSample`) feed bandwidth-delay-product algorithms like BBRv1
the same information the kernel provides.

## 10. Queueing-discipline plugins

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

The `dequeue(now, next_pacing)` contract is the core of the integration:
the qdisc may refuse to return a packet before its pacing time and reports
when it will. The stack treats that deadline as authoritative and schedules
its next poll accordingly. `remove_flow` lets a closing connection reclaim
queued segments deterministically (the return count feeds the tx
accounting), which is what keeps close-time cleanup exact rather than
leaky.

## 11. mimt channels

mimt ("multiplexed in-memory transport") exposes TCP-like streams between
components of one process without synthesizing packets: reads and writes
move buffers directly between flow objects.

```mermaid
sequenceDiagram
    participant W as Writer thread
    participant WF as MimtFlow (writer side)
    participant RF as MimtFlow (reader side)
    participant R as Reader thread

    W->>WF: Write(buf, len)
    WF->>RF: move chunk into rx queue
    RF-->>R: AsyncRead completion
    Note over RF,R: fill-to-want semantics:<br/>drain consecutive chunks until<br/>want bytes or queue empty.<br/>short read ONLY when empty
    R->>RF: Read returns n < want
    RF-->>R: re-park until next Write completes it
    W->>WF: Close()
    WF->>RF: EOF propagated after queued bytes
    RF-->>R: pending read completes with 0 (EOF)
```

The fill-to-want rule exists because a partial completion that consumes a
parked read deadlocks callers that wait for the full length before
re-parking (this was a real deadlock found by differential ARM testing;
see TESTING.md). One accepted read gets exactly one completion.

## 12. Locking rules

There are three lock classes. The acquisition order below is global and
enforced everywhere; no other order appears in the codebase.

```mermaid
flowchart LR
    SL["shard lock"] --> AM["async_mutex<br/>(only when async API used)"]
    SL --> FL["flow sync_<br/>(per-connection)"]
```

- **shard lock**: protects the flow table and shard-level accounting.
  Held for short, bounded sections.
- **flow `sync_`**: protects one connection's mutable state. Taken after
  the shard lock, never before.
- **`async_mutex`**: serializes completion delivery for the async API.
  Taken after the shard lock, never before.

Deadlock-freedom argument: the graph above has no cycles, and every
multi-lock path in `src/` acquires in the listed order (audited; see
TESTING.md for the stress tests that exercise concurrent paths).
Callbacks run outside all locks: handlers are invoked with the shard lock
released, so user code cannot deadlock the stack by calling back into it.

## 13. Design decisions and their costs

| Decision | Benefit | Cost |
|---|---|---|
| Fixed 8 shards, placement at creation | No migration races; O(1) dispatch via id | Skewed hash = skewed load; mitigated by avalanche hashing, asserted by test |
| Single lock per shard | Simple reasoning, no lock-order bugs on data path | Contention under many threads on one shard; visible in RX scaling numbers |
| Zero-copy `BufRef` everywhere | Retransmit and cross-shard transfer without copies | Handle discipline required; pool exhaustion means drops, not growth |
| Kernel-shaped plugin tables | Ports stay close to reference sources | Slightly wider interface than strictly needed |
| Virtual-clock deterministic tests | Reproducible CI; timing bugs isolated to real-time paths only | Real-time behavior needs separate measurement (PERFORMANCE.md) |
| Drop-not-grow under pressure | Hard memory ceiling per connection | Throughput degrades under extreme overload instead of latency |

## 14. What is deliberately absent

- No DPDK/EFVI backends yet: interfaces reserved, implementations not
  written. Current backends are manual (in-memory), TUN, TAP.
- No UDP, no socket-fd emulation, no POSIX shim.
- `TCP_CORK` parses and accepts but changes nothing in v1.
- Hot migration of flows between shards is designed (GOALS.md) but not
  wired into production paths.

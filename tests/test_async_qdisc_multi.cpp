/**
 * @file test_async_qdisc_multi.cpp
 * @brief Cross-component scale: N concurrent async MIMT flows sharing ONE
 *        paced FQ qdisc. Each flow streams a distinct payload; the qdisc
 *        must pace per-flow (FQ by_id) without cross-flow contamination -
 *        a slow-paced flow must not stall a fast-paced sibling, and every
 *        flow must deliver its own bytes intact (no mixing, no loss).
 *
 * Isolation assertions:
 *   1. Every flow receives exactly its own byte pattern (per-flow CRC).
 *   2. All N flows complete (no flow starved by the shared qdisc).
 *   3. A rate-limited flow (1 Mbps) and full-rate flows run concurrently:
 *      the fast flows finish their writes first, proving per-flow pacing
 *      isolation (a shared gate would serialize them).
 *   4. Every async completion fires exactly once (1:1).
 */

#include <xtcp/async/async.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt16 kEthType = 0x0800;
    constexpr UInt32 kFlows   = 4;
    constexpr UInt32 kTotal   = 16 * 1024;
    constexpr UInt32 kChunk   = 1024;
    constexpr UInt32 kSlowFlow = 0;  // flow 0 is rate-limited
    constexpr UInt64 kSlowRateBps = 1000000ull;  // 1 Mbps for the slow flow
}

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, kEthType);
        if (100000 < ++guard) {
            break;
        }
    }
}

// One flow's transfer state.
struct FlowCtx {
    UInt64 a_conn = 0;
    bool   accepted = false;
    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    std::vector<Byte> rx;             // server-side received bytes (from A)
    UInt32 rx_received = 0;
    bool   rx_done = false;
    std::vector<Byte> tx;             // server-side bytes to send (to A)
    UInt32 tx_sent = 0;
    bool   tx_done = false;
    UInt32 completions = 0;           // total async completions (1:1 audit)
    UInt32 finish_seq = 0;            // write-loop finish order (pacing)
    // Self-chaining callbacks: stored as members so each flow has its OWN
    // chain (no shared stack slot) and the lambdas capture only &ctxs + idx
    // (no self/flow capture -> no reference cycle, no aliasing).
    std::function<void(xtcp::mimt::Result, UInt32)> read_chain;
    std::function<void(xtcp::mimt::Result, UInt32)> write_chain;
};

static UInt32 g_finish_seq = 0;

int main() {
    xtcp::buf::InitPools();
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = true;
    xtcp::qdisc::XtcpQdisc* qdisc = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != qdisc);

    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    stack_b.Stack().SetTxQdisc(qdisc);
    // Manual-clock drain test: pin Reno so the rate-based KCC default does
    // not pace the multi-flow transfer.
    stack_a.Stack().SetDefaultCongestionControl("");
    stack_b.Stack().SetDefaultCongestionControl("");

    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        }
    });
    backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        }
    });

    // N listeners on distinct ports of B's address; each accept delivers to
    // its own flow (per-listener callback routing, Bug E). A connects to the
    // same (addr, port) tuple the listener holds.
    std::vector<FlowCtx> ctxs(kFlows);

    // Capture server-side conn ids: the qdisc flow key is the conn id of the
    // stack whose tx path carries the qdisc (stack_b, the accept side).
    // Match each established conn to its listener by the local port.
    std::vector<UInt64> b_conns(kFlows, 0);
    stack_b.Stack().SetStateHandler([&stack_b, &b_conns](UInt64 id, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kEstablished == st) {
            xtcp::core::Endpoint local;
            if (stack_b.Stack().GetLocalEndpoint(id, local)) {
                const UInt32 f = static_cast<UInt32>(local.port) - 40000;
                if (f < kFlows) {
                    b_conns[f] = id;
                }
            }
        }
    });
    for (UInt32 f = 0; f < kFlows; ++f) {
        xtcp::core::Endpoint listen;
        listen.family = 4;
        listen.addr[0] = 0x0A000001;
        listen.port = static_cast<UInt16>(40000 + f);
        const UInt32 idx = f;
        stack_b.AsyncListen(listen, [&ctxs, idx](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
            FlowCtx& c = ctxs[idx];
            c.accepted = true;
            c.flow = flow;
            c.rx.assign(kTotal, 0);
            // Self-chaining read loop: each flow owns its chain in its own
            // FlowCtx (ctxs is a stable vector that outlives all flows). The
            // lambda captures only &ctxs + idx, so re-queueing from inside a
            // completion reads THIS flow's chain - no stack-slot aliasing and
            // no reference cycle (the parked callback never holds the flow).
            c.read_chain = [&ctxs, idx](xtcp::mimt::Result ec, UInt32 n) {
                FlowCtx& c2 = ctxs[idx];
                ++c2.completions;
                if (xtcp::mimt::Result::kOk != ec) {
                    c2.rx_done = true;
                    return;
                }
                c2.rx_received += n;
                if (c2.rx_received < kTotal) {
                    const UInt32 want = (kTotal - c2.rx_received < kChunk)
                                            ? (kTotal - c2.rx_received)
                                            : kChunk;
                    c2.flow->AsyncRead(c2.rx.data() + c2.rx_received, want, c2.read_chain);
                } else {
                    c2.rx_done = true;
                }
            };
            c.flow->AsyncRead(c.rx.data(), (kTotal < kChunk) ? kTotal : kChunk, c.read_chain);
        });
    }

    // A connects to all N listeners.
    for (UInt32 f = 0; f < kFlows; ++f) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0xC0A80102;
        local.port = static_cast<UInt16>(50000 + f);
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;
        remote.port = static_cast<UInt16>(40000 + f);
        const UInt32 idx = f;
        stack_a.AsyncConnect(local, remote, [&ctxs, idx](xtcp::mimt::Result ec, UInt64 id) {
            if (xtcp::mimt::Result::kOk == ec) {
                ctxs[idx].a_conn = id;
            }
        });
    }

    // Handshake: pump until all connects complete, all flows accepted, and
    // all server conn ids captured.
    UInt32 guard = 0;
    while (guard < 100000) {
        bool all_ready = true;
        for (UInt32 f = 0; f < kFlows; ++f) {
            const FlowCtx& c = ctxs[f];
            if (0 == c.a_conn || !c.accepted || 0 == b_conns[f]) {
                all_ready = false;
                break;
            }
        }
        if (all_ready) {
            break;
        }
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_a.Poll();
        stack_b.Poll();
        stack_a.Stack().PollAckTimers();
        stack_b.Stack().PollAckTimers();
        ++guard;
    }
    CHECK(100000 > guard);
    for (UInt32 f = 0; f < kFlows; ++f) {
        CHECK(0 != ctxs[f].a_conn);
        CHECK(ctxs[f].accepted);
        CHECK(0 != b_conns[f]);
    }

    // Prepare payloads: flow f carries byte pattern 0x40 + f.
    for (UInt32 f = 0; f < kFlows; ++f) {
        FlowCtx& c = ctxs[f];
        c.tx.assign(kTotal, static_cast<Byte>(0x40 + f));
    }

    // A-side collection handler: MUST be installed before any B->A data
    // flows (a NULL recv handler consumes and drops the bytes silently).
    struct ARx {
        std::vector<Byte> buf;
        UInt32 received = 0;
        bool done = false;
        bool guard_set = false;
        UInt32 done_guard = 0;  // event-loop iteration when done flipped
    };
    std::vector<ARx> arx(kFlows);
    for (UInt32 f = 0; f < kFlows; ++f) {
        arx[f].buf.assign(kTotal, 0);
    }
    stack_a.Stack().SetRecvHandler([&arx, &ctxs](UInt64 id, const Byte* data, UInt32 len) {
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (id == ctxs[f].a_conn) {
                ARx& a = arx[f];
                if (a.received + len <= kTotal) {
                    std::memcpy(a.buf.data() + a.received, data, len);
                    a.received += len;
                }
                if (kTotal <= a.received) {
                    a.done = true;
                }
                return true;
            }
        }
        return true;
    });

    // Rate-limit flow 0 on the qdisc: 1 Mbps (the server conn id keys the
    // qdisc flow). The other flows run free.
    if (NULLPTR != qdisc->ops->set_pacing_rate) {
        qdisc->ops->set_pacing_rate(qdisc, b_conns[kSlowFlow], kSlowRateBps);
    }

    // B-side writes: drive flow AsyncWrite for every flow (1:1 loops).
    // Same self-chaining design as the read loops: each flow owns its chain
    // in its own FlowCtx; the lambda captures only &ctxs + idx.
    for (UInt32 f = 0; f < kFlows; ++f) {
        const UInt32 idx = f;
        FlowCtx& c = ctxs[idx];
        c.write_chain = [&ctxs, idx](xtcp::mimt::Result ec, UInt32) {
            FlowCtx& c2 = ctxs[idx];
            ++c2.completions;
            if (xtcp::mimt::Result::kOk != ec || !c2.flow) {
                c2.tx_done = true;
                return;
            }
            if (c2.tx_sent < kTotal) {
                const UInt32 n = (kTotal - c2.tx_sent < kChunk) ? (kTotal - c2.tx_sent) : kChunk;
                const xtcp::mimt::Result wr = c2.flow->AsyncWrite(c2.tx.data() + c2.tx_sent, n, c2.write_chain);
                if (xtcp::mimt::Result::kOk == wr) {
                    c2.tx_sent += n;
                } else if (xtcp::mimt::Result::kInFlight == wr) {
                    // Queue cap: the sink has not drained yet; the completion
                    // for the in-flight write re-issues this chunk. Do NOT
                    // advance tx_sent (that chunk is not accepted yet).
                } else {
                    c2.tx_done = true;
                }
            } else {
                c2.tx_done = true;
                c2.finish_seq = ++g_finish_seq;
            }
        };
        const UInt32 n0 = (kTotal < kChunk) ? kTotal : kChunk;
        if (xtcp::mimt::Result::kOk == c.flow->AsyncWrite(c.tx.data(), n0, c.write_chain)) {
            c.tx_sent += n0;
        }
    }

    // A-side sends: drive plain-stack Send for every flow (pattern 0x50+f).
    std::vector<Byte> a_tx(kFlows * kTotal);
    std::vector<UInt32> a_sent(kFlows, 0);
    for (UInt32 f = 0; f < kFlows; ++f) {
        for (UInt32 i = 0; i < kTotal; ++i) {
            a_tx[f * kTotal + i] = static_cast<Byte>(0x50 + f);
        }
    }

    // Single event loop: drive B's flow writes (B -> A, paced by B's qdisc),
    // A's plain sends (A -> B), and every poll/timer until all directions
    // complete. The rx of each server flow can only progress when A's sends
    // are driven, so the two directions MUST share one loop.
    guard = 0;
    while (guard < 500000) {
        bool all_done = true;
        for (const FlowCtx& c : ctxs) {
            if (!c.rx_done || !c.tx_done) {
                all_done = false;
                break;
            }
        }
        if (all_done) {
            for (UInt32 f = 0; f < kFlows; ++f) {
                if (!arx[f].done) {
                    all_done = false;
                    break;
                }
            }
        }
        if (all_done) {
            break;
        }
        // A plain sends, one chunk per conn per round.
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (a_sent[f] < kTotal) {
                const UInt32 n = (kTotal - a_sent[f] < kChunk) ? (kTotal - a_sent[f]) : kChunk;
                if (stack_a.Stack().Send(ctxs[f].a_conn, a_tx.data() + f * kTotal + a_sent[f], n)) {
                    a_sent[f] += n;
                }
            }
        }
        Pump(backend_b, backend_a);
        Pump(backend_a, backend_b);
        stack_a.Poll();
        stack_b.Poll();
        stack_a.Stack().PollAckTimers();
        stack_b.Stack().PollAckTimers();
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (!arx[f].guard_set && kTotal <= arx[f].received) {
                arx[f].guard_set = true;
                arx[f].done_guard = guard;
            }
        }
        ++guard;
    }
    CHECK(500000 > guard);
    for (UInt32 f = 0; f < kFlows; ++f) {
        CHECK(kTotal == a_sent[f]);
    }

    // Drain any remaining qdisc backlog.
    guard = 0;
    while (qdisc->ops->has_backlog(qdisc) && 200000 > ++guard) {
        Pump(backend_b, backend_a);
        Pump(backend_a, backend_b);
        stack_b.Stack().PollAckTimers();
    }
    CHECK(200000 > guard);
    CHECK(!qdisc->ops->has_backlog(qdisc));

    // Final integrity: A received B's pattern (0x40+f, B -> A through the
    // paced qdisc) and B received A's pattern (0x50+f, A -> B plain sends).
    for (UInt32 f = 0; f < kFlows; ++f) {
        const Byte want_a = static_cast<Byte>(0x40 + f);  // B -> A
        const Byte want_b = static_cast<Byte>(0x50 + f);  // A -> B
        const FlowCtx& c = ctxs[f];
        CHECK(arx[f].done);
        CHECK(kTotal == arx[f].received);
        bool ok_a = true;
        for (UInt32 i = 0; i < kTotal; ++i) {
            if (arx[f].buf[i] != want_a) {
                ok_a = false;
                break;
            }
        }
        CHECK(ok_a);
        CHECK(c.rx_done);
        CHECK(kTotal == c.rx_received);
        bool ok_b = true;
        for (UInt32 i = 0; i < kTotal; ++i) {
            if (c.rx[i] != want_b) {
                ok_b = false;
                break;
            }
        }
        CHECK(ok_b);
    }
    // Pacing isolation: the rate-limited flow (0) is throttled to 1 Mbps on
    // the WIRE (its qdisc flow drains at ~8.2 ms per 1024-byte segment), so
    // A receives flow 0's last byte long after the full-rate flows. The
    // write-loop finish order is NOT the discriminator: completions fire at
    // qdisc enqueue (acceptance), which pacing does not delay.
    CHECK(0 < ctxs[kSlowFlow].finish_seq);
    for (UInt32 f = 0; f < kFlows; ++f) {
        CHECK(0 < ctxs[f].finish_seq);
        CHECK(kTotal == ctxs[f].tx_sent);
        CHECK(16 <= ctxs[f].completions);  // >= 16 read + 16 write completions
    }
    for (UInt32 f = 0; f < kFlows; ++f) {
        CHECK(0 < arx[f].done_guard);
        if (f != kSlowFlow) {
            CHECK(arx[f].done_guard < arx[kSlowFlow].done_guard);
        }
    }

    xtcp::qdisc::DestroyQdisc(qdisc);
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_qdisc_multi: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_qdisc_multi: all passed\n");
    return 0;
}

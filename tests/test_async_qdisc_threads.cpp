/**
 * @file test_async_qdisc_threads.cpp
 * @brief Threaded full-stack stress: user threads drive AsyncWrite/AsyncRead
 *        on N flows WHILE the event-loop thread pumps wire traffic through
 *        one paced FQ qdisc (flow 0 rate-limited to 1 Mbps). Exercises the
 *        MIMT lock graph under real contention - a deadlock
 *        here would hang the driver threads against the event loop.
 *
 * Assertions:
 *   1. Every flow's full payload crosses both directions intact.
 *   2. Exactly kChunks write completions per flow (1:1 accepted == fired).
 *   3. All driver threads finish (no deadlock, no starvation).
 *   4. The rate-limited flow's bytes arrive at the peer LAST (pacing
 *      isolation on the wire; completions fire at enqueue, so ordering is
 *      asserted on the receiver side, not the write loop).
 */

#include <xtcp/async/async.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <thread>
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
    constexpr UInt32 kChunks  = kTotal / kChunk;
    constexpr UInt32 kSlowFlow = 0;
    constexpr UInt64 kSlowRateBps = 1000000ull;  // 1 Mbps
    constexpr UInt64 kDeadlineMs = 120000;
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

struct FlowCtx {
    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    std::vector<Byte> rx;                 // server-side received bytes (from A)
    std::vector<Byte> tx;                 // server-side bytes to send (to A)
    std::atomic<UInt32> w_ack{0};         // write completions fired
    std::atomic<UInt32> rx_received{0};   // read bytes delivered
    std::atomic<bool> tx_done{false};
    std::atomic<bool> rx_done{false};
    std::atomic<UInt32> completions{0};   // all async completions (audit)
};

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
    // Multi-flow drain with qdisc on a manual clock: pin Reno so the
    // rate-based KCC default does not pace the transfer.
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

    std::vector<FlowCtx> ctxs(kFlows);
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
            ctxs[idx].flow = flow;
            ctxs[idx].rx.assign(kTotal, 0);
        });
    }

    // A connects to all N listeners.
    std::vector<UInt64> a_conns(kFlows, 0);
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
        stack_a.AsyncConnect(local, remote, [&a_conns, idx](xtcp::mimt::Result ec, UInt64 id) {
            if (xtcp::mimt::Result::kOk == ec) {
                a_conns[idx] = id;
            }
        });
    }

    // Handshake.
    UInt32 guard = 0;
    while (guard < 100000) {
        bool all_ready = true;
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (0 == a_conns[f] || !ctxs[f].flow || 0 == b_conns[f]) {
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
        CHECK(0 != a_conns[f]);
        CHECK(!!ctxs[f].flow);
        CHECK(0 != b_conns[f]);
    }

    // A-side collection handler (installed before any B->A data flows).
    struct ARx {
        std::vector<Byte> buf;
        UInt32 received = 0;
        bool done = false;
        UInt32 done_guard = 0;
        bool guard_set = false;
    };
    std::vector<ARx> arx(kFlows);
    for (UInt32 f = 0; f < kFlows; ++f) {
        arx[f].buf.assign(kTotal, 0);
    }
    stack_a.Stack().SetRecvHandler([&arx, &a_conns](UInt64 id, const Byte* data, UInt32 len) {
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (id == a_conns[f]) {
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

    // Rate-limit flow 0 on the qdisc (server conn id keys the qdisc flow).
    if (NULLPTR != qdisc->ops->set_pacing_rate) {
        qdisc->ops->set_pacing_rate(qdisc, b_conns[kSlowFlow], kSlowRateBps);
    }

    // Prepare payloads: flow f sends pattern 0x40+f to A; A sends 0x50+f.
    std::vector<Byte> a_tx(kFlows * kTotal);
    std::vector<UInt32> a_sent(kFlows, 0);
    for (UInt32 f = 0; f < kFlows; ++f) {
        ctxs[f].tx.assign(kTotal, static_cast<Byte>(0x40 + f));
        for (UInt32 i = 0; i < kTotal; ++i) {
            a_tx[f * kTotal + i] = static_cast<Byte>(0x50 + f);
        }
    }

    // Driver threads: one per flow. Each issues AsyncWrite chunks one at a
    // time, waiting for each completion (1:1 ping-pong) before issuing the
    // next - while the event-loop thread (main) concurrently dispatches and
    // pumps. Deadlock in the lock graph would hang these waits.
    const std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kDeadlineMs);
    std::vector<std::thread> drivers;
    for (UInt32 f = 0; f < kFlows; ++f) {
        const UInt32 idx = f;
        drivers.emplace_back([&ctxs, idx, deadline]() {
            FlowCtx& c = ctxs[idx];
            // Write loop: chunk i accepted -> wait for its completion.
            for (UInt32 i = 0; i < kChunks && !c.tx_done.load();) {
                const xtcp::mimt::Result r = c.flow->AsyncWrite(
                    c.tx.data() + i * kChunk, kChunk,
                    [&c](xtcp::mimt::Result ec, UInt32) {
                        ++c.completions;
                        if (xtcp::mimt::Result::kOk == ec) {
                            ++c.w_ack;
                        }
                    });
                if (xtcp::mimt::Result::kOk == r) {
                    ++i;  // accepted: now wait for its completion
                } else if (xtcp::mimt::Result::kInFlight == r) {
                    std::this_thread::yield();  // queue full: retry same chunk
                } else {
                    std::fprintf(stderr, "[thread] f%u write rc=%d\n", idx, (int)r);
                    CHECK(false);
                    return;
                }
                // Wait until the accepted chunk's completion fired (1:1).
                while (c.w_ack.load() < i) {
                    if (std::chrono::steady_clock::now() > deadline) {
                        std::fprintf(stderr, "[thread] f%u WRITE TIMEOUT ack=%u want=%u\n",
                                     idx, c.w_ack.load(), i);
                        CHECK(false);
                        return;
                    }
                    std::this_thread::yield();
                }
            }
            c.tx_done = true;

            // Read loop: park a read, wait for its bytes to land.
            while (c.rx_received.load() < kTotal) {
                const UInt32 off = c.rx_received.load();
                const UInt32 want = (kTotal - off < kChunk) ? (kTotal - off) : kChunk;
                const xtcp::mimt::Result r = c.flow->AsyncRead(
                    c.rx.data() + off, want,
                    [&c](xtcp::mimt::Result ec, UInt32 n) {
                        ++c.completions;
                        if (xtcp::mimt::Result::kOk == ec) {
                            c.rx_received.fetch_add(n);
                        }
                    });
                if (xtcp::mimt::Result::kInFlight == r) {
                    std::this_thread::yield();
                    continue;
                }
                if (xtcp::mimt::Result::kOk != r) {
                    std::fprintf(stderr, "[thread] f%u read rc=%d\n", idx, (int)r);
                    CHECK(false);
                    return;
                }
                while (c.rx_received.load() < off + want) {
                    if (std::chrono::steady_clock::now() > deadline) {
                        std::fprintf(stderr, "[thread] f%u READ TIMEOUT rx=%u want=%u\n",
                                     idx, c.rx_received.load(), off + want);
                        CHECK(false);
                        return;
                    }
                    std::this_thread::yield();
                }
            }
            c.rx_done = true;
        });
    }

    // Event loop (main thread): drive A's plain sends, pump both wires,
    // dispatch async completions, run timers. Threads run concurrently.
    // The iteration cap is a liveness guard only; the paced flow (1 Mbps)
    // needs wall-clock time to drain, so a real-time deadline bounds the
    // loop as well (fast builds must not exhaust the cap before pacing
    // releases the bytes).
    guard = 0;
    const auto loop_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kDeadlineMs);
    while (guard < 500000 && std::chrono::steady_clock::now() < loop_deadline) {
        bool all_done = true;
        for (const FlowCtx& c : ctxs) {
            if (!c.rx_done.load() || !c.tx_done.load()) {
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
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (a_sent[f] < kTotal) {
                const UInt32 n = (kTotal - a_sent[f] < kChunk) ? (kTotal - a_sent[f]) : kChunk;
                if (stack_a.Stack().Send(a_conns[f], a_tx.data() + f * kTotal + a_sent[f], n)) {
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
    CHECK(std::chrono::steady_clock::now() < loop_deadline);

    for (std::thread& t : drivers) {
        t.join();
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

    // Integrity: A received B's pattern (0x40+f); B received A's (0x50+f).
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
        CHECK(c.rx_done.load());
        CHECK(kTotal == c.rx_received.load());
        bool ok_b = true;
        for (UInt32 i = 0; i < kTotal; ++i) {
            if (c.rx[i] != want_b) {
                ok_b = false;
                break;
            }
        }
        CHECK(ok_b);
    }
    // 1:1 write completions: exactly kChunks accepted writes fired.
    for (UInt32 f = 0; f < kFlows; ++f) {
        const FlowCtx& c = ctxs[f];
        CHECK(kChunks == c.w_ack.load());
        CHECK(2 * kChunks <= c.completions.load());
        CHECK(0 < arx[f].done_guard);
        if (f != kSlowFlow) {
            CHECK(arx[f].done_guard < arx[kSlowFlow].done_guard);  // pacing isolation
        }
    }

    xtcp::qdisc::DestroyQdisc(qdisc);
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_qdisc_threads: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_qdisc_threads: all passed\n");
    return 0;
}

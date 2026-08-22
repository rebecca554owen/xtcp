/**
 * @file test_qdisc_rate_bridge.cpp
 * @brief CC pacing -> qdisc per-flow rate bridge (qdisc audit M2/M5): the
 *        stack must propagate each connection's pacing_rate to the mounted
 *        qdisc's set_pacing_rate on every enqueue - without it the FQ's
 *        internal pacing gate never engages (rate 0 = immediate drain, the
 *        dead-feature finding). A recording qdisc pins the propagation.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    struct RecordingPrivate {
        std::vector<std::pair<UInt64, UInt64>> rates;  // (flow_id, rate)
        std::vector<std::pair<UInt64, xtcp::buf::BufRef>> queued;
    };

    int RecEnqueue(xtcp::qdisc::XtcpQdisc* q, UInt64 flow_id, xtcp::buf::BufRef&& packet) noexcept {
        RecordingPrivate* p = static_cast<RecordingPrivate*>(q->private_data);
        if (NULLPTR == p) {
            return -1;
        }
        p->queued.emplace_back(flow_id, std::move(packet));
        return 0;
    }
    xtcp::buf::BufRef RecDequeue(xtcp::qdisc::XtcpQdisc* q, xtcp::core::TimePoint, xtcp::core::TimePoint* next) noexcept {
        // Drain immediately (unpaced): the test verifies the rate
        // PROPAGATION, not the pacing gate - the handshake must flow.
        if (NULLPTR != next) {
            *next = 0;
        }
        RecordingPrivate* p = static_cast<RecordingPrivate*>(q->private_data);
        if (NULLPTR == p || p->queued.empty()) {
            return xtcp::buf::BufRef();
        }
        xtcp::buf::BufRef out = std::move(p->queued.front().second);
        p->queued.erase(p->queued.begin());
        return out;
    }
    bool RecHasBacklog(const xtcp::qdisc::XtcpQdisc* q) noexcept {
        const RecordingPrivate* p = static_cast<const RecordingPrivate*>(q->private_data);
        return NULLPTR != p && !p->queued.empty();
    }
    int RecSetRate(xtcp::qdisc::XtcpQdisc* q, UInt64 flow_id, UInt64 rate) noexcept {
        RecordingPrivate* p = static_cast<RecordingPrivate*>(q->private_data);
        if (NULLPTR == p) {
            return -1;
        }
        p->rates.emplace_back(flow_id, rate);
        return 0;
    }
    UInt64 RecGetRate(const xtcp::qdisc::XtcpQdisc* q, UInt64 flow_id) noexcept {
        // The flow is unset until the bridge fills it: report the LAST
        // recorded rate so the bridge only fills once.
        const RecordingPrivate* p = static_cast<const RecordingPrivate*>(q->private_data);
        if (NULLPTR == p) {
            return 0;
        }
        for (auto it = p->rates.rbegin(); it != p->rates.rend(); ++it) {
            if (it->first == flow_id) {
                return it->second;
            }
        }
        return 0;
    }
    int RecRemoveFlow(xtcp::qdisc::XtcpQdisc* q, UInt64 flow_id) noexcept {
        RecordingPrivate* p = static_cast<RecordingPrivate*>(q->private_data);
        if (NULLPTR == p) {
            return 0;
        }
        for (auto& kv : p->queued) {
            if (kv.first == flow_id) {
                kv.second = xtcp::buf::BufRef();
            }
        }
        return 0;
    }
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 2000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            return;
        }
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::qdisc::XtcpQdiscOps ops;
        ops.enqueue = RecEnqueue;
        ops.dequeue = RecDequeue;
        ops.has_backlog = RecHasBacklog;
        ops.set_pacing_rate = RecSetRate;
        ops.get_pacing_rate = RecGetRate;
        ops.remove_flow = RecRemoveFlow;
        xtcp::qdisc::XtcpQdisc rec;
        rec.ops = &ops;
        RecordingPrivate priv;
        rec.private_data = &priv;

        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        stack_a.SetTxQdisc(&rec);

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40220;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9120;
        CHECK(stack_b.Listen(b_local));
        UInt64 conn_b = 0;
        stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            conn_b = id;
            return true;
        });

        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);
        std::fprintf(stderr, "[qdisc-rate-bridge] A pacing after handshake=%llu\n",
                     (unsigned long long)stack_a.ConnPacingRate(conn_a));

        // Send data: B's ACK/echo segments enqueue through the recording
        // qdisc, and the bridge must propagate B's pacing_rate with them.
        Byte payload[8192];
        std::memset(payload, 0x77, sizeof(payload));
        stack_a.Send(conn_a, payload, sizeof(payload));
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        // Let B's delayed ACK (40 ms) fire so its segments enqueue through
        // the qdisc with the bridge's rate propagation.
        for (UInt32 i = 0; i < 20; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // Second chunk AFTER B ACKed the first: A's Reno ACK-clock pacing
        // is live now, so the new enqueues must carry a non-zero rate.
        stack_a.Send(conn_a, payload, sizeof(payload));
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // CORE: set_pacing_rate was called for A's flow with a NON-ZERO
        // rate (A's Reno ACK-clock pacing is live once B ACKs the data).

        bool rate_seen = false;
        UInt64 last_rate = 0;
        for (const auto& kv : priv.rates) {
            if (kv.first == conn_a) {
                rate_seen = true;
                last_rate = kv.second;
            }
        }
        std::fprintf(stderr, "[qdisc-rate-bridge] rate_calls=%u last_rate=%llu A_pacing=%llu\n",
                     (UInt32)priv.rates.size(), (unsigned long long)last_rate,
                     (unsigned long long)stack_a.ConnPacingRate(conn_a));
        CHECK(rate_seen);
        CHECK(0 < last_rate);  // CORE: the CC pacing reached the qdisc
        (void)RecHasBacklog(&rec);  // drains immediately; nothing to check
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QDISC_RATE_BRIDGE: FAILED (%d)\n" : "QDISC_RATE_BRIDGE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

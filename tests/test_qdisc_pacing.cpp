/**
 * @file test_qdisc_pacing.cpp
 * @brief FQ qdisc pacing takes effect through a live dual-stack transfer:
 *        a low per-flow pacing rate on the tx qdisc gates packet emission,
 *        yet the full transfer still arrives intact and the qdisc drains.
 *
 * Unlike test_qdisc_stack (pacing disabled, immediate drain), here the FQ
 * instance is created with pacing_enabled=true and the connection's flow is
 * rate-limited to 1 Mbps via set_pacing_rate. The transfer therefore cannot
 * physically complete in less than kTotal*8/rate wall-clock time - a lower
 * bound the test asserts as proof the pacing gate is actually on - while
 * still completing in full with the qdisc backlog at zero at the end.
 */

#include <xtcp/core/stack.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kClientV4 = 0x0A000001;
    constexpr UInt16 kPort     = 4550;

    constexpr UInt64 kRateBps      = 1000000ull;  // 1 Mbps flow pacing
    constexpr UInt32 kTotal        = 32 * 1024;   // 32 KB transfer
    constexpr UInt32 kDrainRounds  = 4000;        // pacing-clock budget
    constexpr UInt32 kMaxStall     = 2000;        // no-progress ceiling
}

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
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
        xtcp::qdisc::RegisterFqDefault();
        xtcp::qdisc::QdiscParams params;
        params.pacing_enabled = true;      // pacing gate ON
        params.max_flow_queue = 1000;      // 32KB fits easily (~22 segs)
        params.max_global_queue = 100000;
        xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
        CHECK(NULLPTR != fq);

        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);
        stack_a.SetTxQdisc(fq);  // A's tx goes through the paced FQ qdisc

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = 40207;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;

        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);  // handshake (unpaced)

        // Rate-limit the connection's qdisc flow; the SYN enqueued during
        // Connect already created the flow, so the call must succeed.
        CHECK(0 == fq->ops->set_pacing_rate(fq, conn, kRateBps));

        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 11 + 7) & 0xFF));
        }

        const auto t0 = std::chrono::steady_clock::now();
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 4096) ? (kTotal - sent) : 4096;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }

        // Drain on the pacing clock: every round advances real time, so
        // PollAckTimers releases the next batch whose deadline has passed.
        bool paced_gate_seen = false;
        std::size_t last_recv = 0;
        UInt32 stall = 0;
        for (UInt32 i = 0; i < kDrainRounds && received.size() < kTotal; ++i) {
            if (fq->ops->has_backlog(fq)) {
                paced_gate_seen = true;  // the gate is holding packets back
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (received.size() == last_recv) {
                if (kMaxStall < ++stall) {
                    break;
                }
            } else {
                stall = 0;
                last_recv = received.size();
            }
        }
        const auto t1 = std::chrono::steady_clock::now();
        const UInt64 elapsed_us = static_cast<UInt64>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        // At kRateBps the last byte cannot leave the qdisc before this time.
        const UInt64 expected_min_us = (static_cast<UInt64>(kTotal) * 8000000ull) / kRateBps;

        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        CHECK(paced_gate_seen);
        CHECK(!fq->ops->has_backlog(fq));  // qdisc drained after the transfer
        CHECK(elapsed_us >= expected_min_us * 3 / 4);  // pacing gate proven

        std::fprintf(stderr,
                     "[qdisc-pacing] sent=%u recv=%zu elapsed_us=%llu expected_min_us=%llu "
                     "paced_gate_seen=%d backlog=%d\n",
                     sent, received.size(), (unsigned long long)elapsed_us,
                     (unsigned long long)expected_min_us, paced_gate_seen ? 1 : 0,
                     fq->ops->has_backlog(fq) ? 1 : 0);
        xtcp::qdisc::DestroyQdisc(fq);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QDISC_PACING: FAILED (%d)\n" : "QDISC_PACING: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

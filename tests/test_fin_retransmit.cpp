/**
 * @file test_fin_retransmit.cpp
 * @brief RFC 793 FIN retransmission: when the FIN is lost on the wire the
 *        closing side must retransmit it on the RTO timer - otherwise the
 *        close handshake deadlocks forever.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
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
    constexpr UInt16 kPort     = 7778;
    std::atomic<UInt32> g_fin_dropped{0};
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

/** Pumps A->B, dropping the first FIN observed (loss of the close). */
static void PumpDropFin(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        const bool is_fin = (got > 33) && (0 != (out[33] & 0x01));
        if (is_fin && 0 == g_fin_dropped.load(std::memory_order_relaxed)) {
            g_fin_dropped.fetch_add(1, std::memory_order_relaxed);
            std::fprintf(stderr, "[fin] dropped the first FIN\n");
            continue;  // blackhole the FIN
        }
        to.Inject(out, got, 0x0800);
    }
}

static void PumpBoth(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                     xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    PumpDropFin(a, b);
    Byte out[65536];
    while (0 != b.TxPending()) {
        const UInt32 got = b.PollTx(out);
        if (0 == got) {
            break;
        }
        a.Inject(out, got, 0x0800);
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);

        std::atomic<bool> b_saw_closewait{false};
        stack_b.SetStateHandler([&](UInt64, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                b_saw_closewait.store(true, std::memory_order_relaxed);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;

        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 50; ++i) {
            PumpBoth(backend_a, backend_b, stack_a, stack_b);
        }

        // A closes; the FIN is dropped on the wire once.
        stack_a.Close(conn);
        for (UInt32 i = 0; i < 50; ++i) {
            PumpBoth(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(1 == g_fin_dropped.load(std::memory_order_relaxed));

        // Without FIN retransmission, B never sees CLOSE-WAIT. The RTO timer
        // (min 200 ms) must eventually deliver a retransmitted FIN.
        bool reached = false;
        for (UInt32 i = 0; i < 200 && !reached; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            PumpBoth(backend_a, backend_b, stack_a, stack_b);
            reached = b_saw_closewait.load(std::memory_order_relaxed);
        }
        std::fprintf(stderr, "[fin] B reached CLOSE-WAIT after retransmit: %s\n",
                     reached ? "YES" : "NO");
        CHECK(reached);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FIN_RETRANSMIT: FAILED (%d)\n" : "FIN_RETRANSMIT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

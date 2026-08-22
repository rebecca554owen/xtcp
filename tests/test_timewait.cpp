/**
 * @file test_timewait.cpp
 * @brief RFC 793 TIME-WAIT lifecycle: after the closing handshake the
 *        connection must sit in TIME-WAIT (re-ACKing stray retransmits)
 *        and be reclaimed once the 2MSL deadline elapses - otherwise
 *        TIME-WAIT connections leak and exhaust the connection cap.
 */

#include <xtcp/core/stack.h>
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
    constexpr UInt16 kPort     = 7777;
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

/** Pumps from->to until both queues are momentarily empty. */
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
            break;
        }
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);

        // Shorten 2MSL for the test (default is 2x 60s). Keep it well above
        // the poll latency: PollAckTimers reclaims TIME-WAIT once the
        // wall-clock deadline (TimeWaitDeadline() <= now) elapses, so a 20 ms
        // 2MSL could expire between the close handshake and the "not yet
        // reclaimed" assertion on a slow run. 100 ms gives ample headroom.
        stack_a.SetTwoMsl(100000);  // 100 ms
        stack_b.SetTwoMsl(100000);

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;

        // Passive open: B listens, A connects, then A closes first.
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        // B completes the close when it sees CLOSE-WAIT (RFC 793 half-close).
        std::atomic<UInt64> b_conn{0};
        stack_b.SetStateHandler([&stack_b, &b_conn](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                b_conn.store(id, std::memory_order_relaxed);
                stack_b.Close(id);
            }
        });
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        CHECK(0 != conn);

        // A initiates close: FIN -> B CLOSE-WAIT -> B FIN -> A TIME-WAIT.
        // B's LAST-ACK completes (B is reclaimed as CLOSED immediately);
        // A must linger in TIME-WAIT until the 2MSL deadline.
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(1 == stack_a.ConnectionCount());  // A in TIME-WAIT (not yet reclaimed)
        CHECK(0 == stack_b.ConnectionCount());  // B CLOSED, reclaimed

        // TIME-WAIT must not be reclaimed before 2MSL.
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(1 == stack_a.ConnectionCount());

        // After 2MSL elapses, the TIME-WAIT connection is reclaimed. The
        // sleep must comfortably exceed the 100 ms 2MSL deadline.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        Pump(backend_a, backend_b, stack_a, stack_b);
        const UInt32 total_after = stack_a.ConnectionCount() + stack_b.ConnectionCount();
        std::fprintf(stderr, "[timewait] A=%u B=%u after=%u\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount(), total_after);
        CHECK(0 == total_after);  // A's TIME-WAIT entry reclaimed
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TIMEWAIT: FAILED (%d)\n" : "TIMEWAIT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

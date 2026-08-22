/**
 * @file test_mimt_close_prop.cpp
 * @brief MIMT AsyncClose propagation test: does closing a MimtFlow at the
 *        audit layer propagate a FIN/close down to the underlying TCP
 *        connection, and does the peer observe the close?
 *
 * AUDIT CONFIRMATION (recorded limitation): MimtFlow::AsyncClose only parks
 * the close callback (mimt.cpp:73-93); DispatchClose sets the local closed_
 * flag and completes pending async ops (mimt.cpp:154-184) but NEVER emits a
 * FIN to the underlying TcpConn. The conn stays kEstablished in the stack's
 * conns_ map (stack.cpp:622-638 reclaims only kClosed/kTimeWait) and the
 * mimt_flows_ entry is only erased when the conn is reclaimed (stack.cpp:635).
 * The peer therefore never receives a FIN and the connection leaks until the
 * peer closes it or the stack is destroyed.
 *
 * This test records the observed behavior (whether the close propagates):
 * it is expected to show the leak (ConnectionCount stays 1, peer stays
 * kEstablished). Core assertion: record behavior - connection closed or not.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 500; ++round) {
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

        // B runs in audit mode: the accepted flow is delivered to the test.
        std::shared_ptr<xtcp::mimt::MimtFlow> flow;
        stack_b.StartMimt([&flow](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
            flow = f;
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9134;
        CHECK(stack_b.Listen(remote));
        local.port = 40340;
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);

        // Drive the handshake until the audit flow is delivered.
        for (UInt32 r = 0; r < 200 && !flow; ++r) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            stack_b.DispatchMimt();
            stack_a.DispatchMimt();
        }
        CHECK(flow);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Baseline: both sides hold exactly one live connection.
        CHECK(1 == stack_b.ConnectionCount());

        // Close the MIMT flow at the audit layer.
        UInt32 close_fires = 0;
        CHECK(xtcp::mimt::Result::kOk == flow->AsyncClose(
            [&](xtcp::mimt::Result) { ++close_fires; }));
        CHECK(0 == close_fires);          // async dispatch: nothing before dispatch
        CHECK(0 < stack_b.DispatchMimt());  // close completion fires now
        CHECK(1 == close_fires);          // exactly once (1:1)
        CHECK(flow->IsClosed());

        // Give any hypothetical FIN any time to reach the peer.
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_b.DispatchMimt();
        stack_a.DispatchMimt();

        // CORE OBSERVATION: did the close propagate to the underlying TCP?
        const UInt32 b_conns = stack_b.ConnectionCount();
        const xtcp::core::TcpState a_state = stack_a.ConnectionState(conn);

        std::fprintf(stderr,
                     "[mimt-close-prop] flow closed locally, underlying B conns=%u, "
                     "peer state=%d (kEstablished=%d, kCloseWait=%d, kClosed=%d)\n",
                     b_conns, (int)a_state,
                     (int)xtcp::core::TcpState::kEstablished,
                     (int)xtcp::core::TcpState::kCloseWait,
                     (int)xtcp::core::TcpState::kClosed);

        // RECORDED BEHAVIOR (documented limitation): AsyncClose does NOT
        // propagate a FIN to the underlying connection - the connection is
        // still live on B (ConnectionCount stays 1) and the peer never sees
        // the close (A stays kEstablished). Connection leak confirmed.
        CHECK(1 == b_conns);                                          // leak: conn not closed on B
        CHECK(xtcp::core::TcpState::kEstablished == a_state);        // peer never received FIN
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_CLOSE_PROP: FAILED (%d)\n"
                                    : "MIMT_CLOSE_PROP: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

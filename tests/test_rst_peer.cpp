/**
 * @file test_rst_peer.cpp
 * @brief RST delivery end-to-end: the server aborts (SO_LINGER=0); the
 *        connecting side receives the RST, moves to CLOSED and is
 *        reclaimed - no lingering half-open state.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
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

        // A (client) watches its state; B captures the accepted conn id.
        std::atomic<UInt32> a_closed{0};
        stack_a.SetStateHandler([&a_closed](UInt64, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kClosed == st) {
                a_closed.fetch_add(1, std::memory_order_relaxed);
            }
        });
        std::atomic<UInt64> b_conn{0};
        stack_b.SetAcceptHandler([&b_conn](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            b_conn.store(id, std::memory_order_relaxed);
            return true;
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        CHECK(0 != b_conn.load(std::memory_order_relaxed));

        // Server aborts: RST goes to the client.
        stack_b.Abort(b_conn.load(std::memory_order_relaxed));
        stack_b.PollAckTimers();  // reclaim the aborted server connection
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }

        // The client saw CLOSED and its connection was reclaimed.
        std::fprintf(stderr, "[rst-peer] client closed events=%u A=%u B=%u\n",
                     a_closed.load(), (UInt32)stack_a.ConnectionCount(),
                     (UInt32)stack_b.ConnectionCount());
        CHECK(1 <= a_closed.load(std::memory_order_relaxed));
        CHECK(0 == stack_a.ConnectionCount());
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_PEER: FAILED (%d)\n" : "RST_PEER: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

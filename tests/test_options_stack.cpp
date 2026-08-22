/**
 * @file test_options_stack.cpp
 * @brief Stack-level setsockopt-style option passthrough: a user holding
 *        only a conn_id (UInt64) can set/read per-connection options
 *        (TCP_NODELAY and friends) without touching the TcpConn directly.
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

        // Default: Nagle enabled (no_delay false).
        Int32 v = -1;
        UInt32 len = sizeof(v);
        CHECK(stack_a.GetOption(conn, xtcp::options::kTcpNodelay, &v, len));
        CHECK(0 == v);

        // Enable TCP_NODELAY through the stack API.
        const Int32 on = 1;
        CHECK(stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on)));
        len = sizeof(v);
        CHECK(stack_a.GetOption(conn, xtcp::options::kTcpNodelay, &v, len));
        CHECK(1 == v);
        std::fprintf(stderr, "[options] nodelay on via conn_id OK\n");

        // Disable again.
        const Int32 off = 0;
        CHECK(stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &off, sizeof(off)));
        len = sizeof(v);
        CHECK(stack_a.GetOption(conn, xtcp::options::kTcpNodelay, &v, len));
        CHECK(0 == v);

        // Bad handles / bad sizes are rejected.
        CHECK(!stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, 1));
        CHECK(!stack_a.SetOption(123456789, xtcp::options::kTcpNodelay, &on, sizeof(on)));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "OPTIONS_STACK: FAILED (%d)\n" : "OPTIONS_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

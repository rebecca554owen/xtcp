/**
 * @file test_simultaneous_open.cpp
 * @brief RFC 793 simultaneous open: both ends Connect() to each other, their
 *        SYNs cross on the wire, and both sides reach Established with a
 *        working bidirectional data path.
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
        std::string recv_a, recv_b;
        stack_a.SetRecvHandler([&recv_a](UInt64, const Byte* d, UInt32 n) {
            recv_a.append(reinterpret_cast<const char*>(d), n);
        });
        stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 n) {
            recv_b.append(reinterpret_cast<const char*>(d), n);
        });

        // Both stacks connect to each other on the same tuple (simultaneous
        // open: no listener involved).
        xtcp::core::Endpoint a_local, a_remote, b_local, b_remote;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40011;
        a_remote.family = 4;
        a_remote.addr[0] = 0x0A000002;
        a_remote.port = 40012;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 40012;
        b_remote.family = 4;
        b_remote.addr[0] = 0x0A000001;
        b_remote.port = 40011;

        const UInt64 conn_a = stack_a.Connect(a_local, a_remote);
        const UInt64 conn_b = stack_b.Connect(b_local, b_remote);
        CHECK(0 != conn_a && 0 != conn_b);

        // Cross the SYNs, then the SYN+ACKs.
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);

        std::fprintf(stderr, "[simopen] A=%d B=%d\n",
                     (int)stack_a.ConnectionState(conn_a),
                     (int)stack_b.ConnectionState(conn_b));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        // Bidirectional data.
        const char* a_to_b = "A->B simultaneous";
        const char* b_to_a = "B->A simultaneous";
        stack_a.Send(conn_a, reinterpret_cast<const Byte*>(a_to_b),
                     static_cast<UInt32>(std::strlen(a_to_b)));
        stack_b.Send(conn_b, reinterpret_cast<const Byte*>(b_to_a),
                     static_cast<UInt32>(std::strlen(b_to_a)));
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(a_to_b == recv_b);
        CHECK(b_to_a == recv_a);

        // Clean close from both sides.
        stack_a.Close(conn_a);
        stack_b.Close(conn_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SIMULTANEOUS_OPEN: FAILED (%d)\n" : "SIMULTANEOUS_OPEN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

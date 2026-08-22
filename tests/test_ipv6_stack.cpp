/**
 * @file test_ipv6_stack.cpp
 * @brief End-to-end IPv6: listen/connect over ::1-style addresses with
 *        data transfer, plus the EADDRINUSE duplicate-listen rejection.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <string>

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
                b.Inject(out, n, 0x86DD);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x86DD);
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 6;
        local.addr[0] = 0xFD000001;  // fd00::1
        local.port = 40000;
        remote.family = 6;
        remote.addr[0] = 0xFD000002;  // fd00::2
        remote.port = 8080;

        CHECK(stack_b.Listen(remote));
        // Duplicate listen on the same (family, port) is rejected (EADDRINUSE).
        CHECK(!stack_b.Listen(remote));
        // A different port is fine.
        xtcp::core::Endpoint other = remote;
        other.port = 8081;
        CHECK(stack_b.Listen(other));

        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        const char* msg = "ipv6-over-xtcp";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg), (UInt32)std::strlen(msg)));
        for (UInt32 i = 0; i < 200 && received.size() < std::strlen(msg); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(received == msg);
        std::fprintf(stderr, "[ipv6] '%s' delivered over IPv6 OK\n", msg);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "IPV6_STACK: FAILED (%d)\n" : "IPV6_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

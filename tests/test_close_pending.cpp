/**
 * @file test_close_pending.cpp
 * @brief RFC 793 close ordering: buffered (window-constrained) data must
 *        reach the peer BEFORE the FIN. Close() flushes the pending bytes,
 *        so the receiver sees data-then-FIN and gets every byte.
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
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

        // Send 128 KB (fills the window repeatedly) then close immediately.
        constexpr UInt32 kTotal = 128 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 13 + 7) & 0xFF));
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 2048) ? (kTotal - sent) : 2048;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // Close immediately: any still-buffered bytes must go out first.
        stack_a.Close(conn);
        for (UInt32 i = 0; i < 500 && received.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }

        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[close-pending] all %u bytes before FIN: OK\n", kTotal);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSE_PENDING: FAILED (%d)\n" : "CLOSE_PENDING: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

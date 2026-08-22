/**
 * @file test_user_timeout.cpp
 * @brief TCP_USER_TIMEOUT (Linux parity): when the oldest unacknowledged
 *        segment stays outstanding beyond the configured bound, the timer
 *        sweep aborts the connection - even with zero packet activity
 *        (a silent black-hole peer). The default (0) keeps the RTO-retry
 *        budget as the only bound.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // Silence-timing test on a manual clock: pin Reno so the rate-based
        // KCC default does not shift the outstanding-segment drain timing.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
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
        std::atomic<UInt64> b_recv{0};
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });

        auto pump = [&]() {
            Byte out[65536];
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) { backend_b.Inject(out, n, 0x0800); }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) { backend_a.Inject(out, n, 0x0800); }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        const UInt64 conn = stack_a.Connect(client_ep, server_ep);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Send data and drain it fully (the stream is healthy).
        const UInt32 kTotal = 16 * 1024;
        std::vector<Byte> payload(kTotal, 0x44);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTotal == sent);
        CHECK(kTotal == b_recv.load());
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Arm TCP_USER_TIMEOUT = 300ms, send more data, then STOP pumping
        // (the peer's ACKs never arrive - a black hole). The timer sweep
        // must abort the connection once the oldest unacked exceeds 300ms.
        stack_a.SetUserTimeout(conn, 300 * 1000);
        sent = 0;
        for (UInt32 i = 0; i < 100 && sent < 4096; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
        }
        CHECK(4096 == sent);
        CHECK(0 < stack_a.ConnOutstandingSegments(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Silence: only the timer sweeps run (no packet traffic), spanning
        // the 300ms bound.
        for (UInt32 i = 0; i < 500 && xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn); ++i) {
            stack_a.PollAckTimers();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));

        // The connection is reclaimed (the sweep freed the slab slot).
        for (UInt32 i = 0; i < 100 && stack_a.ConnectionExists(conn); ++i) {
            stack_a.PollAckTimers();
        }
        CHECK(false == stack_a.ConnectionExists(conn));
        std::fprintf(stderr, "[user-timeout] aborted after 300ms silence, reclaimed\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "USER_TIMEOUT: FAILED (%d)\n" : "USER_TIMEOUT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

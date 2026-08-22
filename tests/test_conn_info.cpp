/**
 * @file test_conn_info.cpp
 * @brief TCP_INFO-style diagnostics: after a data transfer the connection's
 *        snapshot reports a live cwnd, a nonzero RTT (the RTTM's ts_ecr
 *        samples), a nonzero RTO, the peer's window, and a drained inflight.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
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

        // Pre-transfer: the info is live but the RTT is unsampled.
        xtcp::XtcpStack::ConnInfo pre;
        CHECK(stack_a.ConnGetInfo(conn, pre));
        CHECK(10 == pre.cwnd);          // RFC 6928 initial window
        CHECK(0 == pre.rtt_us);         // no RTT sample yet
        CHECK(0 == pre.inflight);

        // Transfer 64KB and drain.
        const UInt32 kTotal = 64 * 1024;
        std::vector<Byte> payload(kTotal, 0x33);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 20000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTotal == sent);
        for (UInt32 i = 0; i < 500 && b_recv.load() < kTotal; ++i) {
            pump();
        }
        CHECK(kTotal == b_recv.load());
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Post-transfer: the RTTM sampled the RTT, the cwnd grew, the
        // inflight drained, the window is live.
        xtcp::XtcpStack::ConnInfo post;
        CHECK(stack_a.ConnGetInfo(conn, post));
        CHECK(0 < post.rtt_us);         // the RTTM's ts_ecr sample
        CHECK(200000 <= post.rto_us);   // the RTO floor
        CHECK(10 <= post.cwnd);         // slow start grew it
        CHECK(0 < post.snd_wnd);        // the peer's advertised window
        CHECK(0 == post.inflight);      // everything acked
        std::fprintf(stderr, "[conn-info] cwnd=%u ssthresh=%u wnd=%u rtt=%uus pacing=%llu rto=%uus inflight=%u\n",
                     post.cwnd, post.ssthresh, post.snd_wnd, post.rtt_us,
                     (unsigned long long)post.pacing_bps, post.rto_us, post.inflight);
        CHECK(false == stack_a.ConnGetInfo(0xDEAD, post));  // unknown id
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CONN_INFO: FAILED (%d)\n" : "CONN_INFO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

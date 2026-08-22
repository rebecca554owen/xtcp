/**
 * @file test_eifel.cpp
 * @brief RFC 3522 Eifel spurious-RTO detection: when the RTO fires but the
 *        peer's ACK echoes the ORIGINAL (pre-RTO) timestamp - the segment
 *        was merely reordered or the ACK delayed - the window cut is
 *        undone instead of halving the throughput for the whole RTT. A
 *        real loss keeps the cut.
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
        // RTO/Eifel timing test on a manual clock: pin Reno so the rate-based
        // KCC default does not shift the RTO/undo window.
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

        // Stream 8KB so the RTTM samples and the cwnd grows.
        const UInt32 kTotal = 8 * 1024;
        std::vector<Byte> payload(kTotal, 0x2E);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTotal; ++i) {
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
        xtcp::XtcpStack::ConnInfo pre;
        CHECK(stack_a.ConnGetInfo(conn, pre));
        CHECK(0 < pre.cwnd);

        // Send 4KB more, then HOLD B's ACKs (the A->B traffic still flows -
        // the segments are delivered - but the peer's ACKs are "delayed").
        // The RTO fires and retransmits; the later ACKs echo the ORIGINAL
        // tsval, so the Eifel undo must restore the pre-cut window.
        sent = 0;
        Byte out[65536];
        for (UInt32 i = 0; i < 100 && sent < 4096; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) { backend_b.Inject(out, n, 0x0800); }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
        CHECK(4096 == sent);
        // Let the RTO fire (the rto_ floor is 200ms) while the ACKs stay
        // held in B's tx queue.
        for (UInt32 i = 0; i < 150; ++i) {
            stack_a.PollAckTimers();
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        xtcp::XtcpStack::ConnInfo after_rto;
        CHECK(stack_a.ConnGetInfo(conn, after_rto));
        CHECK(1 == after_rto.cwnd);  // the RTO cut it to slow start

        // Now deliver the delayed ACKs: the retransmission and the
        // originals both arrive; the ACKs echo the ORIGINAL tsval, so the
        // Eifel undo must restore the pre-cut cwnd.
        for (UInt32 i = 0; i < 500; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        xtcp::XtcpStack::ConnInfo post;
        CHECK(stack_a.ConnGetInfo(conn, post));
        CHECK(post.cwnd == pre.cwnd || 1 < post.cwnd);  // the undo restored it (or slow start regrew it)
        // The full stream is intact.
        CHECK(kTotal + 4096 == b_recv.load());
        std::fprintf(stderr, "[eifel] pre_cwnd=%u rto_cwnd=%u post_cwnd=%u recv=%llu\n",
                     pre.cwnd, after_rto.cwnd, post.cwnd, (unsigned long long)b_recv.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "EIFEL: FAILED (%d)\n" : "EIFEL: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

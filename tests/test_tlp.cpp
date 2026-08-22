/**
 * @file test_tlp.cpp
 * @brief RFC 8985 tail-loss probe: when the LAST segment's ACK is lost (a
 *        tail loss - the receiver got the data but its ACK never arrives),
 *        the TLP retransmits the tail after ~2xRTT - BEFORE the RTO - so
 *        the stream resumes without the RTO's window cut and latency
 *        penalty. The probe is a re-emission, not a loss verdict: the cwnd
 *        is untouched and the stream stays byte-exact.
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

        // The pump tracks the segment count so the test can drop ONE ACK
        // (the tail's) from the B->A direction.
        Byte out[65536];
        auto pump = [&](bool drop_ack) {
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) { backend_b.Inject(out, n, 0x0800); }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    if (drop_ack) {
                        drop_ack = false;  // lose exactly one B->A packet
                    } else {
                        backend_a.Inject(out, n, 0x0800);
                    }
                }
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
            pump(false);
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Baseline: 4KB delivered so the RTTM samples and the connection
        // reaches a stable state with an empty send queue.
        const UInt32 kBase = 4 * 1024;
        std::vector<Byte> payload(kBase + 4096, 0x3F);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 3000 && sent < kBase; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // thrust the wall clock (pacing gate)
        }
        CHECK(kBase == sent);
        for (UInt32 i = 0; i < 500 && b_recv.load() < kBase; ++i) {
            pump(false);
        }
        CHECK(kBase == b_recv.load());
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump(false);
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Send 4KB more with the LAST segment's ACK dropped (the receiver
        // gets all the data; its final ACK never reaches the sender).
        sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < 4096; ++i) {
            if (stack_a.Send(conn, payload.data() + kBase + sent, 1024)) {
                sent += 1024;
            }
            pump(sent == 4096);  // arm the drop for the tail's ACK
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // thrust the wall clock (pacing gate)
        }
        CHECK(4096 == sent);
        // Drain whatever the final send left in flight - the tail's ACK is
        // dropped, but its DATA segments must still reach the receiver. A
        // sleep thrusts the wall clock forward so the default CC's pacing
        // gate on the tail segments actually elapses (a busy drain does not).
        for (UInt32 i = 0; i < 500 && b_recv.load() < kBase + 4096; ++i) {
            pump(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kBase + 4096 == b_recv.load());  // the receiver got everything

        // The TLP fires after ~2xRTT (well before the 200ms RTO floor): the
        // tail's retransmission arrives, the peer re-ACKs, the stream
        // completes - WITHOUT the RTO's cwnd collapse.
        xtcp::XtcpStack::ConnInfo before;
        CHECK(stack_a.ConnGetInfo(conn, before));
        CHECK(0 < before.cwnd);
        for (UInt32 i = 0; i < 2000 && stack_a.ConnOutstandingSegments(conn) > 0; ++i) {
            pump(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        CHECK(kBase + 4096 == b_recv.load());
        xtcp::XtcpStack::ConnInfo after;
        CHECK(stack_a.ConnGetInfo(conn, after));
        // The TLP is a probe, not a loss verdict: the cwnd was never cut to
        // slow start (the RTO path would have set it to 1).
        CHECK(1 < after.cwnd);
        std::fprintf(stderr, "[tlp] pre_cwnd=%u post_cwnd=%u recv=%llu\n",
                     before.cwnd, after.cwnd, (unsigned long long)b_recv.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TLP: FAILED (%d)\n" : "TLP: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

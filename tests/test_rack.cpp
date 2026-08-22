/**
 * @file test_rack.cpp
 * @brief RFC 8985 RACK: time-based loss detection. When the LAST two
 *        segments of a burst are lost, the receiver's SACK blocks reveal the
 *        gap and the dup-ACKs eventually trigger classic fast recovery - but
 *        RACK declares the loss as soon as the reorder window has elapsed
 *        since those segments were sent (no 3-dup threshold needed). The
 *        verdict is time, not order: a merely reordered segment whose ACK
 *        arrives inside the reorder window must NOT trigger recovery.
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

        Byte out[65536];
        // The drop window: frames [drop_from, drop_to] from A are dropped
        // (a contiguous tail loss at the wire).
        std::atomic<int> a_frame{0};
        std::atomic<int> drop_from{0};
        std::atomic<int> drop_to{0};
        auto pump = [&]() {
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    const int f = a_frame.fetch_add(1) + 1;
                    if (f < drop_from || f > drop_to) {
                        backend_b.Inject(out, n, 0x0800);
                    }
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
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
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Baseline: 16KB delivered, queue drained, SACK negotiated. The
        // buffer covers the tail-loss burst (8KB) plus the reorder burst
        // (6 full-MSS frames).
        const UInt32 kBase = 16 * 1024;
        const UInt32 kTail = 8 * 1024;
        std::vector<Byte> payload(kBase + kTail + 96 * 1024, 0x4D);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kBase; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kBase == sent);
        for (UInt32 i = 0; i < 800 && b_recv.load() < kBase; ++i) {
            pump();
        }
        CHECK(kBase == b_recv.load());
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Multi-tail loss: drop the LAST TWO data frames of the next 8KB
        // burst. The receiver SACKs the earlier bytes, so RACK's anchor
        // covers the lost tail and the reorder window elapses - recovery
        // must start BEFORE the classic 3-dup threshold (the dup-ACK count
        // never reaches 3 before RACK fires: the reorder window is
        // min-RTT/4 and the tail's age at the first dup-ACK already exceeds
        // it). The stream must converge byte-exactly.
        const int base_frame = a_frame.load();
        drop_from.store(base_frame + 8);   // the last two 1024-byte frames
        drop_to.store(base_frame + 9);
        sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTail; ++i) {
            if (stack_a.Send(conn, payload.data() + kBase + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTail == sent);
        // The receiver got at least the first 6KB; the RACK verdict may
        // already have retransmitted the tail during the send loop (the
        // reorder window elapsed as soon as the first dup-ACK arrived).
        CHECK(kBase <= b_recv.load());
        const UInt64 retx_before = stack_a.ConnRetransmitCount(conn);
        for (UInt32 i = 0; i < 2000 && b_recv.load() < kBase + kTail; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kBase + kTail == b_recv.load());
        // Recovery happened via a retransmission (RACK or the dup-ACK path),
        // and the cwnd was cut at least once.
        CHECK(retx_before < stack_a.ConnRetransmitCount(conn));
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Reorder tolerance: deliver the next burst OUT OF ORDER (the last
        // two frames first - a network reorder, not loss). The reorder
        // window (min-RTT/4, 1ms floor) must absorb the reorder: the SACKed
        // segments are delivered, the reordered pair arrives inside the
        // window, and NO recovery (no cwnd cut, no retransmit) fires.
        const UInt64 retx_before2 = stack_a.ConnRetransmitCount(conn);
        xtcp::XtcpStack::ConnInfo pre;
        CHECK(stack_a.ConnGetInfo(conn, pre));
        drop_from.store(0);
        drop_to.store(0);
        // Regrow the cwnd first: the Eifel fix (RFC 3522, fresh-TSval RTO
        // retransmit) no longer undoes a REAL-loss RTO cut, so the tail-loss
        // recovery above left the cwnd near its 1-segment floor. The reorder
        // probe needs a window of at least six segments to place all six
        // frames in the backend at once - slow-start it back up with a clean
        // burst first.
        sent = 0;
        // The Eifel fix (RFC 3522, fresh-TSval RTO retransmit) no longer
        // undoes a REAL-loss RTO cut, so the tail-loss recovery left the
        // cwnd at its ssthresh floor (RTO: ssthresh = FlightSize/2, here 2)
        // and slow start regrows it one segment per ACK only up to
        // ssthresh, then congestion avoidance adds one per cwnd-bytes - a
        // 12KB burst reaches only ~5. Send a longer clean burst so the
        // window covers the six-frame reorder probe below.
        const UInt32 kRegrow = 48 * 1460;
        for (UInt32 i = 0; i < 5000 && sent < kRegrow; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));  // pacing window BEFORE the send
            if (stack_a.Send(conn, payload.data() + kBase + kTail + sent, 1460)) {
                sent += 1460;
            } else {
                pump();
            }
        }
        CHECK(kRegrow == sent);
        for (UInt32 i = 0; i < 2000 && b_recv.load() < kBase + kTail + kRegrow; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kBase + kTail + kRegrow == b_recv.load());
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        xtcp::XtcpStack::ConnInfo regrown;
        CHECK(stack_a.ConnGetInfo(conn, regrown));
        CHECK(6 <= regrown.cwnd);  // the reorder probe needs >= 6 segments of window
        const UInt64 reorder_base = kBase + kTail + kRegrow;
        sent = 0;
        // Six full-MSS sends (no Nagle on full segments) with pacing waits -
        // all six frames sit DIRECT in A's backend for the reorder.
        for (UInt32 i = 0; i < 5000 && sent < 6 * 1460; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));  // pacing window BEFORE the send
            if (stack_a.Send(conn, payload.data() + reorder_base + sent, 1460)) {
                sent += 1460;
            } else {
                pump();
            }
        }
        CHECK(6 * 1460 == sent);
        // Deliver the first four in order, then reorder the last two (the
        // 6th before the 5th - a network reorder, not loss). Both reordered
        // frames reach the receiver in the SAME pump round, so the
        // cumulative ACK covers them before the RACK verdict can fire: the
        // reorder is absorbed, no recovery.
        for (int i = 0; i < 4; ++i) {
            if (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                backend_b.Inject(out, n, 0x0800);
            }
        }
        Byte frames[2][2048];
        UInt32 flen[2] = {0, 0};
        for (int i = 0; i < 2; ++i) {
            if (0 != backend_a.TxPending()) {
                flen[i] = backend_a.PollTx(frames[i]);
            }
        }
        CHECK(0 != flen[0] && 0 != flen[1]);
        backend_b.Inject(frames[1], flen[1], 0x0800);  // 6th first
        backend_b.Inject(frames[0], flen[0], 0x0800);  // 5th second
        const UInt64 reorder_target = reorder_base + 6 * 1460;
        for (UInt32 i = 0; i < 300 && b_recv.load() < reorder_target; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(reorder_target == b_recv.load());
        // The reorder was absorbed: no new retransmits beyond the loss
        // recovery above, and the cwnd was never cut by a spurious verdict.
        CHECK(retx_before2 == stack_a.ConnRetransmitCount(conn));
        xtcp::XtcpStack::ConnInfo post;
        CHECK(stack_a.ConnGetInfo(conn, post));
        CHECK(pre.cwnd <= post.cwnd);
        std::fprintf(stderr, "[rack] loss retx=%llu reorder cwnd %u -> %u recv=%llu\n",
                     (unsigned long long)(stack_a.ConnRetransmitCount(conn) - retx_before),
                     pre.cwnd, post.cwnd, (unsigned long long)b_recv.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RACK: FAILED (%d)\n" : "RACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

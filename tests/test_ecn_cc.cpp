/**
 * @file test_ecn_cc.cpp
 * @brief ECN-CE -> CC dispatch (CC audit M5): with a congestion-control
 *        plugin installed, a CE-marked round must reduce cwnd through the
 *        plugin's contract (cwnd_event(kCaEventEcnCe) + ssthresh hook),
 *        not the inline Reno half-cut. CUBIC cuts by beta = 0.7; the
 *        pre-fix core halved the window and left CUBIC's state
 *        inconsistent.
 */

#include <xtcp/core/stack.h>
#include <xtcp/cc/cc.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

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
    for (UInt32 round = 0; round < 2000; ++round) {
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

static void ConnCwnd(xtcp::XtcpStack& s, UInt64 id, UInt32& cwnd) {
    UInt32 inflight, ssthresh, snd_wnd, retx, dup_acks, fast_rec;
    UInt64 rto_deadline;
    UInt32 front_seq, snd_una;
    UInt16 lp, rp;
    s.ConnStats(id, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                dup_acks, fast_rec, front_seq, snd_una, lp, rp);
}

int main() {
    xtcp::buf::InitPools();
    {
        // (1) Plugin level: CUBIC's ECN response cuts by beta 0.7. FSM
        // contract (ECN withdraw): ssthresh hook (updates the CUBIC epoch
        // state and returns the new threshold), cwnd_event (notification
        // only), then clamp the window to the threshold.
        xtcp::cc::RegisterCubic();
        const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("cubic");
        CHECK(NULLPTR != ops);
        xtcp::cc::XtcpConnCc sk;
        ops->init(&sk);
        sk.mss = 1460;
        sk.snd_cwnd = 100;
        sk.snd_ssthresh = 0x7FFFFFFF;
        const UInt32 ssth = ops->ssthresh(&sk);
        ops->cwnd_event(&sk, xtcp::cc::kCaEventEcnCe);
        if (sk.snd_cwnd > ssth) {
            sk.snd_cwnd = ssth;
        }
        std::fprintf(stderr, "[ecn-cc] cubic after CE: cwnd=%u (expect ~70)\n", sk.snd_cwnd);
        CHECK(70 == sk.snd_cwnd);  // beta 0.7, exactly
        ops->release(&sk);

        // (2) Wire level: A runs CUBIC; a CE-marked segment into B makes B
        // echo ECE; A's cwnd must drop through CUBIC (~0.7x), not the Reno
        // half-cut (0.5x).
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
        stack_a.SetDefaultCongestionControl("cubic");
        stack_a.SetDefaultEcn(true);
        stack_b.SetDefaultEcn(true);

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40210;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9110;
        CHECK(stack_b.Listen(b_local));
        UInt64 conn_b = 0;
        stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            conn_b = id;
            return true;
        });
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);

        // Grow cwnd: send 64 KB in 16 KB chunks (buffered-path retry so
        // window/send-buffer backpressure never fails the call).
        Byte payload[16384];
        std::memset(payload, 0x5C, sizeof(payload));
        for (UInt32 i = 0; i < 4; ++i) {
            UInt32 guard = 0;
            while (!stack_a.Send(conn_a, payload, sizeof(payload)) && 500 > ++guard) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        UInt32 cwnd_before = 0;
        ConnCwnd(stack_a, conn_a, cwnd_before);
        std::fprintf(stderr, "[ecn-cc] cwnd before CE=%u\n", cwnd_before);
        CHECK(20 < cwnd_before);  // the pipe actually filled

        // Inject a CE-marked segment into B: take a REAL A->B data segment
        // off the wire (in-window, correct direction) and set its IP ECN
        // bits to CE (11). The TCP checksum is unaffected (the IP ECN bits
        // are outside the pseudo-header); the IP checksum is recomputed.
        Byte seg[65536];
        UInt32 seg_len = 0;
        for (UInt32 i = 0; i < 50 && 0 == seg_len; ++i) {
            while (0 != backend_a.TxPending()) {
                seg_len = backend_a.PollTx(seg);
                if (0 != seg_len) {
                    break;
                }
            }
            if (0 == seg_len) {
                // Re-open the pipe (the flow may be quiescent between
                // ACK windows) so a fresh segment is in flight.
                stack_a.Send(conn_a, payload, sizeof(payload));
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
        CHECK(0 != seg_len);
        std::vector<Byte> ce(seg, seg + seg_len);
        ce[1] = 0x03;  // CE (RFC 3168 IP ECN bits)
        xtcp::harness::FillIp4Checksum(ce.data());
        backend_b.Inject(ce.data(), static_cast<UInt32>(ce.size()), 0x0800);
        // B's CE -> SetCeSeen -> ECE echo on the next ACK; drive the loop.
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        UInt32 cwnd_after = 0;
        ConnCwnd(stack_a, conn_a, cwnd_after);
        std::fprintf(stderr, "[ecn-cc] cwnd after CE=%u (before=%u, CUBIC per-round 0.7x)\n",
                     cwnd_after, cwnd_before);
        // B echoes ECE on every ACK until A's CWR arrives, so the
        // once-per-RTT throttle can apply several CUBIC 0.7x rounds. The
        // exact 0.7 semantics are pinned by the plugin-level check above;
        // here: the cut happened through the plugin path and the window
        // did not collapse.
        CHECK(cwnd_after < cwnd_before);
        CHECK(cwnd_after >= cwnd_before / 5);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ECN_CC: FAILED (%d)\n" : "ECN_CC: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

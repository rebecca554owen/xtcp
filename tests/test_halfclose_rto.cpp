/**
 * @file test_halfclose_rto.cpp
 * @brief Half-close + tail data segment loss: while A sits in FIN-WAIT-1 with
 *        unacknowledged data, a dropped data segment must be recovered by the
 *        RTO timer retransmitting the DATA FIRST - not retransmitting only the
 *        FIN.
 *
 * Intent
 * ------
 * RFC 793 close: the FIN (seq snd_nxt_-1) follows all data. When the local
 * side closes with data still unacknowledged (FIN-WAIT-1), the FIN cannot be
 * acknowledged until the missing data fills the peer's gap. The FinWait1/2
 * RTO path (tcp_fsm.cpp:746-760) therefore must, when retrans_queue_ still
 * holds data, retransmit the FRONT DATA SEGMENT (RetransmitFront) and only
 * fall back to re-sending the FIN once the queue is empty. A buggy
 * implementation that retransmits ONLY the FIN leaves the peer's gap unfilled:
 * snd_una_ never advances, the peer never ACKs the FIN, and the close
 * deadlocks with the tail of the payload stranded.
 *
 * Scenario
 * --------
 *   - Dual-stack A<->B over two ManualBackends (back-to-back).
 *   - A's connection uses a custom CC ("bigwin", snd_cwnd = 10 MSS) so the
 *     RFC 5681 initial window (3 MSS, tcp_fsm.cpp:532) cannot limit the burst:
 *     all 8 KiB must be in flight (retrans_queue_) when Close runs.
 *   - A sends 8192 bytes (6 segments at MSS 1460) in one call and immediately
 *     Close()s: A enters FIN-WAIT-1 with all 8192 bytes unacknowledged.
 *   - The pump precisely drops the LAST A->B data segment (the one whose seq
 *     ends at the FIN's seq) by hold-and-lookahead: hold the current data
 *     packet; when the FIN is seen on the wire, the held packet is the tail
 *     data segment - blackhole it, deliver everything else including the FIN.
 *     B therefore receives segments 1-5 plus an out-of-order FIN (buffered).
 *   - B ACKs the frontier (7300); A prunes retrans_queue_ down to the dropped
 *     segment; the RTO timer fires. The FinWait1 RTO path must emit a DATA
 *     retransmission of the exact dropped seq (payload > 0).
 *   - B fills the gap, consumes the buffered FIN, ACKs 8193 (A -> FIN-WAIT-2),
 *     then B closes -> A reaches TIME-WAIT.
 *
 * Core assertions
 * --------------
 *   CHECK(kFinWait1 == A state right after Send+Close) - data unacked in FIN-WAIT-1
 *   CHECK(1 == drop_count && 0 < drop_len)            - exactly one real data segment dropped
 *   CHECK(0 < retx_of_drop)                            - the dropped DATA was retransmitted (not just the FIN)
 *   CHECK(kTotal == bytes_recv)                        - B received all 8192 bytes
 *   CHECK(crc_expect == crc_recv)                      - exact byte integrity
 *   CHECK(0 < retx)                                    - stack-level retransmission counter engaged
 *   CHECK(kTimeWait == end || kClosed == end)          - close completes to TIME-WAIT/Closed
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/cc/cc.h>

#include <chrono>
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

namespace {

// TCP wire offsets on a 20-byte IPv4 header (no IP options).
UInt32 IpHeaderLen(const Byte* p) { return static_cast<UInt32>(p[0] & 0x0F) * 4; }

UInt32 TcpSeq(const Byte* p) {
    const UInt32 ip = IpHeaderLen(p);
    return (static_cast<UInt32>(p[ip + 4]) << 24) |
           (static_cast<UInt32>(p[ip + 5]) << 16) |
           (static_cast<UInt32>(p[ip + 6]) << 8) |
           static_cast<UInt32>(p[ip + 7]);
}

UInt32 PayloadLen(const Byte* p, UInt32) {
    const UInt32 ip = IpHeaderLen(p);
    const UInt32 tcp_hdr_len = static_cast<UInt32>(p[ip + 12] >> 4) * 4;
    const UInt32 ip_total = (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
    if (ip_total < ip + tcp_hdr_len) {
        return 0;
    }
    return ip_total - ip - tcp_hdr_len;
}

// Big initial window so the whole 8 KiB test payload is in flight at Close
// (the default RFC 5681 initial window of 3 MSS caps the burst at 4380 B).
void BigWinInit(xtcp::cc::XtcpConnCc* sk) noexcept {
    sk->snd_cwnd = 10;
}
const xtcp::cc::XtcpCongestionOps kBigWin = {
    "bigwin",   // name
    BigWinInit, // init
    NULLPTR,    // release
    NULLPTR,    // ssthresh
    NULLPTR,    // cong_avoid
    NULLPTR,    // set_state
    NULLPTR,    // cwnd_event
    NULLPTR,    // pkts_acked
    NULLPTR,    // undo_cwnd
    NULLPTR,    // cong_control
    NULLPTR,    // reinit_ssthresh
    0,          // flags
};

/**
 * @brief Precise-drop state: the pump blackholes exactly one A->B data
 *        segment - the LAST one, i.e. the data segment whose seq ends at the
 *        FIN's seq (hold-and-lookahead across pump calls).
 */
struct DropCtl {
    bool   drop_done   = false;  // the tail data segment has been dropped
    bool   have_held   = false;  // a data packet is held pending the FIN
    Byte   held[65536];
    UInt32 held_len    = 0;
    UInt32 drop_seq    = 0;      // seq of the blackholed data segment
    UInt32 drop_len    = 0;      // payload length of the blackholed segment
    UInt32 drop_count  = 0;      // data segments blackholed (must be exactly 1)
    UInt32 retx_of_drop = 0;     // wire retransmissions of drop_seq with payload
    UInt32 total_a_data = 0;     // A->B data segments observed (incl. retransmits)
};

/** Feeds one A->B packet through the drop/observe/inject pipeline. */
void DeliverOne(const Byte* p, UInt32 n, xtcp::ndi::ManualBackend& b, DropCtl& ctl) {
    const bool is_fin  = 0 != (p[IpHeaderLen(p) + 13] & 0x01);
    const UInt32 plen  = PayloadLen(p, n);
    const bool is_data = 0 < plen;
    if (is_fin && !is_data) {
        // FIN: any held data packet is the tail data segment - drop it.
        if (ctl.have_held) {
            ctl.drop_seq = TcpSeq(ctl.held);
            ctl.drop_len = PayloadLen(ctl.held, ctl.held_len);
            ++ctl.drop_count;
            ctl.have_held = false;
            ctl.drop_done = true;  // exactly one tail segment is blackholed
        }
        b.Inject(p, n, 0x0800);
        return;
    }
    if (is_data) {
        ++ctl.total_a_data;
        if (!ctl.drop_done) {
            // Hold: if another data segment follows, the held one is not the
            // tail; if a FIN follows, the held one is the tail (dropped above).
            if (ctl.have_held) {
                b.Inject(ctl.held, ctl.held_len, 0x0800);
            }
            std::memcpy(ctl.held, p, n);
            ctl.held_len = n;
            ctl.have_held = true;
            return;
        }
        // Post-drop: count retransmissions of the dropped segment (payload>0
        // is implied - a bare FIN retransmit has seq drop_seq+drop_len and
        // zero payload, so it would not match here).
        if (TcpSeq(p) == ctl.drop_seq) {
            ++ctl.retx_of_drop;
        }
        b.Inject(p, n, 0x0800);
        return;
    }
    // Pure ACK / window probe from A (no payload, no FIN): inject.
    if (ctl.have_held) {
        b.Inject(ctl.held, ctl.held_len, 0x0800);
        ctl.have_held = false;
    }
    b.Inject(p, n, 0x0800);
}

/**
 * @brief Pumps both directions, blackholing the LAST A->B data segment exactly
 *        once, and advances both stacks' timers. Mirrors test_ecn_loss's pump
 *        plus the precise tail-drop interception.
 */
void PumpDropLast(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                  xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, DropCtl& ctl) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                DeliverOne(out, n, b, ctl);
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

}  // namespace

int main() {
    xtcp::buf::InitPools();
    CHECK(xtcp::cc::RegisterCongestionControl(kBigWin));
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

        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });
        // B's passive conn id is captured from the state handler - each stack
        // generates its own ids, never assume conn_b == conn_a + 1.
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40299;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9161;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        DropCtl ctl;
        PumpDropLast(backend_a, backend_b, stack_a, stack_b, ctl);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Widen the initial window: the whole 8 KiB payload must be in flight
        // (retrans_queue_) when Close runs, or the "tail data segment" is not
        // yet on the wire and there is nothing to lose.
        CHECK(stack_a.SetCongestionControl(conn, "bigwin"));

        // A sends 8192 bytes (6 segments) and closes immediately: FIN-WAIT-1
        // with all 8192 bytes unacknowledged.
        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 17 + i / 7) & 0xFF);
        }
        CHECK(stack_a.Send(conn, payload.data(), kTotal));
        stack_a.Close(conn);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[halfclose-rto] A state after Send+Close=%d (expect 5=FinWait1)\n",
                     static_cast<int>(mid));
        CHECK(xtcp::core::TcpState::kFinWait1 == mid);

        // First pump: drop exactly the LAST A->B data segment; deliver the
        // FIN. B gets segments 1-5 + an out-of-order FIN, ACKs the frontier.
        PumpDropLast(backend_a, backend_b, stack_a, stack_b, ctl);
        std::fprintf(stderr, "[halfclose-rto] dropped=%u len=%u data_segs_seen=%u\n",
                     ctl.drop_count, ctl.drop_len, ctl.total_a_data);
        CHECK(1 == ctl.drop_count);          // precisely one segment blackholed
        CHECK(0 < ctl.drop_len);             // and it was a real data segment
        CHECK(xtcp::core::TcpState::kFinWait1 == stack_a.ConnectionState(conn));

        // Wait out the RTO (200 ms floor after the first RTT sample, 1 s
        // before it; 80 * 50 ms covers either). The FinWait1 RTO path must
        // retransmit the DROPPED DATA segment, not just the FIN.
        bool got_retx = false;
        for (UInt32 i = 0; i < 80 && !got_retx; ++i) {
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            PumpDropLast(backend_a, backend_b, stack_a, stack_b, ctl);
            got_retx = (0 < ctl.retx_of_drop);
            if (!got_retx) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        std::fprintf(stderr, "[halfclose-rto] wire retransmissions of dropped seq=%u\n",
                     ctl.retx_of_drop);
        CHECK(got_retx);  // the dropped DATA was retransmitted (data-first, not FIN-only)

        // B fills the gap, consumes the out-of-order FIN, ACKs 8193 (A ->
        // FIN-WAIT-2). Confirm the full payload arrived intact.
        for (UInt32 i = 0; i < 50 && bytes_recv < kTotal; ++i) {
            PumpDropLast(backend_a, backend_b, stack_a, stack_b, ctl);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        std::fprintf(stderr, "[halfclose-rto] B received=%llu/8192 crc=%u/%u\n",
                     (unsigned long long)bytes_recv, crc_recv, crc_expect);
        CHECK(kTotal == bytes_recv);          // all 8192 bytes recovered
        CHECK(crc_expect == crc_recv);        // exact byte integrity

        // Stack-level retransmission counter engaged (RetransmitFront).
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto_deadline = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        CHECK(0 < retx);

        // B closes its half: A (FIN-WAIT-2) receives B's FIN -> TIME-WAIT.
        CHECK(0 != conn_b);
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 300; ++i) {
            PumpDropLast(backend_a, backend_b, stack_a, stack_b, ctl);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[halfclose-rto] A final state=%d (expect 10=TimeWait or 0=Closed)\n",
                     static_cast<int>(end));
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "HALFCLOSE_RTO: FAILED (%d)\n" : "HALFCLOSE_RTO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

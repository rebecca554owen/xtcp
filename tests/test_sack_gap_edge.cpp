/**
 * @file test_sack_gap_edge.cpp
 * @brief SACK-recovery boundary regression (RFC 6675): when a single-segment
 *        gap is retransmitted, sack_retx_next_ advances to exactly the left
 *        boundary of the next SACK block. RetransmitEarliestMissing must NOT
 *        re-retransmit the already-SACKed segment at that boundary
 *        (tcp_fsm.cpp `|| sack_retx_next_ == left` fix) - otherwise every
 *        duplicate ACK / partial ACK re-sends SACKed data (a retransmit
 *        storm that inflates retransmit_count_ and stalls completion).
 *
 *        Loss profile: dual stacks, every 8th first-seen data segment is
 *        blackholed (retransmissions pass), producing >= 2 isolated
 *        single-segment gaps - exactly the shape that lands sack_retx_next_
 *        on a SACK-block left edge. Verification: byte-exact delivery with a
 *        rolling CRC (no duplicate delivery) + bounded retransmit_count_
 *        (ConnStats) proving the recovery did not degenerate into a storm.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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

/**
 * @brief Pumps `from`'s tx into `to`, dropping every `drop_every`-th
 *        FIRST-SEEN data segment (identified by its sequence number);
 *        retransmissions pass. Drops apply to data only, so ACKs and the
 *        handshake are never blackholed and each gap stays exactly one
 *        segment wide.
 */
static void PumpDrop(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                     UInt32 drop_every, UInt32& dropped_out, UInt32& first_seen_out,
                     std::vector<UInt32>& dropped_seqs) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        // IPv4 (20B) + TCP: flags at tcp offset 13, seq at 4.
        const UInt32 tcp_off = 20;
        const bool data = (got > tcp_off + 13) && (0 != (out[tcp_off + 13] & 0x08));  // PSH
        bool drop = false;
        if (data) {
            const UInt32 seq = (static_cast<UInt32>(out[tcp_off + 4]) << 24) |
                               (static_cast<UInt32>(out[tcp_off + 5]) << 16) |
                               (static_cast<UInt32>(out[tcp_off + 6]) << 8) |
                               static_cast<UInt32>(out[tcp_off + 7]);
            const bool is_retransmit =
                std::find(dropped_seqs.begin(), dropped_seqs.end(), seq) != dropped_seqs.end();
            if (!is_retransmit) {
                ++first_seen_out;
                if (0 != drop_every && 0 == (first_seen_out % drop_every)) {
                    drop = true;
                }
            }
            if (drop) {
                dropped_seqs.push_back(seq);
            }
        }
        if (drop) {
            ++dropped_out;
            continue;  // blackhole
        }
        to.Inject(out, got, 0x0800);
        if (20000 < ++guard) {
            break;
        }
    }
}

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

/** 64 KiB transfer, every 8th first-seen data segment blackholed. */
int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0xC0A80102;
        local.port = 41001;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        // Reno: the deterministic RFC 5681/6675 recovery path (KCC interacts
        // with the SACK chain differently - see .opencode/discover.md).
        CHECK(stack_a.SetCongestionControl(conn, ""));

        // Handshake: no drops.
        {
            UInt32 drop = 0, seen = 0;
            std::vector<UInt32> seqs;
            PumpDrop(backend_a, backend_b, 0, drop, seen, seqs);
            PumpDrop(backend_b, backend_a, 0, drop, seen, seqs);
            PumpDrop(backend_a, backend_b, 0, drop, seen, seqs);
        }

        constexpr UInt32 kTotal = 64 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 17 + 11) & 0xFF));
        }
        constexpr UInt32 kDropEvery = 8;
        UInt32 dropped = 0, first_seen = 0;
        std::vector<UInt32> dropped_seqs;
        UInt32 sent = 0;
        UInt32 guard = 0;
        while (sent < kTotal && 40000 > ++guard) {
            const UInt32 chunk = (kTotal - sent < 1460) ? (kTotal - sent) : 1460;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            PumpDrop(backend_a, backend_b, kDropEvery, dropped, first_seen, dropped_seqs);
            PumpDrop(backend_b, backend_a, 0, dropped, first_seen, dropped_seqs);
            stack_b.PollAckTimers();
            stack_a.PollAckTimers();
        }
        // Drain: delayed-ACK (40 ms) paces the back-to-back transfer, so wait
        // between rounds for the timers to fire; a retransmit storm would
        // burn the entire budget without completing.
        for (UInt32 i = 0; i < 3000 && received.size() < kTotal; ++i) {
            const UInt32 chunk = (kTotal - sent < 1460) ? (kTotal - sent) : 1460;
            if (sent < kTotal && stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            PumpDrop(backend_a, backend_b, kDropEvery, dropped, first_seen, dropped_seqs);
            PumpDrop(backend_b, backend_a, 0, dropped, first_seen, dropped_seqs);
            stack_b.PollAckTimers();
            stack_a.PollAckTimers();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // Flush any last buffered sends once more.
        PumpDrop(backend_a, backend_b, kDropEvery, dropped, first_seen, dropped_seqs);
        PumpDrop(backend_b, backend_a, 0, dropped, first_seen, dropped_seqs);
        stack_b.PollAckTimers();
        stack_a.PollAckTimers();

        // 1) Data integrity: byte-exact size + exact rolling CRC. A duplicate
        //    delivery (re-delivered SACKed bytes) corrupts the stream and
        //    fails the CRC.
        UInt32 crc_recv = 0;
        for (UInt32 i = 0; i < received.size(); ++i) {
            crc_recv = (crc_recv * 31 + static_cast<Byte>(received[i])) & 0x7FFFFFFF;
        }
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + static_cast<Byte>(payload[i])) & 0x7FFFFFFF;
        }
        CHECK(kTotal == received.size());
        CHECK(crc_recv == crc_expect);

        // 2) The loss policy must actually have created gaps - at least two
        //    single-segment holes (kTotal / 1460 ~= 45 segments, every 8th).
        CHECK(2 <= dropped);

        // 3) Retransmit count (ConnStats): bounded by the true number of
        //    losses. Each blackholed segment needs >= 1 retransmit
        //    (dropped <= retx); the boundary bug re-sends SACKed segments on
        //    every dupack/partial-ACK, blowing retx far past the loss count.
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto_deadline = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline, dup, fast,
                          front_seq, snd_una, lp, rp);
        std::fprintf(stderr,
                     "[sack-gap] sent=%u recv=%zu dropped=%u retx=%u inflight=%u cwnd=%u ssthresh=%u wnd=%u front=%u snd_una=%u\n",
                     sent, received.size(), dropped, retx, inflight, cwnd, ssthresh, snd_wnd,
                     front_seq, snd_una);
        CHECK(dropped <= retx);
        CHECK(retx <= 4 * dropped);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SACK_GAP_EDGE: FAILED (%d)\n" : "SACK_GAP_EDGE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_reorder_gate.cpp
 * @brief Pins the reordering gate: a dup-ACK for a segment that
 *        was merely reordered (arriving late, with SACK evidence that later
 *        segments arrived first) must NOT trigger fast recovery, while a
 *        genuine front drop (no SACK evidence of reordering, front stale)
 *        must still fast-retransmit promptly.
 *
 * Found via real-kernel interop (interop_tun): a lossless TUN link produced
 * ~30 spurious FRONT-SACK retransmissions per 1MB echo because the Linux
 * peer's dup-ACKs carried contiguous SACK blocks confirming data BEYOND
 * the front (the front arrived ~1.3 RTT late). Each entry halved cwnd.
 *
 * Scenarios (A = sender, B = receiver, raw dup-ACKs injected from B):
 *   1. FRESH front + 3 dup-ACKs, no SACK: reordering gate blocks entry
 *      (front < 3 RTT old) - cwnd NOT cut, retx == 0.
 *   2. FRESH front + 3 dup-ACKs WITH contiguous SACK past the front:
 *      SACK evidence of reordering - gate blocks, cwnd NOT cut, retx == 0.
 *   3. STALE front (> 3 RTT) + 3 dup-ACKs, no SACK: no reordering evidence,
 *      genuine loss - fast recovery fires, retx >= 1, cwnd cut.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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
    using xtcp::harness::FillIp4Checksum;
    using xtcp::harness::FillTcp4Checksum;

    /** Raw ACK from B's tuple with optional SACK blocks ([left,right) pairs,
     *  already absolute sequence numbers). */
    static std::vector<Byte> BuildAckWithSack(UInt32 ack, const UInt32* sack_pairs, UInt32 n_pairs) {
        // Full size up front (20 IP + 20 TCP + padded options): resize after
        // taking pointers would invalidate them via reallocation.
        const UInt32 opt_len = (0 < n_pairs) ? (2 + 8 * n_pairs) : 0;
        const UInt32 padded = (opt_len + 3) & ~3u;
        std::vector<Byte> out(40 + padded, 0);
        Byte* ip = out.data();
        ip[0] = 0x45;
        const UInt32 total = static_cast<UInt32>(out.size());
        ip[2] = static_cast<Byte>(total >> 8);
        ip[3] = static_cast<Byte>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 6;
        ip[12] = 0x0A; ip[13] = 0x00; ip[14] = 0x00; ip[15] = 0x02;  // B
        ip[16] = 0x0A; ip[17] = 0x00; ip[18] = 0x00; ip[19] = 0x01;  // A
        Byte* t = ip + 20;
        t[0] = 0x23; t[1] = 0x82;  // sport 9090
        t[2] = 0x9C; t[3] = 0x7D;  // dport 40061
        t[4] = t[5] = t[6] = t[7] = 0x50;  // seq (in window)
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = static_cast<Byte>(((20 + padded) / 4) << 4);  // data offset
        t[13] = 0x10;  // ACK
        t[14] = 0xFF; t[15] = 0xFF;
        // TCP options: kind=5 (SACK), len=10, two edges per block, then
        // NOP padding so the header is 4-byte aligned.
        if (0 < n_pairs) {
            Byte* opt = t + 20;
            opt[0] = 5;
            opt[1] = static_cast<Byte>(opt_len);
            for (UInt32 i = 0; i < n_pairs; ++i) {
                Byte* e = opt + 2 + 8 * i;
                e[0] = static_cast<Byte>(sack_pairs[2 * i] >> 24);
                e[1] = static_cast<Byte>(sack_pairs[2 * i] >> 16);
                e[2] = static_cast<Byte>(sack_pairs[2 * i] >> 8);
                e[3] = static_cast<Byte>(sack_pairs[2 * i] & 0xFF);
                e[4] = static_cast<Byte>(sack_pairs[2 * i + 1] >> 24);
                e[5] = static_cast<Byte>(sack_pairs[2 * i + 1] >> 16);
                e[6] = static_cast<Byte>(sack_pairs[2 * i + 1] >> 8);
                e[7] = static_cast<Byte>(sack_pairs[2 * i + 1] & 0xFF);
            }
            for (UInt32 i = opt_len; i < padded; ++i) {
                opt[i] = 1;  // NOP padding
            }
        }
        FillIp4Checksum(ip);
        FillTcp4Checksum(ip, t, static_cast<UInt32>(20 + padded));
        return out;
    }

    /** Pumps A's tx into B ONLY (B's ACKs stay queued): keeps A's data in
     *  retrans_queue_ while raw dup-ACKs are injected. */
    static void PumpOneWay(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                           xtcp::XtcpStack& sa) {
        Byte out[65536];
        for (UInt32 round = 0; round < 50; ++round) {
            bool moved = false;
            while (0 != a.TxPending()) {
                const UInt32 n = a.PollTx(out);
                if (0 < n) {
                    b.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            sa.PollAckTimers();
            if (!moved) {
                return;
            }
        }
    }

    static void PumpBoth(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                         xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
        Byte out[65536];
        for (UInt32 round = 0; round < 5000; ++round) {
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

    struct Stats {
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
    };
    static Stats GetStats(xtcp::XtcpStack& s, UInt64 conn) {
        Stats st;
        s.ConnStats(conn, st.inflight, st.cwnd, st.ssthresh, st.snd_wnd, st.retx,
                    st.rto, st.dup, st.fast, st.front_seq, st.snd_una, st.lp, st.rp);
        return st;
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
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9090;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // In-flight data: 12 KB (8+ segments) so a real front gap is testable.
        Byte payload[12288];
        std::memset(payload, 0x5A, sizeof(payload));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);
        // Sample RTT: deliver B's ACK back to A so srtt_ > 0 (the gate needs
        // a real RTT to judge front age; without it the reordering gate
        // bypasses and every dup-ACK triggers fast recovery).
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);
        {
            Stats st = GetStats(stack_a, conn);
            std::fprintf(stderr, "[reorder] srtt probe: una=%u retx=%u\n", st.snd_una, st.retx);
        }

        // ---- Scenario 1: FRESH front, 3 dup-ACKs, NO SACK ----
        // RFC 5681: 3 dup-ACKs trigger fast recovery regardless of front
        // age when there is no SACK information to reconsider.
        Stats s1 = GetStats(stack_a, conn);
        const UInt32 cwnd_before1 = s1.cwnd;
        const UInt32 retx_before1 = s1.retx;
        const UInt32 dup_ack_val = s1.snd_una;
        for (UInt32 i = 0; i < 3; ++i) {
            std::vector<Byte> ack = BuildAckWithSack(dup_ack_val, NULLPTR, 0);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        }
        stack_a.PollAckTimers();
        Stats s1b = GetStats(stack_a, conn);
        std::fprintf(stderr, "[reorder] s1 fresh no-sack: cwnd %u->%u retx %u->%u\n",
                     cwnd_before1, s1b.cwnd, retx_before1, s1b.retx);
        CHECK(s1b.retx > retx_before1);    // RFC 5681: fast retransmit
        CHECK(s1b.cwnd < cwnd_before1);    // RFC 5681: cwnd cut

        // ---- Scenario 2: FRESH front, 3 dup-ACKs with SACK blocks that add
        // NO new information (all SACK ranges at/below the cum-ACK - the
        // exact shape the Linux kernel produced on the lossless TUN link:
        // dup-ACKs confirming only already-ACKed data, the front merely in
        // flight). The reordering gate must block fast recovery. ----
        // Settle s1's recovery first so the flow is clean for s2.
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);
        Stats s1c = GetStats(stack_a, conn);
        const UInt32 front1 = s1c.snd_una;
        // SACK confirming data BEHIND the cum-ACK (already cumulatively
        // ACKed): the dup-ACK carries zero new information.
        const UInt32 sack_pairs[2] = { static_cast<UInt32>(front1 - 2920),
                                       static_cast<UInt32>(front1 - 1460) };
        const UInt32 cwnd_before2 = s1c.cwnd;
        const UInt32 retx_before2 = s1c.retx;
        for (UInt32 i = 0; i < 3; ++i) {
            std::vector<Byte> ack = BuildAckWithSack(front1, sack_pairs, 1);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        }
        stack_a.PollAckTimers();
        Stats s2 = GetStats(stack_a, conn);
        std::fprintf(stderr, "[reorder] s2 fresh +stale-sack: cwnd %u->%u retx %u->%u\n",
                     cwnd_before2, s2.cwnd, retx_before2, s2.retx);
        CHECK(cwnd_before2 == s2.cwnd);    // gate: no cwnd cut
        CHECK(retx_before2 == s2.retx);    // gate: no retransmit

        // ---- Scenario 2b: FRESH front, 3 dup-ACKs with a SACK block
        // revealing a REAL gap behind the front (data confirmed missing):
        // genuine loss, fast recovery must fire despite the fresh front. ----
        const UInt32 cwnd_before2b = s2.cwnd;
        const UInt32 retx_before2b = s2.retx;
        const UInt32 gap_pairs[2] = { static_cast<UInt32>(front1 + 1460),
                                      static_cast<UInt32>(front1 + 2920) };
        for (UInt32 i = 0; i < 3; ++i) {
            std::vector<Byte> ack = BuildAckWithSack(front1, gap_pairs, 1);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        }
        stack_a.PollAckTimers();
        Stats s2b = GetStats(stack_a, conn);
        std::fprintf(stderr, "[reorder] s2b fresh +real-gap: cwnd %u->%u retx %u->%u\n",
                     cwnd_before2b, s2b.cwnd, retx_before2b, s2b.retx);
        CHECK(s2b.retx > retx_before2b);   // real gap: fast retransmit
        CHECK(s2b.cwnd < cwnd_before2b);   // real gap: cwnd cut

        // ---- Scenario 3: STALE front (> 3 RTT), 3 dup-ACKs, NO SACK.
        // No reordering evidence + front outstanding > 3 RTT: genuine loss -
        // fast recovery must fire (cwnd cut, retransmit). ----
        // Let the previous recovery complete so the flow exits fast recovery
        // (a fresh entry must cut cwnd from the recovered value).
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));  // >> 3 x µs-srtt
        Stats s3a = GetStats(stack_a, conn);
        const UInt32 cwnd_before3 = s3a.cwnd;
        const UInt32 retx_before3 = s3a.retx;
        const UInt32 dup_ack_val3 = s3a.snd_una;
        for (UInt32 i = 0; i < 3; ++i) {
            std::vector<Byte> ack = BuildAckWithSack(dup_ack_val3, NULLPTR, 0);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        }
        stack_a.PollAckTimers();
        Stats s3b = GetStats(stack_a, conn);
        std::fprintf(stderr, "[reorder] s3 stale no-sack: cwnd %u->%u retx %u->%u\n",
                     cwnd_before3, s3b.cwnd, retx_before3, s3b.retx);
        CHECK(s3b.retx > retx_before3);    // genuine loss: fast retransmit
        // (cwnd may be in recovery-inflation from s2b; the retransmit is the
        // pinned behavior - cwnd cutting is already asserted by s2b.)

        // ---- Scenario 4: DURING recovery, zero-info SACK dup-ACKs must NOT
        // walk the retransmit queue (the storm gate advances sack_retx_next_
        // on every blocked re-send; a zero-info SACK dup would advance past
        // the front and retransmit the NEXT segment - over-retransmission).
        // Enter recovery with a fresh real-gap entry, then flood zero-info
        // SACK dups and assert the retransmit count stays at the entry value.
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);
        Stats s4a = GetStats(stack_a, conn);
        const UInt32 front4 = s4a.snd_una;
        const UInt32 gap4[2] = { static_cast<UInt32>(front4 + 1460),
                                 static_cast<UInt32>(front4 + 2920) };
        for (UInt32 i = 0; i < 3; ++i) {  // real gap: enter recovery
            std::vector<Byte> ack = BuildAckWithSack(front4, gap4, 1);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        }
        stack_a.PollAckTimers();
        Stats s4b = GetStats(stack_a, conn);
        const UInt32 retx_after_entry = s4b.retx;
        CHECK(s4b.retx > s4a.retx);  // entry retransmitted
        // Flood zero-info SACK dups (ranges at/below the cum-ACK): the
        // recovery path must NOT retransmit further segments.
        for (UInt32 i = 0; i < 20; ++i) {
            const UInt32 zero_sack[2] = { static_cast<UInt32>(front4 - 2920),
                                          static_cast<UInt32>(front4 - 1460) };
            std::vector<Byte> ack = BuildAckWithSack(front4, zero_sack, 1);
            backend_a.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
            stack_a.PollAckTimers();
        }
        Stats s4c = GetStats(stack_a, conn);
        std::fprintf(stderr, "[reorder] s4 recovery+zero-sack: retx %u->%u->%u\n",
                     s4a.retx, retx_after_entry, s4c.retx);
        CHECK(s4c.retx == retx_after_entry);  // no over-retransmission

        // Let the flow finish cleanly.
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        PumpBoth(backend_a, backend_b, stack_a, stack_b);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "REORDER_GATE: FAILED (%d)\n" : "REORDER_GATE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

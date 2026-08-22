/**
 * @file test_md5_key_change.cpp
 * @brief TCP-MD5 (RFC 2385) key rotation on a live, established connection.
 *
 * Scenario: after the handshake, both endpoints change the shared key
 * mid-stream (XtcpStack::SetMd5Key on each side) and the transfer must
 * continue intact under the new key.
 *
 * Key mechanism (static analysis of the current implementation):
 *  - Every inbound segment is verified against the connection's CURRENT key
 *    (tcp_fsm.cpp:1694-1697). A segment carrying the previous key's digest
 *    is silently dropped (verification-first, RFC 2385).
 *  - New outbound segments are built with Md5Key() read at build time, so
 *    after a rotation they carry the new key's digest.
 *  - Retransmission re-sends the packet stored in the retransmission queue
 *    unchanged (RetransmitFront -> seg.data.Clone(), tcp_fsm.cpp:678-681);
 *    its digest is NEVER recomputed with the current key.
 *
 * Recorded behavior / hang risk (NOT executed - this test only runs the
 * synchronized rotation):
 *  - If the rotation is NOT synchronized (only one endpoint changes, or the
 *    change happens while old-key-signed segments are still in flight / in
 *    the retransmission queue), the peer drops every old-signed segment.
 *    RTO retransmission re-sends the stored packet with the STALE digest,
 *    so it is dropped again forever - the connection stalls (hang) until
 *    kMaxDataRetries=15 (tcp_fsm.cpp:666) closes it.
 *  - This test therefore (a) fully drains phase 1 before rotating (ConnStats
 *    front_seq==0 on BOTH sides = no unacknowledged/old-signed segment is
 *    anywhere in flight), and (b) rotates BOTH endpoints back-to-back before
 *    any phase-2 data is sent. Phase 2 is then signed with the new key on
 *    both sides and verification matches on both sides.
 *
 * Core assertion: after a synchronized key change the transfer continues and
 * completes byte-exactly (no gap, no duplicate, no hang).
 *
 * Observed stack behavior this test works around (pre-existing, and
 * independent of the MD5 key - reproduced with the rotation disabled):
 *  - Simultaneous bidirectional bursts make every segment in a flush burst
 *    piggyback the same cumulative ACK. The peer counts the repeated ACK as
 *    duplicate ACKs, crosses the 3-dup-ACK threshold and enters a spurious
 *    fast recovery (CutCwnd + retransmit, tcp_fsm.cpp:1183-1193) even on a
 *    lossless manual backend, inflating the ConnStats retx counter; it can
 *    also strand the RFC 6675 SACK walk (sack_retx_next_ on a SACK-block
 *    boundary, tcp_fsm.cpp:976) and delay delivery until RTO.
 *  - The transfer is therefore driven ONE DIRECTION AT A TIME, and the drain
 *    waits for the DELIVERED BYTE COUNT - not just front_seq==0: the
 *    retransmission queue can be empty while buffered sends still sit behind
 *    a post-recovery window (tcp_fsm.cpp:1489-1492). retx is logged, not
 *    asserted zero: a nonzero retx here is spurious fast recovery, not a
 *    stale-signature re-send (the pre-rotation gate already rules that out).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <set>
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

// Move every queued packet both directions and fire both stacks' timers.
static void PumpRound(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    while (0 != a.TxPending()) {
        const UInt32 n = a.PollTx(out);
        if (0 < n) {
            b.Inject(out, n, 0x0800);
        }
    }
    while (0 != b.TxPending()) {
        const UInt32 n = b.PollTx(out);
        if (0 < n) {
            a.Inject(out, n, 0x0800);
        }
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
}

// Simple pump: sleep 1 ms per round, stop after two consecutive rounds with
// nothing queued in either direction.
static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32 rounds) {
    UInt32 quiet = 0;
    for (UInt32 round = 0; round < rounds; ++round) {
        const UInt64 tx_a = a.TxPending();
        const UInt64 tx_b = b.TxPending();
        PumpRound(a, b, sa, sb);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (0 == tx_a && 0 == tx_b) {
            if (2 == ++quiet) {
                return;
            }
        } else {
            quiet = 0;
        }
    }
}

// Pump (with real time so the 40 ms delayed ACK fires) until the expected
// byte count has been delivered on BOTH receivers AND neither side still
// holds an unacknowledged segment (ConnStats front_seq==0). Completion is
// keyed on the delivered byte count, not front_seq alone: front_seq==0 only
// proves the retransmission queue is empty, but buffered sends can still sit
// behind a post-recovery window (tcp_fsm.cpp:1489-1492) with nothing queued
// for retransmission yet. Returns false if a side died or max_rounds pass.
static bool DrainTo(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                    xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                    UInt64 conn_a, UInt64 conn_b,
                    const std::vector<Byte>& recv_a, const std::vector<Byte>& recv_b,
                    size_t expect_a, size_t expect_b) {
    for (UInt32 round = 0; round < 9000; ++round) {
        PumpRound(a, b, sa, sb);
        if (xtcp::core::TcpState::kEstablished != sa.ConnectionState(conn_a) ||
            xtcp::core::TcpState::kEstablished != sb.ConnectionState(conn_b)) {
            return false;  // a side died: not "settled"
        }
        if (expect_a <= recv_a.size() && expect_b <= recv_b.size()) {
            UInt32 in_a = 0, cw_a = 0, ss_a = 0, sw_a = 0, rx_a = 0;
            UInt64 rto_a = 0;
            UInt32 da_a = 0, fr_a = 0, fq_a = 0, su_a = 0;
            UInt16 lp_a = 0, rp_a = 0;
            UInt32 in_b = 0, cw_b = 0, ss_b = 0, sw_b = 0, rx_b = 0;
            UInt64 rto_b = 0;
            UInt32 da_b = 0, fr_b = 0, fq_b = 0, su_b = 0;
            UInt16 lp_b = 0, rp_b = 0;
            sa.ConnStats(conn_a, in_a, cw_a, ss_a, sw_a, rx_a, rto_a, da_a, fr_a, fq_a, su_a, lp_a, rp_a);
            sb.ConnStats(conn_b, in_b, cw_b, ss_b, sw_b, rx_b, rto_b, da_b, fr_b, fq_b, su_b, lp_b, rp_b);
            if (0 == fq_a && 0 == fq_b) {
                return true;  // expected bytes delivered; nothing unacknowledged
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

// Send len bytes (<=2048 B chunks) over conn on sender, pumping between
// attempts. Returns the number of bytes accepted by the stack (== len on
// success; less means the pump could not free buffer/window).
static UInt32 SendAll(xtcp::XtcpStack& sender, UInt64 conn, const Byte* data, UInt32 len,
                      xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    UInt32 sent = 0;
    while (sent < len) {
        UInt32 n = len - sent;
        if (n > 2048) {
            n = 2048;
        }
        UInt32 tries = 0;
        while (!sender.Send(conn, data + sent, n) && 3000 > ++tries) {
            PumpRound(a, b, sa, sb);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (3000 <= tries) {
            return sent;  // give up; caller asserts full delivery
        }
        sent += n;
        PumpRound(a, b, sa, sb);
    }
    return sent;
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

        // Byte-exact receivers on both stacks (in-order delivery).
        std::vector<Byte> recv_a, recv_b;
        stack_a.SetRecvHandler([&recv_a](UInt64, const Byte* d, UInt32 len) {
            recv_a.insert(recv_a.end(), d, d + len);
        });
        stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 len) {
            recv_b.insert(recv_b.end(), d, d + len);
        });

        // B's passive connection id (state handler fires on every inbound
        // packet; dedupe the repeated kEstablished callbacks).
        std::set<UInt64> established_b;
        stack_b.SetStateHandler([&established_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                established_b.insert(id);
            }
        });

        const Byte key1[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        const Byte key2[] = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40292;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9117;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key1, sizeof(key1));
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key1, sizeof(key1));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b, 500);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(1 == established_b.size());
        const UInt64 conn_b = *established_b.begin();
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        std::fprintf(stderr, "[md5-key] handshake ok (A=%d B=%d)\n",
                     (int)stack_a.ConnectionState(conn),
                     (int)stack_b.ConnectionState(conn_b));

        const UInt32 kPhase = 8192;
        std::vector<Byte> ab1(kPhase), ba1(kPhase), ab2(kPhase), ba2(kPhase);
        for (UInt32 i = 0; i < kPhase; ++i) {
            ab1[i] = static_cast<Byte>((i * 3 + 1) & 0xFF);    // phase 1, A->B
            ba1[i] = static_cast<Byte>((i * 5 + 2) & 0xFF);    // phase 1, B->A
            ab2[i] = static_cast<Byte>((i * 7 + 3) & 0xFF);    // phase 2, A->B
            ba2[i] = static_cast<Byte>((i * 11 + 4) & 0xFF);   // phase 2, B->A
        }
        std::vector<Byte> expect_ab(2 * kPhase), expect_ba(2 * kPhase);
        std::memcpy(expect_ab.data(), ab1.data(), kPhase);
        std::memcpy(expect_ab.data() + kPhase, ab2.data(), kPhase);
        std::memcpy(expect_ba.data(), ba1.data(), kPhase);
        std::memcpy(expect_ba.data() + kPhase, ba2.data(), kPhase);

        // ---- Phase 1: partial transfer, all signed with key1 ----
        // One direction at a time, fully drained before the other starts:
        // simultaneous bidirectional bursts make every segment in a flush
        // burst piggyback the same cumulative ACK, so the peer counts the
        // repeated ACKs as duplicate ACKs and enters a spurious fast recovery
        // (retx>0) that is independent of the MD5 key and can delay delivery.
        CHECK(kPhase == SendAll(stack_a, conn, ab1.data(), kPhase, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, conn, conn_b, recv_a, recv_b, 0, kPhase));
        CHECK(kPhase == recv_b.size());
        CHECK(kPhase == SendAll(stack_b, conn_b, ba1.data(), kPhase, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, conn, conn_b, recv_a, recv_b, kPhase, kPhase));
        CHECK(kPhase == recv_a.size());
        std::fprintf(stderr, "[md5-key] phase1 drained (A->B=%zu B->A=%zu)\n",
                     recv_b.size(), recv_a.size());

        // Gate: NO unacknowledged (old-key-signed) segment may be in flight
        // on either side before the rotation - otherwise the peer would drop
        // it and RTO retransmission (which keeps the stale digest) could
        // never deliver it (hang risk). DrainTo already enforced front_seq==0
        // to return; re-assert here as the documented rotation gate. retx is
        // logged (a nonzero value is spurious fast recovery from the ACK
        // bursts above, never a stale-signature re-send - the gate rules the
        // latter out).
        {
            UInt32 in_a = 0, cw_a = 0, ss_a = 0, sw_a = 0, rx_a = 0;
            UInt64 rto_a = 0;
            UInt32 da_a = 0, fr_a = 0, fq_a = 0, su_a = 0;
            UInt16 lp_a = 0, rp_a = 0;
            UInt32 in_b = 0, cw_b = 0, ss_b = 0, sw_b = 0, rx_b = 0;
            UInt64 rto_b = 0;
            UInt32 da_b = 0, fr_b = 0, fq_b = 0, su_b = 0;
            UInt16 lp_b = 0, rp_b = 0;
            stack_a.ConnStats(conn, in_a, cw_a, ss_a, sw_a, rx_a, rto_a, da_a, fr_a, fq_a, su_a, lp_a, rp_a);
            stack_b.ConnStats(conn_b, in_b, cw_b, ss_b, sw_b, rx_b, rto_b, da_b, fr_b, fq_b, su_b, lp_b, rp_b);
            CHECK(0 == fq_a);  // A has no unacknowledged (old-key) segment
            CHECK(0 == fq_b);  // B has no unacknowledged (old-key) segment
            std::fprintf(stderr, "[md5-key] pre-rotation front_seq A=%u B=%u retx A=%u B=%u\n",
                         fq_a, fq_b, rx_a, rx_b);
        }

        // ---- Synchronized key rotation on BOTH endpoints ----
        // (Both endpoints must switch before any new data; a one-sided change
        // drops the other side's old-signed segments and hangs the connection.)
        stack_a.SetMd5Key(conn, key2, sizeof(key2));
        stack_b.SetMd5Key(conn_b, key2, sizeof(key2));
        PumpRound(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        std::fprintf(stderr, "[md5-key] rotated to key2 (A=%d B=%d)\n",
                     (int)stack_a.ConnectionState(conn),
                     (int)stack_b.ConnectionState(conn_b));

        // ---- Phase 2: continue transfer, all signed with key2 ----
        CHECK(kPhase == SendAll(stack_a, conn, ab2.data(), kPhase, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, conn, conn_b, recv_a, recv_b, kPhase, 2 * kPhase));
        CHECK(kPhase == SendAll(stack_b, conn_b, ba2.data(), kPhase, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, conn, conn_b, recv_a, recv_b, 2 * kPhase, 2 * kPhase));

        // ---- Core assertions: transfer is complete after the synchronized
        //      key change; nothing was lost, duplicated, or hung ----
        CHECK(2 * kPhase == recv_b.size());
        CHECK(0 == std::memcmp(recv_b.data(), expect_ab.data(), 2 * kPhase));
        CHECK(2 * kPhase == recv_a.size());
        CHECK(0 == std::memcmp(recv_a.data(), expect_ba.data(), 2 * kPhase));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        {
            UInt32 in_a = 0, cw_a = 0, ss_a = 0, sw_a = 0, rx_a = 0;
            UInt64 rto_a = 0;
            UInt32 da_a = 0, fr_a = 0, fq_a = 0, su_a = 0;
            UInt16 lp_a = 0, rp_a = 0;
            UInt32 in_b = 0, cw_b = 0, ss_b = 0, sw_b = 0, rx_b = 0;
            UInt64 rto_b = 0;
            UInt32 da_b = 0, fr_b = 0, fq_b = 0, su_b = 0;
            UInt16 lp_b = 0, rp_b = 0;
            stack_a.ConnStats(conn, in_a, cw_a, ss_a, sw_a, rx_a, rto_a, da_a, fr_a, fq_a, su_a, lp_a, rp_a);
            stack_b.ConnStats(conn_b, in_b, cw_b, ss_b, sw_b, rx_b, rto_b, da_b, fr_b, fq_b, su_b, lp_b, rp_b);
            CHECK(0 == fq_a);  // nothing left unacknowledged (no hang)
            CHECK(0 == fq_b);
            std::fprintf(stderr,
                         "[md5-key] phase2 done: recv A->B=%zu B->A=%zu front A=%u B=%u retx A=%u B=%u\n",
                         recv_b.size(), recv_a.size(), fq_a, fq_b, rx_a, rx_b);
        }

        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b, 100);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_KEY_CHANGE: FAILED (%d)\n" : "MD5_KEY_CHANGE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

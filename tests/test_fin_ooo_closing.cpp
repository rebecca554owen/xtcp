/**
 * @file test_fin_ooo_closing.cpp
 * @brief Out-of-order FINs in the closing states (FIN-WAIT-1/2):
 *   1. (M3) An OOO FIN + fully-ACKed FIN in FIN-WAIT-1 must advance to
 *      FIN-WAIT-2 (with its 60 s timeout) instead of stranding the
 *      connection in FIN-WAIT-1 with no timers (permanent slot leak).
 *   2. (M2) A buffered OOO data+FIN whose gap fills while in FIN-WAIT-2
 *      must enter TIME-WAIT (2MSL, RFC 793) - pre-fix the FIN was ACKed
 *      through the reassembly drain with no state transition, skipping
 *      2MSL and delaying reclamation by the full FIN-WAIT-2 timeout.
 *   3. (m1) An OOO pure FIN must be buffered (not dropped + retransmitted)
 *      and consumed when the gap fills.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <string>
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
    for (UInt32 round = 0; round < 1000; ++round) {
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

static UInt32 ReadSeq(const Byte* pkt) {
    return (static_cast<UInt32>(pkt[24]) << 24) | (static_cast<UInt32>(pkt[25]) << 16) |
           (static_cast<UInt32>(pkt[26]) << 8) | static_cast<UInt32>(pkt[27]);
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
        std::string a_recv;
        stack_a.SetRecvHandler([&a_recv](UInt64, const Byte* d, UInt32 len) {
            a_recv.append(reinterpret_cast<const char*>(d), len);
        });

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40182;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9091;
        CHECK(stack_b.Listen(b_local));

        // Full handshake, capturing both ISNs from the wire (B's ISN is
        // DeriveIss-derived, not sequential - never assume b_iss + 1).
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Byte pkt[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {  // A's SYN
            n = backend_a.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 a_iss = ReadSeq(pkt);
        backend_b.Inject(pkt, n, 0x0800);
        while (0 != backend_b.TxPending()) {  // B's SYN+ACK
            n = backend_b.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 b_iss = ReadSeq(pkt);
        backend_a.Inject(pkt, n, 0x0800);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        std::fprintf(stderr, "[fin-ooo-closing] established a_iss=%08x b_iss=%08x\n", a_iss, b_iss);

        // A closes: FIN emitted, A -> FIN-WAIT-1. Do NOT pump yet - B's
        // immediate ACK of the FIN would advance A to FIN-WAIT-2, and the
        // crafted OOO segment below must hit A while still in FIN-WAIT-1
        // (the exact stranding scenario).
        stack_a.Close(conn_a);
        CHECK(xtcp::core::TcpState::kFinWait1 == stack_a.ConnectionState(conn_a));

        // (1) OOO data+FIN from B (seq = b_iss + 3, a 2-byte gap) carrying a
        // full ACK of A's FIN (ack = a_iss + 2). A must NOT strand in
        // FIN-WAIT-1: it advances to FIN-WAIT-2 (the 60 s timeout keeps the
        // slot reclaimable) and buffers the segment for reassembly.
        std::vector<Byte> ooo = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 9091, 40182, b_iss + 3, a_iss + 2, 0x19);
        ooo.push_back('W'); ooo.push_back('X'); ooo.push_back('Y'); ooo.push_back('Z');
        ooo[2] = 0; ooo[3] = 44;
        xtcp::harness::FillIp4Checksum(ooo.data());
        xtcp::harness::FillTcp4Checksum(ooo.data(), ooo.data() + 20, 24);
        backend_a.Inject(ooo.data(), static_cast<UInt32>(ooo.size()), 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        std::fprintf(stderr, "[fin-ooo-closing] after OOO data+FIN: A=%d (expect %d FinWait2)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a)),
                     static_cast<int>(xtcp::core::TcpState::kFinWait2));
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn_a));
        // Now let A's FIN reach B (B -> CLOSE-WAIT) and B's ACK come back.
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn_a));

        // (2) The gap fills (2 in-order bytes). The drain consumes the
        // buffered data+FIN; A must enter TIME-WAIT (2MSL) - pre-fix it
        // stayed in FIN-WAIT-2 for the full 60 s and skipped TIME-WAIT.
        std::vector<Byte> fill = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 9091, 40182, b_iss + 1, a_iss + 2, 0x10);
        fill.push_back('A'); fill.push_back('B');
        fill[2] = 0; fill[3] = 42;
        xtcp::harness::FillIp4Checksum(fill.data());
        xtcp::harness::FillTcp4Checksum(fill.data(), fill.data() + 20, 22);
        backend_a.Inject(fill.data(), static_cast<UInt32>(fill.size()), 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        std::fprintf(stderr, "[fin-ooo-closing] after gap fill: A=%d (expect %d TimeWait)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a)),
                     static_cast<int>(xtcp::core::TcpState::kTimeWait));
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn_a));
        CHECK(6 == a_recv.size());
        CHECK('A' == a_recv[0] && 'B' == a_recv[1]);
        CHECK('W' == a_recv[2] && 'Z' == a_recv[5]);

        // (3) An OOO pure FIN must be buffered and consumed on gap fill -
        // same machinery on a second connection pair (fresh ISNs). Drain
        // A's leftover re-ACKs from scenario 1 first, or the ISN capture
        // below reads the stale segment instead of A2's SYN.
        while (0 != backend_a.TxPending()) {
            backend_a.PollTx(pkt);
        }
        xtcp::core::Endpoint a_local2 = a_local;
        a_local2.port = 40183;
        const UInt64 conn_a2 = stack_a.Connect(a_local2, b_local);
        CHECK(0 != conn_a2);
        while (0 != backend_a.TxPending()) {  // A2's SYN
            n = backend_a.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        const UInt32 a_iss2 = ReadSeq(pkt);
        backend_b.Inject(pkt, n, 0x0800);
        while (0 != backend_b.TxPending()) {  // B's SYN+ACK (new ISN)
            n = backend_b.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        const UInt32 b_iss2 = ReadSeq(pkt);
        backend_a.Inject(pkt, n, 0x0800);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a2));
        stack_a.Close(conn_a2);
        CHECK(xtcp::core::TcpState::kFinWait1 == stack_a.ConnectionState(conn_a2));

        // OOO pure FIN at seq = b_iss2 + 2 (gap of 1), ack = a_iss2 + 2.
        std::vector<Byte> pure_fin = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 9091, 40183, b_iss2 + 2, a_iss2 + 2, 0x11);
        pure_fin[2] = 0; pure_fin[3] = 40;
        xtcp::harness::FillIp4Checksum(pure_fin.data());
        xtcp::harness::FillTcp4Checksum(pure_fin.data(), pure_fin.data() + 20, 20);
        backend_a.Inject(pure_fin.data(), static_cast<UInt32>(pure_fin.size()), 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        // Not stranded in FIN-WAIT-1: the ack==snd_nxt_ check advances to
        // FIN-WAIT-2 even though the FIN itself is out of order.
        std::fprintf(stderr, "[fin-ooo-closing] A2 after OOO pure FIN: %d (expect %d FinWait2)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a2)),
                     static_cast<int>(xtcp::core::TcpState::kFinWait2));
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn_a2));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn_a2));

        // Gap fill (1 in-order byte at seq = b_iss2 + 1): the buffered pure
        // FIN is consumed -> TIME-WAIT.
        std::vector<Byte> fill2 = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 9091, 40183, b_iss2 + 1, a_iss2 + 2, 0x10);
        fill2.push_back('C');
        fill2[2] = 0; fill2[3] = 41;
        xtcp::harness::FillIp4Checksum(fill2.data());
        xtcp::harness::FillTcp4Checksum(fill2.data(), fill2.data() + 20, 21);
        backend_a.Inject(fill2.data(), static_cast<UInt32>(fill2.size()), 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        std::fprintf(stderr, "[fin-ooo-closing] A2 after gap fill: %d (expect %d TimeWait)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a2)),
                     static_cast<int>(xtcp::core::TcpState::kTimeWait));
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn_a2));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FIN_OOO_CLOSING: FAILED (%d)\n" : "FIN_OOO_CLOSING: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

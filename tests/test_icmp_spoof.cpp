/**
 * @file test_icmp_spoof.cpp
 * @brief ICMP frag-needed legitimacy: a forged ICMP must not be able to
 *        drive a live flow's MSS down without bound.
 *
 *        Scenario (dual-stack A -> B):
 *          1. A legitimate ICMP "fragmentation needed" (MTU 576) lowers the
 *             flow's MSS to 536 and the wire segments shrink to <= 536.
 *          2. A flood of FORGED ICMPs must not keep lowering the MSS:
 *             - embedded 4-tuple mismatch (no flow matches -> dropped), and
 *             - correct 4-tuple injected at high rate with tiny MTUs
 *               (overspeed) must be rate-limited / floored.
 *          3. The connection must still transmit.
 *
 *        RECORDED OBSERVATION:
 *          TcpConn::OnMtuReduced (tcp.h:352) now clamps the new MSS to a
 *          RFC 879 floor of 256, so the overspeed flood can only drive the
 *          MSS down to 256 (MTU 60 -> MSS 256, not 20). Rate limiting is not
 *          implemented (no icmp_count/last_icmp/icmp_rate); the floor is the
 *          defense under test here. The forged flood with a WRONG embedded
 *          4-tuple must be dropped by the flow lookup (MSS stays 536).
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt64 g_tx_payload_max = 0;
static UInt64 g_tx_segs = 0;

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

/** Builds an ICMPv4 frag-needed (type 3 code 4) whose EMBEDDED original
 *  packet is emb_src_ip:emb_src_port -> emb_dst_ip:emb_dst_port, announcing
 *  `mtu`. The outer source is a router (10.0.0.254) -> 10.0.0.1. */
static UInt32 BuildIcmpFragNeeded(Byte* out, UInt32 emb_src_ip, UInt16 emb_src_port,
                                  UInt32 emb_dst_ip, UInt16 emb_dst_port, UInt16 mtu) {
    std::memset(out, 0, 68);
    out[0] = 0x45;
    out[2] = 0; out[3] = 68;                 // total length
    out[9] = 1;                              // ICMP
    out[12] = 0x0A; out[13] = 0; out[14] = 0; out[15] = 0xFE;  // router 10.0.0.254
    out[16] = 0x0A; out[17] = 0; out[18] = 0; out[19] = 0x01;  // dst 10.0.0.1
    out[20] = 3;                             // destination unreachable
    out[21] = 4;                             // fragmentation needed
    out[26] = static_cast<Byte>(mtu >> 8);
    out[27] = static_cast<Byte>(mtu & 0xFF);
    // Embedded original IP header (the segment that was too big).
    Byte* orig = out + 28;
    orig[0] = 0x45;
    orig[2] = 0; orig[3] = 40;              // embedded IP total length (20+20)
    orig[9] = 6;                             // TCP
    orig[12] = static_cast<Byte>(emb_src_ip >> 24); orig[13] = static_cast<Byte>(emb_src_ip >> 16);
    orig[14] = static_cast<Byte>(emb_src_ip >> 8);  orig[15] = static_cast<Byte>(emb_src_ip);
    orig[16] = static_cast<Byte>(emb_dst_ip >> 24); orig[17] = static_cast<Byte>(emb_dst_ip >> 16);
    orig[18] = static_cast<Byte>(emb_dst_ip >> 8);  orig[19] = static_cast<Byte>(emb_dst_ip);
    // Embedded TCP header (ports drive the flow lookup).
    Byte* tcp = orig + 20;
    tcp[0] = static_cast<Byte>(emb_src_port >> 8); tcp[1] = static_cast<Byte>(emb_src_port);
    tcp[2] = static_cast<Byte>(emb_dst_port >> 8); tcp[3] = static_cast<Byte>(emb_dst_port);
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the spoof check.
    xtcp::harness::FillIp4Checksum(out);
    return 68;
}

/** Delivers a raw ICMP frag-needed to the victim stack. */
static void InjectIcmp(xtcp::XtcpStack& victim, const Byte* pkt, UInt32 len) {
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(len);
    std::memcpy(buf.Data(), pkt, len);
    buf.SetLen(len);
    victim.OnPacket(std::move(buf));
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
            // Record the TCP payload size of A's outgoing segments (IP 20 +
            // TCP 20 on the loopback wire).
            if (p.len >= 40) {
                const UInt32 payload = p.len - 40;
                ++g_tx_segs;
                if (payload > g_tx_payload_max) {
                    g_tx_payload_max = payload;
                }
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        UInt64 bytes_recv = 0;
        stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;   // 10.0.0.1
        local.port = 40031;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;  // 10.0.0.2
        remote.port = 9091;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        const UInt32 kChunk = 4096;
        Byte payload[kChunk];
        std::memset(payload, 0x55, sizeof(payload));
        Byte icmp[68];

        // ---------------------------------------------------------------
        // Phase 1: one LEGITIMATE ICMP (MTU 576) -> MSS 536, wire <= 536.
        // ---------------------------------------------------------------
        UInt32 guard = 0;
        g_tx_payload_max = 0;
        g_tx_segs = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[icmp-spoof] pre-ICMP max_payload=%llu segs=%llu mss=%u\n",
                     (unsigned long long)g_tx_payload_max, (unsigned long long)g_tx_segs,
                     (UInt32)stack_a.ConnPeerMss(conn));
        CHECK(1460 == g_tx_payload_max);  // full-size segments before PMTU

        BuildIcmpFragNeeded(icmp, local.addr[0], local.port, remote.addr[0], remote.port, 576);
        InjectIcmp(stack_a, icmp, 68);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK(536 == stack_a.ConnPeerMss(conn));

        g_tx_payload_max = 0;
        g_tx_segs = 0;
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[icmp-spoof] post-ICMP max_payload=%llu segs=%llu mss=%u\n",
                     (unsigned long long)g_tx_payload_max, (unsigned long long)g_tx_segs,
                     (UInt32)stack_a.ConnPeerMss(conn));
        CHECK(0 < g_tx_segs);
        CHECK(536 >= g_tx_payload_max);  // legit reduction took effect on the wire

        // ---------------------------------------------------------------
        // Phase 2: FORGED flood with mismatched embedded 4-tuples.
        //          No flow matches -> the MSS must stay unchanged.
        // ---------------------------------------------------------------
        for (UInt32 i = 0; i < 100; ++i) {
            // Wrong embedded sport: base 41000 + i never equals local.port
            // (40031), so the forged 4-tuple can never match the flow.
            BuildIcmpFragNeeded(icmp,
                                local.addr[0], static_cast<UInt16>(41000 + i),  // wrong sport
                                remote.addr[0], remote.port,
                                60);
            InjectIcmp(stack_a, icmp, 68);
            BuildIcmpFragNeeded(icmp,
                                0x0A0000FE, 1,                                   // wrong src ip
                                0x0A0000FF, static_cast<UInt16>(1 + i),          // wrong dst ip:port
                                60);
            InjectIcmp(stack_a, icmp, 68);
        }
        std::fprintf(stderr, "[icmp-spoof] after mismatch-flood mss=%u\n",
                     (UInt32)stack_a.ConnPeerMss(conn));
        CHECK(536 == stack_a.ConnPeerMss(conn));  // forged mismatches are dropped

        // ---------------------------------------------------------------
        // Phase 3: FORGED overspeed flood with the CORRECT embedded
        //          4-tuple but tiny MTUs. Must not push MSS below 256.
        // ---------------------------------------------------------------
        const UInt16 kTinyMtus[] = { 300, 250, 200, 150, 100, 68, 60 };
        for (UInt32 i = 0; i < 20; ++i) {
            for (UInt16 mtu : kTinyMtus) {
                BuildIcmpFragNeeded(icmp, local.addr[0], local.port,
                                    remote.addr[0], remote.port, mtu);
                InjectIcmp(stack_a, icmp, 68);
            }
        }
        std::fprintf(stderr, "[icmp-spoof] after overspeed-flood mss=%u (floor 256)\n",
                     (UInt32)stack_a.ConnPeerMss(conn));
        CHECK(256 <= stack_a.ConnPeerMss(conn));  // invariant floor; FAILS w/o rate limit+floor

        // ---------------------------------------------------------------
        // Phase 4: the connection must still transmit end to end.
        // ---------------------------------------------------------------
        bytes_recv = 0;
        g_tx_payload_max = 0;
        g_tx_segs = 0;
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 300 && bytes_recv < kChunk; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[icmp-spoof] final received=%llu max_payload=%llu\n",
                     (unsigned long long)bytes_recv, (unsigned long long)g_tx_payload_max);
        CHECK(kChunk == bytes_recv);  // connection still transmits

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ICMP_SPOOF: FAILED (%d)\n" : "ICMP_SPOOF: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

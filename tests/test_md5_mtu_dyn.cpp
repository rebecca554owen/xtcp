/**
 * @file test_md5_mtu_dyn.cpp
 * @brief TCP-MD5 (RFC 2385) connection under DYNAMIC path-MTU changes:
 *        multiple ICMP "fragmentation needed" messages step the MSS down
 *        through three levels (1460 -> 1160 -> 536 -> 256) while an MD5
 *        transfer runs at every level. Each level's segments must stay
 *        correctly signed (the lossless wire delivers everything to B) and
 *        shrink to the announced MTU.
 *
 *        MD5 specifics (code-confirmed in the reference tests):
 *          - Every segment carries the 20-byte MD5 option, so the payload is
 *            capped at peer_mss_ - 20 (tcp_fsm.cpp:1238); a data segment is
 *            IP20 + TCP20 + MD5opt20 + payload.
 *          - An ICMP frag-needed lowers peer_mss_ to next_hop_mtu - 40
 *            (stack.cpp:712-720 flow lookup, tcp.h:352-364), floored at 256
 *            (RFC 879).
 *          - On a LOSSLESS wire, any segment whose MD5 digest does not verify
 *            is dropped (VerifyMd5Segment, tcp_fsm.cpp:1699). So B receiving
 *            every byte intact is direct evidence that every segment across
 *            all MTU levels was correctly signed.
 *
 *        Levels (MTU -> MSS -> payload cap -> max wire):
 *          base    : 1500 -> 1460 -> 1440 -> 1500
 *          ICMP1200: 1200 -> 1160 -> 1140 -> 1200
 *          ICMP576 :  576 ->  536 ->  516 ->  576
 *          ICMP296 :  296 ->  256 ->  236 ->  296   (RFC 879 floor)
 *
 *        Core assertions:
 *          1. Each ICMP lowers ConnPeerMss exactly: 1160, 536, 256.
 *          2. After each ICMP the A->B wire segments shrink to the announced
 *             MTU (max wire == 1200, 576, 296).
 *          3. Every level's chunk is delivered completely and byte-exact to B
 *             (MD5 verification passed for every segment - nothing dropped).
 *
 * Ports 40330/9185 are stack-internal 4-tuples only; ctest runs each test as
 * its own executable so no cross-test conflict.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"
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

// Largest A->B MD5 data segment (total IP packet length) observed since the
// last reset. Pure MD5 ACKs are exactly 60 bytes; anything larger carries
// payload.
static UInt64 g_wire_max = 0;

// Pump A and B, tracking the largest A->B packet (data segments are > 60 B).
static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                if (n > 60 && n > g_wire_max) {
                    g_wire_max = n;
                }
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

// Builds and injects an ICMP "fragmentation needed" (RFC 1191) whose
// embedded original segment carries the A->B 4-tuple, so the flow lookup in
// stack.cpp:712-720 lowers the victim (A) connection's MSS to mtu-40.
static void InjectIcmpFragNeeded(xtcp::XtcpStack& victim, UInt16 src_port,
                                 UInt16 dst_port, UInt16 mtu) {
    // IP header (20) + ICMP header (8) + embedded IP header (20) + embedded
    // TCP header (20). The outer IPv4 header checksum is validated under the
    // checksum-validate build, so it must be correct (the parser does not
    // validate the ICMP message checksum).
    Byte pkt[68];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 68;                 // total length
    pkt[9] = 1;                              // ICMP
    pkt[12] = 0x0A; pkt[13] = 0x00;          // outer src = 10.0.0.2 (router/B side)
    pkt[14] = 0x00; pkt[15] = 0x02;
    pkt[16] = 0x0A; pkt[17] = 0x00;          // outer dst = 10.0.0.1 (A)
    pkt[18] = 0x00; pkt[19] = 0x01;
    pkt[20] = 3;                             // destination unreachable
    pkt[21] = 4;                             // fragmentation needed
    pkt[26] = static_cast<Byte>(mtu >> 8);
    pkt[27] = static_cast<Byte>(mtu);
    // Embedded original IP header (the segment that was too big): A -> B.
    Byte* orig = pkt + 28;
    orig[0] = 0x45;
    orig[2] = 0; orig[3] = 40;               // embedded IP total length (20+20)
    orig[9] = 6;                             // TCP
    orig[12] = 0x0A; orig[13] = 0x00;        // embedded src = 10.0.0.1 (A)
    orig[14] = 0x00; orig[15] = 0x01;
    orig[16] = 0x0A; orig[17] = 0x00;        // embedded dst = 10.0.0.2 (B)
    orig[18] = 0x00; orig[19] = 0x02;
    // Embedded TCP header (ports drive the flow lookup).
    Byte* tcp = orig + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    xtcp::harness::FillIp4Checksum(pkt);     // outer header checksum (validated under cksum)
    xtcp::core::IcmpFragNeeded parsed;
    CHECK(xtcp::core::ParseIcmpFragNeeded(pkt, sizeof(pkt), parsed));
    CHECK(parsed.valid);
    CHECK(mtu == parsed.mtu);
    CHECK(src_port == parsed.src_port && dst_port == parsed.dst_port);
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
    victim.OnPacket(std::move(buf));
}

// Send len bytes over conn, pumping between attempts (the send buffer can
// fill while unacked bytes drain). Returns bytes accepted (== len on success).
static UInt32 SendChunk(xtcp::XtcpStack& sa, UInt64 conn, const Byte* data,
                        UInt32 len, xtcp::ndi::ManualBackend& a,
                        xtcp::ndi::ManualBackend& b, xtcp::XtcpStack& sb) {
    UInt32 sent = 0;
    while (sent < len) {
        UInt32 n = len - sent;
        if (n > 2048) {
            n = 2048;
        }
        UInt32 tries = 0;
        while (!sa.Send(conn, data + sent, n) && 500 > ++tries) {
            Pump(a, b, sa, sb);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (500 <= tries) {
            return sent;
        }
        sent += n;
        Pump(a, b, sa, sb);
    }
    return sent;
}

// Pump (with real time so the 40 ms delayed ACK can fire) until B delivered
// expect bytes. Returns true when reached.
static bool DrainTo(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                    xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                    const std::string& received, size_t expect) {
    for (UInt32 i = 0; i < 3000 && received.size() < expect; ++i) {
        Pump(a, b, sa, sb);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return received.size() >= expect;
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        const Byte key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40330;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9185;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        g_wire_max = 0;
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(1460 == stack_a.ConnPeerMss(conn));  // base MSS before any ICMP

        // Four distinct 8 KiB chunks: base + one per ICMP level. Distinct
        // patterns make a mis-delivered chunk detectable by memcmp.
        const UInt32 kChunk = 8192;
        const UInt32 kLevels = 4;
        std::vector<Byte> payload(kChunk * kLevels);
        for (UInt32 i = 0; i < payload.size(); ++i) {
            const UInt32 level = i / kChunk;
            payload[i] = static_cast<Byte>((i * 13 + level * 7 + 3) & 0xFF);
        }

        // ---- Level 0 (base, MSS 1460): full-size MD5 segments ----
        CHECK(kChunk == SendChunk(stack_a, conn, payload.data(), kChunk,
                                  backend_a, backend_b, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, received, kChunk));
        std::fprintf(stderr, "[md5-mtu-dyn] level0(base) mss=%u max_wire=%llu recv=%llu\n",
                     stack_a.ConnPeerMss(conn), (unsigned long long)g_wire_max,
                     (unsigned long long)received.size());
        CHECK(1500 == g_wire_max);  // full-size MD5 segments in flight

        // ---- Level 1: ICMP MTU 1200 -> MSS 1160 (payload 1140, wire 1200) ----
        g_wire_max = 0;
        InjectIcmpFragNeeded(stack_a, local.port, remote.port, 1200);
        CHECK(1160 == stack_a.ConnPeerMss(conn));  // CORE: first step down
        CHECK(kChunk == SendChunk(stack_a, conn, payload.data() + kChunk, kChunk,
                                  backend_a, backend_b, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, received, 2 * kChunk));
        std::fprintf(stderr, "[md5-mtu-dyn] level1(1200) mss=%u max_wire=%llu recv=%llu\n",
                     stack_a.ConnPeerMss(conn), (unsigned long long)g_wire_max,
                     (unsigned long long)received.size());
        CHECK(1200 == g_wire_max);  // CORE: segments shrank to the announced MTU

        // ---- Level 2: ICMP MTU 576 -> MSS 536 (payload 516, wire 576) ----
        g_wire_max = 0;
        InjectIcmpFragNeeded(stack_a, local.port, remote.port, 576);
        CHECK(536 == stack_a.ConnPeerMss(conn));  // CORE: second step down
        CHECK(kChunk == SendChunk(stack_a, conn, payload.data() + 2 * kChunk, kChunk,
                                  backend_a, backend_b, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, received, 3 * kChunk));
        std::fprintf(stderr, "[md5-mtu-dyn] level2(576) mss=%u max_wire=%llu recv=%llu\n",
                     stack_a.ConnPeerMss(conn), (unsigned long long)g_wire_max,
                     (unsigned long long)received.size());
        CHECK(576 == g_wire_max);  // CORE: segments shrank again

        // ---- Level 3: ICMP MTU 296 -> MSS 256 (RFC 879 floor; wire 296) ----
        g_wire_max = 0;
        InjectIcmpFragNeeded(stack_a, local.port, remote.port, 296);
        CHECK(256 == stack_a.ConnPeerMss(conn));  // CORE: floored at 256
        CHECK(kChunk == SendChunk(stack_a, conn, payload.data() + 3 * kChunk, kChunk,
                                  backend_a, backend_b, stack_b));
        CHECK(DrainTo(backend_a, backend_b, stack_a, stack_b, received, 4 * kChunk));
        std::fprintf(stderr, "[md5-mtu-dyn] level3(296) mss=%u max_wire=%llu recv=%llu\n",
                     stack_a.ConnPeerMss(conn), (unsigned long long)g_wire_max,
                     (unsigned long long)received.size());
        CHECK(296 == g_wire_max);  // CORE: floored MSS segments (236 payload)

        // ---- CORE: multi-level MTU drop + MD5 transfer complete ----
        CHECK(kChunk * kLevels == received.size());  // B received everything
        CHECK(0 == std::memcmp(payload.data(), received.data(), payload.size()));  // byte-exact
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "\nMD5_MTU_DYN: FAILED (%d)\n" : "\nMD5_MTU_DYN: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

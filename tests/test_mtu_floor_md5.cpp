/**
 * @file test_mtu_floor_md5.cpp
 * @brief RFC 1191 PMTU with TCP-MD5 (RFC 2385) and a PATHOLOGICAL MTU:
 *        an ICMP "fragmentation needed" announcing MTU 60 (well below any
 *        sane path) must not drive the flow's MSS below the RFC 879 floor
 *        of 256, and the connection must still transfer data intact.
 *
 *        TcpConn::OnMtuReduced (tcp.h:352) clamps the new MSS to 256:
 *            new_mss = next_hop_mtu - 40  ->  60 - 40 = 20
 *            new_mss = max(new_mss, 256)  ->  256
 *        An MD5 flow additionally caps the payload at peer_mss_ - 20
 *        (tcp_fsm.cpp:1245), so post-ICMP segments are
 *        IP20 + TCP40(MD5 option) + 236 payload = 296 bytes.
 *
 *        Core assertions:
 *          1. ConnPeerMss >= 256 after the pathological ICMP (== 256).
 *          2. The full transfer still completes, bytes intact.
 *          3. Post-ICMP A->B wire segments shrink to <= 296 bytes.
 *
 * Ports 40310/9168 are stack-internal 4-tuples only; ctest runs each test
 * as its own executable so no cross-test conflict.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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

// A->B wire-size tracking (total IP packet length of data segments).
static UInt64 g_wire_max = 0;

// Pump A and B, tracking the largest A->B packet seen (data segments are
// larger than 60 bytes; pure ACKs are 40 bytes and ignored).
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
// stack.cpp:712-720 lowers the victim (A) connection's MSS. The announced
// MTU is pathological (60) to exercise the RFC 879 floor.
static void InjectIcmpFragNeeded(xtcp::XtcpStack& victim, UInt16 src_port,
                                 UInt16 dst_port, UInt16 mtu) {
    // IP header (20) + ICMP header (8) + embedded IP header (20) + embedded
    // TCP header (20). Checksums are not validated by the parser.
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
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the PMTU lowering.
    xtcp::harness::FillIp4Checksum(pkt);
    xtcp::core::IcmpFragNeeded parsed;
    CHECK(xtcp::core::ParseIcmpFragNeeded(pkt, sizeof(pkt), parsed));
    CHECK(parsed.valid);
    CHECK(mtu == parsed.mtu);
    CHECK(src_port == parsed.src_port && dst_port == parsed.dst_port);
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the PMTU lowering.
    victim.OnPacket(std::move(buf));
}

// MD5 conn + pathological ICMP (MTU 60). The MSS must floor at 256 (not
// 60-40=20) and the full transfer must still complete intact.
static void RunFloorScenario() {
    std::fprintf(stderr, "\n--- Floor: MD5 conn + pathological ICMP MTU 60 ---\n");
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
    local.port = 40310;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9168;
    CHECK(stack_b.Listen(remote));
    stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
    const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
    CHECK(0 != conn);
    g_wire_max = 0;
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
    CHECK(1460 == stack_a.ConnPeerMss(conn));

    const UInt32 kTotal = 65536;
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 7 + i / 97) & 0xFF);
    }

    // Send the first half with pumping between chunks; full-size (1500B)
    // MD5 segments go on the wire and are drained before the ICMP.
    const UInt32 kHalf = kTotal / 2;
    UInt32 accepted = 0;
    while (accepted < kHalf) {
        UInt32 n = kHalf - accepted;
        if (n > 2048) {
            n = 2048;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    std::fprintf(stderr, "[mtu-floor] pre-ICMP accepted=%llu max_wire=%llu\n",
                 (unsigned long long)accepted, (unsigned long long)g_wire_max);
    CHECK(1500 == g_wire_max);  // full-size MD5 segments (1460 + 40) in flight

    // Pathological PMTU: MTU 60 -> raw MSS 20 -> floored to 256.
    InjectIcmpFragNeeded(stack_a, local.port, remote.port, 60);
    std::fprintf(stderr, "[mtu-floor] post-ICMP ConnPeerMss=%u\n",
                 stack_a.ConnPeerMss(conn));
    CHECK(256 <= stack_a.ConnPeerMss(conn));   // CORE: never below the RFC 879 floor
    CHECK(256 == stack_a.ConnPeerMss(conn));   // pathological MTU 60 floors exactly at 256

    // Send the remaining half. Track wire size for the new MSS (296B max:
    // IP20 + TCP40-with-MD5 + 236 payload). Settle first so the pre-reduction
    // 1500B segments drain out of the wire before the measurement window
    // opens (their size must not pollute the post-reduction max - the race
    // was exposed by ASan's slowdown).
    for (UInt32 i = 0; i < 30; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    g_wire_max = 0;
    while (accepted < kTotal) {
        UInt32 n = kTotal - accepted;
        if (n > 2048) {
            n = 2048;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    for (UInt32 i = 0; i < 3000 && received.size() < kTotal; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::fprintf(stderr, "[mtu-floor] final accepted=%llu received=%llu max_wire=%llu\n",
                 (unsigned long long)accepted, (unsigned long long)received.size(),
                 (unsigned long long)g_wire_max);
    CHECK(kTotal == accepted);
    CHECK(kTotal == received.size());          // CORE: transport still complete
    CHECK(0 == std::memcmp(payload.data(), received.data(), kTotal));  // intact
    CHECK(296 >= g_wire_max);                  // segments shrank to the floored MSS
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    stack_a.Close(conn);
    for (UInt32 i = 0; i < 100; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
}

int main() {
    xtcp::buf::InitPools();
    RunFloorScenario();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "\nMTU_FLOOR_MD5: FAILED (%d)\n" : "\nMTU_FLOOR_MD5: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

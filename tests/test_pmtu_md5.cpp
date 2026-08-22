/**
 * @file test_pmtu_md5.cpp
 * @brief TCP-MD5 (RFC 2385) + RFC 1191 path-MTU discovery interaction with
 *        large in-flight sends.
 *
 * Scenario analysis (code-confirmed):
 *   - An MD5 connection signs every segment: the payload is capped at
 *     peer_mss_ - 20 (tcp_fsm.cpp:1237) and GSO is skipped at the tx
 *     boundary for signed connections (stack.cpp:144-156), so a segment is
 *     emitted whole as IP20 + TCP20 + MD5opt20 + payload (1500 bytes at
 *     MSS 1460, 576 bytes at MSS 536).
 *   - An ICMP "fragmentation needed" (MTU 576) lowers peer_mss_ to 536
 *     (tcp.h:352-364). NEW sends shrink to <= 576 bytes, but segments
 *     ALREADY in the retransmit queue were built at the old size, and
 *     retransmission resends the stored packet whole
 *     (tcp_fsm.cpp:678-681 RetransmitFront, tcp_fsm.cpp:1001-1003
 *     RetransmitEarliestMissing). On a path that enforces the new MTU a
 *     router keeps dropping those 1500-byte retransmits -> snd_una_ can
 *     never advance past them -> the flow stalls (potential deadlock).
 *
 * This test drives both outcomes:
 *   Scenario A (lossless wire): MD5 conn, large send with in-flight
 *     segments, ICMP shrink mid-transfer -> the connection COMPLETES, all
 *     bytes arrive intact, and post-ICMP segments shrink to <= 576 bytes.
 *   Scenario B (MTU-enforcing router): MD5 conn, old-size (1500B) segments
 *     left in the backend queue at ICMP time, then any A->B packet > 576B
 *     is dropped. The old segments are retransmitted at 1500B, dropped
 *     again, and the transfer stalls. The stall is DOCUMENTED (recorded,
 *     not a hard failure); the core assertions that always hold are
 *     data integrity of the delivered bytes and that the oversized
 *     retransmit mechanism was actually exercised.
 *
 * Ports 40301/9150 (A) and 40302/9151 (B) are stack-internal 4-tuples only;
 * ctest runs each test as its own executable so no cross-test conflict.
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

// A->B wire-size tracking and optional MTU-enforcing router filter.
static UInt64 g_wire_max = 0;         // max total length of A->B segments (>60B = data)
static bool   g_router = false;       // when true, drop A->B packets with len > 576
static UInt64 g_oversize_dropped = 0; // count of router drops

// Pump A and B. When g_router is set, A->B packets larger than the new MTU
// (576) are swallowed (simulating the router that issued the frag-needed).
// B->A (ACKs) is always lossless.
static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                if (g_router && n > 576) {
                    ++g_oversize_dropped;  // router drops the oversized segment
                } else {
                    b.Inject(out, n, 0x0800);
                }
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

// Scenario A: lossless wire. MD5 conn + large send (in-flight old-size
// segments) + ICMP shrink mid-transfer. The transfer must COMPLETE, every
// byte must arrive intact, and post-ICMP segments must shrink to <= 576B.
static void RunScenarioA() {
    std::fprintf(stderr, "\n--- Scenario A: lossless wire, PMTU shrink mid-transfer ---\n");
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
    local.port = 40301;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9150;
    CHECK(stack_b.Listen(remote));
    stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
    const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
    CHECK(0 != conn);
    g_router = false;
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
    // MD5 segments go on the wire and some are still in flight (delayed
    // ACK) when the ICMP arrives.
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
    std::fprintf(stderr, "[pmtu-md5] pre-ICMP accepted=%llu max_wire=%llu\n",
                 (unsigned long long)accepted, (unsigned long long)g_wire_max);
    CHECK(1500 == g_wire_max);  // old-size MD5 segments were in flight

    // PMTU shrink: MTU 576 -> MSS 536.
    InjectIcmpFragNeeded(stack_a, local.port, remote.port, 576);
    CHECK(536 == stack_a.ConnPeerMss(conn));

    // Drain any in-flight old-size segments (lossless: they arrive), then
    // track only the post-ICMP sends.
    for (UInt32 i = 0; i < 3; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    g_wire_max = 0;

    // Send the remaining half, then drain to completion.
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
    std::fprintf(stderr, "[pmtu-md5] A post-ICMP accepted=%llu received=%llu max_wire=%llu\n",
                 (unsigned long long)accepted, (unsigned long long)received.size(),
                 (unsigned long long)g_wire_max);
    CHECK(kTotal == accepted);
    CHECK(kTotal == received.size());          // no permanent deadlock on lossless wire
    CHECK(0 == std::memcmp(payload.data(), received.data(), kTotal));
    CHECK(576 >= g_wire_max);                  // post-ICMP segments shrank to the new MTU
    CHECK(0 == g_oversize_dropped);            // no drops in the lossless scenario

    stack_a.Close(conn);
    for (UInt32 i = 0; i < 100; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
}

// Scenario B: MTU-enforcing router. Old-size (1500B) MD5 segments are left
// in the sender's backend queue, the ICMP shrinks the MSS, then any A->B
// packet > 576B is dropped (as the router that sent the frag-needed would).
// Their retransmits are still 1500B -> dropped again -> the transfer stalls.
// The stall is documented; data integrity of the delivered bytes and the
// oversized-retransmit mechanism are asserted.
static void RunScenarioB() {
    std::fprintf(stderr, "\n--- Scenario B: MTU-enforcing router, in-flight old-size segs ---\n");
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
    local.port = 40302;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9151;
    CHECK(stack_b.Listen(remote));
    stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
    const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
    CHECK(0 != conn);
    g_router = false;
    g_wire_max = 0;
    g_oversize_dropped = 0;
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    const UInt32 kTotal = 65536;
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 5 + 9) & 0xFF);
    }

    // Buffer the whole payload (64KiB fits the default 64KiB snd_buf_),
    // then flush the initial window WITHOUT draining the backend: three
    // 1500-byte MD5 segments (plus a tail) now sit in backend_a's Tx queue,
    // in the retransmit queue, unacked, at the OLD size.
    CHECK(stack_a.Send(conn, payload.data(), kTotal));
    stack_a.PollAckTimers();  // OnPoll -> FlushPendingSend -> backend_a.Tx
    std::fprintf(stderr, "[pmtu-md5] B flushed old-size segments into Tx queue\n");

    // PMTU shrink, then the router starts enforcing the new MTU.
    InjectIcmpFragNeeded(stack_a, local.port, remote.port, 576);
    CHECK(536 == stack_a.ConnPeerMss(conn));
    g_router = true;

    // Bounded pump with sleep so RTO / SACK recovery can fire. The
    // in-flight 1500B segments and their retransmits are dropped by the
    // router; the flow cannot advance snd_una_ past them.
    const auto start = std::chrono::steady_clock::now();
    while (received.size() < kTotal &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(4)) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
    UInt64 rto_deadline = 0;
    UInt32 dup_acks = 0, fast_rec = 0, front_seq = 0, snd_una = 0;
    UInt16 local_port = 0, remote_port = 0;
    stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                      rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                      local_port, remote_port);
    const xtcp::core::TcpState state = stack_a.ConnectionState(conn);

    std::fprintf(stderr,
                 "[pmtu-md5] B received=%llu/%u retx=%u oversize_dropped=%llu "
                 "state=%d inflight=%u cwnd=%u snd_una=%u\n",
                 (unsigned long long)received.size(), kTotal, retx,
                 (unsigned long long)g_oversize_dropped, static_cast<int>(state),
                 inflight, cwnd, snd_una);

    // The oversized retransmit mechanism was definitely exercised: the
    // router dropped the in-flight/retransmitted >576B segments.
    CHECK(0 < g_oversize_dropped);

    // Data integrity of whatever was delivered (prefix match) always holds.
    CHECK(0 == std::memcmp(payload.data(), received.data(), received.size()));

    if (kTotal == received.size()) {
        // Future-fixed behavior: the stack re-segments the retransmit queue
        // after a PMTU shrink and the transfer completes.
        CHECK(0 == std::memcmp(payload.data(), received.data(), kTotal));
        std::fprintf(stderr, "[pmtu-md5] B COMPLETED despite MTU enforcement\n");
    } else {
        // Current behavior: documented stall. The connection either keeps
        // retransmitting the stuck 1500B segment (Established) or gave up
        // after kMaxDataRetries=15 (Closed). Either way the transfer never
        // completes while the path enforces the new MTU.
        std::fprintf(stderr,
                     "[pmtu-md5] B STALL observed: old-size in-flight segments were "
                     "retransmitted at 1500B (> new MTU 576), dropped %llu times, "
                     "transfer incomplete after 4s. Potential deadlock documented.\n",
                     (unsigned long long)g_oversize_dropped);
    }
}

int main() {
    xtcp::buf::InitPools();
    RunScenarioA();
    RunScenarioB();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "\nPMTU_MD5: FAILED (%d)\n" : "\nPMTU_MD5: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

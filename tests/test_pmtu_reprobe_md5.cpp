/**
 * @file test_pmtu_reprobe_md5.cpp
 * @brief MD5 + PMTU re-probe complete loop on a TCP-MD5 (RFC 2385)
 *        connection: the ICMP "fragmentation needed" (RFC 1191) lowers the
 *        negotiated MSS, the wire segments shrink to the reduced size, the
 *        periodic re-probe restores the full MSS (the path may have grown),
 *        segments grow back to full size, and the MD5-protected transfer
 *        completes intact.
 *
 *        MD5 specifics: every segment carries the 20-byte MD5 option, so the
 *        payload is capped at peer_mss_ - 20 (tcp_fsm.cpp:1238). At the
 *        negotiated MSS 1460 a data segment is IP20+TCP20+MD5opt20+1440 =
 *        1500 bytes; after the ICMP (MTU 576) the MSS drops to 536 and a
 *        segment is IP20+TCP20+MD5opt20+516 = 576 bytes. The re-probe
 *        (tcp_fsm.cpp:1424-1431, driven by PollAckTimers -> OnPoll) restores
 *        peer_mss_ = orig_peer_mss_ = 1460 and segments grow back to 1500
 *        bytes. Payload observation must therefore be p.len - 60 (a non-MD5
 *        data segment would be p.len - 40).
 *
 * Core assertions:
 *   1. Reduced MSS effective: ConnPeerMss == 536 and post-ICMP A->B
 *      segments carry at most 516 bytes of payload.
 *   2. Re-probe restores: after the (short) probe interval elapses, OnPoll
 *      restores ConnPeerMss == 1460 and segments grow back to 1440-byte
 *      payloads.
 *   3. MD5 transfer intact: every sent byte is delivered and the content
 *      matches (all three 4096-byte phases arrive with identical content).
 *
 * The re-probe interval is set BEFORE the ICMP so the deadline armed by
 * OnMtuReduced (tcp.h:366) uses the new short interval; setting it after the
 * reduction leaves the probe on the old 600 s default.
 *
 * Ports 40323/9181 are stack-internal 4-tuples only; ctest runs each test
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

// Largest A->B MD5 data payload observed (wire len minus IP20/TCP20/MD5opt20).
static UInt64 g_tx_payload_max = 0;

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

// Builds and injects an ICMP "fragmentation needed" (RFC 1191) whose
// embedded original segment carries the A->B 4-tuple, so the flow lookup in
// stack.cpp:712-720 lowers the victim (A) connection's MSS to mtu-40.
static void InjectIcmpFragNeeded(xtcp::XtcpStack& victim, UInt16 src_port,
                                 UInt16 dst_port, UInt16 mtu) {
    Byte pkt[68];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 68;
    pkt[9] = 1;
    pkt[12] = 0x0A; pkt[13] = 0x00;
    pkt[14] = 0x00; pkt[15] = 0x02;
    pkt[16] = 0x0A; pkt[17] = 0x00;
    pkt[18] = 0x00; pkt[19] = 0x01;
    pkt[20] = 3;
    pkt[21] = 4;
    pkt[26] = static_cast<Byte>(mtu >> 8);
    pkt[27] = static_cast<Byte>(mtu);
    Byte* orig = pkt + 28;
    orig[0] = 0x45;
    orig[2] = 0; orig[3] = 40;
    orig[9] = 6;
    orig[12] = 0x0A; orig[13] = 0x00;
    orig[14] = 0x00; orig[15] = 0x01;
    orig[16] = 0x0A; orig[17] = 0x00;
    orig[18] = 0x00; orig[19] = 0x02;
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
            // Track the largest MD5 data payload A sends to B (MD5 segments
            // are IP20 + TCP20 + MD5opt20 + payload; pure ACKs are 60 bytes).
            if (p.len > 60) {
                const UInt32 payload = p.len - 60;
                if (payload > g_tx_payload_max) {
                    g_tx_payload_max = payload;
                }
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        const Byte key[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40323;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9181;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(1460 == stack_a.ConnPeerMss(conn));

        Byte payload[4096];
        std::memset(payload, 0xA3, sizeof(payload));

        // Phase 1: full-size MD5 segments (payload 1440, wire 1500).
        UInt32 guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const UInt64 full_max = g_tx_payload_max;
        std::fprintf(stderr, "[pmtu-reprobe-md5] full max_payload=%llu\n",
                     (unsigned long long)full_max);
        CHECK(1440 == full_max);

        // Set the re-probe interval BEFORE the reduction so the deadline
        // armed by OnMtuReduced (tcp.h:366) uses the new (short) interval.
        stack_a.SetMtuProbeInterval(conn, 50000);
        InjectIcmpFragNeeded(stack_a, local.port, remote.port, 576);
        CHECK(536 == stack_a.ConnPeerMss(conn));  // CORE: reduced MSS effective

        // Phase 2: post-ICMP segments shrink to 516-byte payloads.
        g_tx_payload_max = 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const UInt64 small_max = g_tx_payload_max;
        std::fprintf(stderr, "[pmtu-reprobe-md5] reduced max_payload=%llu\n",
                     (unsigned long long)small_max);
        CHECK(516 >= small_max);  // CORE: segments shrank to the new MSS

        // Phase 3: the periodic re-probe fires (50 ms); OnPoll restores the
        // negotiated MSS, then a fresh send uses full-size segments again.
        // Sleeps advance the wall clock so the ACK-driven flush of the
        // buffered send actually emits before the measurement (the fast-pump
        // race was exposed by ASan's slowdown).
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(1460 == stack_a.ConnPeerMss(conn));  // CORE: re-probe restored
        g_tx_payload_max = 0;
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const UInt64 restored_max = g_tx_payload_max;
        std::fprintf(stderr, "[pmtu-reprobe-md5] restored max_payload=%llu\n",
                     (unsigned long long)restored_max);
        CHECK(1440 == restored_max);  // CORE: full-size segments are back

        // Drain to completion; all 3 * 4096 bytes must arrive intact.
        for (UInt32 i = 0; i < 200 && received.size() < 3 * sizeof(payload); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[pmtu-reprobe-md5] received=%llu\n",
                     (unsigned long long)received.size());
        CHECK(3 * sizeof(payload) == received.size());  // CORE: all bytes delivered
        for (UInt32 i = 0; i < 3; ++i) {
            CHECK(0 == std::memcmp(payload, received.data() + i * sizeof(payload),
                                   sizeof(payload)));    // CORE: content intact
        }

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PMTU_REPROBE_MD5: FAILED (%d)\n"
                                    : "PMTU_REPROBE_MD5: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_pmtu_reprobe.cpp
 * @brief RFC 1191 periodic MTU re-probe: after an ICMP "fragmentation
 *        needed" lowered the flow's MSS, the periodic re-probe restores the
 *        negotiated MSS (the path may have grown) and wire segments grow
 *        back to full size.
 */

#include <xtcp/core/stack.h>
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

static void InjectIcmpFragNeeded(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                                 UInt16 src_port, UInt16 dst_port, UInt16 mtu) {
    Byte pkt[68];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 68;
    pkt[9] = 1;
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    pkt[20] = 3;
    pkt[21] = 4;
    pkt[26] = static_cast<Byte>(mtu >> 8);
    pkt[27] = static_cast<Byte>(mtu);
    Byte* orig = pkt + 28;
    orig[0] = 0x45;
    orig[2] = 0; orig[3] = 40;
    orig[9] = 6;
    orig[12] = static_cast<Byte>(dst_ip >> 24); orig[13] = static_cast<Byte>(dst_ip >> 16);
    orig[14] = static_cast<Byte>(dst_ip >> 8);  orig[15] = static_cast<Byte>(dst_ip);
    orig[16] = static_cast<Byte>(src_ip >> 24); orig[17] = static_cast<Byte>(src_ip >> 16);
    orig[18] = static_cast<Byte>(src_ip >> 8);  orig[19] = static_cast<Byte>(src_ip);
    Byte* tcp = orig + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the PMTU lowering.
    xtcp::harness::FillIp4Checksum(pkt);
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
            // Track the largest TCP payload A sends to B.
            if (p.len >= 40) {
                const UInt32 payload = p.len - 40;
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
        local.addr[0] = 0x0A000001;
        local.port = 40201;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9108;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        Byte payload[4096];
        std::memset(payload, 0x77, sizeof(payload));

        // Send: full-size segments.
        UInt32 guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const UInt64 full_max = g_tx_payload_max;
        std::fprintf(stderr, "[pmtu-reprobe] full max_payload=%llu\n",
                     (unsigned long long)full_max);
        CHECK(1460 == full_max);

        // ICMP frag-needed lowers the MSS; the re-probe interval is set
        // BEFORE the reduction so the new interval governs the scheduled
        // probe (the deadline is armed by OnMtuReduced).
        stack_a.SetMtuProbeInterval(conn, 50000);
        InjectIcmpFragNeeded(stack_a, 0x0A000002, 0x0A000001, 40201, 9108, 576);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        g_tx_payload_max = 0;
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const UInt64 small_max = g_tx_payload_max;
        std::fprintf(stderr, "[pmtu-reprobe] reduced max_payload=%llu\n",
                     (unsigned long long)small_max);
        CHECK(536 >= small_max);

        // The periodic re-probe fires (50 ms): pump first so OnPoll's
        // re-probe restores the MSS, then a fresh send uses full segments.
        // Sleeps advance the wall clock: the flush of the buffered send is
        // ACK-driven, and a pure fast pump never fires the delayed-ACK timer
        // (the measurement raced it under ASan's slowdown).
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
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
        std::fprintf(stderr, "[pmtu-reprobe] restored max_payload=%llu\n",
                     (unsigned long long)restored_max);
        CHECK(1460 == restored_max);

        for (UInt32 i = 0; i < 200 && bytes_recv < 3 * sizeof(payload); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[pmtu-reprobe] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(3 * sizeof(payload) == bytes_recv);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PMTU_REPROBE: FAILED (%d)\n" : "PMTU_REPROBE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

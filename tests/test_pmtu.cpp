/**
 * @file test_pmtu.cpp
 * @brief RFC 1191 path-MTU discovery: an ICMP "fragmentation needed" lowers
 *        the flow's MSS, wire segments shrink to the new MTU, and the full
 *        payload still arrives intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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
static UInt64 g_tx_bytes = 0;
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

static void InjectIcmpFragNeeded(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                                 UInt16 src_port, UInt16 dst_port, UInt16 mtu) {
    // Real truncated shape (RFC 792/1812): the router copies the original IP
    // header verbatim, so its total_len still says the ORIGINAL datagram
    // length (1500) while the ICMP message carries only the first 28 bytes
    // (IP header + first 8 bytes of the TCP header). A parser that rejects
    // the embedded header for total_len > actual bytes would drop the
    // endpoints and silently kill PMTUD. Checksums are not validated.
    // Layout: outer IP (20) + ICMP (8) + embedded IP (20) + 8 TCP bytes.
    Byte pkt[56];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = sizeof(pkt);         // total length
    pkt[9] = 1;                              // ICMP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    pkt[20] = 3;                             // destination unreachable
    pkt[21] = 4;                             // fragmentation needed
    pkt[26] = static_cast<Byte>(mtu >> 8);
    pkt[27] = static_cast<Byte>(mtu);
    // Embedded original IP header (the segment that was too big).
    Byte* orig = pkt + 28;
    orig[0] = 0x45;
    orig[2] = 0x05; orig[3] = 0xDC;          // total_len 1500 (original, not the 28 present)
    orig[9] = 6;                             // TCP
    orig[12] = static_cast<Byte>(dst_ip >> 24); orig[13] = static_cast<Byte>(dst_ip >> 16);
    orig[14] = static_cast<Byte>(dst_ip >> 8);  orig[15] = static_cast<Byte>(dst_ip);
    orig[16] = static_cast<Byte>(src_ip >> 24); orig[17] = static_cast<Byte>(src_ip >> 16);
    orig[18] = static_cast<Byte>(src_ip >> 8);  orig[19] = static_cast<Byte>(src_ip);
    // Embedded TCP header (first 8 bytes; ports drive the flow lookup).
    Byte* tcp = orig + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    xtcp::core::IcmpFragNeeded parsed;
    CHECK(xtcp::core::ParseIcmpFragNeeded(pkt, sizeof(pkt), parsed));
    std::fprintf(stderr, "[pmtu] ICMP parsed: valid=%d mtu=%u src_port=%u dst_port=%u\n",
                 parsed.valid ? 1 : 0, parsed.mtu, parsed.src_port, parsed.dst_port);
    CHECK(parsed.valid);
    CHECK(576 == parsed.mtu);
    CHECK(src_port == parsed.src_port && dst_port == parsed.dst_port);
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the PMTU lowering.
    xtcp::harness::FillIp4Checksum(pkt);
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
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
            // Record the TCP payload size of A's outgoing segments (IP header
            // 20 + TCP header 20 at minimum on the loopback wire).
            if (p.len >= 20 + 20) {
                const UInt32 payload = p.len - 40;
                ++g_tx_segs;
                g_tx_bytes += payload;
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
        local.port = 40021;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9090;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Send with the negotiated MSS (1460): wire segments are full-size.
        const UInt32 kChunk = 4096;
        Byte payload[kChunk];
        std::memset(payload, 0x55, sizeof(payload));
        g_tx_payload_max = 0;
        g_tx_segs = 0;
        UInt32 guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[pmtu] pre-ICMP max payload=%llu segs=%llu\n",
                     (unsigned long long)g_tx_payload_max, (unsigned long long)g_tx_segs);
        CHECK(1460 == g_tx_payload_max);  // full-size segments before PMTU

        // The router reports fragmentation needed (MTU 576 -> MSS 536).
        InjectIcmpFragNeeded(stack_a, 0x0A000002, 0x0A000001, 40021, 9090, 576);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        // Send again: segments shrink to <= 536 payload.
        g_tx_payload_max = 0;
        g_tx_segs = 0;
        guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[pmtu] post-ICMP max payload=%llu segs=%llu\n",
                     (unsigned long long)g_tx_payload_max, (unsigned long long)g_tx_segs);
        CHECK(0 < g_tx_segs);
        CHECK(536 >= g_tx_payload_max);  // MSS dropped to 576-40 = 536

        // Everything still arrives intact.
        for (UInt32 i = 0; i < 200 && bytes_recv < 2 * kChunk; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[pmtu] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(2 * kChunk == bytes_recv);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PMTU: FAILED (%d)\n" : "PMTU: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

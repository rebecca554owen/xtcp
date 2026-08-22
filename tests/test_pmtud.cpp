/**
 * @file test_pmtud.cpp
 * @brief RFC 1191 path-MTU discovery: an ICMP "fragmentation needed"
 *        (type 3, code 4) for a flow lowers that connection's effective MSS
 *        to MTU - 40 (IPv4 headers), and unrelated flows are unaffected.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, 0x0800);
        if (2000 < ++guard) {
            break;
        }
    }
}

/** Builds an ICMPv4 fragmentation-needed packet for the flow (A -> B). */
static UInt32 BuildIcmpFragNeeded(Byte* out, UInt32 mtu,
                                  UInt32 orig_src, UInt16 orig_sport,
                                  UInt32 orig_dst, UInt16 orig_dport) {
    // IPv4 header: router (10.0.0.254) -> A.
    UInt32 off = 0;
    out[off++] = 0x45;
    out[off++] = 0x00;
    const UInt32 total = 20 + 8 + 20 + 20;  // ip + icmp + orig-ip + orig-tcp
    out[off++] = static_cast<Byte>(total >> 8);
    out[off++] = static_cast<Byte>(total & 0xFF);
    out[off++] = 0;  // id
    out[off++] = 0;
    out[off++] = 0x00;  // flags
    out[off++] = 0x00;
    out[off++] = 64;    // ttl
    out[off++] = 1;     // ICMP
    out[off++] = 0x00;  // checksum placeholder
    out[off++] = 0x00;
    out[off++] = 0x0A;  // src 10.0.0.254
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0xFE;
    out[off++] = 0x0A;  // dst 10.0.0.1
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;
    // ICMP header: type 3, code 4, mtu.
    out[off++] = 3;
    out[off++] = 4;
    out[off++] = 0x00;  // checksum placeholder
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = static_cast<Byte>(mtu >> 8);
    out[off++] = static_cast<Byte>(mtu & 0xFF);
    // Original IP header: A -> B, proto TCP.
    out[off++] = 0x45;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x28;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 64;
    out[off++] = 6;     // TCP
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = static_cast<Byte>(orig_src >> 24);
    out[off++] = static_cast<Byte>(orig_src >> 16);
    out[off++] = static_cast<Byte>(orig_src >> 8);
    out[off++] = static_cast<Byte>(orig_src & 0xFF);
    out[off++] = static_cast<Byte>(orig_dst >> 24);
    out[off++] = static_cast<Byte>(orig_dst >> 16);
    out[off++] = static_cast<Byte>(orig_dst >> 8);
    out[off++] = static_cast<Byte>(orig_dst & 0xFF);
    // Original TCP header: sport/dport/seq/ack (20 bytes total).
    out[off++] = static_cast<Byte>(orig_sport >> 8);
    out[off++] = static_cast<Byte>(orig_sport & 0xFF);
    out[off++] = static_cast<Byte>(orig_dport >> 8);
    out[off++] = static_cast<Byte>(orig_dport & 0xFF);
    out[off++] = 0x00;  // seq
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;  // ack
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x50;  // data offset
    out[off++] = 0x00;
    out[off++] = 0xFF;  // window
    out[off++] = 0xFF;
    out[off++] = 0x00;  // checksum
    out[off++] = 0x00;
    out[off++] = 0x00;  // urgent
    out[off++] = 0x00;
    // Outer IPv4 header checksum is validated under the checksum-validate
    // build; a zero-checksum ICMP is dropped before the PMTU lowering.
    xtcp::harness::FillIp4Checksum(out);
    return off;
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend ba, bb;
        xtcp::XtcpStack sa(&ba), sb(&bb);
        Wire(ba, bb, sa, sb);

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0xC0A80102;  // 192.168.1.2
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;  // 10.0.0.1
        remote.port = 443;
        CHECK(sb.Listen(remote));
        const UInt64 conn = sa.Connect(local, remote);
        CHECK(0 != conn);
        Pump(ba, bb);
        Pump(bb, ba);
        Pump(ba, bb);

        CHECK(1460 == sa.ConnPeerMss(conn));  // default MSS

        // ICMP fragmentation-needed for THIS flow with MTU 1400.
        Byte icmp[256];
        const UInt32 icmp_len = BuildIcmpFragNeeded(icmp, 1400,
                                                    local.addr[0], local.port,
                                                    remote.addr[0], remote.port);
        // Verify the parser layer first.
        xtcp::core::IcmpFragNeeded parsed;
        std::fprintf(stderr, "[pmtud] pkt[0..31]: ");
        for (UInt32 i = 0; i < 32 && i < icmp_len; ++i) {
            std::fprintf(stderr, "%02X ", icmp[i]);
        }
        std::fprintf(stderr, "\n");
        const bool parsed_ok = xtcp::core::ParseIcmpFragNeeded(icmp, icmp_len, parsed);
        std::fprintf(stderr, "[pmtud] parse ok=%d mtu=%u src=%08X:%u dst=%08X:%u\n",
                     parsed_ok ? 1 : 0, (UInt32)parsed.mtu,
                     parsed.src_addr[0], (UInt32)parsed.src_port,
                     parsed.dst_addr[0], (UInt32)parsed.dst_port);
        CHECK(parsed_ok);
        CHECK(1400 == parsed.mtu);
        CHECK(parsed.src_addr[0] == local.addr[0] && parsed.src_port == local.port);
        CHECK(parsed.dst_addr[0] == remote.addr[0] && parsed.dst_port == remote.port);
        ba.Inject(icmp, icmp_len, 0x0800);

        CHECK(1360 == sa.ConnPeerMss(conn));  // 1400 - 40

        // An ICMP for a DIFFERENT flow must not affect this connection.
        Byte icmp2[256];
        const UInt32 icmp2_len = BuildIcmpFragNeeded(icmp2, 1000,
                                                     0xC0A80109, 50000,
                                                     remote.addr[0], 445);
        ba.Inject(icmp2, icmp2_len, 0x0800);
        CHECK(1360 == sa.ConnPeerMss(conn));  // unchanged

        std::fprintf(stderr, "[pmtud] mss=%u (expect 1360 after MTU 1400)\n",
                     (UInt32)sa.ConnPeerMss(conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PMTUD: FAILED (%d)\n" : "PMTUD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

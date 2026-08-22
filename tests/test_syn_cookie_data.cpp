/**
 * @file test_syn_cookie_data.cpp
 * @brief RFC 4987 SYN-cookie + piggyback data: once live connections reach
 *        the syncookie threshold, the listener answers SYNs statelessly
 *        (ISN = cookie). A legitimate client then completes the handshake
 *        with a cookie ACK that also carries application data - the
 *        rebuilt connection must deliver that piggybacked payload intact.
 *        (Audit gap: the cookie-ACK piggyback delivery path,
 *        stack.cpp cookie-ACK rebuild -> TcpConn::OnSegment -> recv, was
 *        untested.)
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

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;  // 10.0.0.2
    constexpr UInt32 kClientV4 = 0x0A000001;  // 10.0.0.1
    constexpr UInt16 kPort     = 8080;

    /** Captures the SYN+ACK cookie (ISN) for a flow. */
    struct CookieProbe {
        bool   got = false;
        UInt32 cookie = 0;
    };
}

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

/** Full-duplex pump (real dual-stack wiring), draining both backends. */
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

/**
 * Drains the server backend's Tx, optionally capturing the stateless
 * SYN+ACK cookie (server sport == kPort, SYN+ACK, not FIN). The packet is
 * dropped (not forwarded to the real client stack): the cookie-mode peer
 * is the raw client below, not stack_a.
 */
static void PumpServer(xtcp::ndi::ManualBackend& from, CookieProbe* probe) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        if (NULLPTR != probe && !probe->got && got >= 52) {
            const UInt16 sport = static_cast<UInt16>((out[20] << 8) | out[21]);
            const Byte flags = out[33];
            if (0 != (flags & 0x12) && kPort == sport && 0 == (flags & 0x01)) {
                probe->cookie = (static_cast<UInt32>(out[24]) << 24) |
                                (static_cast<UInt32>(out[25]) << 16) |
                                (static_cast<UInt32>(out[26]) << 8) |
                                static_cast<UInt32>(out[27]);
                probe->got = true;
            }
        }
        if (2000 < ++guard) {
            break;
        }
    }
}

/** Builds a raw SYN (with an MSS option) for the cookie-mode client flow. */
static UInt32 BuildSyn(Byte* out, UInt32 src, UInt16 sport, UInt32 dst, UInt16 dport, UInt32 seq) {
    // Valid checksums: a zero-checksum SYN is dropped under the
    // checksum-validate build and the cookie path never runs.
    std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(src, dst, sport, dport, seq, 0, 0x02);
    syn.push_back(2); syn.push_back(4); syn.push_back(0x05); syn.push_back(0xB4);  // MSS 1460
    syn[2] = 0; syn[3] = 44;   // total length 44 (incl. MSS option)
    syn[20 + 12] = 0x60;       // data offset 24 (incl. MSS)
    xtcp::harness::FillIp4Checksum(syn.data());
    xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20, 24);
    std::memcpy(out, syn.data(), syn.size());
    return static_cast<UInt32>(syn.size());
}

/**
 * Builds the client's cookie ACK (ack = cookie + 1, seq = client_seq) with
 * the application payload piggybacked directly on the ACK packet.
 */
static UInt32 BuildCookieAckData(Byte* out, UInt32 src, UInt16 sport, UInt32 dst, UInt16 dport,
                                 UInt32 cookie, UInt32 client_seq,
                                 const Byte* payload, UInt32 payload_len) {
    const UInt32 ack = cookie + 1;
    // Valid checksums: a zero-checksum ACK is dropped under the
    // checksum-validate build and the cookie rebuild never happens.
    std::vector<Byte> seg = xtcp::harness::BuildIp4Tcp(
        src, dst, sport, dport, client_seq, ack, 0x18, payload, payload_len);
    std::memcpy(out, seg.data(), seg.size());
    return static_cast<UInt32>(seg.size());
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);

        UInt64 conn_b = 0;
        UInt64 conn_rebuilt = 0;
        std::string received;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&conn_rebuilt, &received](UInt64 id, const Byte* d, UInt32 n) {
            conn_rebuilt = id;
            received.append(reinterpret_cast<const char*>(d), n);
        });

        // Cookie mode engages once one live connection exists.
        stack_b.SetSyncookieThreshold(1);

        xtcp::core::Endpoint client, server;
        client.family = 4;
        client.addr[0] = kClientV4;
        client.port = 40000;
        server.family = 4;
        server.addr[0] = kServerV4;
        server.port = kPort;
        CHECK(stack_b.Listen(server));

        // First legitimate connection (below threshold): normal handshake.
        const UInt64 conn1 = stack_a.Connect(client, server);
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));
        CHECK(0 != conn_b);
        CHECK(1 == stack_b.ConnectionCount());

        // The next SYN is answered statelessly: the SYN+ACK carries a cookie
        // in its ISN and no connection state is created.
        constexpr UInt16 kCookieClientPort = 50004;
        constexpr UInt32 kClientSynSeq = 0x50000000;
        Byte syn[256];
        const UInt32 syn_len = BuildSyn(syn, kClientV4, kCookieClientPort, kServerV4, kPort,
                                        kClientSynSeq);
        CookieProbe probe;
        backend_b.Inject(syn, syn_len, 0x0800);
        PumpServer(backend_b, &probe);
        CHECK(probe.got);
        CHECK(1 == stack_b.ConnectionCount());  // stateless: no new state

        // The client completes the handshake with a cookie ACK that ALSO
        // piggybacks application data (seq = SYN seq + 1, ack = cookie + 1).
        // The rebuilt connection must deliver that payload intact.
        constexpr UInt32 kTotal = 512;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 7) & 0xFF);
        }
        Byte ack[2048];
        const UInt32 ack_len = BuildCookieAckData(ack, kClientV4, kCookieClientPort, kServerV4,
                                                  kPort, probe.cookie, kClientSynSeq + 1,
                                                  payload.data(), kTotal);
        backend_b.Inject(ack, ack_len, 0x0800);
        PumpServer(backend_b, NULLPTR);
        std::fprintf(stderr, "[syn-cookie-data] cookie=%08X conns=%u recv=%llu rebuilt=%llu\n",
                     probe.cookie, static_cast<unsigned>(stack_b.ConnectionCount()),
                     static_cast<unsigned long long>(received.size()),
                     static_cast<unsigned long long>(conn_rebuilt));

        // Rebuilt connection + intact piggyback delivery (core assertion).
        CHECK(2 == stack_b.ConnectionCount());
        CHECK(0 != conn_rebuilt);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_rebuilt));
        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));

        stack_a.Close(conn1);
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYN_COOKIE_DATA: FAILED (%d)\n"
                                    : "SYN_COOKIE_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

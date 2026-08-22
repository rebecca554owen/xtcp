/**
 * @file test_mss_malformed.cpp
 * @brief RFC 1122 s4.2.2.6: a malformed TCP option stream on the handshake
 *        (truncated length byte) yields NO usable MSS - the connection must
 *        behave exactly as if no options were present: peer MSS = 536.
 *        Pre-fix the parse failure silently left the constructor default
 *        1460 in place while an ABSENT option correctly forced 536 - the
 *        same wire condition, two different states. Both handshake sides
 *        are exercised: the server's SYN path and the client's SYN+ACK path.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

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

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40013;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 8080;
        CHECK(stack_b.Listen(b_local));

        // --- Server side: a SYN with a malformed option region (one option
        // byte = MSS kind 2, no length byte; data offset 5 = 21-byte header).
        UInt64 accepted = 0;
        stack_b.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&,
                                             const xtcp::core::Endpoint&) {
            accepted = id;
            return true;
        });
        std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40013, 8080, 0x11223344, 0, 0x02);
        syn.push_back(2);          // MSS kind, truncated (no length byte)
        syn[2] = 0; syn[3] = 41;   // 20 IP + 21 TCP
        syn[20 + 12] = 0x50;       // data offset 5 (21-byte header)
        xtcp::harness::FillIp4Checksum(syn.data());
        xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20, 21);
        backend_b.Inject(syn.data(), static_cast<UInt32>(syn.size()), 0x0800);
        stack_b.PollAckTimers();
        CHECK(0 != accepted);
        CHECK(xtcp::core::TcpState::kSynRcvd == stack_b.ConnectionState(accepted));
        const UInt16 peer_mss_srv = stack_b.ConnPeerMss(accepted);
        std::fprintf(stderr, "[mss-malformed] server peer MSS=%u (expect 536)\n", peer_mss_srv);
        CHECK(536 == peer_mss_srv);

        // --- Client side: A connects for real; craft the SYN+ACK A sees
        // with the same malformed option region. A's peer MSS must be 536.
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Byte pkt[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 a_syn_seq = ReadSeq(pkt);
        // Do not deliver A's SYN to B (B would build its own conn) - craft
        // the SYN+ACK directly.
        std::vector<Byte> synack = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 8080, 40013, 0x55667788, a_syn_seq + 1, 0x12);
        synack.push_back(2);          // MSS kind, truncated (no length byte)
        synack[2] = 0; synack[3] = 41;
        synack[20 + 12] = 0x50;
        xtcp::harness::FillIp4Checksum(synack.data());
        xtcp::harness::FillTcp4Checksum(synack.data(), synack.data() + 20, 21);
        backend_a.Inject(synack.data(), static_cast<UInt32>(synack.size()), 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        const UInt16 peer_mss_cli = stack_a.ConnPeerMss(conn_a);
        std::fprintf(stderr, "[mss-malformed] client peer MSS=%u (expect 536)\n", peer_mss_cli);
        CHECK(536 == peer_mss_cli);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MSS_MALFORMED: FAILED (%d)\n" : "MSS_MALFORMED: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

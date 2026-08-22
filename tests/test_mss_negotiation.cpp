/**
 * @file test_mss_negotiation.cpp
 * @brief Peer MSS negotiation: a peer advertising MSS=536 forces the server
 *        to send segments no larger than 536+40 on the wire.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    std::atomic<UInt32> g_max_pkt{0};
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a;
        xtcp::XtcpStack stack_a(&backend_a);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });

        std::atomic<UInt64> server_conn{0};
        stack_a.SetAcceptHandler([&server_conn](UInt64 id, const xtcp::core::Endpoint&,
                                                const xtcp::core::Endpoint&) {
            server_conn.store(id, std::memory_order_relaxed);
            return true;
        });
        xtcp::core::Endpoint server;
        server.family = 4;
        server.addr[0] = 0x0A000002;
        server.port = 8080;
        CHECK(stack_a.Listen(server));

        // SYN with MSS=536 (valid checksums: a zero-checksum SYN is dropped
        // under the checksum-validate build and the handshake never starts).
        std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40000, 8080, 0x10000000, 0, 0x02);
        // Extend the TCP header with the MSS option (kind 2, len 4, value
        // 536): grow the packet, fix IP total length + TCP data offset, then
        // recompute both checksums.
        syn.push_back(2); syn.push_back(4); syn.push_back(0x02); syn.push_back(0x18);
        syn[2] = 0; syn[3] = 44;           // IP total length = 44
        syn[20 + 12] = 0x60;               // TCP data offset 6 (24-byte header)
        xtcp::harness::FillIp4Checksum(syn.data());
        xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20, 24);
        backend_a.Inject(syn.data(), static_cast<UInt32>(syn.size()), 0x0800);

        // Read the SYN+ACK, complete the handshake.
        Byte out[65536];
        UInt32 sa_len = 0;
        while (0 != backend_a.TxPending()) {
            sa_len = backend_a.PollTx(out);
            if (0 != sa_len) {
                break;
            }
        }
        CHECK(0 != sa_len);
        const UInt32 iss = (static_cast<UInt32>(out[24]) << 24) |
                           (static_cast<UInt32>(out[25]) << 16) |
                           (static_cast<UInt32>(out[26]) << 8) |
                           static_cast<UInt32>(out[27]);
        Byte ack[40];
        std::memset(ack, 0, sizeof(ack));
        ack[0] = 0x45;
        ack[2] = 0; ack[3] = 40;
        ack[8] = 64;
        ack[9] = 6;
        ack[12] = 0x0A; ack[13] = 0x00; ack[14] = 0x00; ack[15] = 0x01;
        ack[16] = 0x0A; ack[17] = 0x00; ack[18] = 0x00; ack[19] = 0x02;
        ack[20] = 0x9C; ack[21] = 0x40;
        ack[22] = 0x1F; ack[23] = 0x90;
        ack[24] = 0x10; ack[25] = 0x00; ack[26] = 0x00; ack[27] = 0x01;
        const UInt32 ack_num = iss + 1;
        ack[28] = static_cast<Byte>(ack_num >> 24); ack[29] = static_cast<Byte>(ack_num >> 16);
        ack[30] = static_cast<Byte>(ack_num >> 8);  ack[31] = static_cast<Byte>(ack_num & 0xFF);
        ack[32] = 0x50; ack[33] = 0x10;
        ack[34] = 0xFF; ack[35] = 0xFF;
        // Handshake-completion ACK needs valid checksums too.
        xtcp::harness::FillIp4Checksum(ack);
        xtcp::harness::FillTcp4Checksum(ack, ack + 20, 20);
        backend_a.Inject(ack, sizeof(ack), 0x0800);
        stack_a.PollAckTimers();
        CHECK(1 == stack_a.ConnectionCount());
        CHECK(0 != server_conn.load(std::memory_order_relaxed));

        const UInt64 cid = server_conn.load(std::memory_order_relaxed);
        const UInt16 peer_mss = stack_a.ConnPeerMss(cid);
        std::fprintf(stderr, "[mss] peer_mss=%u (expect 536)\n", peer_mss);
        CHECK(536 == peer_mss);
        Byte payload[8192];
        std::memset(payload, 0x5C, sizeof(payload));
        UInt32 sent = 0;
        while (sent < sizeof(payload)) {
            const UInt32 chunk = sizeof(payload) - sent;
            if (stack_a.Send(server_conn.load(std::memory_order_relaxed),
                             payload + sent, chunk)) {
                sent += chunk;
            }
            stack_a.PollAckTimers();
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n && n > g_max_pkt.load(std::memory_order_relaxed)) {
                    g_max_pkt.store(n, std::memory_order_relaxed);
                }
                // The peer never ACKs (test backend); the window fills and
                // sends stop, which is fine for the segment-size assertion.
                if (32 * 1024 < sent) {
                    break;
                }
            }
        }
        const UInt32 max_pkt = g_max_pkt.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[mss] peer MSS=536, max data packet=%u (cap 576)\n", max_pkt);
        CHECK(576 >= max_pkt);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MSS_NEGOTIATION: FAILED (%d)\n" : "MSS_NEGOTIATION: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

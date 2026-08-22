/**
 * @file test_ack_carry.cpp
 * @brief Handshake-completion ACK encoding across the ISN low-byte wrap:
 *        the listener ISN (0x10000000 | (port << 16), incremented per SYN)
 *        hits iss & 0xFF == 0xFF every 256th connection. The ACK must be
 *        encoded as (iss + 1) with the carry propagated through the full
 *        32-bit value - splitting iss and adding 1 only to the low byte
 *        loses the carry into byte 30 and stalls the handshake (the
 *        listener's OnSynAck requires hdr.ack == entry.iss + 1).
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>

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

/** Fills the IPv4 header checksum and the TCP checksum (pseudo-header
 *  included) of a hand-built segment. XTCP_CHECKSUM_VALIDATE builds drop
 *  segments with invalid checksums, so hand-built test packets must be
 *  checksum-correct. */
static void FixChecksums(Byte* pkt, UInt32 len) {
    const UInt32 ihl = static_cast<UInt32>(pkt[0] & 0x0F) * 4;
    // IPv4 header checksum (RFC 791): fold of the 20-byte header, then 1's
    // complement. The header's own checksum field (bytes 10-11) is zeroed
    // before summing (RFC 791: the field is the 1's complement of the sum
    // with the field zeroed).
    pkt[10] = 0;
    pkt[11] = 0;
    {
        UInt32 sum = 0;
        for (UInt32 i = 0; i < ihl; i += 2) {
            sum += static_cast<UInt32>((pkt[i] << 8) | pkt[i + 1]);
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        const UInt16 csum = static_cast<UInt16>(~sum & 0xFFFF);
        pkt[10] = static_cast<Byte>(csum >> 8);
        pkt[11] = static_cast<Byte>(csum & 0xFF);
    }
    // TCP checksum (RFC 793): pseudo-header (src, dst, zero, proto, tcp_len)
    // + the TCP segment, folded.
    const UInt32 tcp_len = len - ihl;
    Byte pseudo[12];
    pseudo[0] = pkt[12]; pseudo[1] = pkt[13]; pseudo[2] = pkt[14]; pseudo[3] = pkt[15];
    pseudo[4] = pkt[16]; pseudo[5] = pkt[17]; pseudo[6] = pkt[18]; pseudo[7] = pkt[19];
    pseudo[8] = 0;
    pseudo[9] = 6;  // TCP
    pseudo[10] = static_cast<Byte>(tcp_len >> 8);
    pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
    pkt[ihl + 16] = 0;  // TCP checksum field
    pkt[ihl + 17] = 0;
    {
        UInt32 sum = 0;
        for (UInt32 i = 0; i < 12; i += 2) {
            sum += static_cast<UInt32>((pseudo[i] << 8) | pseudo[i + 1]);
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        for (UInt32 i = 0; i < tcp_len; i += 2) {
            sum += static_cast<UInt32>((pkt[ihl + i] << 8) | pkt[ihl + i + 1]);
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        const UInt16 csum = static_cast<UInt16>(~sum & 0xFFFF);
        pkt[ihl + 16] = static_cast<Byte>(csum >> 8);
        pkt[ihl + 17] = static_cast<Byte>(csum & 0xFF);
    }
}

int main() {
    xtcp::buf::InitPools();
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack.OnPacket(std::move(buf));
        }
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = 0x0A000002;
    server.port = 8080;
    CHECK(stack.Listen(server));
    stack.SetMaxConnections(1024);

    // 600 handshakes: connections 255 and 511 land on iss & 0xFF == 0xFF
    // (the listener ISN base is 0x101F9000 for port 8080), exercising the
    // ACK-carry case at least twice.
    std::vector<UInt64> ids;
    stack.SetAcceptHandler([&ids](UInt64 id, const xtcp::core::Endpoint&,
                                  const xtcp::core::Endpoint&) {
        ids.push_back(id);
        return true;
    });
    constexpr UInt32 kConns = 600;
    for (UInt32 i = 0; i < kConns; ++i) {
        Byte syn[40];
        std::memset(syn, 0, sizeof(syn));
        syn[0] = 0x45;
        syn[2] = 0; syn[3] = 40;
        syn[8] = 64;
        syn[9] = 6;
        const UInt32 src_ip = 0x0A010001u + (i / 60000);
        syn[12] = static_cast<Byte>(src_ip >> 24); syn[13] = static_cast<Byte>(src_ip >> 16);
        syn[14] = static_cast<Byte>(src_ip >> 8);  syn[15] = static_cast<Byte>(src_ip & 0xFF);
        syn[16] = 0x0A; syn[17] = 0x00; syn[18] = 0x00; syn[19] = 0x02;
        const UInt16 sport = static_cast<UInt16>(1024 + (i % 60000));
        syn[20] = static_cast<Byte>(sport >> 8); syn[21] = static_cast<Byte>(sport & 0xFF);
        syn[22] = 0x1F; syn[23] = 0x90;
        syn[24] = static_cast<Byte>(i >> 24); syn[25] = static_cast<Byte>(i >> 16);
        syn[26] = static_cast<Byte>(i >> 8); syn[27] = static_cast<Byte>(i & 0xFF);
        syn[32] = 0x50; syn[33] = 0x02;
        syn[34] = 0xFF; syn[35] = 0xFF;
        FixChecksums(syn, sizeof(syn));
        backend.Inject(syn, sizeof(syn), 0x0800);

        Byte synack[65536];
        const UInt32 sa_len = backend.PollTx(synack);
        CHECK(sa_len >= 40 && 0 != (synack[33] & 0x12));
        if (sa_len >= 40 && 0 != (synack[33] & 0x12)) {
            const UInt32 iss = (static_cast<UInt32>(synack[24]) << 24) |
                               (static_cast<UInt32>(synack[25]) << 16) |
                               (static_cast<UInt32>(synack[26]) << 8) |
                               static_cast<UInt32>(synack[27]);
            // Correct encoding: add 1 to the FULL 32-bit ISN before
            // splitting into bytes (carry must propagate).
            const UInt32 ack_num = iss + 1;
            Byte ack[40];
            std::memset(ack, 0, sizeof(ack));
            ack[0] = 0x45;
            ack[2] = 0; ack[3] = 40;
            ack[8] = 64;
            ack[9] = 6;
            const UInt32 src_ip_v = 0x0A010001u + (i / 60000);
            ack[12] = static_cast<Byte>(src_ip_v >> 24); ack[13] = static_cast<Byte>(src_ip_v >> 16);
            ack[14] = static_cast<Byte>(src_ip_v >> 8);  ack[15] = static_cast<Byte>(src_ip_v & 0xFF);
            ack[16] = 0x0A; ack[17] = 0x00; ack[18] = 0x00; ack[19] = 0x02;
            ack[20] = static_cast<Byte>(sport >> 8); ack[21] = static_cast<Byte>(sport & 0xFF);
            ack[22] = 0x1F; ack[23] = 0x90;
            ack[24] = static_cast<Byte>(i >> 24); ack[25] = static_cast<Byte>(i >> 16);
            ack[26] = static_cast<Byte>(i >> 8); ack[27] = static_cast<Byte>(i & 0xFF);
            ack[28] = static_cast<Byte>(ack_num >> 24); ack[29] = static_cast<Byte>(ack_num >> 16);
            ack[30] = static_cast<Byte>(ack_num >> 8);  ack[31] = static_cast<Byte>(ack_num & 0xFF);
            ack[32] = 0x50; ack[33] = 0x10;
            ack[34] = 0xFF; ack[35] = 0xFF;
            FixChecksums(ack, sizeof(ack));
            backend.Inject(ack, sizeof(ack), 0x0800);
        }
    }
    stack.PollAckTimers();

    // Every handshake must have completed: no connection left in SYN-RCVD.
    UInt32 established = 0;
    UInt32 synrcvd = 0;
    for (const UInt64 id : ids) {
        const auto st = stack.ConnectionState(id);
        if (xtcp::core::TcpState::kEstablished == st) {
            ++established;
        }
        if (xtcp::core::TcpState::kSynRcvd == st) {
            ++synrcvd;
        }
    }
    std::fprintf(stderr, "[ack-carry] conns=%zu accepted=%zu established=%u synrcvd=%u\n",
                 static_cast<size_t>(stack.ConnectionCount()), ids.size(),
                 established, synrcvd);
    CHECK(kConns == ids.size());
    CHECK(kConns == established);
    CHECK(0 == synrcvd);

    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_ack_carry: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_ack_carry: all passed\n");
    return 0;
}

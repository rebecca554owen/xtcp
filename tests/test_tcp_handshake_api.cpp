/**
 * @file test_tcp_handshake_api.cpp
 * @brief Explicit handshake send API (SendSyn/SendSynAck): active and
 *        passive open chains driven by explicit emission.
 */

#include <xtcp/core/tcp.h>

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

typedef std::vector<xtcp::buf::BufRef> TxLog;

static std::vector<Byte> BuildSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                      UInt16 flags) noexcept {
    std::vector<Byte> seg(20, 0);
    Byte* t = seg.data();
    t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
    t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                             ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                             ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                             ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                             ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00) |
                             ((flags & xtcp::core::kFlagEce) ? 0x40 : 0x00) |
                             ((flags & xtcp::core::kFlagCwr) ? 0x80 : 0x00));
    t[14] = 0xFF; t[15] = 0xFF;
    return seg;
}

static xtcp::core::Endpoint MakeLocal() noexcept {
    xtcp::core::Endpoint e;
    e.family = 4;
    e.addr[0] = 0xC0A80102;
    e.port = 40000;
    return e;
}
static xtcp::core::Endpoint MakeRemote() noexcept {
    xtcp::core::Endpoint e;
    e.family = 4;
    e.addr[0] = 0x0A000001;
    e.port = 443;
    return e;
}

static void TestActiveOpen() {
    TxLog log;
    const UInt32 iss = 0x1000, irs = 0x2000;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    conn.SendSyn();  // explicit SYN emission
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    CHECK(0x02 == (t[13] & 0x02));  // SYN
    CHECK(0 == (t[13] & 0x10));     // no ACK
    const UInt32 seq = (static_cast<UInt32>(t[4]) << 24) | (static_cast<UInt32>(t[5]) << 16) |
                       (static_cast<UInt32>(t[6]) << 8) | t[7];
    CHECK(iss == seq);
    CHECK(xtcp::core::TcpState::kSynSent == conn.State());

    // Peer answers SYN+ACK -> ACK -> Established.
    const std::vector<Byte> synack = BuildSegment(443, 40000, irs, iss + 1,
                                                  xtcp::core::kFlagSyn | xtcp::core::kFlagAck);
    conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), 1000);
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
    CHECK(2 == log.size());
    const Byte* ack_t = log[1].Data() + 20;
    const UInt32 ack = (static_cast<UInt32>(ack_t[8]) << 24) | (static_cast<UInt32>(ack_t[9]) << 16) |
                       (static_cast<UInt32>(ack_t[10]) << 8) | ack_t[11];
    CHECK(irs + 1 == ack);
}

static void TestPassiveOpen() {
    TxLog log;
    const UInt32 iss = 0x3000, irs = 0x4000;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynRcvd, MakeRemote(), MakeLocal(), iss, irs,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    conn.SendSynAck();  // explicit SYN+ACK emission
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    CHECK(0x02 == (t[13] & 0x02));  // SYN
    CHECK(0x10 == (t[13] & 0x10));  // ACK
    const UInt32 seq = (static_cast<UInt32>(t[4]) << 24) | (static_cast<UInt32>(t[5]) << 16) |
                       (static_cast<UInt32>(t[6]) << 8) | t[7];
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(iss == seq);
    CHECK(irs + 1 == ack);

    // Final ACK completes the handshake.
    const std::vector<Byte> ack_seg = BuildSegment(443, 40000, irs + 1, iss + 1, xtcp::core::kFlagAck);
    conn.OnSegment(ack_seg.data(), static_cast<UInt32>(ack_seg.size()), 1000);
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
}

static std::vector<Byte> BuildSegmentWithWscale(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                                UInt16 flags, UInt16 window, Byte wscale) noexcept {
    std::vector<Byte> seg(24, 0);
    Byte* t = seg.data();
    t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
    t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x60;  // data offset 6 (24 bytes)
    t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                             ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    t[14] = static_cast<Byte>(window >> 8);
    t[15] = static_cast<Byte>(window & 0xFF);
    t[20] = 3;     // WSOPT
    t[21] = 3;
    t[22] = wscale;
    t[23] = 1;     // NOP padding
    return seg;
}

static void TestWindowScale() {
    TxLog log;
    const UInt32 iss = 0x1000, irs = 0x2000;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });
    conn.SetRcvWscale(7);

    // SYN must carry MSS(2,4,1460), SACK-permitted(4,2), WSOPT(3,3,7) and
    // the RFC 7323 TSopt offer (kind 8) - 44-byte header.
    conn.SendSyn();
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    CHECK(0xB0 == t[12]);       // data offset 11 (44-byte header)
    CHECK(2 == t[20]);          // kind MSS
    CHECK(4 == t[21]);
    CHECK(0x05 == t[22]);
    CHECK(0xB4 == t[23]);       // MSS 1460
    CHECK(4 == t[24]);          // kind SACK-permitted
    CHECK(2 == t[25]);
    CHECK(3 == t[28]);          // kind WSOPT
    CHECK(8 == t[32]);          // kind TSopt (RFC 7323 offer)
    CHECK(10 == t[33]);

    // Peer SYN+ACK with WSOPT(5) and window 1000 -> scaled send window.
    const std::vector<Byte> synack = BuildSegmentWithWscale(443, 40000, irs, iss + 1,
                                                            xtcp::core::kFlagSyn | xtcp::core::kFlagAck,
                                                            1000, 5);
    conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), 1000);
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
    CHECK(5 == conn.SndWscale());

    // Response ACK advertises our window scaled by 7.
    const Byte* ack_t = log[1].Data() + 20;
    const UInt16 advertised = static_cast<UInt16>((ack_t[14] << 8) | ack_t[15]);
    CHECK(511 == advertised);  // 65535 >> 7
}

static void TestEcnNegotiation() {
    TxLog log;
    const UInt32 iss = 0x1000, irs = 0x2000;

    // Request ECN: SYN carries ECE.
    {
        TxLog log2;
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                                 [&log2](xtcp::buf::BufRef&& p) { log2.push_back(std::move(p)); });
        conn.SetEcnRequested(true);
        conn.SendSyn();
        CHECK(1 == log2.size());
        const Byte* t = log2[0].Data() + 20;
        CHECK(0 != (t[13] & 0x40));  // ECE on SYN
    }

    // Peer SYN+ACK carries ECE -> ECN active.
    {
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                                 [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });
        conn.SetEcnRequested(true);
        conn.SendSyn();
        const std::vector<Byte> synack = BuildSegment(443, 40000, irs, iss + 1,
                                                      xtcp::core::kFlagSyn | xtcp::core::kFlagAck |
                                                          xtcp::core::kFlagEce);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), 1000);
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());
        CHECK(conn.EcnActive());
    }

    // Peer without ECE -> ECN not active.
    {
        TxLog log2;
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                                 [&log2](xtcp::buf::BufRef&& p) { log2.push_back(std::move(p)); });
        conn.SetEcnRequested(true);
        const std::vector<Byte> synack = BuildSegment(443, 40000, irs, iss + 1,
                                                      xtcp::core::kFlagSyn | xtcp::core::kFlagAck);
        conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()), 1000);
        CHECK(!conn.EcnActive());
    }

    // No request -> SYN without ECE.
    {
        TxLog log2;
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, MakeLocal(), MakeRemote(), iss, irs,
                                 [&log2](xtcp::buf::BufRef&& p) { log2.push_back(std::move(p)); });
        conn.SendSyn();
        const Byte* t = log2[0].Data() + 20;
        CHECK(0 == (t[13] & 0x40));  // no ECE without request
    }
}

int main() {
    xtcp::buf::InitPools();
    TestActiveOpen();
    TestPassiveOpen();
    TestWindowScale();
    TestEcnNegotiation();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_tcp_handshake_api: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_tcp_handshake_api: all passed\n");
    return 0;
}

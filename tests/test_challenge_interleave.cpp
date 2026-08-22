/**
 * @file test_challenge_interleave.cpp
 * @brief : the RFC 5961 RST challenge limit (8/s) and the
 *        out-of-order dup-ACK limit (100/s) are INDEPENDENT rate-limit
 *        windows. An interleaved OOO flood + out-of-window RST flood must
 *        produce ALL the ACKs (10 dup-ACKs + 5 challenges = 15) - a shared
 *        cap would suppress everything past 8.
 */

#include <xtcp/core/tcp.h>

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

namespace {

typedef std::vector<xtcp::buf::BufRef> TxLog;

xtcp::core::TxSink MakeSink(TxLog& log) {
    return [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); };
}

std::vector<Byte> BuildSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack, UInt16 flags,
                               const Byte* payload = NULLPTR, UInt32 payload_len = 0) {
    std::vector<Byte> seg(20 + payload_len, 0);
    seg[0] = static_cast<Byte>(sport >> 8);
    seg[1] = static_cast<Byte>(sport & 0xFF);
    seg[2] = static_cast<Byte>(dport >> 8);
    seg[3] = static_cast<Byte>(dport & 0xFF);
    seg[4] = static_cast<Byte>(seq >> 24);
    seg[5] = static_cast<Byte>(seq >> 16);
    seg[6] = static_cast<Byte>(seq >> 8);
    seg[7] = static_cast<Byte>(seq & 0xFF);
    seg[8] = static_cast<Byte>(ack >> 24);
    seg[9] = static_cast<Byte>(ack >> 16);
    seg[10] = static_cast<Byte>(ack >> 8);
    seg[11] = static_cast<Byte>(ack & 0xFF);
    seg[12] = 0x50;
    seg[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                                ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                                ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                                ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                                ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    seg[14] = 0xFF;
    seg[15] = 0xFF;
    if (0 < payload_len) {
        std::memcpy(seg.data() + 20, payload, payload_len);
    }
    return seg;
}

}  // namespace

int main() {
    xtcp::buf::InitPools();
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
    conn.SetRecvHandler([](const Byte*, UInt32) { return true; });

    // 10 out-of-order data segments -> 10 dup-ACKs.
    std::vector<Byte> payload(1460, 0x5B);
    for (UInt32 i = 1; i <= 10; ++i) {
        const std::vector<Byte> seg = BuildSegment(remote.port, local.port, irs + 1 + i * 1460, iss + 1,
                                                   xtcp::core::kFlagAck | xtcp::core::kFlagPsh,
                                                   payload.data(), 1460);
        log.clear();
        conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()));
        CHECK(1 == log.size());  // one dup-ACK per OOO arrival
    }
    // 5 out-of-window RSTs -> 5 challenge ACKs (independent 8/s limit).
    // rcv_nxt_ = irs + 1 (the OOO data never advanced it); an RST 1M seqs
    // beyond the 65535 receive window is invalid per RFC 5961 -> challenge.
    for (UInt32 i = 0; i < 5; ++i) {
        const std::vector<Byte> rst = BuildSegment(remote.port, local.port, irs + 1 + 1000000 + i, 0,
                                                   xtcp::core::kFlagRst | xtcp::core::kFlagAck);
        log.clear();
        conn.OnSegment(rst.data(), static_cast<UInt32>(rst.size()));
        CHECK(1 == log.size());  // one challenge ACK per out-of-window RST
    }
    std::fprintf(stderr, "[ch-int] interleaved dup-ACKs + challenges all emitted\n");
    CHECK(0 == g_failures);
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CHALLENGE_INTERLEAVE: FAILED (%d)\n" : "CHALLENGE_INTERLEAVE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

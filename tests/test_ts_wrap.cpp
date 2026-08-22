/**
 * @file test_ts_wrap.cpp
 * @brief RFC 7323 wrap-edge: a peer whose millisecond clock sits near the
 *        2^32 wrap (~49-day uptime) must have its FIRST data segment
 *        accepted. The PAWS anchor (TsRecent) is initialized from the
 *        SYN+ACK's TSval (RFC 7323 s4.2) - without that, the first data's
 *        TSval compares "stale" against the initial zero anchor and the
 *        connection stalls forever (the retransmissions carry the same
 *        TSval and are dropped too).
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/tcp.h>

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

using namespace xtcp;
using namespace xtcp::core;

// Builds an IPv4+TCP segment with the RFC 7323 TSopt (the payload is the
// TCP header's start).
static void BuildTsSegment(Byte* out, UInt32 seq, UInt32 ack, UInt16 flags,
                           UInt32 ts_val, const Byte* payload, UInt32 payload_len) {
    const UInt32 total = 20 + 32 + payload_len;
    std::memset(out, 0, 20 + 32 + 64);
    out[0] = 0x45;
    out[2] = static_cast<Byte>(total >> 8);
    out[3] = static_cast<Byte>(total & 0xFF);
    out[8] = 64;
    out[9] = 6;
    out[12] = 0x0A; out[13] = 0x00; out[14] = 0x00; out[15] = 0x01;
    out[16] = 0x0A; out[17] = 0x00; out[18] = 0x00; out[19] = 0x02;
    Byte* t = out + 20;
    t[0] = 0x01; t[1] = 0xBB;   // sport
    t[2] = 0x9C; t[3] = 0x40;   // dport
    t[4] = static_cast<Byte>(seq >> 24);
    t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8);
    t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24);
    t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8);
    t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x80;  // data offset 8 (20 + 12 TSopt)
    t[13] = static_cast<Byte>(flags);
    t[20] = 8;     // kind: TSopt
    t[21] = 10;
    t[22] = static_cast<Byte>(ts_val >> 24);
    t[23] = static_cast<Byte>(ts_val >> 16);
    t[24] = static_cast<Byte>(ts_val >> 8);
    t[25] = static_cast<Byte>(ts_val & 0xFF);
    t[26] = 0; t[27] = 0; t[28] = 0; t[29] = 0;  // tsecr
    t[30] = 1;    // NOP
    t[31] = 1;    // NOP
    if (0 < payload_len && NULLPTR != payload) {
        std::memcpy(t + 32, payload, payload_len);
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000002;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;
        remote.port = 443;
        const UInt32 iss = 0x1000, irs = 0x2000;

        UInt32 delivered = 0;
        TcpConn conn(TcpState::kSynSent, local, remote, iss, irs,
                     [](buf::BufRef&&) {});
        conn.SetRecvHandler([&delivered](const Byte*, UInt32 len) {
            delivered += len;
            return true;
        });
        conn.SendSyn();  // snd_nxt_ = iss + 1 (the SYN-ACK's ACK must validate)

        // The peer's clock is near the 2^32 wrap: ts = 0xFFFFFFF0.
        Byte synack[128];
        BuildTsSegment(synack, irs, iss + 1, kFlagSyn | kFlagAck, 0xFFFFFFF0, NULLPTR, 0);
        conn.OnSegment(synack + 20, 20 + 32, 1000);  // OnSegment takes the TCP header
        CHECK(TcpState::kEstablished == conn.State());

        // The first data segment continues the wrapped clock. Its TSval is
        // NEWER than the SYN+ACK's anchor - the PAWS check must accept it
        // (the zero-anchor bug would compare 0xFFFFFFF1 against 0 and drop).
        Byte data[128];
        const Byte payload[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
        BuildTsSegment(data, irs + 1, iss + 1, kFlagAck | kFlagPsh, 0xFFFFFFF1, payload, 8);
        conn.OnSegment(data + 20, 32 + 8, 1000);
        CHECK(8 == delivered);

        // A genuinely STALE segment (an older TSval than the anchor) is
        // still dropped by PAWS even at the exact frontier.
        Byte stale[128];
        BuildTsSegment(stale, irs + 9, iss + 1, kFlagAck | kFlagPsh, 0xFFFFFFF0, payload, 8);
        conn.OnSegment(stale + 20, 32 + 8, 1000);
        CHECK(8 == delivered);  // PAWS dropped it: no new bytes
        std::fprintf(stderr, "[ts-wrap] wrap-anchored, delivered=%u\n", delivered);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TS_WRAP: FAILED (%d)\n" : "TS_WRAP: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

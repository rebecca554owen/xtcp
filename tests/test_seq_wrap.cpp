/**
 * @file test_seq_wrap.cpp
 * @brief Sequence-number wraparound (RFC 1982): SeqLt comparisons and
 *        out-of-order reassembly across the 2^32 boundary.
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
        }                                                                 \
    } while (0)

using xtcp::core::SeqLt;

/** Builds a raw TCP segment (IP payload form) with valid checksum. */
static std::vector<Byte> BuildTcpSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                         UInt16 flags, const Byte* payload, UInt32 payload_len) {
    std::vector<Byte> seg(20 + payload_len, 0);
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
                             ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    t[14] = 0xFF; t[15] = 0xFF;
    if (0 < payload_len) {
        std::memcpy(t + 20, payload, payload_len);
    }
    return seg;
}

static void TestSeqLt() {
    CHECK(SeqLt(0x00000000u, 0x00000001u));
    CHECK(SeqLt(0xFFFFFFFFu, 0x00000000u));  // wrap: FFFFFFFF < 00000000
    CHECK(SeqLt(0xFFFFFFF0u, 0x00000010u));  // wrap within window
    CHECK(!SeqLt(0x00000010u, 0xFFFFFFF0u)); // not after (far ahead)
    CHECK(!SeqLt(0x00000001u, 0x00000001u)); // equal
}

static void TestWrapReassembly() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A010001;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A010002;
    remote.port = 443;

    // rcv_nxt == 0xFFFFFFF0 (peer SYN occupied one slot before the wrap).
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100,
                             0xFFFFFFF0u - 1u, [](xtcp::buf::BufRef&&) {});

    std::vector<Byte> delivered;
    conn.SetRecvHandler([&delivered](const Byte* d, UInt32 len) {
        delivered.insert(delivered.end(), d, d + len);
        return true;
    });

    // Post-wrap segment seq=0x00000000 arrives first (out of order).
    const Byte p0[] = { 'x', 'y', 'z' };
    std::vector<Byte> wrap = BuildTcpSegment(remote.port, local.port, 0x00000000u, 0, 0, p0, 3);
    conn.OnSegment(wrap.data(), (UInt32)wrap.size(), 1000);
    CHECK(0 == delivered.size());  // buffered, nothing contiguous

    // In-order run 0xFFFFFFF0..0xFFFFFFFF (16 bytes) delivered; the drain must
    // walk across the wrap and also deliver the buffered post-wrap segment.
    for (UInt32 i = 0; i < 16; ++i) {
        const Byte one = static_cast<Byte>('a' + i);
        std::vector<Byte> seg = BuildTcpSegment(remote.port, local.port, 0xFFFFFFF0u + i, 0, 0, &one, 1);
        conn.OnSegment(seg.data(), (UInt32)seg.size(), 1000);
    }
    CHECK(19 == delivered.size());            // 16-byte run + drained post-wrap
    CHECK(0 == std::memcmp(delivered.data() + 16, p0, 3));  // order preserved
}

int main() {
    xtcp::buf::InitPools();
    TestSeqLt();
    TestWrapReassembly();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "test_seq_wrap: %s\n", (0 == g_failures) ? "all passed" : "FAILED");
    return g_failures ? 1 : 0;
}

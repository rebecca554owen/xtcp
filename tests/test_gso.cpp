/**
 * @file test_gso.cpp
 * @brief GSO segmentation tests: boundaries, zero-copy payload references,
 *        byte-for-byte consistency, ZC gate.
 */

#include <xtcp/core/gso.h>
#include <xtcp/core/ip.h>

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

/**
 * @brief Builds a full IPv4+TCP packet (like TcpConn::SendData output).
 */
static xtcp::buf::BufRef BuildSuperSegment(UInt32 payload_len, UInt32 seq, UInt32 ack) noexcept {
    const UInt32 total = 40 + payload_len;
    xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(total);
    if (p.IsEmpty()) {
        return p;
    }
    Byte* b = p.Data();
    std::memset(b, 0, total);
    b[0] = 0x45;
    b[2] = static_cast<Byte>(total >> 8);
    b[3] = static_cast<Byte>(total & 0xFF);
    b[8] = 64;
    b[9] = 6;
    b[12] = 0xC0; b[13] = 0xA8; b[14] = 0x01; b[15] = 0x02;
    b[16] = 0x0A; b[17] = 0x00; b[18] = 0x00; b[19] = 0x01;
    // TCP header
    Byte* t = b + 20;
    t[0] = 0x01; t[1] = 0xBB;   // sport 443
    t[2] = 0x9C; t[3] = 0x40;   // dport 40000
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = 0x18;  // PSH|ACK
    t[14] = 0xFF; t[15] = 0xFF;
    // Payload pattern.
    for (UInt32 i = 0; i < payload_len; ++i) {
        b[40 + i] = static_cast<Byte>(i * 7 + 3);
    }
    // IP checksum.
    const UInt16 ip_sum = xtcp::core::Checksum(b, 20);
    b[10] = static_cast<Byte>(ip_sum >> 8);
    b[11] = static_cast<Byte>(ip_sum & 0xFF);
    // TCP checksum with pseudo header.
    Byte pseudo[12];
    std::memcpy(pseudo, b + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10] = static_cast<Byte>((20 + payload_len) >> 8);
    pseudo[11] = static_cast<Byte>((20 + payload_len) & 0xFF);
    const UInt16 s1 = xtcp::core::Checksum(pseudo, 12);
    const UInt16 s2 = xtcp::core::Checksum(t, 20 + payload_len);
    UInt32 sum = (static_cast<UInt32>(~s1) & 0xFFFF) + (static_cast<UInt32>(~s2) & 0xFFFF);
    sum = (sum & 0xFFFF) + (sum >> 16);
    const UInt16 tcp_sum = static_cast<UInt16>(~sum & 0xFFFF);
    t[16] = static_cast<Byte>(tcp_sum >> 8);
    t[17] = static_cast<Byte>(tcp_sum & 0xFF);
    p.SetLen(total);
    return p;
}

static void TestBasicSegmentation() {
    const UInt32 payload_len = 3000;
    xtcp::buf::BufRef super = BuildSuperSegment(payload_len, 1000, 500);
    CHECK(!super.IsEmpty());

    std::vector<xtcp::core::GsoSeg> segs;
    CHECK(xtcp::core::GsoSegment(super, 1460, segs));
    CHECK(3 == segs.size());  // 1460 + 1460 + 80

    // Sequence continuity.
    CHECK(1000 == segs[0].seq);
    CHECK(2460 == segs[1].seq);
    CHECK(3920 == segs[2].seq);
    CHECK(1460 == segs[0].payload_len);
    CHECK(1460 == segs[1].payload_len);
    CHECK(80 == segs[2].payload_len);
}

static void TestExactMultiple() {
    xtcp::buf::BufRef super = BuildSuperSegment(2920, 100, 200);
    CHECK(!super.IsEmpty());
    std::vector<xtcp::core::GsoSeg> segs;
    CHECK(xtcp::core::GsoSegment(super, 1460, segs));
    CHECK(2 == segs.size());
    CHECK(1460 == segs[0].payload_len);
    CHECK(1460 == segs[1].payload_len);
}

static void TestSmallPayload() {
    xtcp::buf::BufRef super = BuildSuperSegment(100, 100, 200);
    CHECK(!super.IsEmpty());
    std::vector<xtcp::core::GsoSeg> segs;
    CHECK(xtcp::core::GsoSegment(super, 1460, segs));
    CHECK(1 == segs.size());
    CHECK(100 == segs[0].payload_len);
}

static void TestZeroCopyReferences() {
    const UInt32 payload_len = 3000;
    xtcp::buf::BufRef super = BuildSuperSegment(payload_len, 1000, 500);
    CHECK(!super.IsEmpty());
    const Byte* payload_base = super.Data() + 40;

    std::vector<xtcp::core::GsoSeg> segs;
    CHECK(xtcp::core::GsoSegment(super, 1460, segs));
    CHECK(3 == segs.size());

    // Payload IOV must point INTO the super-segment buffer (zero copy).
    for (UInt32 i = 0; i < segs.size(); ++i) {
        const xtcp::core::GsoSeg& seg = segs[i];
        const UInt32 off = i * 1460;
        CHECK(2 == seg.iovs.size());
        const xtcp::core::GsoIov& payload_iov = seg.iovs[1];
        CHECK(payload_iov.data == payload_base + off);
        CHECK(payload_iov.len == seg.payload_len);
    }
}

static void TestByteConsistency() {
    const UInt32 payload_len = 10000;
    xtcp::buf::BufRef super = BuildSuperSegment(payload_len, 777, 888);
    CHECK(!super.IsEmpty());
    const Byte* payload_base = super.Data() + 40;

    std::vector<xtcp::core::GsoSeg> segs;
    CHECK(xtcp::core::GsoSegment(super, 1460, segs));

    // Reassembling all payload IOVs must equal the original payload bytes.
    UInt32 cursor = 0;
    for (const xtcp::core::GsoSeg& seg : segs) {
        const xtcp::core::GsoIov& p = seg.iovs[1];
        CHECK(0 == std::memcmp(p.data, payload_base + cursor, p.len));
        cursor += p.len;
    }
    CHECK(cursor == payload_len);
}

static void TestInvalidInput() {
    std::vector<xtcp::core::GsoSeg> segs;
    xtcp::buf::BufRef empty;
    CHECK(!xtcp::core::GsoSegment(empty, 1460, segs));

    // Packet too small.
    xtcp::buf::BufRef tiny = BuildSuperSegment(10, 1, 2);
    CHECK(!tiny.IsEmpty());
    CHECK(!xtcp::core::GsoSegment(tiny, 0, segs));  // zero mss
    CHECK(xtcp::core::GsoSegment(tiny, 1460, segs));  // 10-byte payload -> 1 seg
}

int main() {
    xtcp::buf::InitPools();
    TestBasicSegmentation();
    TestExactMultiple();
    TestSmallPayload();
    TestZeroCopyReferences();
    TestByteConsistency();
    TestInvalidInput();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_gso: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_gso: all passed\n");
    return 0;
}

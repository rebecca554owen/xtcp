/**
 * @file test_frag6.cpp
 * @brief IPv6 fragment reassembly (RFC 8200): the table is version-agnostic,
 *        but the IPv6 contract differs in its key (version 6, 4-word
 *        addresses) and its offset semantics (fragment header carries the
 *        offset in 8-octet units, same as IPv4). These tests pin the IPv6
 *        behavior: aligned completion, the 8-octet rule for non-final
 *        fragments, overlap rejection, out-of-order arrival, and the
 *        ReassembledCount() evidence counter.
 */

#include <xtcp/core/ip.h>

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

static xtcp::core::FragKey MakeKey6(UInt32 src0, UInt32 src1, UInt32 dst0, UInt32 dst1, UInt32 id) {
    xtcp::core::FragKey key;
    key.version = 6;
    key.src[0] = src0; key.src[1] = src1; key.src[2] = 0; key.src[3] = 0;
    key.dst[0] = dst0; key.dst[1] = dst1; key.dst[2] = 0; key.dst[3] = 0;
    key.id = id;
    return key;
}

static void TestIpv6AlignedSequenceCompletes() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    // fd00::1 -> fd00::2, fragment id 0xABCD1234.
    xtcp::core::FragKey key = MakeKey6(0xFD000000, 0x00000001, 0xFD000000, 0x00000002, 0xABCD1234);

    Byte payload[24];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0x80 + i);
    }
    xtcp::buf::BufRef out;

    // RFC 8200 s4.5: all fragments except the last must be 8-octet multiples.
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 8;
    CHECK(0 == table.Add(1000, key, f0, out));

    // Out-of-order: last fragment (bytes 16..24) arrives first, leaving the
    // middle hole (bytes 8..16) unfilled - the set stays pending.
    xtcp::core::Fragment f2;
    f2.offset = 2; f2.more = false; f2.data = payload + 16; f2.len = 8;
    CHECK(0 == table.Add(2000, key, f2, out));

    // Middle fragment fills the hole and completes the datagram.
    xtcp::core::Fragment f1;
    f1.offset = 1; f1.more = true; f1.data = payload + 8; f1.len = 8;
    CHECK(1 == table.Add(3000, key, f1, out));
    CHECK(!out.IsEmpty());
    CHECK(24 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 24));
    out.Unref();
    CHECK(0 == table.SetCount());
    CHECK(1 == table.ReassembledCount());
    xtcp::buf::ShutdownPools();
}

static void TestIpv6MalformedNonFinalRejected() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey6(0xFD000000, 0x00000001, 0xFD000000, 0x00000002, 0x0BADF00D);

    Byte payload[24];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0x90 + i);
    }
    xtcp::buf::BufRef out;

    // Malformed: non-final fragment with len = 12 (not a multiple of 8).
    // RFC 8200 requires 8-octet multiples for all but the last fragment;
    // the bitmap is 8-byte granular, so accepting this would mark unit 1
    // without fully writing it.
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 12;
    CHECK(-1 == table.Add(1000, key, f0, out));
    CHECK(0 == table.SetCount());
    CHECK(0 == table.ReassembledCount());
    xtcp::buf::ShutdownPools();
}

static void TestIpv6OverlapRejected() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey6(0xFD000000, 0x00000001, 0xFD000000, 0x00000002, 0x1F2E3D4C);

    Byte payload[24];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0xA0 + i);
    }
    xtcp::buf::BufRef out;

    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 16;
    CHECK(0 == table.Add(1000, key, f0, out));

    // Overlapping fragment: offset 1 (byte 8) with len 8 covers bytes 8..15,
    // already written by f0 (bytes 0..15) - must be rejected.
    xtcp::core::Fragment f1;
    f1.offset = 1; f1.more = true; f1.data = payload + 8; f1.len = 8;
    CHECK(-1 == table.Add(2000, key, f1, out));

    xtcp::core::Fragment f2;
    f2.offset = 2; f2.more = false; f2.data = payload + 16; f2.len = 8;
    CHECK(1 == table.Add(3000, key, f2, out));
    CHECK(!out.IsEmpty());
    CHECK(24 == out.Len());
    out.Unref();
    CHECK(0 == table.SetCount());
    CHECK(1 == table.ReassembledCount());
    xtcp::buf::ShutdownPools();
}

static void TestIpv6FirstFragmentMidOffset() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey6(0xFD000000, 0x00000001, 0xFD000000, 0x00000002, 0x12344321);

    // A set whose FIRST arrival has a non-zero offset (the first fragment of
    // the datagram arrives later): offset 2 (byte 16) arrives first, then
    // offset 0 completes.
    Byte payload[24];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0xB0 + i);
    }
    xtcp::buf::BufRef out;

    xtcp::core::Fragment f0;
    f0.offset = 2; f0.more = false; f0.data = payload + 16; f0.len = 8;
    CHECK(0 == table.Add(1000, key, f0, out));

    xtcp::core::Fragment f1;
    f1.offset = 0; f1.more = true; f1.data = payload; f1.len = 16;
    CHECK(1 == table.Add(2000, key, f1, out));
    CHECK(!out.IsEmpty());
    CHECK(24 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 24));
    out.Unref();
    CHECK(0 == table.SetCount());
    CHECK(1 == table.ReassembledCount());
    xtcp::buf::ShutdownPools();
}

int main() {
    TestIpv6AlignedSequenceCompletes();
    TestIpv6MalformedNonFinalRejected();
    TestIpv6OverlapRejected();
    TestIpv6FirstFragmentMidOffset();
    xtcp::buf::ShutdownPools();

    if (0 < g_failures) {
        std::fprintf(stderr, "test_frag6: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_frag6: all passed\n");
    return 0;
}

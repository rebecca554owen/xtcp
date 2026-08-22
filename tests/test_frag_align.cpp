/**
 * @file test_frag_align.cpp
 * @brief Fragment reassembly: RFC 791 alignment gate. Non-final fragments
 *        must be a multiple of 8 octets; the reassembly bitmap is 8-byte
 *        granular, so a malformed non-final fragment of length % 8 != 0
 *        marks an 8-byte unit it does not fully write - a later fragment
 *        starting at the next unit boundary completes the set with the
 *        gap bytes never written (uninitialized heap copied into the
 *        reassembled datagram).
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

static xtcp::core::FragKey MakeKey(Byte version, UInt32 src, UInt32 dst, UInt32 id) {
    xtcp::core::FragKey key;
    key.version = version;
    key.src[0] = src;
    key.dst[0] = dst;
    key.id = id;
    return key;
}

static void TestMalformedNonFinalFragmentRejected() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey(4, 0xC0A80101, 0x0A000002, 0x4242);

    Byte payload[24];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0x50 + i);
    }
    xtcp::buf::BufRef out;

    // Malformed: non-final fragment with len = 12 (not a multiple of 8).
    // It marks 8-byte units 0..1 while writing only bytes 0..11; a
    // subsequent fragment starting at byte 16 would complete the set with
    // bytes 12..15 never written (uninitialized heap disclosure).
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 12;
    CHECK(-1 == table.Add(1000, key, f0, out));
    CHECK(0 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

static void TestAlignedSequenceCompletes() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey(4, 0xC0A80101, 0x0A000002, 0x4343);

    Byte payload[32];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0x60 + i);
    }
    xtcp::buf::BufRef out;

    // RFC 791 compliant: non-final fragment length is a multiple of 8.
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 8;
    CHECK(0 == table.Add(1000, key, f0, out));

    xtcp::core::Fragment f1;
    f1.offset = 1; f1.more = true; f1.data = payload + 8; f1.len = 8;
    CHECK(0 == table.Add(2000, key, f1, out));

    xtcp::core::Fragment f2;
    f2.offset = 2; f2.more = false; f2.data = payload + 16; f2.len = 16;
    CHECK(1 == table.Add(3000, key, f2, out));
    CHECK(!out.IsEmpty());
    CHECK(32 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 32));
    out.Unref();
    CHECK(0 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

static void TestAlignedTailPartialUnitOk() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1000000, 8);
    xtcp::core::FragKey key = MakeKey(4, 0xC0A80101, 0x0A000002, 0x4444);

    Byte payload[20];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0x70 + i);
    }
    xtcp::buf::BufRef out;

    // Only the FINAL fragment may be a partial unit (total 20 bytes).
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 8;
    CHECK(0 == table.Add(1000, key, f0, out));

    xtcp::core::Fragment f1;
    f1.offset = 1; f1.more = false; f1.data = payload + 8; f1.len = 12;
    CHECK(1 == table.Add(2000, key, f1, out));
    CHECK(!out.IsEmpty());
    CHECK(20 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 20));
    out.Unref();
    CHECK(0 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

int main() {
    TestMalformedNonFinalFragmentRejected();
    TestAlignedSequenceCompletes();
    TestAlignedTailPartialUnitOk();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_frag_align: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_frag_align: all passed\n");
    return 0;
}

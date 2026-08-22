/**
 * @file test_ip.cpp
 * @brief IPv4/IPv6 parsing, checksums (RFC 1071/1624), fragment reassembly.
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

/* RFC 1071 example: 8-byte message 00 01 f2 03 f4 f5 f6 f7 -> checksum 0x220d */
static void TestChecksumRfc1071() {
    const Byte data[8] = { 0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7 };
    CHECK(0x220D == xtcp::core::Checksum(data, sizeof(data)));
}

static void TestChecksumDelta() {
    const Byte data[8] = { 0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7 };
    const UInt16 full = xtcp::core::Checksum(data, sizeof(data));
    const UInt16 old_word = static_cast<UInt16>((data[0] << 8) | data[1]);
    const UInt16 new_word = 0x1234;
    const UInt16 delta = xtcp::core::ChecksumDelta(full, old_word, new_word);

    Byte mutated[8];
    std::memcpy(mutated, data, sizeof(data));
    mutated[0] = static_cast<Byte>(new_word >> 8);
    mutated[1] = static_cast<Byte>(new_word & 0xFF);
    const UInt16 refull = xtcp::core::Checksum(mutated, sizeof(mutated));
    CHECK(delta == refull);  // incremental == full recomputation
}

static void TestParseIp4() {
    // 20-byte IPv4 header, proto TCP, src 192.168.1.1, dst 10.0.0.2
    Byte packet[40];
    std::memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;
    packet[2] = 0x00; packet[3] = 40;          // total length
    packet[8] = 64;                            // TTL
    packet[9] = 6;                             // TCP
    packet[12] = 192; packet[13] = 168; packet[14] = 1; packet[15] = 1;
    packet[16] = 10; packet[17] = 0; packet[18] = 0; packet[19] = 2;

    xtcp::core::Ip4Hdr hdr;
    CHECK(xtcp::core::ParseIp4(packet, sizeof(packet), hdr));
    CHECK(6 == hdr.proto);
    CHECK(20 == hdr.hdr_len);
    CHECK(20 == hdr.payload_off);
    CHECK(40 == hdr.total_len);
    CHECK(0xC0A80101 == hdr.src);
    CHECK(0x0A000002 == hdr.dst);

    // Truncated packet must fail.
    CHECK(!xtcp::core::ParseIp4(packet, 19, hdr));
    // Wrong version must fail.
    packet[0] = 0x65;
    CHECK(!xtcp::core::ParseIp4(packet, sizeof(packet), hdr));
    packet[0] = 0x45;
    // total_len longer than packet must fail.
    packet[3] = 200;
    CHECK(!xtcp::core::ParseIp4(packet, sizeof(packet), hdr));
    packet[3] = 40;
}

static void TestParseIp6() {
    Byte packet[60];
    std::memset(packet, 0, sizeof(packet));
    packet[0] = 0x60;
    packet[1] = 0x00;
    packet[4] = 0x00; packet[5] = 20;         // payload length
    packet[6] = 6;                            // next header: TCP
    packet[7] = 64;                           // hop limit
    packet[8] = 0x20; packet[9] = 0x01;       // src 2001:db8::1
    packet[10] = 0x0D; packet[11] = 0xB8;
    packet[24] = 0x20; packet[25] = 0x01;     // dst 2001:db8::2
    packet[26] = 0x0D; packet[27] = 0xB8;

    xtcp::core::Ip6Hdr hdr;
    CHECK(xtcp::core::ParseIp6(packet, sizeof(packet), hdr));
    CHECK(6 == hdr.proto);
    CHECK(40 == hdr.payload_off);
    CHECK(40 == hdr.hdr_len);
    CHECK(0x20010DB8 == hdr.src[0]);
    CHECK(0x20010DB8 == hdr.dst[0]);
    CHECK(0 == hdr.frag_more);

    // Truncated must fail.
    CHECK(!xtcp::core::ParseIp6(packet, 39, hdr));
    // Wrong version must fail.
    packet[0] = 0x50;
    CHECK(!xtcp::core::ParseIp6(packet, sizeof(packet), hdr));
    packet[0] = 0x60;
}

static void TestFragmentReassemblyFull() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1'000'000, 16);

    xtcp::core::FragKey key;
    key.version = 4;
    key.src[0] = 0xC0A80101;
    key.dst[0] = 0x0A000002;
    key.id = 0x1234;

    Byte payload[100];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(i);
    }

    xtcp::buf::BufRef out;

    // Out-of-order arrival.
    xtcp::core::Fragment f2;
    f2.offset = 8;  f2.more = false; f2.data = payload + 64; f2.len = 36;   // [64,100)
    CHECK(0 == table.Add(1000, key, f2, out));

    xtcp::core::Fragment f0;
    f0.offset = 0;  f0.more = true;  f0.data = payload; f0.len = 32;        // [0,32)
    CHECK(0 == table.Add(2000, key, f0, out));

    xtcp::core::Fragment f1;
    f1.offset = 4;  f1.more = true;  f1.data = payload + 32; f1.len = 32;   // [32,64)
    CHECK(1 == table.Add(3000, key, f1, out));
    CHECK(!out.IsEmpty());
    CHECK(100 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 100));
    CHECK(0 == table.SetCount());
    out.Unref();
}

static void TestFragmentDuplicateRejected() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1'000'000, 16);

    xtcp::core::FragKey key;
    key.version = 6;
    key.src[0] = 0x20010DB8;
    key.dst[0] = 0x20010DB8;
    key.id = 0xABCD;

    Byte payload[64];
    std::memset(payload, 0x11, sizeof(payload));

    xtcp::buf::BufRef out;
    xtcp::core::Fragment f;
    f.offset = 0; f.more = true; f.data = payload; f.len = 32;
    CHECK(0 == table.Add(1000, key, f, out));

    // Duplicate of the same units must be rejected.
    CHECK(-1 == table.Add(2000, key, f, out));
    CHECK(1 == table.SetCount());

    // Completing with the tail must still work.
    xtcp::core::Fragment tail;
    tail.offset = 4; tail.more = false; tail.data = payload + 32; tail.len = 32;
    CHECK(1 == table.Add(3000, key, tail, out));
    CHECK(64 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 64));
    out.Unref();
}

static void TestFragmentExpire() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1'000'000, 16);

    xtcp::core::FragKey key;
    key.version = 4;
    key.src[0] = 1;
    key.dst[0] = 2;
    key.id = 0x777;

    Byte payload[16];
    std::memset(payload, 0x22, sizeof(payload));
    xtcp::buf::BufRef out;
    xtcp::core::Fragment f;
    f.offset = 0; f.more = true; f.data = payload; f.len = 8;
    CHECK(0 == table.Add(1000, key, f, out));
    CHECK(1 == table.SetCount());

    // No expiry while fresh.
    CHECK(0 == table.Expire(1'000'000));
    CHECK(1 == table.SetCount());
    // Expiry after the timeout.
    CHECK(1 == table.Expire(2'000'100));
    CHECK(0 == table.SetCount());
}

int main() {
    TestChecksumRfc1071();
    TestChecksumDelta();
    TestParseIp4();
    TestParseIp6();
    TestFragmentReassemblyFull();
    TestFragmentDuplicateRejected();
    TestFragmentExpire();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_ip: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_ip: all passed\n");
    return 0;
}

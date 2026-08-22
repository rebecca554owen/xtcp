/**
 * @file test_tcp_opts.cpp
 * @brief TCP option parsing (RFC 7323 WSOPT/timestamps, SACK, MSS).
 */

#include <xtcp/core/tcp.h>

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

static void TestWscale() {
    // 20-byte header + WSOPT (kind 3, len 3, value 7) + EOL padding.
    Byte seg[28];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x70;  // data offset 7 (28 bytes)
    seg[20] = 3;     // kind WSOPT
    seg[21] = 3;
    seg[22] = 7;     // wscale 7
    seg[23] = 0;     // EOL

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 28, opts));
    CHECK(opts.has_wscale);
    CHECK(7 == opts.wscale);
    CHECK(!opts.has_sack);
    CHECK(!opts.has_timestamp);
}

static void TestWscaleCapped() {
    Byte seg[28];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x70;
    seg[20] = 3;
    seg[21] = 3;
    seg[22] = 20;  // out of range: capped to 14
    seg[23] = 0;

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 28, opts));
    CHECK(opts.has_wscale);
    CHECK(14 == opts.wscale);
}

static void TestSackAndMss() {
    // MSS(4) + SACK(2) + NOP + NOP + EOL = 20 + 4 + 2 + 1 + 1 = 28
    Byte seg[28];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x70;
    seg[20] = 2;             // MSS
    seg[21] = 4;
    seg[22] = 0x05;
    seg[23] = 0xB4;          // 1460
    seg[24] = 4;             // SACK permitted
    seg[25] = 2;
    seg[26] = 1;             // NOP
    seg[27] = 1;             // NOP

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 28, opts));
    CHECK(opts.has_mss);
    CHECK(1460 == opts.mss);
    CHECK(opts.has_sack);
}

static void TestTimestamps() {
    // TSopt (kind 8, len 10): 20 + 10 + 2 NOP = 32
    Byte seg[36];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x80;  // data offset 8 (32 bytes) + 2 NOP padding
    seg[20] = 8;     // Timestamps
    seg[21] = 10;
    seg[22] = 0x00; seg[23] = 0x01; seg[24] = 0x02; seg[25] = 0x03;  // ts_val 0x00010203
    seg[26] = 0x0A; seg[27] = 0x0B; seg[28] = 0x0C; seg[29] = 0x0D;  // ts_ecr 0x0A0B0C0D
    seg[30] = 1;  // NOP
    seg[31] = 1;  // NOP
    seg[32] = 0;  // EOL
    seg[33] = 0;  // EOL

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 32, opts));
    CHECK(opts.has_timestamp);
    CHECK(0x00010203 == opts.ts_val);
    CHECK(0x0A0B0C0D == opts.ts_ecr);
}

static void TestMalformed() {
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;
    // Option with length beyond the header.
    seg[20] = 3;
    seg[21] = 3;
    seg[22] = 7;   // len 3 fits (20+3=23 <= 24)
    // Now a malformed option: length byte claims more than available.
    Byte bad[22];
    std::memset(bad, 0, sizeof(bad));
    bad[12] = 0x60;  // hdr_len 24
    bad[20] = 8;     // timestamps
    bad[21] = 10;    // len 10 but only 2 bytes remain -> malformed
    xtcp::core::TcpOpts opts;
    CHECK(!xtcp::core::ParseTcpOpts(bad, sizeof(bad), 24, opts));
}

// --- Error-path and edge-case tests ---

static void TestEmptyOptions() {
    // Data offset = 5 (20 bytes, no option space).
    Byte seg[20];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x50;  // data offset 5

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 20, opts));
    CHECK(!opts.has_wscale);
    CHECK(!opts.has_sack);
    CHECK(!opts.has_timestamp);
    CHECK(!opts.has_mss);
}

static void TestNopPaddingOnly() {
    // 20 + 4 NOPs = 24 bytes; data offset 6.
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;  // data offset 6
    seg[20] = 1;  // NOP
    seg[21] = 1;  // NOP
    seg[22] = 1;  // NOP
    seg[23] = 1;  // NOP

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));
    CHECK(!opts.has_wscale);
    CHECK(!opts.has_sack);
    CHECK(!opts.has_timestamp);
    CHECK(!opts.has_mss);
}

static void TestComboAllFourOptions() {
    // MSS(4) + NOP + WSCALE(3) + SACK(2) + NOP + NOP + TS(10) = 4+1+3+2+1+1+10 = 22
    // 20 + 22 = 42 bytes. Data offset = ceil(42/4) = 11 -> 0xB0.
    Byte seg[44];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0xB0;  // data offset 11 (44 bytes)
    UInt32 off = 20;
    // MSS: kind=2, len=4, val=1460
    seg[off++] = 2; seg[off++] = 4;
    seg[off++] = 0x05; seg[off++] = 0xB4;
    // NOP
    seg[off++] = 1;
    // WSCALE: kind=3, len=3, val=7
    seg[off++] = 3; seg[off++] = 3; seg[off++] = 7;
    // SACK permitted: kind=4, len=2
    seg[off++] = 4; seg[off++] = 2;
    // NOP + NOP
    seg[off++] = 1; seg[off++] = 1;
    // TS: kind=8, len=10, ts_val=0xDEADBEEF, ts_ecr=0xCAFEBABE
    seg[off++] = 8; seg[off++] = 10;
    seg[off++] = 0xDE; seg[off++] = 0xAD; seg[off++] = 0xBE; seg[off++] = 0xEF;
    seg[off++] = 0xCA; seg[off++] = 0xFE; seg[off++] = 0xBA; seg[off++] = 0xBE;

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 44, opts));
    CHECK(opts.has_mss);
    CHECK(1460 == opts.mss);
    CHECK(opts.has_wscale);
    CHECK(7 == opts.wscale);
    CHECK(opts.has_sack);
    CHECK(opts.has_timestamp);
    CHECK(0xDEADBEEF == opts.ts_val);
    CHECK(0xCAFEBABE == opts.ts_ecr);
}

static void TestSackBlock() {
    // SACK-permitted(2) + NOP + SACK blocks(10: kind=5, len=10, 1 block)
    // = 2 + 1 + 10 = 13 bytes. 20+13=33 -> data offset ceil(33/4)=9 -> 0x90.
    // That gives 36 bytes; 3 pad bytes are harmless (options end at hdr_len).
    Byte seg[36];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x90;  // data offset 9 (36 bytes)
    UInt32 off = 20;
    seg[off++] = 4; seg[off++] = 2;        // SACK permitted
    seg[off++] = 1;                          // NOP
    seg[off++] = 5; seg[off++] = 10;        // SACK blocks, len=10 (1 block)
    // Block 1: left=1000, right=2000
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x03; seg[off++] = 0xE8; // 1000
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x07; seg[off++] = 0xD0; // 2000

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 36, opts));
    CHECK(opts.has_sack);
    CHECK(1 == opts.sack_count);
    CHECK(1000 == opts.sack[0][0]);
    CHECK(2000 == opts.sack[0][1]);
}

static void TestSackTwoBlocks() {
    // SACK-permitted(2) + NOP + SACK blocks(18: kind=5, len=18, 2 blocks)
    // = 2 + 1 + 18 = 21 bytes. 20+21=41 -> data offset ceil(41/4)=11 -> 0xB0.
    // 44 bytes; 3 pad bytes.
    Byte seg[44];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0xB0;  // data offset 11 (44 bytes)
    UInt32 off = 20;
    seg[off++] = 4; seg[off++] = 2;        // SACK permitted
    seg[off++] = 1;                          // NOP
    seg[off++] = 5; seg[off++] = 18;        // SACK blocks, len=18 (2 blocks)
    // Block 1: left=1000, right=2000
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x03; seg[off++] = 0xE8;
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x07; seg[off++] = 0xD0;
    // Block 2: left=3000, right=4000
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x0B; seg[off++] = 0xB8;
    seg[off++] = 0; seg[off++] = 0; seg[off++] = 0x0F; seg[off++] = 0xA0;

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 44, opts));
    CHECK(opts.has_sack);
    CHECK(2 == opts.sack_count);
    CHECK(1000 == opts.sack[0][0]);
    CHECK(2000 == opts.sack[0][1]);
    CHECK(3000 == opts.sack[1][0]);
    CHECK(4000 == opts.sack[1][1]);
}

static void TestMssInvalidLength() {
    // MSS with len=3 (should be 4).
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;  // data offset 6
    seg[20] = 2;     // MSS
    seg[21] = 3;     // WRONG: should be 4
    seg[22] = 0x05;
    seg[23] = 0xB4;

    xtcp::core::TcpOpts opts;
    CHECK(!xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));  // parser rejects: MSS len=3 leaves trailing junk
    CHECK(!opts.has_mss);
}

static void TestSackPermInvalidLength() {
    // SACK permitted with len=3 (should be 2).
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;
    seg[20] = 4;  // SACK permitted
    seg[21] = 3;  // WRONG: should be 2
    seg[22] = 1;  // NOP
    seg[23] = 1;  // NOP

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));
    CHECK(!opts.has_sack);  // rejected
}

static void TestWscaleInvalidLength() {
    // WSCALE with len=4 (should be 3).
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;
    seg[20] = 3;  // WSCALE
    seg[21] = 4;  // WRONG: should be 3
    seg[22] = 7;
    seg[23] = 0;

    xtcp::core::TcpOpts opts;
    CHECK(xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));
    CHECK(!opts.has_wscale);  // rejected
}

static void TestTimestampInvalidLength() {
    // TS with len=8 (should be 10).
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;
    seg[20] = 8;  // TS
    seg[21] = 8;  // WRONG: should be 10
    seg[22] = 0; seg[23] = 1;

    xtcp::core::TcpOpts opts;
    CHECK(!xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));  // parser rejects: TS len=8 leaves trailing junk
    CHECK(!opts.has_timestamp);
}

static void TestOptionBeyondHeader() {
    // Segment: hdr_len=6 (24 bytes), but option at offset 20 claims len=5
    // (20+5=25 > 24). Should fail.
    Byte seg[24];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x60;  // data offset 6
    seg[20] = 2;     // MSS
    seg[21] = 5;     // len 5 -> 20+5=25 > 24

    xtcp::core::TcpOpts opts;
    CHECK(!xtcp::core::ParseTcpOpts(seg, sizeof(seg), 24, opts));
}

static void TestTruncatedSegment() {
    // Segment shorter than the data offset claims.
    Byte seg[16];
    std::memset(seg, 0, sizeof(seg));
    seg[12] = 0x70;  // data offset 7 (28 bytes) but seg is only 16 bytes

    xtcp::core::TcpOpts opts;
    CHECK(!xtcp::core::ParseTcpOpts(seg, sizeof(seg), 16, opts));
}

int main() {
    TestWscale();
    TestWscaleCapped();
    TestSackAndMss();
    TestTimestamps();
    TestMalformed();
    TestEmptyOptions();
    TestNopPaddingOnly();
    TestComboAllFourOptions();
    TestSackBlock();
    TestSackTwoBlocks();
    TestMssInvalidLength();
    TestSackPermInvalidLength();
    TestWscaleInvalidLength();
    TestTimestampInvalidLength();
    TestOptionBeyondHeader();
    TestTruncatedSegment();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_tcp_opts: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_tcp_opts: all passed\n");
    return 0;
}

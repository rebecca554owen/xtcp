/**
 * @file test_tfo_cookie16.cpp
 * @brief RFC 7413 cookie-length compatibility. A peer such as Linux may
 *        send a TFO cookie longer than the 8-byte shape; the parser must
 *        accept the RFC 7413 range - cookies 4-16 bytes (opt_len 6-18) -
 *        instead of only opt_len == 10 (8-byte cookie), keeping the first
 *        8 bytes (internal storage and the SYN builder are fixed-length).
 *
 *        Verified two ways:
 *          1. Directly: ParseTcpOpts on a raw TCP header carrying the TFO
 *             option (kind 34) with opt_len 10 (8-byte cookie) and 18
 *             (16-byte cookie) -> accepted; opt_len 26 (24-byte cookie)
 *             and 28 (26-byte cookie) -> rejected (beyond RFC 7413's max).
 *          2. End-to-end: a hand-crafted SYN+ACK carrying a 16-byte TFO
 *             cookie (opt_len 18) is injected into a client; the client
 *             parses and caches the cookie via SetTfoCookie and it is then
 *             readable through GetTfoCookieFor (used by ConnectWithTfo on
 *             reconnection). A 24-byte cookie (opt_len 26) is out of RFC
 *             range, so the handshake still completes but nothing is cached
 *             (TFO degrades to plain TCP - a documented code boundary).
 *
 *        Note: a 16-byte cookie has opt_len 18; opt_len 26 is a 24-byte
 *        cookie (beyond the RFC 7413 maximum of 16 bytes).
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/tcp.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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

/* A 16-byte cookie (Linux sends long cookies; the RFC allows 4-16). */
static const Byte kCookie16[16] = {
    0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
    0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9
};

/* A 24-byte cookie (opt_len 26): beyond RFC 7413's 16-byte maximum. */
static const Byte kCookie24[24] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7
};

/**
 * @brief Builds a raw TCP header whose only option is a TFO cookie
 *        (kind 34, opt_len = 2 + cookie_bytes) and parses it.
 * @param cookie_bytes  Cookie size (4-24).
 * @param cookie        Cookie bytes.
 * @param out           Filled on success.
 * @return ParseTcpOpts result (well-formed header).
 */
static bool ParseWithTfo(UInt32 cookie_bytes, const Byte* cookie,
                         xtcp::core::TcpOpts& out) {
    const UInt32 opt_len = 2 + cookie_bytes;          // kind + len + cookie
    const UInt32 pad = (4 - (opt_len % 4)) % 4;       // NOP pad to 4-byte word
    const UInt32 hdr_len = 20 + opt_len + pad;
    Byte seg[60];  // TCP header maximum
    std::memset(seg, 0, sizeof(seg));
    seg[12] = static_cast<Byte>((hdr_len / 4) << 4);  // data offset
    seg[20] = 34;                                     // kind: TFO
    seg[21] = static_cast<Byte>(opt_len);
    std::memcpy(seg + 22, cookie, cookie_bytes);
    for (UInt32 i = 20 + opt_len; i < hdr_len; ++i) {
        seg[i] = 1;  // NOP
    }
    return xtcp::core::ParseTcpOpts(seg, hdr_len, hdr_len, out);
}

/* 8-byte cookie (opt_len 10): the historical shape, still accepted. */
static void TestParser8() {
    const Byte cookie[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    xtcp::core::TcpOpts opts;
    CHECK(ParseWithTfo(8, cookie, opts));
    CHECK(opts.has_tfo);
    CHECK(0 == std::memcmp(opts.tfo_cookie, cookie, 8));
    std::fprintf(stderr, "[tfo-cookie16] parser accepts 8-byte cookie (opt_len 10)\n");
}

/* 16-byte cookie (opt_len 18): the primary RFC 7413 long-cookie case. */
static void TestParser16() {
    xtcp::core::TcpOpts opts;
    CHECK(ParseWithTfo(16, kCookie16, opts));
    CHECK(opts.has_tfo);
    CHECK(0 == std::memcmp(opts.tfo_cookie, kCookie16, 8));
    std::fprintf(stderr, "[tfo-cookie16] parser accepts 16-byte cookie (opt_len 18)\n");
}

/* 24-byte cookie (opt_len 26): beyond RFC 7413's 4-16 byte range -> rejected
 * (the parser accepts only cookies of 4-16 bytes, opt_len 6-18). */
static void TestParser24() {
    xtcp::core::TcpOpts opts;
    CHECK(ParseWithTfo(24, kCookie24, opts));  // header is well-formed...
    CHECK(!opts.has_tfo);                       // ...but the cookie is out of range
    std::fprintf(stderr, "[tfo-cookie16] parser rejects 24-byte cookie (opt_len 26, > RFC 7413 max)\n");
}

/* 26-byte cookie (opt_len 28): beyond the accepted range -> not a cookie. */
static void TestParserOversize() {
    const Byte cookie[26] = { 0 };
    xtcp::core::TcpOpts opts;
    CHECK(ParseWithTfo(26, cookie, opts));  // header is well-formed...
    CHECK(!opts.has_tfo);                    // ...but the TFO cookie is rejected
    std::fprintf(stderr, "[tfo-cookie16] parser rejects opt_len 28 (boundary)\n");
}

/**
 * @brief End-to-end: a client handshakes with a peer whose SYN+ACK carries
 *        a TFO cookie; the cookie must be parsed and cached so the next
 *        ConnectWithTfo can reuse it.
 * @param local_port   Client's local port.
 * @param remote_port  Peer's port.
 * @param cookie       Cookie bytes carried in the hand-crafted SYN+ACK.
 * @param cookie_bytes Cookie size.
 * @param expect_cached True: the cookie is within RFC 7413 (4-16 bytes) and
 *        must be cached; false: it exceeds the RFC maximum, so the handshake
 *        still completes but no cookie is cached (TFO degrades to plain TCP).
 */
static void RunStackCookieTest(UInt16 local_port, UInt16 remote_port,
                               const Byte* cookie, UInt32 cookie_bytes,
                               bool expect_cached) {
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack.OnPacket(std::move(buf));
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = local_port;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = remote_port;

    // A connects: the SYN goes out; read it to learn A's ISN.
    const UInt64 conn = stack.Connect(local, remote);
    CHECK(0 != conn);
    Byte syn[65536];
    const UInt32 syn_len = backend.PollTx(syn);
    CHECK(0 != syn_len);
    const UInt32 iss = (static_cast<UInt32>(syn[24]) << 24) |
                       (static_cast<UInt32>(syn[25]) << 16) |
                       (static_cast<UInt32>(syn[26]) << 8) |
                       static_cast<UInt32>(syn[27]);
    CHECK(0 != iss);

    // Hand-crafted SYN+ACK (IP v4 + TCP) carrying MSS and a long TFO cookie.
    const UInt32 opt_len = 2 + cookie_bytes;                       // TFO option
    const UInt32 tcp_hdr_len =
        20 + 4 + opt_len + ((4 - ((4 + opt_len) % 4)) % 4);        // + MSS + pad
    const UInt32 total = 20 + tcp_hdr_len;
    std::vector<Byte> pkt(total);
    std::memset(pkt.data(), 0, total);
    pkt[0] = 0x45;
    pkt[2] = static_cast<Byte>(total >> 8); pkt[3] = static_cast<Byte>(total);
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = 0x0A; pkt[13] = 0x00; pkt[14] = 0x00; pkt[15] = 0x02;  // src = remote
    pkt[16] = 0x0A; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x01;  // dst = local
    Byte* t = pkt.data() + 20;
    t[0] = static_cast<Byte>(remote_port >> 8); t[1] = static_cast<Byte>(remote_port);
    t[2] = static_cast<Byte>(local_port >> 8);  t[3] = static_cast<Byte>(local_port);
    t[4] = 0x10; t[5] = 0x00; t[6] = 0x00; t[7] = 0x00;              // server ISN
    const UInt32 ack = iss + 1;                                     // A's ISN + 1
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack);
    t[12] = static_cast<Byte>((tcp_hdr_len / 4) << 4);              // data offset
    t[13] = 0x12;                                                   // SYN | ACK
    t[14] = 0xFF; t[15] = 0xFF;                                     // window 65535
    t[20] = 2; t[21] = 4; t[22] = 0x05; t[23] = 0xB4;               // MSS 1460
    t[24] = 34;                                                     // kind: TFO
    t[25] = static_cast<Byte>(opt_len);
    std::memcpy(t + 26, cookie, cookie_bytes);
    for (UInt32 i = 24 + opt_len; i < tcp_hdr_len; ++i) {
        t[i] = 1;                                                   // NOP padding
    }
    // Valid checksums: a zero-checksum SYN+ACK is dropped under the
    // checksum-validate build and the TFO cookie path never runs.
    xtcp::harness::FillIp4Checksum(pkt.data());
    xtcp::harness::FillTcp4Checksum(pkt.data(), pkt.data() + 20, tcp_hdr_len);
    backend.Inject(pkt.data(), total, 0x0800);

    // The SYN+ACK completed the handshake. A cookie within RFC 7413 (4-16
    // bytes) is parsed and cached for the next fast-open SYN (ConnectWithTfo
    // reads it via GetTfoCookieFor); one beyond the 16-byte maximum is
    // rejected by the parser, so nothing is cached but the connection lives.
    CHECK(1 == stack.ConnectionCount());
    CHECK(xtcp::core::TcpState::kEstablished == stack.ConnectionState(conn));
    Byte got[8];
    if (expect_cached) {
        CHECK(stack.GetTfoCookieFor(remote, got));
        CHECK(0 == std::memcmp(got, cookie, 8));
        std::fprintf(stderr,
                     "[tfo-cookie16] stack cached %u-byte cookie for peer:%u "
                     "(first 8: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
                     cookie_bytes, remote_port, got[0], got[1], got[2], got[3],
                     got[4], got[5], got[6], got[7]);
    } else {
        CHECK(!stack.GetTfoCookieFor(remote, got));
        std::fprintf(stderr,
                     "[tfo-cookie16] stack rejects %u-byte cookie for peer:%u "
                     "(beyond RFC 7413 max; handshake complete, TFO disabled)\n",
                     cookie_bytes, remote_port);
    }
}

int main() {
    TestParser8();
    TestParser16();
    TestParser24();
    TestParserOversize();

    xtcp::buf::InitPools();
    {
        // 16-byte cookie (opt_len 18): the RFC 7413 maximum, must be cached.
        RunStackCookieTest(40000, 8080, kCookie16, sizeof(kCookie16), true);
        // 24-byte cookie (kind 34, length 26): beyond RFC 7413, rejected.
        RunStackCookieTest(40002, 8081, kCookie24, sizeof(kCookie24), false);
    }
    xtcp::buf::ShutdownPools();

    std::fprintf(stderr,
                 g_failures ? "TFO_COOKIE16: FAILED (%d)\n" : "TFO_COOKIE16: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

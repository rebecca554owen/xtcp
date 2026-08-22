/**
 * @file test_md5.cpp
 * @brief RFC 1321 MD5 vectors + RFC 2385 TCP-MD5 signing/verification.
 */

#include <xtcp/core/md5.h>
#include <xtcp/core/tcp.h>

#include <cstdio>
#include <cstdint>
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

static void TestMd5Vectors() {
    struct Vec {
        const char* in;
        const char* hex;
    };
    const Vec vecs[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "a", "0cc175b9c0f1b6a831c399e269772661" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "d174ab98d277d9f5a5611c2c9f419d9f" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
          "57edf4a22be3c955ac49da2e2107b67a" },
    };
    for (const Vec& v : vecs) {
        std::uint8_t digest[16];
        xtcp::core::Md5Compute(v.in, std::strlen(v.in), digest);
        char hex[33];
        for (int i = 0; i < 16; ++i) {
            std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
        }
        if (0 != std::strcmp(hex, v.hex)) {
            std::fprintf(stderr, "  got=%.32s want=%s len=%zu\\n", hex, v.hex, std::strlen(v.in));
        }
        CHECK(0 == std::strcmp(hex, v.hex));
    }
}

static void TestMd5Verify() {
    // TCP-MD5 segment signing then verification round-trip through
    // TcpConn (no payload, pure ACK with MD5 option).
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A010001;  // 10.1.0.1
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A010002;  // 10.1.0.2
    remote.port = 443;

    const Byte key[] = { 't', 'e', 's', 't', '-', 'k', 'e', 'y' };

    struct Sink {
        std::vector<std::vector<Byte>> pkts;
        void operator()(xtcp::buf::BufRef&& p) {
            pkts.emplace_back(p.Data(), p.Data() + p.Len());
        }
    };
    Sink sink;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&sink](xtcp::buf::BufRef&& p) { sink(std::move(p)); });
    conn.SetMd5Key(key, sizeof(key));
    CHECK(conn.Md5Enabled());

    // Send a data segment: it must carry the MD5 option and a valid signature.
    const Byte payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    conn.SendData(payload, sizeof(payload), 1000);
    CHECK(1 == sink.pkts.size());
    const std::vector<Byte>& pkt = sink.pkts[0];
    const Byte* ip = pkt.data();
    CHECK(24 <= pkt.size());
    const Byte* t = ip + 20;
    const UInt32 tcp_len = static_cast<UInt32>(pkt.size() - 20);
    CHECK(0x0A == (t[12] >> 4));  // data offset 10 (20 + 20-byte MD5 option)

    // Correct key: the peer accepts the segment and delivers the payload.
    xtcp::core::TcpConn peer(xtcp::core::TcpState::kEstablished, remote, local, 200, 100,
                             [](xtcp::buf::BufRef&&) {});
    peer.SetMd5Key(key, sizeof(key));
    UInt32 peer_recv = 0;
    peer.SetRecvHandler([&peer_recv](const Byte*, UInt32 len) { peer_recv += len; return true; });
    peer.OnSegment(t, tcp_len, 1000);
    CHECK(4 == peer_recv);

    // Wrong key: the segment must be dropped (no delivery).
    const Byte bad_key[] = { 'w', 'r', 'o', 'n', 'g' };
    xtcp::core::TcpConn peer2(xtcp::core::TcpState::kEstablished, remote, local, 200, 100,
                              [](xtcp::buf::BufRef&&) {});
    peer2.SetMd5Key(bad_key, sizeof(bad_key));
    UInt32 peer2_recv = 0;
    peer2.SetRecvHandler([&peer2_recv](const Byte*, UInt32 len) { peer2_recv += len; return true; });
    peer2.OnSegment(t, tcp_len, 1000);
    CHECK(0 == peer2_recv);
}

int main() {
    xtcp::buf::InitPools();
    TestMd5Vectors();
    TestMd5Verify();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "test_md5: %s\n", (0 == g_failures) ? "all passed" : "FAILED");
    return g_failures ? 1 : 0;
}

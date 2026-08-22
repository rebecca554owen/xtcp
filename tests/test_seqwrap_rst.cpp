/**
 * @file test_seqwrap_rst.cpp
 * @brief RST sequence-window validation (RFC 5961) at the 2^32 sequence
 *        wraparound boundary (RFC 1982). With rcv_nxt near the wrap, an RST
 *        whose seq lies inside the (wrapped) receive window must close the
 *        connection; an RST outside the window must NOT close it - the stack
 *        replies with a challenge ACK instead (RFC 5961).
 *
 * This is a unit-level test on TcpConn directly: the receive frontier is
 * placed at 0xFFFFFFF0 (just before the wrap) without transferring gigabytes
 * of data, then hand-built RST/data segments are injected around the wrap.
 *
 * Window geometry: rcv_nxt_ = 0xFFFFFFF0, rcv_wnd_ = 65535 (0xFFFF), so the
 * wrapped receive window is [rcv_nxt_, rcv_nxt_ + rcv_wnd_) mod 2^32 =
 * [0xFFFFFFF0, 0x0000FFEF) - the window END is 0x0000FFEF, not 0x000000EF
 * (0xFFFFFFF0 + 0xFFFF wraps to 0x0000FFEF).
 *
 * NOTE (documented deviation): the current implementation (tcp_fsm.cpp
 * kEstablished RST case) honors an RST whose seq is anywhere inside the
 * receive window, which is the RFC 793 acceptance rule. RFC 5961 (and Linux
 * tcp_validate_incoming) tighten this to seq == RCV.NXT only; that stricter
 * rule is NOT implemented. This test asserts the current window-based
 * behavior. If the code is later tightened to RFC 5961, the out-of-window
 * expectations below must be re-reviewed.
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

using xtcp::core::TcpState;

/** Builds a raw TCP segment (IP payload form) with valid header fields. */
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

/**
 * Creates an Established connection whose receive frontier sits at
 * rcv_nxt == 0xFFFFFFF0, i.e. the RFC 1982 window [rcv_nxt, rcv_nxt+rcv_wnd)
 * spans the 2^32 boundary: [0xFFFFFFF0, 0x0000FFEF) mod 2^32.
 * The sink counts emitted packets (a challenge ACK = exactly one).
 */
static xtcp::core::TcpConn MakeWrapConn(UInt32* tx_count) {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A010001;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A010002;
    remote.port = 443;
    *tx_count = 0;
    return xtcp::core::TcpConn(TcpState::kEstablished, local, remote, 100,
                               0xFFFFFFF0u - 1u,  // irs -> rcv_nxt_ == 0xFFFFFFF0
                               [tx_count](xtcp::buf::BufRef&&) { ++(*tx_count); });
}

static void InjectRst(xtcp::core::TcpConn& conn, UInt32 seq) {
    std::vector<Byte> seg = BuildTcpSegment(443, 40000, seq, 0, xtcp::core::kFlagRst, NULLPTR, 0);
    conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()), 1000);
}

/** seq values strictly inside the wrapped window -> RST must close. */
static void TestInWindowRstCloses() {
    // Window with rcv_nxt_ = 0xFFFFFFF0, rcv_wnd_ = 65535:
    //   [0xFFFFFFF0, 0xFFFFFFF0 + 65535) mod 2^32 == [0xFFFFFFF0, 0x0000FFEF)
    const UInt32 in_window[] = {
        0xFFFFFFF0u,  // == rcv_nxt_ (window start)
        0xFFFFFFF5u,  // pre-wrap, inside
        0xFFFFFFFFu,  // last pre-wrap slot
        0x00000000u,  // first post-wrap slot
        0x00000010u,  // post-wrap, inside
        0x0000FFEEu,  // last post-wrap slot (window end - 1)
    };
    for (UInt32 seq : in_window) {
        UInt32 tx = 0;
        xtcp::core::TcpConn conn = MakeWrapConn(&tx);
        InjectRst(conn, seq);
        CHECK(TcpState::kClosed == conn.State());
        CHECK(0 == tx);  // valid RST: no challenge ACK emitted
    }
    std::fprintf(stderr, "[seqwrap-rst] in-window RSTs closed the connection at the wrap\n");
}

/** seq values outside the wrapped window -> must be challenged, not closed. */
static void TestOutOfWindowRstChallenged() {
    const UInt32 out_window[] = {
        0xFFFFFFEFu,  // rcv_nxt_ - 1 (just before window start)
        0x0000FFEFu,  // window end (== rcv_nxt_ + rcv_wnd_ mod 2^32)
        0x0000FFF0u,  // just past the wrapped window end
        0x99999999u,  // far outside
    };
    for (UInt32 seq : out_window) {
        UInt32 tx = 0;
        xtcp::core::TcpConn conn = MakeWrapConn(&tx);
        InjectRst(conn, seq);
        CHECK(TcpState::kEstablished == conn.State());
        CHECK(1 == tx);  // RFC 5961: challenge ACK emitted, connection kept
    }
    std::fprintf(stderr, "[seqwrap-rst] out-of-window RSTs were challenged, connection kept\n");
}

/**
 * After a boundary challenge the connection must remain fully usable:
 * in-order data delivered across the wrap, and a subsequent in-window RST
 * still closes it.
 */
static void TestConnectionConsistentAfterChallenge() {
    UInt32 tx = 0;
    xtcp::core::TcpConn conn = MakeWrapConn(&tx);

    // Out-of-window RST at the wrap: challenged, stays Established.
    // (0x0000FFF0 is just past the wrapped window end; 0x000000F0 would be
    // in-window here since 0xFFFFFFF0 + 0xFFFF wraps to 0x0000FFEF.)
    InjectRst(conn, 0x0000FFF0u);
    CHECK(TcpState::kEstablished == conn.State());
    CHECK(1 == tx);

    std::vector<Byte> delivered;
    conn.SetRecvHandler([&delivered](const Byte* d, UInt32 len) {
        delivered.insert(delivered.end(), d, d + len);
        return true;
    });

    // Post-wrap segment arrives first (out of order) and is buffered.
    const Byte p0[] = { 'x', 'y', 'z' };
    std::vector<Byte> wrap = BuildTcpSegment(443, 40000, 0x00000000u, 0, 0, p0, 3);
    conn.OnSegment(wrap.data(), static_cast<UInt32>(wrap.size()), 1000);
    CHECK(0 == delivered.size());

    // In-order run 0xFFFFFFF0..0xFFFFFFFF (16 bytes) drains across the wrap
    // and delivers the buffered post-wrap segment too.
    for (UInt32 i = 0; i < 16; ++i) {
        const Byte one = static_cast<Byte>('a' + i);
        std::vector<Byte> seg = BuildTcpSegment(443, 40000, 0xFFFFFFF0u + i, 0, 0, &one, 1);
        conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()), 1000);
    }
    CHECK(19 == delivered.size());
    CHECK(0 == std::memcmp(delivered.data() + 16, p0, 3));  // order preserved

    // rcv_nxt_ is now 0x00000003 (0xFFFFFFF0 + 16 wraps to 0, then +3);
    // an RST inside the post-wrap window closes the connection.
    InjectRst(conn, 0x00000010u);
    CHECK(TcpState::kClosed == conn.State());
    std::fprintf(stderr, "[seqwrap-rst] connection consistent after boundary challenge\n");
}

int main() {
    xtcp::buf::InitPools();
    TestInWindowRstCloses();
    TestOutOfWindowRstChallenged();
    TestConnectionConsistentAfterChallenge();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "test_seqwrap_rst: %s\n", (0 == g_failures) ? "all passed" : "FAILED");
    return g_failures ? 1 : 0;
}

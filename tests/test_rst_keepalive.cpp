/**
 * @file test_rst_keepalive.cpp
 * @brief Two RFC 5961 / keepalive combination gaps identified by the RST
 *        audit (2026-08-10, discover.md):
 *
 *   Gap 1: a keepalive probe answered by an in-window RST must close the
 *          connection IMMEDIATELY (the RST is honored), not after the
 *          keepalive cnt budget. The probe goes out (seq = snd_nxt_-1),
 *          the peer aborts with RST (seq = our snd_nxt_), and near-
 *          symmetric sequence numbers put snd_nxt_ inside [rcv_nxt_,
 *          rcv_nxt_+rcv_wnd_) so the RST is valid (RFC 5961 s4).
 *
 *   Gap 2: after an out-of-window RST flood burns the challenge-ACK
 *          budget (kChallengeAckLimit = 8 per 1s, tcp_fsm.cpp SendChallengeAck),
 *          a subsequent VALID in-window RST must still be honored. The
 *          rate limiter gates only challenge ACK emission; the in-window
 *          kClosed transition is independent of challenge_count_.
 *
 * Both use the TcpConn unit surface (mirror of test_keepalive.cpp).
 */

#include <xtcp/core/tcp.h>
#include <xtcp/buf/bufref.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    using xtcp::core::TcpConn;
    using xtcp::core::TcpState;
    using xtcp::core::kFlagAck;
    using xtcp::core::kFlagPsh;
    using xtcp::core::kFlagRst;
    using xtcp::core::kFlagFin;

    struct TxLog {
        std::vector<UInt32> lens;
        std::vector<UInt16> flags;
        void Clear() {
            lens.clear();
            flags.clear();
        }
        UInt32 CountWithFlag(UInt16 flag) const {
            UInt32 n = 0;
            for (UInt16 f : flags) {
                if (0 != (f & flag)) {
                    ++n;
                }
            }
            return n;
        }
    };

    std::unique_ptr<xtcp::core::TcpConn> MakeConn(TxLog& log, UInt32 iss, UInt32 irs) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A010002;
        local.port = 443;
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A010001;
        remote.port = 40000;
        return std::make_unique<xtcp::core::TcpConn>(
            TcpState::kEstablished, local, remote, iss, irs,
            [&log](xtcp::buf::BufRef&& p) {
                log.lens.push_back(p.Len());
                const Byte* d = p.Data();
                log.flags.push_back(static_cast<UInt16>(d[20 + 13] & 0x3F));
            });
    }

    /** Raw TCP segment (no IP header, no checksum - unit surface). */
    std::vector<Byte> BuildTcp(UInt16 flags, UInt32 seq, UInt32 ack,
                               const Byte* payload = NULLPTR, UInt32 payload_len = 0) {
        std::vector<Byte> out(20 + payload_len, 0);
        out[0] = 0x9C; out[1] = 0x40;
        out[2] = 0x01; out[3] = 0xBB;
        out[4] = static_cast<Byte>(seq >> 24); out[5] = static_cast<Byte>(seq >> 16);
        out[6] = static_cast<Byte>(seq >> 8);  out[7] = static_cast<Byte>(seq & 0xFF);
        out[8] = static_cast<Byte>(ack >> 24); out[9] = static_cast<Byte>(ack >> 16);
        out[10] = static_cast<Byte>(ack >> 8); out[11] = static_cast<Byte>(ack & 0xFF);
        out[12] = 0x50; out[13] = static_cast<Byte>(flags & 0x3F);
        out[14] = 0xFF; out[15] = 0xFF;
        if (0 < payload_len) {
            std::memcpy(out.data() + 20, payload, payload_len);
        }
        return out;
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        // ---- Gap 1: keepalive probe answered by an in-window RST ----
        // Near-symmetric sequence numbers: local iss = 0x40000000,
        // remote irs = 0x3FFFF000, both directions advance 5 bytes, so
        // snd_nxt_ = 0x40000006 sits inside [rcv_nxt_ = 0x3FFFF006,
        // rcv_nxt_ + rcv_wnd_).
        TxLog log;
        auto conn = MakeConn(log, 0x40000000, 0x3FFFF000);
        const std::vector<Byte> base = BuildTcp(kFlagAck, 0x3FFFF001, 0x40000001);
        conn->OnSegment(base.data(), static_cast<UInt32>(base.size()), 1000);

        const Byte hello[5] = {1, 2, 3, 4, 5};
        CHECK(conn->SendData(hello, 5, 2000));  // snd_nxt_ -> 0x40000006
        const Byte world[5] = {6, 7, 8, 9, 10};
        const std::vector<Byte> data_in = BuildTcp(
            kFlagAck | kFlagPsh, 0x3FFFF001, 0x40000006, world, 5);
        conn->OnSegment(data_in.data(), static_cast<UInt32>(data_in.size()), 3000);
        log.Clear();

        conn->SetKeepalive(10000, 5000, 3);  // idle 10 ms, intvl 5 ms, cnt 3

        // Idle elapses: a keepalive probe (pure ACK, seq = snd_nxt_-1) goes out.
        // last_rx_ was refreshed at t=3000 by the in-window data; idle 10000 us
        // elapses at t=13000, so poll at 14000.
        conn->OnPoll(14000);
        CHECK(1 == log.CountWithFlag(kFlagAck));
        CHECK(0 == log.CountWithFlag(kFlagFin));
        CHECK(0 == log.CountWithFlag(kFlagRst));
        std::fprintf(stderr, "[rst-keepalive] keepalive probe sent\n");

        // Peer aborts with RST carrying seq = our snd_nxt_ (in window).
        const std::vector<Byte> rst = BuildTcp(kFlagAck | kFlagRst, 0x40000006, 0x40000006);
        conn->OnSegment(rst.data(), static_cast<UInt32>(rst.size()), 14000);
        CHECK(xtcp::core::TcpState::kClosed == conn->State());
        std::fprintf(stderr,
                     "[rst-keepalive] in-window RST honored after probe: closed immediately\n");
    }
    {
        // ---- Gap 2: RST flood burns challenge budget, valid RST still honored ----
        TxLog log;
        auto conn = MakeConn(log, 0x40000000, 0x50000000);
        const std::vector<Byte> base = BuildTcp(kFlagAck, 0x50000001, 0x40000001);
        conn->OnSegment(base.data(), static_cast<UInt32>(base.size()), 1000);
        log.Clear();

        // Out-of-window flood (mirror of test_challenge_rate.cpp): every RST is
        // challenged, but SendChallengeAck throttles to 8 per 1s wall-clock.
        const UInt32 kRstCount = 200;
        for (UInt32 i = 0; i < kRstCount; ++i) {
            const std::vector<Byte> flood = BuildTcp(kFlagRst, 0x99999999u + i, 0);
            conn->OnSegment(flood.data(), static_cast<UInt32>(flood.size()), 2000 + i * 10);
        }
        const UInt32 acks = log.CountWithFlag(kFlagAck);
        std::fprintf(stderr, "[rst-keepalive] %u out-of-window RSTs -> %u challenge ACKs\n",
                     kRstCount, acks);
        CHECK(acks <= 8);
        CHECK(1 <= acks);  // the flood was challenged at least once
        CHECK(xtcp::core::TcpState::kEstablished == conn->State());  // storm does not close

        // A valid in-window RST (seq = rcv_nxt_ + 1) after the storm must still
        // be honored: the limiter gates only challenge emission, not the
        // in-window kClosed transition.
        const std::vector<Byte> valid = BuildTcp(kFlagAck | kFlagRst, 0x50000002, 0);
        conn->OnSegment(valid.data(), static_cast<UInt32>(valid.size()), 5000);
        CHECK(xtcp::core::TcpState::kClosed == conn->State());
        std::fprintf(stderr,
                     "[rst-keepalive] valid in-window RST honored after storm\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_KEEPALIVE: FAILED (%d)\n" : "RST_KEEPALIVE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

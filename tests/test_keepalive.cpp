/**
 * @file test_keepalive.cpp
 * @brief Keepalive (Linux TCP_KEEPIDLE semantics): idle connections send
 *        probe ACKs; after cnt unanswered probes the connection aborts
 *        (RST). Any inbound segment resets the idle counter.
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

    struct TxLog {
        std::vector<UInt32> lens;
        std::vector<UInt16> flags;
        void Clear() {
            lens.clear();
            flags.clear();
        }
    };

    std::unique_ptr<xtcp::core::TcpConn> MakeConn(TxLog& log, UInt32 iss = 0x40000000) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A010002;
        local.port = 443;
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A010001;
        remote.port = 40000;
        return std::make_unique<xtcp::core::TcpConn>(
            TcpState::kEstablished, local, remote, iss, 0x50000000,
            [&log](xtcp::buf::BufRef&& p) {
                log.lens.push_back(p.Len());
                const Byte* d = p.Data();
                log.flags.push_back(static_cast<UInt16>(d[20 + 13] & 0x3F));
            });
    }

    /** Pure ACK segment (TCP only). */
    std::vector<Byte> BuildAck(UInt32 ack, UInt32 seq) {
        std::vector<Byte> out(20, 0);
        out[0] = 0x9C; out[1] = 0x40;
        out[2] = 0x01; out[3] = 0xBB;
        out[4] = static_cast<Byte>(seq >> 24); out[5] = static_cast<Byte>(seq >> 16);
        out[6] = static_cast<Byte>(seq >> 8);  out[7] = static_cast<Byte>(seq & 0xFF);
        out[8] = static_cast<Byte>(ack >> 24); out[9] = static_cast<Byte>(ack >> 16);
        out[10] = static_cast<Byte>(ack >> 8); out[11] = static_cast<Byte>(ack & 0xFF);
        out[12] = 0x50; out[13] = 0x10;
        out[14] = 0xFF; out[15] = 0xFF;
        return out;
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        // 1) Probe after idle, reset by inbound traffic.
        TxLog log;
        auto conn = MakeConn(log);
        conn->SetKeepalive(10000, 5000, 3);  // idle 10 ms, intvl 5 ms, cnt 3

        const std::vector<Byte> ack = BuildAck(0x40000001, 0x50000001);
        conn->OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 1000);

        // Idle elapses: OnPoll sends a keepalive probe (pure ACK).
        conn->OnPoll(11000);
        CHECK(1 == log.lens.size());
        const UInt16 flags = log.flags[0];
        CHECK(0 == (flags & 0x01));  // not FIN
        std::fprintf(stderr, "[keepalive] probe sent after idle\n");
        log.Clear();

        // Peer answers: idle resets, no further probes (before idle elapses).
        conn->OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 12000);
        conn->OnPoll(21500);  // 9500 us since rx < idle 10000
        CHECK(0 == log.lens.size());
        std::fprintf(stderr, "[keepalive] traffic reset idle: no probe\n");

        // 2) Dead peer: cnt unanswered probes abort (RST).
        TxLog log2;
        auto conn2 = MakeConn(log2, 0x40001000);
        conn2->SetKeepalive(10000, 5000, 3);
        const std::vector<Byte> ack2 = BuildAck(0x40001001, 0x50001001);
        conn2->OnSegment(ack2.data(), static_cast<UInt32>(ack2.size()), 1000);

        // Three probe rounds, no peer response.
        for (UInt32 i = 0; i < 3; ++i) {
            conn2->OnPoll(11000 + i * 6000);
        }
        // The fourth round sees cnt reached and aborts.
        conn2->OnPoll(11000 + 3 * 6000);
        CHECK(xtcp::core::TcpState::kClosed == conn2->State());
        bool saw_rst = false;
        for (UInt16 f : log2.flags) {
            if (0 != (f & 0x04)) {
                saw_rst = true;
            }
        }
        std::fprintf(stderr, "[keepalive] dead peer aborted, RST=%s\n", saw_rst ? "yes" : "no");
        CHECK(saw_rst);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE: FAILED (%d)\n" : "KEEPALIVE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

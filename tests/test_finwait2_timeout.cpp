/**
 * @file test_finwait2_timeout.cpp
 * @brief Linux tcp_fin_timeout: after our FIN is ACKed (FIN-WAIT-2), a peer
 *        that never sends its own FIN would hold the connection forever;
 *        the timeout reclaims it (Closed).
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

    std::unique_ptr<xtcp::core::TcpConn> MakeConn(UInt32 iss = 0x40000000) {
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
            [](xtcp::buf::BufRef&&) noexcept {});
    }

    /** Pure ACK segment (TCP only) acknowledging the FIN. */
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
        auto conn = MakeConn();
        conn->SetFinWait2Timeout(10000);  // 10 ms for the test

        // Close: FIN sent, state FIN-WAIT-1.
        conn->Close(1000);
        CHECK(TcpState::kFinWait1 == conn->State());

        // The peer ACKs the FIN: FIN-WAIT-2 with the timeout armed.
        const std::vector<Byte> ack = BuildAck(0x40000001 + 1, 0x50000001);
        conn->OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 2000);
        CHECK(TcpState::kFinWait2 == conn->State());
        CHECK(0 != conn->FinWait2Deadline());

        // Before the deadline: still FIN-WAIT-2.
        conn->OnPoll(5000);
        CHECK(TcpState::kFinWait2 == conn->State());

        // Deadline passes: reclaimed (Closed), no FIN ever needed.
        conn->OnPoll(20000);
        CHECK(TcpState::kClosed == conn->State());
        std::fprintf(stderr, "[finwait2] reclaimed after tcp_fin_timeout\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FINWAIT2: FAILED (%d)\n" : "FINWAIT2: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

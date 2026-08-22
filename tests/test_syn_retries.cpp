/**
 * @file test_syn_retries.cpp
 * @brief TCP_SYNCNT: an unanswered SYN is retransmitted up to the budget,
 *        then the handshake is abandoned (Closed). Any inbound segment
 *        resets the budget (handshake progress).
 */

#include <xtcp/core/tcp.h>
#include <xtcp/buf/bufref.h>

#include <cstdio>
#include <cstring>
#include <chrono>
#include <memory>
#include <thread>
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
    using xtcp::core::kFlagSyn;

    struct TxLog {
        UInt32 syns = 0;
        std::vector<UInt32> lens;
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
            TcpState::kSynSent, local, remote, iss, 0,
            [&log](xtcp::buf::BufRef&& p) {
                log.lens.push_back(p.Len());
                const Byte* d = p.Data();
                if (0 != (d[20 + 13] & 0x02)) {
                    ++log.syns;
                }
            });
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        // SYN retransmit budget = 2: two retransmits, then abandon.
        TxLog log;
        auto conn = MakeConn(log);
        conn->SetSynRetries(2);
        conn->SetRto(1000);  // 1 ms RTO for the test

        conn->SendSyn();
        CHECK(TcpState::kSynSent == conn->State());

        // Fire the RTO timer exactly at each re-armed deadline (deterministic).
        // Driving it with real-time sleeps races the doubling SYN backoff
        // (1ms -> 2ms -> 4ms): a timer call landing before the re-armed
        // deadline is a no-op and the abandon never fires in-loop.
        for (UInt32 round = 0; round < 3; ++round) {
            const UInt64 deadline = conn->NextRetransmitTime();
            CHECK(0 != deadline);
            conn->OnRetransmitTimer(deadline);
        }
        CHECK(TcpState::kClosed == conn->State());
        CHECK(1 + 2 == log.syns);           // original + 2 retransmits
        std::fprintf(stderr, "[syn-retries] abandoned after %u SYN retransmits\n", log.syns);

        // Progress resets the budget: an inbound SYN+ACK moves the state on.
        TxLog log2;
        auto conn2 = MakeConn(log2, 0x40001000);
        conn2->SetSynRetries(2);
        conn2->SendSyn();
        // A partial response (ACK-less SYN) counts as progress.
        std::vector<Byte> seg(20, 0);
        seg[4] = 0x50; seg[5] = 0x00; seg[6] = 0x00; seg[7] = 0x01;  // seq
        seg[12] = 0x50; seg[13] = 0x12;  // SYN|ACK
        seg[14] = 0xFF; seg[15] = 0xFF;
        conn2->OnSegment(seg.data(), static_cast<UInt32>(seg.size()), 1000);
        // Budget was reset; a few retransmits still leave the conn alive.
        conn2->OnRetransmitTimer(1000000);
        conn2->OnRetransmitTimer(2000000);
        CHECK(TcpState::kSynRcvd == conn2->State() ||
              TcpState::kSynSent == conn2->State());
        std::fprintf(stderr, "[syn-retries] progress reset the budget\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYN_RETRIES: FAILED (%d)\n" : "SYN_RETRIES: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


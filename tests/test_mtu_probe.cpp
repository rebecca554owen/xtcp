/**
 * @file test_mtu_probe.cpp
 * @brief RFC 1191 periodic MTU re-probe: after a path-MTU reduction, the
 *        connection periodically restores the negotiated MSS (the path may
 *        have grown). A fresh ICMP "fragmentation needed" lowers it again.
 */

#include <xtcp/core/tcp.h>
#include <xtcp/buf/bufref.h>

#include <cstdio>
#include <cstring>
#include <memory>
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
}

int main() {
    xtcp::buf::InitPools();
    {
        auto conn = MakeConn();
        CHECK(1460 == conn->PeerMss());

        // Path-MTU reduction: MSS 1460 -> 1360 (MTU 1400), probe armed.
        conn->SetMtuProbeInterval(1000000);  // 1 s probes for the test
        const UInt64 t0 = xtcp::core::TcpConn::MtuNowUs();
        conn->OnMtuReduced(1400);
        CHECK(1360 == conn->PeerMss());

        // Before the deadline: still reduced.
        conn->OnPoll(t0 + 500000);
        CHECK(1360 == conn->PeerMss());

        // Deadline passes: the negotiated MSS is restored (path may have
        // grown). A new ICMP lowers it again (closed loop).
        conn->OnPoll(t0 + 1100000);
        CHECK(1460 == conn->PeerMss());

        conn->OnMtuReduced(1200);
        CHECK(1160 == conn->PeerMss());
        conn->OnPoll(t0 + 2200000);
        CHECK(1460 == conn->PeerMss());
        std::fprintf(stderr, "[mtu-probe] reduce -> periodic restore -> re-reduce OK\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MTU_PROBE: FAILED (%d)\n" : "MTU_PROBE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_tfo_retransmit.cpp
 * @brief RFC 7413 fast-open retransmit: a lost SYN (with cookie + early
 *        data) is retransmitted WITH its early data - the wire carries the
 *        data again instead of a bare SYN.
 */

#include <xtcp/core/tcp.h>
#include <xtcp/buf/bufref.h>

#include <chrono>
#include <cstdio>
#include <cstring>
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

    struct TxLog {
        std::vector<UInt32> payload_lens;  // bytes after the TCP header
        std::vector<UInt16> flags;
        void Clear() {
            payload_lens.clear();
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
            TcpState::kSynSent, local, remote, iss, 0,
            [&log](xtcp::buf::BufRef&& p) {
                const Byte* d = p.Data();
                log.flags.push_back(static_cast<UInt16>(d[20 + 13] & 0x3F));
                const UInt32 hdr = static_cast<UInt32>(d[20 + 12] >> 4) * 4;
                log.payload_lens.push_back(p.Len() - 20 - hdr);
            });
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        TxLog log;
        auto conn = MakeConn(log);
        conn->SetSynRetries(2);
        conn->SetRto(1000);  // 1 ms RTO

        // Fast-open: the SYN carries early data + a cookie.
        const Byte cookie[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        conn->SetTfoCookie(cookie);
        const char* early = "fastopen-data";
        CHECK(conn->SendSynWithData(reinterpret_cast<const Byte*>(early),
                                    static_cast<UInt32>(std::strlen(early))));
        CHECK(1 == log.payload_lens.size());
        CHECK(static_cast<UInt32>(std::strlen(early)) == log.payload_lens[0]);
        log.Clear();

        // The SYN is lost: the RTO retransmit must carry the data again.
        // Fire at the conn's own deadline (deterministic - the SYN backoff
        // doubles, so a wall-clock call can no-op before the re-armed
        // deadline and the retransmit never fires).
        {
            const UInt64 deadline = conn->NextRetransmitTime();
            CHECK(0 != deadline);
            conn->OnRetransmitTimer(deadline);
        }
        CHECK(1 == log.payload_lens.size());
        if (1 == log.payload_lens.size()) {
            CHECK(static_cast<UInt32>(std::strlen(early)) == log.payload_lens[0]);
            std::fprintf(stderr, "[tfo-retx] retransmitted SYN carries %u data bytes\n",
                         log.payload_lens[0]);
        }

        // A second loss: the next retransmit still carries the data.
        {
            const UInt64 deadline = conn->NextRetransmitTime();
            CHECK(0 != deadline);
            conn->OnRetransmitTimer(deadline);
        }
        CHECK(2 == log.payload_lens.size());
        CHECK(static_cast<UInt32>(std::strlen(early)) == log.payload_lens[1]);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_RETRANSMIT: FAILED (%d)\n" : "TFO_RETRANSMIT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

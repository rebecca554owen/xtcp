/**
 * @file test_nagle.cpp
 * @brief RFC 896 Nagle algorithm: with TCP_NODELAY off, a small segment is
 *        buffered while outstanding (unacknowledged) data exists, and
 *        flushed once the ACK clears the pipeline. With nodelay on, small
 *        segments go out immediately.
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
        void Clear() {
            lens.clear();
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
            });
    }

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
        // 1) Nagle on (default): a small send waits for outstanding data.
        TxLog log;
        auto conn = MakeConn(log);
        Byte mss[1460];
        std::memset(mss, 0x11, sizeof(mss));
        Byte small[100];
        std::memset(small, 0x22, sizeof(small));

        CHECK(conn->SendData(mss, 1460, 1000));   // full segment: goes out
        CHECK(1 == log.lens.size());
        log.Clear();

        // Small send with outstanding data: buffered by Nagle.
        CHECK(conn->SendData(small, 100, 2000));
        CHECK(0 == log.lens.size());              // NOT sent yet
        CHECK(100 == conn->PendingSendBytes());

        // ACK clears the pipeline -> the buffered small segment flushes.
        const std::vector<Byte> ack = BuildAck(0x40000001 + 1460, 0x50000001);
        conn->OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 3000);
        CHECK(0 == conn->PendingSendBytes());
        bool saw_small = false;
        for (UInt32 l : log.lens) {
            if (40 + 100 == l) {
                saw_small = true;
            }
        }
        std::fprintf(stderr, "[nagle] small segment flushed after ACK: %s\n",
                     saw_small ? "yes" : "no");
        CHECK(saw_small);

        // 2) Nodelay on: small segments go out immediately.
        TxLog log2;
        auto conn2 = MakeConn(log2, 0x40001000);
        conn2->SetNodelay(true);
        CHECK(conn2->SendData(mss, 1460, 1000));   // outstanding data
        log2.Clear();
        CHECK(conn2->SendData(small, 100, 2000));  // nodelay: immediate
        CHECK(1 == log2.lens.size());
        std::fprintf(stderr, "[nagle] nodelay sent immediately: yes\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "NAGLE: FAILED (%d)\n" : "NAGLE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

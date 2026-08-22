/**
 * @file test_window_bound.cpp
 * @brief RFC 793 receive-window boundary: segments whose sequence lies
 *        entirely outside the advertised window must be dropped (not
 *        buffered) - otherwise an attacker can exhaust the out-of-order
 *        buffer with window-external data and starve real reassembly.
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

    std::vector<Byte> g_recv;

    std::unique_ptr<xtcp::core::TcpConn> MakeConn(UInt32 iss = 0x50000000, UInt32 irs = 0x60000000) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A010002;
        local.port = 443;
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A010001;
        remote.port = 40000;
        auto conn = std::make_unique<xtcp::core::TcpConn>(
            TcpState::kEstablished, local, remote, iss, irs,
            [](xtcp::buf::BufRef&&) noexcept {});
        conn->SetRecvHandler([](const Byte* d, UInt32 n) {
            g_recv.insert(g_recv.end(), d, d + n);
            return true;
        });
        return conn;
    }

    /** Builds a TCP data segment (no IP header - OnSegment takes raw TCP). */
    std::vector<Byte> BuildSeg(UInt32 seq, const Byte* payload, UInt32 payload_len) {
        std::vector<Byte> seg(20 + payload_len, 0);
        seg[0] = 0x9C; seg[1] = 0x40;   // sport
        seg[2] = 0x01; seg[3] = 0xBB;   // dport
        seg[4] = static_cast<Byte>(seq >> 24); seg[5] = static_cast<Byte>(seq >> 16);
        seg[6] = static_cast<Byte>(seq >> 8);  seg[7] = static_cast<Byte>(seq & 0xFF);
        seg[8] = 0; seg[9] = 0; seg[10] = 0; seg[11] = 0;
        seg[12] = 0x50; seg[13] = 0x18;  // ACK|PSH
        seg[14] = 0xFF; seg[15] = 0xFF;
        if (0 < payload_len) {
            std::memcpy(seg.data() + 20, payload, payload_len);
        }
        return seg;
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        g_recv.clear();
        auto conn = MakeConn();
        const UInt32 rcv_nxt = 0x60000001;  // irs + 1

        // Flood with segments FAR beyond the window (RFC 793: must be
        // dropped, not buffered). Enough to exhaust the ooo buffer if the
        // stack wrongly accepts them.
        Byte junk[1460];
        std::memset(junk, 0xEE, sizeof(junk));
        const UInt32 far_base = rcv_nxt + 200000;
        for (UInt32 i = 0; i < 100; ++i) {
            const std::vector<Byte> far = BuildSeg(far_base + i * 1460, junk, sizeof(junk));
            conn->OnSegment(far.data(), static_cast<UInt32>(far.size()), 1000 + i);
        }
        CHECK(0 == g_recv.size());  // nothing delivered

        // A legitimate in-window out-of-order segment (next expected + 1460).
        const UInt32 ooo_seq = rcv_nxt + 1460;
        Byte data[1460];
        for (UInt32 i = 0; i < sizeof(data); ++i) {
            data[i] = static_cast<Byte>(i & 0xFF);
        }
        const std::vector<Byte> ooo = BuildSeg(ooo_seq, data, sizeof(data));
        conn->OnSegment(ooo.data(), static_cast<UInt32>(ooo.size()), 2000);
        CHECK(0 == g_recv.size());  // out-of-order: buffered, not delivered

        // The in-order head arrives: reassembly must deliver ONLY the
        // in-window data (the flood must not have starved the ooo buffer).
        Byte head[1460];
        for (UInt32 i = 0; i < sizeof(head); ++i) {
            head[i] = static_cast<Byte>(0xA0 + (i & 0x0F));
        }
        const std::vector<Byte> in_order = BuildSeg(rcv_nxt, head, sizeof(head));
        conn->OnSegment(in_order.data(), static_cast<UInt32>(in_order.size()), 3000);
        CHECK(2 * 1460 == g_recv.size());
        CHECK(0 == std::memcmp(g_recv.data(), head, 1460));
        CHECK(0 == std::memcmp(g_recv.data() + 1460, data, 1460));
        std::fprintf(stderr, "[window] flood dropped, in-window reassembly clean\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WINDOW_BOUND: FAILED (%d)\n" : "WINDOW_BOUND: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

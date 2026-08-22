/**
 * @file test_cookie_replay.cpp
 * @brief SYN-cookie replay (RFC 4987, syncookie audit gap 4): replaying the
 *        same cookie ACK twice must NOT create a second connection - the
 *        first rebuild owns the 4-tuple (the replay is a harmless dup-ACK
 *        routed to the live connection). Replay after the connection closes
 *        rebuilds a NEW connection (RFC 793 tuple reuse - inherent to
 *        RFC 4987's statelessness, documented behavior).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            return;
        }
    }
}

static UInt32 ReadSeq(const Byte* pkt) {
    return (static_cast<UInt32>(pkt[24]) << 24) | (static_cast<UInt32>(pkt[25]) << 16) |
           (static_cast<UInt32>(pkt[26]) << 8) | static_cast<UInt32>(pkt[27]);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40200;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9100;
        CHECK(stack_b.Listen(b_local));
        stack_b.SetSyncookieThreshold(1);

        UInt64 accepted[4] = {0, 0, 0, 0};
        UInt32 acc_idx = 0;
        stack_b.SetAcceptHandler([&](UInt64 id, const xtcp::core::Endpoint&,
                                     const xtcp::core::Endpoint&) {
            if (acc_idx < 4) {
                accepted[acc_idx++] = id;
            }
            return true;
        });

        // First legitimate connection pushes the live count past the cookie
        // threshold.
        const UInt64 conn1 = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));
        CHECK(1 == stack_b.ConnectionCount());

        // Crafted SYN (MSS=0 variant) -> stateless SYN+ACK (cookie).
        constexpr UInt32 kSynSeq = 0x22334455;
        std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40201, 9100, kSynSeq, 0, 0x02);
        syn.push_back(2); syn.push_back(4); syn.push_back(0x00); syn.push_back(0x00);  // MSS=0
        syn.push_back(3); syn.push_back(3); syn.push_back(0x07);                        // WSOPT
        syn.push_back(1);
        syn[2] = 0; syn[3] = 48;
        syn[20 + 12] = 0x70;
        xtcp::harness::FillIp4Checksum(syn.data());
        xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20, 28);
        backend_b.Inject(syn.data(), static_cast<UInt32>(syn.size()), 0x0800);
        Byte sa[65536];
        UInt32 n = 0;
        while (0 != backend_b.TxPending()) {
            n = backend_b.PollTx(sa);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 cookie = ReadSeq(sa);
        CHECK(0 != cookie);

        // Cookie ACK completes the rebuild: count 2.
        std::vector<Byte> ack = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40201, 9100, kSynSeq + 1, cookie + 1, 0x10);
        ack[2] = 0; ack[3] = 40;
        xtcp::harness::FillIp4Checksum(ack.data());
        xtcp::harness::FillTcp4Checksum(ack.data(), ack.data() + 20, 20);
        backend_b.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        stack_b.PollAckTimers();
        CHECK(2 == stack_b.ConnectionCount());
        CHECK(1 <= acc_idx);

        // REPLAY the identical cookie ACK: must NOT create a third
        // connection (the flow map routes it to the live rebuild; the dup
        // ACK is a harmless no-op).
        backend_b.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        stack_b.PollAckTimers();
        std::fprintf(stderr, "[cookie-replay] after replay count=%u (expect 2)\n",
                     (UInt32)stack_b.ConnectionCount());
        CHECK(2 == stack_b.ConnectionCount());

        // Replay after the rebuilt connection closes: a NEW connection is
        // rebuilt (RFC 793 tuple reuse - the documented RFC 4987 behavior).
        // Abort (RST) reclaims immediately (Close would wait for the peer's
        // ACK of the FIN; the crafted client never answers). accepted[0] is
        // the real conn1; the cookie rebuild is accepted[1].
        const UInt64 rebuilt = accepted[1];
        CHECK(0 != rebuilt);
        stack_b.Abort(rebuilt);
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        CHECK(1 == stack_b.ConnectionCount());  // only conn1 remains
        backend_b.Inject(ack.data(), static_cast<UInt32>(ack.size()), 0x0800);
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        std::fprintf(stderr, "[cookie-replay] after post-close replay count=%u (expect 2)\n",
                     (UInt32)stack_b.ConnectionCount());
        CHECK(2 == stack_b.ConnectionCount());  // replay rebuilt a fresh conn
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "COOKIE_REPLAY: FAILED (%d)\n" : "COOKIE_REPLAY: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

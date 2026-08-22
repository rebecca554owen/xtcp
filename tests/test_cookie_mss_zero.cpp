/**
 * @file test_cookie_mss_zero.cpp
 * @brief RFC 879 / RFC 1122 s4.2.2.6 in SYN-cookie mode: a client SYN with
 *        an MSS option of 0 - or with NO MSS option - must be treated as
 *        "no usable MSS" (the 536 default). The cookie encodes the MSS
 *        bucket; pre-fix the default bucket was 0 (1460), so a rebuilt
 *        connection sent 1460-byte segments to a 536-byte client while the
 *        stateful path correctly forced 536. Post-fix the default bucket is
 *        the 512 table entry (largest table value <= 536).
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
        a_local.port = 40191;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9105;
        CHECK(stack_b.Listen(b_local));
        // Cookie mode kicks in once one live connection exists.
        stack_b.SetSyncookieThreshold(1);

        std::vector<UInt64> accepted;
        stack_b.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&,
                                             const xtcp::core::Endpoint&) {
            accepted.push_back(id);
            return true;
        });

        // First legitimate connection pushes the live count past the
        // cookie threshold.
        const UInt64 conn1 = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));
        CHECK(1 == stack_b.ConnectionCount());

        // --- Crafted SYN with MSS = 0 (invalid value: treat as absent).
        constexpr UInt32 kSynSeq = 0x11223344;
        std::vector<Byte> syn0 = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40192, 9105, kSynSeq, 0, 0x02);
        syn0.push_back(2); syn0.push_back(4); syn0.push_back(0x00); syn0.push_back(0x00);  // MSS = 0
        syn0.push_back(3); syn0.push_back(3); syn0.push_back(0x07);                        // WSOPT = 7
        syn0.push_back(1);                                                                 // NOP pad
        syn0[2] = 0; syn0[3] = 48;   // 20 IP + 28 TCP
        syn0[20 + 12] = 0x70;        // data offset 7
        xtcp::harness::FillIp4Checksum(syn0.data());
        xtcp::harness::FillTcp4Checksum(syn0.data(), syn0.data() + 20, 28);
        backend_b.Inject(syn0.data(), static_cast<UInt32>(syn0.size()), 0x0800);
        // Stateless SYN+ACK (the cookie): its ISN encodes the MSS bucket.
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
        // Cookie ACK completes the rebuild.
        std::vector<Byte> ack0 = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40192, 9105, kSynSeq + 1, cookie + 1, 0x10);
        ack0[2] = 0; ack0[3] = 40;
        xtcp::harness::FillIp4Checksum(ack0.data());
        xtcp::harness::FillTcp4Checksum(ack0.data(), ack0.data() + 20, 20);
        backend_b.Inject(ack0.data(), static_cast<UInt32>(ack0.size()), 0x0800);
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        CHECK(2 <= accepted.size());
        const UInt16 mss_mss0 = stack_b.ConnPeerMss(accepted[1]);
        std::fprintf(stderr, "[cookie-mss0] MSS=0 rebuilt peer MSS=%u (expect 512)\n", mss_mss0);
        CHECK(512 == mss_mss0);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(accepted[1]));

        // --- Crafted SYN with NO MSS option (absent: same 536 default).
        constexpr UInt32 kSynSeq2 = 0x55667788;
        std::vector<Byte> syn1 = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40193, 9105, kSynSeq2, 0, 0x02);
        xtcp::harness::FillIp4Checksum(syn1.data());
        xtcp::harness::FillTcp4Checksum(syn1.data(), syn1.data() + 20, 20);
        backend_b.Inject(syn1.data(), static_cast<UInt32>(syn1.size()), 0x0800);
        n = 0;
        while (0 != backend_b.TxPending()) {
            n = backend_b.PollTx(sa);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 cookie2 = ReadSeq(sa);
        CHECK(0 != cookie2);
        std::vector<Byte> ack1 = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40193, 9105, kSynSeq2 + 1, cookie2 + 1, 0x10);
        ack1[2] = 0; ack1[3] = 40;
        xtcp::harness::FillIp4Checksum(ack1.data());
        xtcp::harness::FillTcp4Checksum(ack1.data(), ack1.data() + 20, 20);
        backend_b.Inject(ack1.data(), static_cast<UInt32>(ack1.size()), 0x0800);
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        CHECK(3 <= accepted.size());
        const UInt16 mss_none = stack_b.ConnPeerMss(accepted[2]);
        std::fprintf(stderr, "[cookie-mss0] no-MSS rebuilt peer MSS=%u (expect 512)\n", mss_none);
        CHECK(512 == mss_none);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(accepted[2]));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "COOKIE_MSS_ZERO: FAILED (%d)\n" : "COOKIE_MSS_ZERO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

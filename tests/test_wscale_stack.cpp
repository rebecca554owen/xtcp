/**
 * @file test_wscale_stack.cpp
 * @brief Window-scale negotiation end-to-end: a peer advertising WSOPT=7
 *        (Linux default) scales its window by 128; the stack must apply the
 *        shift to the advertised window (snd_wnd_ = window << 7).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack.OnPacket(std::move(buf));
        });
        xtcp::core::Endpoint server;
        server.family = 4;
        server.addr[0] = 0x0A000002;
        server.port = 8080;
        CHECK(stack.Listen(server));
        std::atomic<UInt64> conn_id{0};
        stack.SetAcceptHandler([&conn_id](UInt64 id, const xtcp::core::Endpoint&,
                                          const xtcp::core::Endpoint&) {
            conn_id.store(id, std::memory_order_relaxed);
            return true;
        });

        // SYN with WSOPT = 7 and a 2048-byte advertised window (valid
        // checksums: a zero-checksum SYN is dropped under the checksum-
        // validate build and the handshake never starts).
        std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
            0x0A000001, 0x0A000002, 40000, 8080, 0x10000000, 0, 0x02);
        syn.push_back(2); syn.push_back(4); syn.push_back(0x05); syn.push_back(0xB4);  // MSS 1460
        syn.push_back(3); syn.push_back(3); syn.push_back(0x07); syn.push_back(0);      // WSOPT = 7
        syn[2] = 0; syn[3] = 48;   // IP total length = 48
        syn[20 + 12] = 0x70;       // data offset 7 (28-byte header: MSS + WSOPT)
        syn[34] = 0x08; syn[35] = 0x00;  // window 2048
        xtcp::harness::FillIp4Checksum(syn.data());
        xtcp::harness::FillTcp4Checksum(syn.data(), syn.data() + 20, 28);
        backend.Inject(syn.data(), static_cast<UInt32>(syn.size()), 0x0800);

        // Read the SYN+ACK, then complete the handshake.
        Byte sa[65536];
        const UInt32 sa_len = backend.PollTx(sa);
        CHECK(0 != sa_len);
        const UInt32 iss = (static_cast<UInt32>(sa[24]) << 24) |
                           (static_cast<UInt32>(sa[25]) << 16) |
                           (static_cast<UInt32>(sa[26]) << 8) |
                           static_cast<UInt32>(sa[27]);
        Byte ack[40];
        std::memset(ack, 0, sizeof(ack));
        ack[0] = 0x45;
        ack[2] = 0; ack[3] = 40;
        ack[8] = 64;
        ack[9] = 6;
        ack[12] = 0x0A; ack[13] = 0x00; ack[14] = 0x00; ack[15] = 0x01;
        ack[16] = 0x0A; ack[17] = 0x00; ack[18] = 0x00; ack[19] = 0x02;
        ack[20] = 0x9C; ack[21] = 0x40;
        ack[22] = 0x1F; ack[23] = 0x90;
        ack[24] = 0x10; ack[25] = 0x00; ack[26] = 0x00; ack[27] = 0x01;
        const UInt32 ack_num = iss + 1;
        ack[28] = static_cast<Byte>(ack_num >> 24); ack[29] = static_cast<Byte>(ack_num >> 16);
        ack[30] = static_cast<Byte>(ack_num >> 8);  ack[31] = static_cast<Byte>(ack_num & 0xFF);
        ack[32] = 0x50; ack[33] = 0x10;
        ack[34] = 0xFF; ack[35] = 0xFF;
        // Handshake-completion ACK needs valid checksums too.
        xtcp::harness::FillIp4Checksum(ack);
        xtcp::harness::FillTcp4Checksum(ack, ack + 20, 20);
        backend.Inject(ack, sizeof(ack), 0x0800);
        stack.PollAckTimers();

        // The connection is ESTABLISHED with the peer's window scaled.
        CHECK(1 == stack.ConnectionCount());
        CHECK(0 != conn_id.load(std::memory_order_relaxed));

        // The peer's SYN advertised window 2048 with WSOPT=7: the effective
        // send window is 2048 << 7 = 262144 bytes.
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        stack.ConnStats(conn_id.load(std::memory_order_relaxed), inflight, cwnd, ssthresh,
                        snd_wnd, retx, rto_deadline, dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[wscale] snd_wnd=%u (expect 8388480 = 65535 << 7)\n", snd_wnd);
        // The handshake-completion ACK advertises window 65535 (the raw
        // field, lines 84-85), which supersedes the SYN's 2048 under the
        // SND.WL rule; the effective send window is 65535 << 7 = 8388480.
        // The exact value pins the scale: an off-by-one shift (<<6 or <<8)
        // must fail.
        CHECK(8388480 == snd_wnd);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WSCALE_STACK: FAILED (%d)\n" : "WSCALE_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_synrst_closedport.cpp
 * @brief RFC 793 connection refused: a SYN sent to a port with no listener
 *        (and no matching flow) must be answered with an RST. The fix is
 *        landed (SendClosedPortRst on the SYN receive path, stack.cpp:1337);
 *        this test verifies the post-fix behavior: an RST is answered and no
 *        connection state is created.
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

// RFC 1071: one's-complement checksum (same arithmetic as the stack's).
static UInt16 Checksum(const Byte* p, UInt32 len) {
    UInt32 sum = 0;
    for (UInt32 i = 0; i + 1 < len; i += 2) {
        sum += (static_cast<UInt32>(p[i]) << 8) | p[i + 1];
    }
    if (len & 1) {
        sum += static_cast<UInt32>(p[len - 1]) << 8;
    }
    while (0 != (sum >> 16)) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<UInt16>(~sum & 0xFFFF);
}

/** Builds a raw IPv4 SYN toward the given (unlistened) destination port.
 *  Valid checksums: the closed-port path must still answer the SYN under
 *  the checksum-validate build. */
static UInt32 BuildSyn(Byte* out, UInt16 sport, UInt16 dport, UInt32 seq) {
    std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
        0x0A000001, 0x0A000002, sport, dport, seq, 0, 0x02);
    std::memcpy(out, syn.data(), syn.size());
    return static_cast<UInt32>(syn.size());
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a;
        xtcp::XtcpStack stack_a(&backend_a);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });

        // No listener on stack_a. A SYN to a closed port must be refused.
        const UInt32 kSynSeq = 0x10000000;
        Byte syn[256];
        const UInt32 syn_len = BuildSyn(syn, 40001, 9090, kSynSeq);
        backend_a.Inject(syn, syn_len, 0x0800);

        // Drain stack_a's tx: RFC 793 requires an RST in reply.
        Byte out[65536];
        UInt32 rsts = 0;
        UInt32 ack_of_rst = 0;
        bool rst_has_ack = false;
        bool ip_cksum_ok = true;
        bool tcp_cksum_ok = true;
        while (0 != backend_a.TxPending()) {
            const UInt32 got = backend_a.PollTx(out);
            if (got < 40) {
                continue;
            }
            const Byte flags = out[33];
            if (0 != (flags & 0x04)) {
                ++rsts;
                rst_has_ack = (0 != (flags & 0x10));
                ack_of_rst = (static_cast<UInt32>(out[28]) << 24) |
                             (static_cast<UInt32>(out[29]) << 16) |
                             (static_cast<UInt32>(out[30]) << 8) |
                             static_cast<UInt32>(out[31]);
                // Bug-fix verification: the RST must carry a valid IPv4
                // header checksum AND a valid TCP checksum (pseudo header
                // + TCP header; a real OS drops a zero-checksum RST).
                ip_cksum_ok = (0 == Checksum(out, 20));
                Byte pseudo[32];
                std::memcpy(pseudo, out + 12, 8);          // src IP, dst IP
                pseudo[8] = 0;
                pseudo[9] = 6;                             // TCP
                pseudo[10] = 0;
                pseudo[11] = 20;                           // TCP len (no payload)
                std::memcpy(pseudo + 12, out + 20, 20);    // TCP header
                tcp_cksum_ok = (0 == Checksum(pseudo, 32));
            }
        }
        std::fprintf(stderr, "[synrst-closedport] rsts=%u conns=%u ip_cksum=%d tcp_cksum=%d\n",
                     rsts, (UInt32)stack_a.ConnectionCount(), (int)ip_cksum_ok, (int)tcp_cksum_ok);

        // Expected post-fix behavior: exactly one RST (RFC 793 connection
        // refused), acknowledging the SYN (ack == syn seq + 1), and no
        // connection state was created. The RST must also be well-formed
        // (valid IP + TCP checksums) so a real OS accepts it.
        CHECK(1 == rsts);
        CHECK(rst_has_ack);
        CHECK(kSynSeq + 1 == ack_of_rst);
        CHECK(0 == stack_a.ConnectionCount());
        CHECK(ip_cksum_ok);
        CHECK(tcp_cksum_ok);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYNRST_CLOSEDPORT: FAILED (%d)\n" : "SYNRST_CLOSEDPORT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

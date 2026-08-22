/**
 * @file test_rst_closing.cpp
 * @brief RFC 793: an RST received while the connection is in a closing state
 *        (FIN-WAIT-2 here) closes it immediately rather than waiting for the
 *        peer's FIN or a timer - the sender gives up on the peer.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

static UInt32 g_iss_b = 0;  // peer (B) ISS, sniffed from the SYN+ACK

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

static void InjectRst(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port, UInt32 seq) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[9] = 6;
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = static_cast<Byte>(seq >> 24); tcp[5] = static_cast<Byte>(seq >> 16);
    tcp[6] = static_cast<Byte>(seq >> 8);  tcp[7] = static_cast<Byte>(seq & 0xFF);
    tcp[12] = 0x50; tcp[13] = 0x04;          // RST
    // Valid checksums so the RST is honored under the checksum-validate
    // build too (a zero-checksum RST is dropped there).
    {
        UInt32 sum = 0;
        for (UInt32 i = 0; i < 20; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(pkt[i]) << 8) | pkt[i + 1]);
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        pkt[10] = static_cast<Byte>(~(sum & 0xFFFF) >> 8);
        pkt[11] = static_cast<Byte>(~sum & 0xFF);
    }
    {
        UInt32 sum = 0;
        const Byte pseudo[12] = {
            pkt[12], pkt[13], pkt[14], pkt[15],
            pkt[16], pkt[17], pkt[18], pkt[19],
            0, 6, 0x00, 0x14,
        };
        for (UInt32 i = 0; i < 12; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(pseudo[i]) << 8) | pseudo[i + 1]);
        }
        for (UInt32 i = 0; i < 20; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(tcp[i]) << 8) | tcp[i + 1]);
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        pkt[36] = static_cast<Byte>(~(sum & 0xFFFF) >> 8);
        pkt[37] = static_cast<Byte>(~sum & 0xFF);
    }
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
    victim.OnPacket(std::move(buf));
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                g_iss_b = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
            }
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40171;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9105;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // A closes; B ACKs the FIN and enters CLOSE-WAIT but never sends its
        // own FIN, leaving A in FIN-WAIT-2.
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[rst-closing] before RST A=%d\n",
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn));

        // An RST while closing aborts immediately (RFC 5961: seq == rcv_nxt_
        // is in-window and honored). The valid seq is the peer's current send
        // seq = B's ISS + 1 == A's rcv_nxt_ (sniffed from the SYN+ACK).
        CHECK(0 != g_iss_b);
        InjectRst(stack_a, 0x0A000002, 0x0A000001, 9105, 40171, g_iss_b + 1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState after = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[rst-closing] after RST A=%d\n", (int)after);
        CHECK(xtcp::core::TcpState::kClosed == after);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_CLOSING: FAILED (%d)\n" : "RST_CLOSING: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

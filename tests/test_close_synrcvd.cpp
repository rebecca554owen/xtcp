/**
 * @file test_close_synrcvd.cpp
 * @brief RFC 793 s3.8: Close() while the connection is in SYN-RECEIVED is
 *        an ABORT - the stack must send RST (seq = SND.NXT) and enter
 *        CLOSED. Pre-fix the close sent a FIN, which is dead on arrival: a
 *        peer still in SYN-SENT only processes SYN/SYN+ACK/RST, so both
 *        sides retransmitted for minutes before converging. The peer here
 *        observes the RST and closes immediately.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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

static UInt32 TcpFlags(const Byte* pkt) {
    return pkt[20 + 13];
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

        UInt64 accepted = 0;
        UInt32 closed_notify = 0;
        stack_b.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&,
                                             const xtcp::core::Endpoint&) {
            accepted = id;
            return true;
        });
        stack_b.SetStateHandler([&closed_notify](UInt64, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kClosed == st) {
                ++closed_notify;
            }
        });

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40181;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9090;
        CHECK(stack_b.Listen(b_local));

        // A sends its SYN; deliver it to B ONLY (B's connection is born in
        // SYN-RECEIVED; B's SYN+ACK stays in the backend queue).
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Byte syn[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(syn);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        backend_b.Inject(syn, n, 0x0800);
        Byte synack[65536];
        while (0 != backend_b.TxPending()) {
            n = backend_b.PollTx(synack);  // discard B's SYN+ACK, keep B in SYN-RECEIVED
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != accepted);
        CHECK(xtcp::core::TcpState::kSynRcvd == stack_b.ConnectionState(accepted));

        // The close in SYN-RECEIVED must emit a RST (0x14 = RST|ACK), not a
        // FIN (0x11).
        stack_b.Close(accepted);
        Byte rst[65536];
        n = 0;
        while (0 != backend_b.TxPending()) {
            n = backend_b.PollTx(rst);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 flags = TcpFlags(rst);
        std::fprintf(stderr, "[close-synrcvd] B tx flags=0x%02x (expect RST|ACK 0x14)\n", flags);
        CHECK(0 != (flags & 0x04));             // RST bit set
        CHECK(0 == (flags & 0x01));             // no FIN
        CHECK(1 == closed_notify);              // the app saw the close

        // The peer (SYN-SENT) accepts the RST (its ACK is acceptable) and
        // closes immediately - no minutes of FIN retransmissions.
        backend_a.Inject(rst, n, 0x0800);
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        std::fprintf(stderr, "[close-synrcvd] A state=%d (expect %d closed)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a)),
                     static_cast<int>(xtcp::core::TcpState::kClosed));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn_a));

        // B's side is fully reclaimed.
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSE_SYNRCVD: FAILED (%d)\n" : "CLOSE_SYNRCVD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_ecn_bidi.cpp
 * @brief RFC 3168 ECN bidirectional negotiation: the server side
 *        (SynRcvd->Established) must also set ecn_active_, so data the
 *        server sends back to the client is ECN-marked. Data segments are
 *        marked with ECT(0) in the IP header (RFC 3168) - never ECE, which
 *        is reserved for ACKs (congestion reporting). The client side alone
 *        setting ecn_active_ (tcp_fsm.cpp kSynSent) is not enough - without
 *        the server-side flag, B->A data segments are emitted without ECT
 *        (FlushPendingSend/SendData gate on ecn_active_).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    // backend_a's RxHandler sees B->A traffic (the Pump injects stack_b's
    // tx into backend_a). 0x40 = ECE flag on the wire (byte 13 of TCP);
    // ECT(0) = 0b10 in IP byte 1 low 2 bits.
    std::atomic<UInt32> g_b_to_a_ect{0};   // B->A data segments with ECT(0) in IP header
    std::atomic<UInt32> g_b_to_a_ece{0};   // B->A data segments wrongly carrying ECE
    std::atomic<UInt32> g_ack_ece{0};      // pure ACK segments with ECE
    std::atomic<bool> g_synack_ece{false}; // B's SYN+ACK carried ECE (server agreed)
    std::atomic<bool> g_syn_ece{false};    // A's SYN carried ECE (client requested)
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 500; ++round) {
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

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            // B->A direction: observe the server's SYN+ACK and data segments.
            if (p.len > 33) {
                const Byte flags = p.data[33];
                // SYN+ACK from B must echo the ECE offer.
                if (0 != (flags & 0x12) && 0 != (flags & 0x40)) {
                    g_synack_ece.store(true, std::memory_order_relaxed);
                }
                // B->A data segments carry ECT(0) in the IP header (byte 1
                // low 2 bits = 0b10), never ECE (RFC 3168 data marking).
                if (0 != (flags & 0x08)) {
                    if (0x02 == (p.data[1] & 0x03)) {
                        g_b_to_a_ect.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (0 != (flags & 0x40)) {
                        g_b_to_a_ece.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            // A->B direction: the client's SYN must request ECN, and the
            // handshake-completion ACK carries ECE (congestion report lives
            // on ACKs, not data segments).
            if (p.len > 33) {
                const Byte flags = p.data[33];
                if (0 != (flags & 0x02) && 0 != (flags & 0x40)) {
                    g_syn_ece.store(true, std::memory_order_relaxed);
                }
                if (0 == (flags & 0x02) && 0 == (flags & 0x08) && 0 == (flags & 0x01) &&
                    0 != (flags & 0x10) && 0 != (flags & 0x40)) {
                    g_ack_ece.fetch_add(1, std::memory_order_relaxed);  // pure ACK with ECE
                }
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        std::string received;
        stack_a.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40010;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8090;
        // Both sides request ECN before the handshake (stack-wide default
        // applied at connection creation). A is the client (Connect); B is
        // the server (Listen) and must ALSO end up ECN-active.
        stack_a.SetDefaultEcn(true);
        stack_b.SetDefaultEcn(true);
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);

        // Handshake ECE negotiation happened in both directions.
        std::fprintf(stderr, "[ecn-bidi] SYN-ECE=%s SYNACK-ECE=%s\n",
                     g_syn_ece.load() ? "yes" : "no", g_synack_ece.load() ? "yes" : "no");
        CHECK(g_syn_ece.load());
        CHECK(g_synack_ece.load());

        // The server sends data back to the client; every data segment must
        // carry ECT(0) in the IP header (server-side ecn_active_ after the
        // fix) - never ECE.
        std::string payload(16384, 'R');
        UInt32 sent = 0;
        while (sent < payload.size()) {
            const UInt32 chunk = static_cast<UInt32>(payload.size()) - sent;
            if (stack_b.Send(conn_b, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 200 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "[ecn-bidi] B->A data ECT segments=%u B->A data ECE violations=%u ACK ECE segments=%u\n",
                     g_b_to_a_ect.load(std::memory_order_relaxed),
                     g_b_to_a_ece.load(std::memory_order_relaxed),
                     g_ack_ece.load(std::memory_order_relaxed));
        CHECK(0 < g_b_to_a_ect.load(std::memory_order_relaxed));
        CHECK(0 == g_b_to_a_ece.load(std::memory_order_relaxed));
        CHECK(0 < g_ack_ece.load(std::memory_order_relaxed));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ECN-BIDI: FAILED (%d)\n" : "ECN-BIDI: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

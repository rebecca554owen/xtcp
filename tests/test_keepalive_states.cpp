/**
 * @file test_keepalive_states.cpp
 * @brief Keepalive state gating (keepalive audit gap 1): the probes must
 *        run ONLY in ESTABLISHED. In SYN_SENT / CLOSE-WAIT / FIN-WAIT-2 /
 *        TIME-WAIT a configured keepalive must never emit a probe and never
 *        abort the connection - SYN retransmits (SYN flag) are the only
 *        segments allowed from the SYN_SENT side.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

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

// Drains a backend's tx; returns true when a NON-SYN pure segment was
// emitted (a keepalive probe is an ACK with seq = snd_nxt_-1; a SYN
// retransmit carries the SYN flag).
static bool DrainHasProbe(xtcp::ndi::ManualBackend& be, bool) {
    Byte out[65536];
    bool probe = false;
    while (0 != be.TxPending()) {
        const UInt32 n = be.PollTx(out);
        if (0 == n) {
            continue;
        }
        const Byte flags = out[20 + 13];
        if (0 == (flags & 0x02)) {  // no SYN flag: any other segment
            probe = true;
        }
    }
    return probe;
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
        a_local.port = 40198;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9098;
        CHECK(stack_b.Listen(b_local));
        // Capture B's accepted conn id BEFORE the handshake (the accept
        // handler fires during SYN processing).
        UInt64 conn_b = 0;
        stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            conn_b = id;
            return true;
        });

        // (1) SYN_SENT: keepalive armed on A; the handshake never completes
        // (B's SYN+ACK is withheld). A must only emit SYN retransmits -
        // never keepalive probes.
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        stack_a.SetKeepalive(conn_a, 100000, 100000, 3);  // 100 ms idle/intvl
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
        while (0 != backend_b.TxPending()) {  // withhold B's SYN+ACK from A
            n = backend_b.PollTx(synack);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        stack_a.PollAckTimers();
        const bool probe_synsent = DrainHasProbe(backend_a, true);
        std::fprintf(stderr, "[keepalive-states] SYN_SENT: probe=%d (expect 0)\n", probe_synsent ? 1 : 0);
        CHECK(!probe_synsent);
        CHECK(xtcp::core::TcpState::kSynSent == stack_a.ConnectionState(conn_a));

        // Complete the handshake for the closing-state scenarios.
        backend_a.Inject(synack, n, 0x0800);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);
        stack_b.SetKeepalive(conn_b, 100000, 100000, 3);

        // (2) CLOSE-WAIT / FIN-WAIT-2: A closed first, so A waits in
        // FIN-WAIT-2 for B's FIN while B sits in CLOSE-WAIT (both armed with
        // keepalive). Neither side may probe.
        stack_a.Close(conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kCloseWait == stack_b.ConnectionState(conn_b));
        CHECK(xtcp::core::TcpState::kFinWait2 == stack_a.ConnectionState(conn_a));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        const bool probe_closewait = DrainHasProbe(backend_b, false);
        const bool probe_finwait = DrainHasProbe(backend_a, false);
        std::fprintf(stderr, "[keepalive-states] CLOSE-WAIT probe=%d / FW2 probe=%d (expect 0/0)\n",
                     probe_closewait ? 1 : 0, probe_finwait ? 1 : 0);
        CHECK(!probe_closewait);
        CHECK(!probe_finwait);

        // (3) B closes: B -> LAST-ACK; A's TIME-WAIT re-ACK completes the
        // close (B -> CLOSED). No keepalive interference anywhere.
        stack_b.Close(conn_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState st_b = stack_b.ConnectionState(conn_b);
        const xtcp::core::TcpState st_a = stack_a.ConnectionState(conn_a);
        std::fprintf(stderr, "[keepalive-states] B=%d A=%d after close (expect B closed/lastack, A timewait)\n",
                     static_cast<int>(st_b), static_cast<int>(st_a));
        CHECK((xtcp::core::TcpState::kLastAck == st_b || xtcp::core::TcpState::kClosed == st_b));
        CHECK(xtcp::core::TcpState::kTimeWait == st_a);

        // (4) TIME-WAIT: A in TIME-WAIT with keepalive armed; 2MSL must not
        // be disturbed by probes.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        stack_a.PollAckTimers();
        const bool probe_tw = DrainHasProbe(backend_a, false);
        std::fprintf(stderr, "[keepalive-states] TIME-WAIT: probe=%d (expect 0)\n", probe_tw ? 1 : 0);
        CHECK(!probe_tw);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_STATES: FAILED (%d)\n" : "KEEPALIVE_STATES: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_finwait2.cpp
 * @brief FIN-WAIT-2 reclamation (Linux tcp_fin_timeout): after the local
 *        side closes, a peer that ACKs the FIN but never sends its own FIN
 *        holds the connection in FIN-WAIT-2; the connection is reclaimed
 *        once the configured timeout elapses.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
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

struct Harness {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a;
    xtcp::XtcpStack stack_b;
    UInt64 conn = 0;

    Harness() : stack_a(&backend_a), stack_b(&backend_b) {
        backend_a.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
    }

    void Pump(UInt32 rounds = 1000) {
        Byte out[65536];
        for (UInt32 round = 0; round < rounds; ++round) {
            bool moved = false;
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    backend_b.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (!moved) {
                return;
            }
        }
    }

    void PumpFor(UInt32 ms) {
        for (UInt32 i = 0; i < ms; i += 5) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            Pump();
        }
        Pump();
    }
};

int main() {
    xtcp::buf::InitPools();
    {
        Harness h;
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40041;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9092;
        CHECK(h.stack_b.Listen(remote));
        h.conn = h.stack_a.Connect(local, remote);
        CHECK(0 != h.conn);
        h.Pump();
        CHECK(xtcp::core::TcpState::kEstablished == h.stack_a.ConnectionState(h.conn));

        // B never closes: after the FIN it stays in CLOSE-WAIT and never
        // sends its own FIN, leaving A in FIN-WAIT-2.
        h.stack_a.SetFinWait2Timeout(h.conn, 100000);  // 100 ms
        h.stack_a.Close(h.conn);
        h.Pump();
        CHECK(xtcp::core::TcpState::kFinWait2 == h.stack_a.ConnectionState(h.conn));

        // Pump must comfortably exceed the 100 ms FIN-WAIT-2 timeout so the
        // reclamation (tcp_fsm.cpp OnPoll: finwait2_deadline_ <= now) fires.
        h.PumpFor(200);
        std::fprintf(stderr, "[finwait2] after timeout: A=%d\n",
                     (int)h.stack_a.ConnectionState(h.conn));
        CHECK(xtcp::core::TcpState::kClosed == h.stack_a.ConnectionState(h.conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FINWAIT2: FAILED (%d)\n" : "FINWAIT2: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

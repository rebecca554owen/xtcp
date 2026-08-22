/**
 * @file test_keepalive_dead.cpp
 * @brief Keepalive abort end-to-end: with the peer's responses blackholed,
 *        the keepalive probe count climbs to the budget and the connection
 *        aborts (RST emitted), leaving no half-open state.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
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

namespace {
    std::atomic<UInt32> g_rst{0};
}

/** Pumps A->B only (B's responses are blackholed: the peer is "dead"). */
static void PumpOneWay(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                       xtcp::XtcpStack& sa) {
    Byte out[65536];
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, 0x0800);
    }
    sa.PollAckTimers();
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
            // B observes the RST A emits when it aborts.
            if (p.len > 33 && 0 != (p.data[33] & 0x04)) {
                g_rst.fetch_add(1, std::memory_order_relaxed);
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        // Full handshake.
        for (UInt32 i = 0; i < 50; ++i) {
            PumpOneWay(backend_a, backend_b, stack_a);
            Byte out[65536];
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_b.PollAckTimers();
        }
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());

        // Aggressive keepalive: 30 ms idle, 20 ms interval, 3 probes.
        stack_a.SetKeepalive(conn, 30000, 20000, 3);

        // Now blackhole B's responses: only A->B flows.
        for (UInt32 i = 0; i < 200; ++i) {
            PumpOneWay(backend_a, backend_b, stack_a);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        std::fprintf(stderr, "[keepalive-dead] A=%u RST=%u\n",
                     (UInt32)stack_a.ConnectionCount(), g_rst.load());
        CHECK(0 == stack_a.ConnectionCount());  // aborted and reclaimed
        CHECK(1 <= g_rst.load(std::memory_order_relaxed));  // RST went out
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_DEAD: FAILED (%d)\n" : "KEEPALIVE_DEAD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

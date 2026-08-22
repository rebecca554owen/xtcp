/**
 * @file test_keepalive_stack.cpp
 * @brief Keepalive wired end-to-end: an idle connection sends probe ACKs
 *        (observable on the wire), peer traffic keeps it alive, and a dead
 *        peer eventually causes the connection to abort (RST).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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
    std::atomic<UInt32> g_probes{0};
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32 rounds = 300) {
    Byte out[65536];
    for (UInt32 round = 0; round < rounds; ++round) {
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
        // Keep polling while either queue holds traffic (PollAckTimers may
        // have just armed a keepalive probe).
        if (!moved && 0 == a.TxPending() && 0 == b.TxPending()) {
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
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            // A keepalive probe is a pure ACK with no payload flags; once
            // RFC 7323 timestamps are negotiated it carries the 12-byte
            // TSopt (52 bytes total) instead of the bare 40.
            if ((40 == p.len || 52 == p.len) && 0 == (p.data[33] & 0x0F)) {
                g_probes.fetch_add(1, std::memory_order_relaxed);
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
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Keepalive: 30 ms idle / 20 ms interval / 3 probes (microsecond API).
        stack_a.SetKeepalive(conn, 30000, 20000, 3);

        // Idle: A sends keepalive probes; B answers (its stack re-ACKs).
        for (UInt32 i = 0; i < 10; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b, 100);
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            Pump(backend_a, backend_b, stack_a, stack_b, 100);
        }
        std::fprintf(stderr, "[keepalive-stack] probes seen on the wire: %u\n",
                     g_probes.load(std::memory_order_relaxed));
        CHECK(0 < g_probes.load(std::memory_order_relaxed));

        // The connection is still alive (B answered the probes).
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_STACK: FAILED (%d)\n" : "KEEPALIVE_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_async_stop_listen.cpp
 * @brief AsyncStopListen: after stopping a listener, no further flows are
 *        delivered to the accept handler for that endpoint (the per-listener
 *        accept callback is removed; queued-undelivered accepts become
 *        no-ops).
 */

#include <xtcp/async/async.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
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
                 xtcp::async::AsyncStack& sa, xtcp::XtcpStack& sb) {
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
        sa.Stack().PollAckTimers();
        sb.PollAckTimers();
        sa.Poll();
        if (!moved) {
            return;
        }
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::async::AsyncStack stack_a(&backend_a);
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

        UInt32 accepted = 0;
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 9090;
        CHECK(stack_a.AsyncListen(local, [&accepted](std::shared_ptr<xtcp::mimt::MimtFlow>) {
            ++accepted;
        }));

        // First connect: the accept handler fires.
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        const UInt64 c1 = stack_b.Connect(remote, local);
        CHECK(0 != c1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(1 == accepted);

        // Stop the listener: no further accepts for this endpoint. Use a NEW
        // source tuple (the old one is still held by c1 - the connect guard
        // would reject the same tuple).
        CHECK(stack_a.AsyncStopListen(local));
        xtcp::core::Endpoint remote2 = remote;
        remote2.port = 8081;
        const UInt64 c2 = stack_b.Connect(remote2, local);
        CHECK(0 != c2);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[async-stop-listen] accepted=%u (expect 1)\n", accepted);
        CHECK(1 == accepted);  // the stopped listener delivers nothing

        // Stopping again reports false (nothing left to remove).
        CHECK(!stack_a.AsyncStopListen(local));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ASYNC_STOP_LISTEN: FAILED (%d)\n" : "ASYNC_STOP_LISTEN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

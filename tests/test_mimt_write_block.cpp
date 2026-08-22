/**
 * @file test_mimt_write_block.cpp
 * @brief MIMT write blocking contract: when the write sink returns false
 *        (busy or gone), DispatchWrite must complete every queued write
 *        callback exactly once with an error result (kWouldBlock) and clear
 *        the queue. It must NOT probe the sink forever (infinite retry) nor
 *        strand any accepted write. Core assertions: every callback fires
 *        exactly once and dispatch always terminates (no hang).
 *
 * Fixed behavior under test (mimt.cpp:142-150): sink failure cancels the
 * remaining queue with kWouldBlock instead of break-and-wait-forever.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

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

// Stack-level audit-mode handshake (test_mimt_stack.cpp framework): B runs
// in audit mode, the accepted flow is delivered to the test. Returns the
// delivered flow (nullptr when the handshake/flow delivery fails).
static std::shared_ptr<xtcp::mimt::MimtFlow> EstablishAuditFlow(
    xtcp::ndi::ManualBackend& backend_a, xtcp::ndi::ManualBackend& backend_b,
    xtcp::XtcpStack& stack_a, xtcp::XtcpStack& stack_b, UInt16 client_port) {
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

    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    stack_b.StartMimt([&flow](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
        flow = f;
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8082;
    if (!stack_b.Listen(remote)) {
        return flow;
    }
    local.port = client_port;
    if (0 == stack_a.Connect(local, remote)) {
        return flow;
    }

    for (UInt32 r = 0; r < 200 && !flow; ++r) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_b.DispatchMimt();
        stack_a.DispatchMimt();
    }
    return flow;
}

// Scenario 1 (user spec): busy sink (always returns false), a single queued
// write. Dispatch must fire the callback exactly once with kWouldBlock and
// must probe the sink only once (no infinite retry); a second dispatch is a
// no-op (no double-fire, no hang).
static void TestBusySinkSingleWrite() {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    std::shared_ptr<xtcp::mimt::MimtFlow> flow =
        EstablishAuditFlow(backend_a, backend_b, stack_a, stack_b, 30010);
    CHECK(flow);

    UInt32 sink_calls = 0;
    flow->SetWriteSink([&sink_calls](const Byte*, UInt32) {
        ++sink_calls;
        return false;  // sink permanently busy
    });

    const Byte payload[] = { 'x', 't', 'c', 'p' };
    UInt32 write_fires = 0;
    xtcp::mimt::Result write_ec = xtcp::mimt::Result::kOk;
    UInt32 write_bytes = 1;
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncWrite(
        payload, sizeof(payload),
        [&](xtcp::mimt::Result ec, UInt32 n) {
            ++write_fires;
            write_ec = ec;
            write_bytes = n;
        }));

    // No completion fires before dispatch (async dispatch guarantee).
    CHECK(0 == write_fires);
    CHECK(0 == sink_calls);

    // Dispatch: the busy sink forces the completion on the first dispatch.
    CHECK(1 == stack_b.DispatchMimt());
    CHECK(1 == write_fires);                       // exactly once
    CHECK(xtcp::mimt::Result::kWouldBlock == write_ec);
    CHECK(0 == write_bytes);
    CHECK(1 == sink_calls);                        // probed once: no retry loop

    // Queue cleared: a further dispatch has nothing to do and re-probes nothing.
    CHECK(0 == stack_b.DispatchMimt());
    CHECK(1 == write_fires);
    CHECK(1 == sink_calls);
}

// Scenario 2: several writes queued behind a busy sink. The fixed
// DispatchWrite clears the WHOLE queue: every callback fires exactly once
// with kWouldBlock and the sink is still probed only once.
static void TestBusySinkDrainsQueue() {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    std::shared_ptr<xtcp::mimt::MimtFlow> flow =
        EstablishAuditFlow(backend_a, backend_b, stack_a, stack_b, 30011);
    CHECK(flow);

    UInt32 sink_calls = 0;
    flow->SetWriteSink([&sink_calls](const Byte*, UInt32) {
        ++sink_calls;
        return false;
    });

    const Byte payload[] = { 'x', 't', 'c', 'p' };
    constexpr UInt32 kCount = 3;
    UInt32 write_fires[kCount] = { 0, 0, 0 };
    xtcp::mimt::Result write_ec[kCount] = { xtcp::mimt::Result::kOk,
                                            xtcp::mimt::Result::kOk,
                                            xtcp::mimt::Result::kOk };
    UInt32 write_bytes[kCount] = { 1, 1, 1 };
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(xtcp::mimt::Result::kOk == flow->AsyncWrite(
            payload, sizeof(payload),
            [&, i](xtcp::mimt::Result ec, UInt32 n) {
                ++write_fires[i];
                write_ec[i] = ec;
                write_bytes[i] = n;
            }));
    }
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(0 == write_fires[i]);
    }

    // Dispatch() counts fired subsystems (read/write/close), not callbacks:
    // one subsystem (write) fires, so DispatchMimt returns 1 even though all
    // kCount callbacks complete. Per-index fire counts prove the exact once.
    CHECK(1 == stack_b.DispatchMimt());
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(1 == write_fires[i]);                 // exactly once each
        CHECK(xtcp::mimt::Result::kWouldBlock == write_ec[i]);
        CHECK(0 == write_bytes[i]);
    }
    CHECK(1 == sink_calls);                         // no per-write retry

    CHECK(0 == stack_b.DispatchMimt());
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(1 == write_fires[i]);
    }
}

// Scenario 3: the sink accepts the first write, then goes busy. The first
// callback completes with kOk (bytes delivered), the remaining queued writes
// complete exactly once with kWouldBlock and the queue is cleared.
static void TestPartialProgressThenBlocked() {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    std::shared_ptr<xtcp::mimt::MimtFlow> flow =
        EstablishAuditFlow(backend_a, backend_b, stack_a, stack_b, 30012);
    CHECK(flow);

    UInt32 sink_calls = 0;
    flow->SetWriteSink([&sink_calls](const Byte*, UInt32) {
        return (0 == sink_calls++);  // first probe accepted, then busy
    });

    const Byte payload[] = { 'x', 't', 'c', 'p' };
    constexpr UInt32 kCount = 3;
    UInt32 write_fires[kCount] = { 0, 0, 0 };
    xtcp::mimt::Result write_ec[kCount] = { xtcp::mimt::Result::kOk,
                                            xtcp::mimt::Result::kOk,
                                            xtcp::mimt::Result::kOk };
    UInt32 write_bytes[kCount] = { 1, 1, 1 };
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(xtcp::mimt::Result::kOk == flow->AsyncWrite(
            payload, sizeof(payload),
            [&, i](xtcp::mimt::Result ec, UInt32 n) {
                ++write_fires[i];
                write_ec[i] = ec;
                write_bytes[i] = n;
            }));
    }

    // Same as scenario 2: DispatchMimt returns 1 (write subsystem fired),
    // while the per-index counts verify every callback completed once.
    CHECK(1 == stack_b.DispatchMimt());
    CHECK(1 == write_fires[0]);                     // delivered exactly once
    CHECK(xtcp::mimt::Result::kOk == write_ec[0]);
    CHECK(sizeof(payload) == write_bytes[0]);
    for (UInt32 i = 1; i < kCount; ++i) {
        CHECK(1 == write_fires[i]);                 // cancelled exactly once
        CHECK(xtcp::mimt::Result::kWouldBlock == write_ec[i]);
        CHECK(0 == write_bytes[i]);
    }
    CHECK(2 == sink_calls);                         // accepted probe + busy probe

    CHECK(0 == stack_b.DispatchMimt());
    for (UInt32 i = 0; i < kCount; ++i) {
        CHECK(1 == write_fires[i]);
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        TestBusySinkSingleWrite();
        TestBusySinkDrainsQueue();
        TestPartialProgressThenBlocked();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_WRITE_BLOCK: FAILED (%d)\n"
                                    : "MIMT_WRITE_BLOCK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_mimt_close_cb.cpp
 * @brief MIMT 1:1 close contract: when a flow is closed (AsyncClose), every
 *        pending AsyncRead/AsyncWrite callback must complete exactly once.
 *        The fixed DispatchClose completes the pending read with kClosed;
 *        no callback may ever be stranded (0 fires) or double-fired (2+).
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

static void TestPendingReadClosedOnAsyncClose() {
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

    // B runs in audit mode: the accepted flow is delivered to the test.
    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    stack_b.StartMimt([&flow](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
        flow = f;
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8080;
    CHECK(stack_b.Listen(remote));
    local.port = 30000;
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    // Drive the handshake until the audit flow is delivered.
    for (UInt32 r = 0; r < 200 && !flow; ++r) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_b.DispatchMimt();
        stack_a.DispatchMimt();
    }
    CHECK(flow);

    // Initiate a read that can never get data, then close immediately.
    Byte buf[64];
    UInt32 read_fires = 0;
    xtcp::mimt::Result read_ec = xtcp::mimt::Result::kOk;
    UInt32 read_bytes = 1;
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncRead(
        buf, sizeof(buf),
        [&](xtcp::mimt::Result ec, UInt32 n) {
            ++read_fires;
            read_ec = ec;
            read_bytes = n;
        }));

    UInt32 close_fires = 0;
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncClose(
        [&](xtcp::mimt::Result) { ++close_fires; }));

    // No completion fires before dispatch (async dispatch guarantee).
    CHECK(0 == read_fires);
    CHECK(0 == close_fires);

    // Dispatch: DispatchClose completes the pending read with kClosed.
    CHECK(0 < stack_b.DispatchMimt());
    CHECK(1 == read_fires);                      // exactly once
    CHECK(xtcp::mimt::Result::kClosed == read_ec);
    CHECK(0 == read_bytes);
    CHECK(1 == close_fires);
    CHECK(flow->IsClosed());

    // A further dispatch must not re-fire any callback (strict 1:1).
    CHECK(0 == stack_b.DispatchMimt());
    CHECK(1 == read_fires);
    CHECK(1 == close_fires);
}

static void TestAsyncCloseAfterClosed() {
    // Audit A-4: an AsyncClose issued AFTER the flow already
    // closed must still complete THIS caller's handler exactly once with
    // kClosed - the pre-fix code returned kOk and silently dropped the
    // callback, hanging the caller.
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
    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    stack_b.StartMimt([&flow](std::shared_ptr<xtcp::mimt::MimtFlow> f) { flow = f; });
    UInt64 conn_b = 0;
    stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                       const xtcp::core::Endpoint&) {
        conn_b = id;
        return true;
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8081;
    CHECK(stack_b.Listen(remote));
    local.port = 30001;
    const UInt64 conn_a = stack_a.Connect(local, remote);
    CHECK(0 != conn_a);
    for (UInt32 r = 0; r < 200 && !flow; ++r) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_b.DispatchMimt();
    }
    CHECK(flow);
    CHECK(0 != conn_b);

    // Close both sides: B's conn is reclaimed -> its flow closes.
    stack_a.Close(conn_a);
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(xtcp::core::TcpState::kCloseWait == stack_b.ConnectionState(conn_b));
    stack_b.Close(conn_b);
    Pump(backend_a, backend_b, stack_a, stack_b);
    Pump(backend_a, backend_b, stack_a, stack_b);
    stack_b.PollAckTimers();
    stack_b.PollAckTimers();
    CHECK(0 == stack_b.ConnectionCount());  // B's conn reclaimed
    CHECK(flow->IsClosed());

    // AsyncClose on the already-closed flow: the handler must fire once.
    UInt32 close_fires = 0;
    xtcp::mimt::Result close_ec = xtcp::mimt::Result::kOk;
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncClose(
        [&](xtcp::mimt::Result ec) {
            ++close_fires;
            close_ec = ec;
        }));
    CHECK(1 == close_fires);                          // completed immediately
    CHECK(xtcp::mimt::Result::kClosed == close_ec);   // CORE: A-4 fix
    // Strict 1:1: a second AsyncClose also completes exactly once.
    UInt32 close2 = 0;
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncClose([&](xtcp::mimt::Result) { ++close2; }));
    CHECK(1 == close2);
}

static void TestPendingWriteClosedOnAsyncClose() {
    xtcp::mimt::MimtFlow flow;
    // Sink permanently busy: the queued write is stranded at dispatch time.
    flow.SetWriteSink([](const Byte*, UInt32) { return false; });

    const Byte payload[] = { 'x', 't', 'c', 'p' };
    UInt32 write_fires = 0;
    xtcp::mimt::Result write_ec = xtcp::mimt::Result::kOk;
    UInt32 write_bytes = 1;
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncWrite(
        payload, sizeof(payload),
        [&](xtcp::mimt::Result ec, UInt32 n) {
            ++write_fires;
            write_ec = ec;
            write_bytes = n;
        }));

    UInt32 close_fires = 0;
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncClose(
        [&](xtcp::mimt::Result) { ++close_fires; }));

    CHECK(0 == write_fires);
    CHECK(0 == close_fires);

    // DispatchWrite cannot make progress (busy sink) and DispatchClose is
    // pending: the write must still complete exactly once on this dispatch.
    CHECK(0 < flow.Dispatch());
    CHECK(1 == write_fires);                       // exactly once
    CHECK(xtcp::mimt::Result::kWouldBlock == write_ec);
    CHECK(0 == write_bytes);
    CHECK(1 == close_fires);
    CHECK(flow.IsClosed());

    // No double-fire on a subsequent dispatch.
    CHECK(0 == flow.Dispatch());
    CHECK(1 == write_fires);
    CHECK(1 == close_fires);
}

int main() {
    xtcp::buf::InitPools();
    {
        TestPendingReadClosedOnAsyncClose();
        TestPendingWriteClosedOnAsyncClose();
    TestAsyncCloseAfterClosed();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_CLOSE_CB: FAILED (%d)\n"
                                    : "MIMT_CLOSE_CB: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

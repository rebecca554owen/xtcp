/**
 * @file test_tfo_timewait.cpp
 * @brief A fast-open connection's TIME-WAIT honors the configured 2MSL:
 *        after a TFO reconnect closes, the connection is reclaimed once
 *        the (short) 2MSL deadline elapses.
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

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(100000);  // 100 ms 2MSL
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
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 0;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));

        // First connection learns the TFO cookie.
        UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Fast-open reconnect, then close.
        xtcp::core::Endpoint tfo_local = local;
        tfo_local.port = 40002;
        const char* early = "tw-test";
        conn = stack_a.ConnectWithTfo(tfo_local, remote,
                                      reinterpret_cast<const Byte*>(early),
                                      static_cast<UInt32>(std::strlen(early)));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Before 2MSL: the TFO connection lingers in TIME-WAIT.
        std::fprintf(stderr, "[tfo-tw] after close connsA=%u conn=%d\n",
                     (UInt32)stack_a.ConnectionCount(),
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn));

        // After 2MSL: reclaimed. Sleep must exceed the 100 ms 2MSL deadline.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        for (UInt32 i = 0; i < 50; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[tfo-tw] after 2MSL connsA=%u\n",
                     (UInt32)stack_a.ConnectionCount());
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_TIMEWAIT: FAILED (%d)\n" : "TFO_TIMEWAIT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

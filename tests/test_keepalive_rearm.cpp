/**
 * @file test_keepalive_rearm.cpp
 * @brief Keepalive disable/re-enable semantics (audit m3, Linux parity):
 *        the probe counter is NOT reset by SetKeepalive. With unanswered
 *        probes accumulated, disabling (idle=0) and re-enabling with a
 *        smaller cnt makes the next idle poll abort immediately (the
 *        counter persists - parity with Linux tcp_keepalive). Also pins
 *        the abort itself: cnt unanswered probes against a silent peer
 *        abort the connection.
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

// Pumps A->B only (A's probes reach B; B's replies stay undelivered so A
// sees a silent peer and the probes go unanswered).
static void PumpOneWay(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                       xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 100; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
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
        a_local.port = 40202;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9102;
        CHECK(stack_b.Listen(b_local));

        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // (1) Abort on cnt unanswered probes against a silent peer.
        stack_a.SetKeepalive(conn_a, 100000, 100000, 3);  // 100 ms idle/intvl, cnt 3
        for (UInt32 i = 0; i < 60; ++i) {
            PumpOneWay(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::fprintf(stderr, "[keepalive-rearm] after silent probes: A=%d (expect %d closed)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_a)),
                     static_cast<int>(xtcp::core::TcpState::kClosed));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn_a));

        // (2) Disable/re-enable parity: build up unanswered probes on a
        // fresh connection, disable, re-enable with a smaller cnt - the
        // counter persists (Linux parity), so the next idle poll aborts
        // immediately instead of waiting for cnt fresh probes.
        const UInt64 conn_b2 = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_b2);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_b2));

        stack_a.SetKeepalive(conn_b2, 100000, 100000, 8);  // default-ish cnt
        for (UInt32 i = 0; i < 30; ++i) {  // ~2-3 unanswered probes
            PumpOneWay(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        // Disable, then re-enable with cnt 1: the persisted probe counter
        // (>= 1) makes the next idle check abort immediately.
        stack_a.SetKeepalive(conn_b2, 0, 100000, 8);       // off
        stack_a.SetKeepalive(conn_b2, 100000, 100000, 1);  // re-enable, cnt 1
        for (UInt32 i = 0; i < 40; ++i) {
            PumpOneWay(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::fprintf(stderr, "[keepalive-rearm] after re-enable cnt=1: A=%d (expect %d closed)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_b2)),
                     static_cast<int>(xtcp::core::TcpState::kClosed));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn_b2));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_REARM: FAILED (%d)\n" : "KEEPALIVE_REARM: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

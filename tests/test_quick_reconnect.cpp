/**
 * @file test_quick_reconnect.cpp
 * @brief Same-4-tuple reconnect while the previous connection still sits in
 *        TIME-WAIT: the new SYN must establish a fresh connection (the old
 *        TIME-WAIT entry is displaced and reclaimed on its own clock), and
 *        the new flow must carry data intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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
        stack_a.SetTwoMsl(60000);  // 60 ms: the old entry lingers long enough
        stack_b.SetTwoMsl(60000);
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
        UInt64 conn_b = 0;
        UInt64 bytes_recv = 0;
        stack_b.SetStateHandler([&conn_b, &stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });
        stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40101;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9098;
        CHECK(stack_b.Listen(remote));

        // First connection: same tuple, close it into TIME-WAIT.
        UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn));

        // Reconnect immediately on the same tuple (old entry still in
        // TIME-WAIT).
        UInt64 conn2 = stack_a.Connect(local, remote);
        CHECK(0 != conn2);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[quick-reconnect] new A=%d B=%u\n",
                     (int)stack_a.ConnectionState(conn2), (UInt32)stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn2));
        CHECK(0 != conn_b);

        // Data on the new connection arrives intact.
        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 5 + i / 11) & 0xFF);
        }
        UInt64 sent = 0;
        for (UInt32 round = 0; round < 16 && sent < kTotal; ++round) {
            UInt32 n = static_cast<UInt32>(kTotal - sent);
            if (n > 2048) {
                n = 2048;
            }
            UInt32 g = 0;
            while (!stack_a.Send(conn2, payload.data() + sent, n) && 300 > ++g) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            sent += n;
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == sent);
        for (UInt32 i = 0; i < 500 && bytes_recv < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[quick-reconnect] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        stack_a.Close(conn2);
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QUICK_RECONNECT: FAILED (%d)\n" : "QUICK_RECONNECT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_short_conn.cpp
 * @brief High-frequency short connections: N iterations of
 *        connect -> send small data -> echo back -> close. Exercises the
 *        full lifecycle under churn (no leaks, no half-open residue).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <chrono>
#include <cstring>
#include <thread>
#include <string>

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
        constexpr UInt32 kIterations = 100;
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(50000);
        stack_b.SetTwoMsl(50000);
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

        // Echo server; also closes when the client's FIN arrives (CLOSE-WAIT).
        stack_b.SetRecvHandler([&stack_b](UInt64 id, const Byte* d, UInt32 n) {
            stack_b.Send(id, d, n);
        });
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 0;  // ephemeral each time
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));

        const char* msg = "short-conn";
        const UInt32 msg_len = static_cast<UInt32>(std::strlen(msg));
        UInt32 echoes = 0;
        for (UInt32 i = 0; i < kIterations; ++i) {
            // Connect (ephemeral source port), send, wait for echo, close.
            const UInt64 c = stack_a.Connect(local, remote);
            CHECK(0 != c);
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(stack_a.Send(c, reinterpret_cast<const Byte*>(msg), msg_len));
            // Wait for the echo on A.
            bool got = false;
            std::string recv_buf;
            stack_a.SetRecvHandler([&](UInt64, const Byte* d, UInt32 n) {
                recv_buf.append(reinterpret_cast<const char*>(d), n);
                got = (recv_buf.size() >= msg_len);
            });
            for (UInt32 s = 0; s < 200 && !got; ++s) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            if (got) {
                ++echoes;
            }
            stack_a.Close(c);
            // Let the close complete (FIN + reclaim).
            for (UInt32 s = 0; s < 100; ++s) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        std::fprintf(stderr, "[short-conn] %u iterations, %u echoes OK\n",
                     kIterations, echoes);
        CHECK(kIterations == echoes);
        // Wait for every TIME-WAIT (2MSL = 50 ms) to expire and be reclaimed.
        std::this_thread::sleep_for(std::chrono::milliseconds(70));
        for (UInt32 s = 0; s < 100; ++s) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(0 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SHORT_CONN: FAILED (%d)\n" : "SHORT_CONN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


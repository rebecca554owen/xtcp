/**
 * @file test_scale.cpp
 * @brief Connection-count scaling: thousands of live connections (mostly
 *        idle) must not make the per-connection timer sweep degrade - the
 *        dirty-flag fast path skips idle connections, so PollAckTimers stays
 *        cheap at scale.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
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
        constexpr UInt32 kConns = 3000;
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(5000);
        stack_b.SetTwoMsl(5000);
        UInt32 closewait_fired = 0;
        stack_b.SetStateHandler([&stack_b, &closewait_fired](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                ++closewait_fired;
                stack_b.Close(id);
            }
        });
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40181;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9106;
        CHECK(stack_b.Listen(remote));

        // Establish kConns connections (source ports cycle).
        std::vector<UInt64> conns;
        const UInt32 batch = 200;
        for (UInt32 base = 0; base < kConns; base += batch) {
            const UInt32 n = (kConns - base < batch) ? (kConns - base) : batch;
            for (UInt32 i = 0; i < n; ++i) {
                xtcp::core::Endpoint l = local;
                l.port = static_cast<UInt16>(40181 + ((base + i) % 30000));
                const UInt64 c = stack_a.Connect(l, remote);
                CHECK(0 != c);
                conns.push_back(c);
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[scale] established=%zu A=%u B=%u\n",
                     conns.size(), (UInt32)stack_a.ConnectionCount(),
                     (UInt32)stack_b.ConnectionCount());
        CHECK(kConns == conns.size());
        CHECK(kConns <= stack_a.ConnectionCount());

        // Measure the timer sweep cost with all connections idle.
        const UInt32 kRounds = 20;
        const auto t0 = std::chrono::steady_clock::now();
        for (UInt32 r = 0; r < kRounds; ++r) {
            stack_a.PollAckTimers();
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double us_per_poll =
            std::chrono::duration<double, std::micro>(t1 - t0).count() / kRounds;
        std::fprintf(stderr, "[scale] idle poll %.1f us per sweep (%u conns)\n",
                     us_per_poll, (UInt32)stack_a.ConnectionCount());

        // One active connection still drives traffic at scale.
        UInt64 recv = 0;
        stack_b.SetRecvHandler([&recv](UInt64, const Byte*, UInt32 len) { recv += len; });
        std::vector<Byte> payload(4096, 0x5A);
        const UInt64 active = conns[0];
        UInt32 guard = 0;
        while (!stack_a.Send(active, payload.data(), 4096) && 500 > ++guard) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 200 && recv < 4096; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[scale] active flow at scale recv=%llu\n",
                     (unsigned long long)recv);
        CHECK(4096 == recv);

        for (UInt64 c : conns) {
            stack_a.Close(c);
        }
        for (UInt32 i = 0; i < 800; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            if (0 == stack_a.ConnectionCount() && 0 == stack_b.ConnectionCount()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::fprintf(stderr, "[scale] after close A=%u B=%u closewait_fired=%u\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount(),
                     closewait_fired);
        CHECK(0 == stack_a.ConnectionCount());
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SCALE: FAILED (%d)\n" : "SCALE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

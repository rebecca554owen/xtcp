/**
 * @file test_multi_close_churn.cpp
 * @brief Concurrent multi-connection close churn on a dual stack: open
 *        kConns connections A<->B, then close every one of them
 *        simultaneously from multiple threads. Verifies the concurrent
 *        closes all fully recycle: both stacks' ConnectionCount must return
 *        to zero (no leaks, no lingering TIME-WAIT) and the test must run to
 *        completion without crashing (concurrent per-shard closes deadlock
 *        or corrupt state would hang / trip an assertion instead).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                 \
    } while (0)

namespace {
    constexpr UInt32 kConns    = 50;    // total connections to open + close
    constexpr UInt32 kThreads  = 10;    // threads closing in parallel
    constexpr UInt32 kClientV4 = 0x0A000001;
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt16 kPort     = 9102;
    constexpr UInt32 kStallMax = 20000; // drain bail-out (no progress for this many rounds)
}

/** Moves pending tx both ways; feeds OnPacket and advances timer clock. */
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

/** Pump + real-clock sleep until `done()` or a long progress-free stretch. */
static void DrainUntil(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                       xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                       const std::function<bool()>& done, const char* what) {
    UInt32 stalls = 0;
    while (!done()) {
        const UInt32 before_a = sa.ConnectionCount();
        const UInt32 before_b = sb.ConnectionCount();
        Pump(ba, bb, sa, sb);
        if (before_a == sa.ConnectionCount() && before_b == sb.ConnectionCount()) {
            if (kStallMax <= ++stalls) {
                std::fprintf(stderr, "[multi_close_churn] drain stalled (%s): "
                                     "conns_a=%u conns_b=%u\n",
                             what, (UInt32)sa.ConnectionCount(),
                             (UInt32)sb.ConnectionCount());
                break;
            }
        } else {
            stalls = 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(20000);  // 2MSL = 20ms so TIME-WAIT reclaims fast
        stack_b.SetTwoMsl(20000);
        // Passive close: B answers A's FIN so the close handshake completes.
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = 30000;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;
        CHECK(stack_b.Listen(remote));

        // Phase 1: open kConns connections (each on its own client port).
        std::vector<UInt64> conns;
        conns.reserve(kConns);
        for (UInt32 i = 0; i < kConns; ++i) {
            xtcp::core::Endpoint l = local;
            l.port = static_cast<UInt16>(30000 + i);
            const UInt64 id = stack_a.Connect(l, remote);
            CHECK(0 != id);
            conns.push_back(id);
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // Drain until both stacks hold all kConns established connections.
        DrainUntil(backend_a, backend_b, stack_a, stack_b,
                   [&]() { return kConns == stack_a.ConnectionCount() &&
                                  kConns == stack_b.ConnectionCount(); },
                   "establish");
        CHECK(kConns == stack_a.ConnectionCount());
        CHECK(kConns == stack_b.ConnectionCount());
        std::fprintf(stderr, "[multi_close_churn] established %u conns "
                             "(A=%u B=%u), closing from %u threads\n",
                     kConns, (UInt32)stack_a.ConnectionCount(),
                     (UInt32)stack_b.ConnectionCount(), kThreads);

        // Phase 2: close ALL connections simultaneously (spin-barrier release).
        std::atomic<bool> go{false};
        std::vector<std::thread> closers;
        for (UInt32 t = 0; t < kThreads; ++t) {
            closers.emplace_back([&stack_a, &conns, &go, t]() {
                while (!go.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                const UInt32 begin = t * kConns / kThreads;
                const UInt32 end   = (t + 1) * kConns / kThreads;
                for (UInt32 i = begin; i < end; ++i) {
                    stack_a.Close(conns[i]);
                }
            });
        }
        go.store(true, std::memory_order_release);
        for (auto& c : closers) {
            c.join();
        }

        // Phase 3: drain until both stacks fully recycle every connection.
        DrainUntil(backend_a, backend_b, stack_a, stack_b,
                   [&]() { return 0 == stack_a.ConnectionCount() &&
                                 0 == stack_b.ConnectionCount(); },
                   "reclaim");
        const UInt32 conns_a = stack_a.ConnectionCount();
        const UInt32 conns_b = stack_b.ConnectionCount();
        std::fprintf(stderr, "[multi_close_churn] final A=%u B=%u\n", conns_a, conns_b);
        CHECK(0 == conns_a);
        CHECK(0 == conns_b);
    }
    xtcp::buf::ShutdownPools();

    if (0 != g_failures) {
        std::fprintf(stderr, "MULTI_CLOSE_CHURN: FAILED (%d)\n", g_failures);
    } else {
        std::fprintf(stderr, "MULTI_CLOSE_CHURN: ALL PASSED (all %u conns "
                             "recycled, no crash)\n", kConns);
    }
    return g_failures ? 1 : 0;
}

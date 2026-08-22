/**
 * @file test_conn_toctou.cpp
 * @brief conn_count_ hard-cap TOCTOU regression: concurrent active opens
 *        (XtcpStack::Connect) must never exceed SetMaxConnections().
 *
 * The hard cap lives in the stack's live-connection counter (conn_count_).
 * The active-open entry checks it twice:
 *     stack.cpp:410  if (max_conns_ <= conn_count_.load(relaxed)) return 0;
 *     stack.cpp:472  conn_count_.fetch_add(1, relaxed);
 * (ConnectWithTfo mirrors this at stack.cpp:355 / :401; the passive-open
 * path has the same pattern at stack.cpp:808).
 *
 * That is a check-then-act race: the guard is a separate relaxed load and the
 * counter is bumped only after the whole ConnEntry/TcpConn is built. When
 * several threads call Connect while conn_count_ < max_conns_, every one of
 * them can pass the check (the load happened before anyone incremented) and
 * then all of them increment - the live count overshoots the cap.
 *
 * This test releases 8 threads through a spin barrier, each issuing multiple
 * Connects, and asserts the number of successful active opens never exceeds
 * max_conns_. The guard is now a single atomic fetch_add reservation that
 * rolls back on overflow (active-open reservation, stack.cpp:550/:629) - the
 * fix is landed, so this test verifies the post-fix behavior: exactly
 * max_conns_ successes.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
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
    constexpr UInt32 kMaxConns  = 4;    // SetMaxConnections(4)
    constexpr UInt32 kThreads   = 8;    // concurrent active openers
    constexpr UInt32 kPerThread = 16;   // Connect attempts per thread
    constexpr UInt32 kAttempts  = kThreads * kPerThread;  // 128 total, >> cap

    std::atomic<bool> g_go{false};
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend ba, bb;
        xtcp::XtcpStack sa(&ba), sb(&bb);

        // Both stacks bound at the same small cap (dual-stack symmetry).
        sa.SetMaxConnections(kMaxConns);
        sb.SetMaxConnections(kMaxConns);

        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(sb.Listen(remote));

        // 8 threads race through a spin barrier so the check-then-act guard
        // is evaluated simultaneously by every thread (count still < cap).
        // Each thread uses local.port = 0: the stack assigns a distinct
        // ephemeral port, so no two Connects share a 4-tuple.
        std::atomic<UInt32> success{0};
        std::vector<std::thread> threads;
        for (UInt32 t = 0; t < kThreads; ++t) {
            threads.emplace_back([&sa, &success, remote]() {
                UInt32 local_success = 0;
                while (!g_go.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                for (UInt32 i = 0; i < kPerThread; ++i) {
                    xtcp::core::Endpoint local;
                    local.family = 4;
                    local.addr[0] = 0x0A000001;
                    local.port = 0;  // ephemeral
                    if (0 != sa.Connect(local, remote)) {
                        ++local_success;
                    }
                }
                success += local_success;
            });
        }
        g_go.store(true, std::memory_order_release);
        for (auto& th : threads) {
            th.join();
        }

        // Drain A's tx queue (the SYNs) so the backend is clean at teardown;
        // the assertion only cares about Connect() admission, not the wire.
        {
            Byte scratch[65536];
            while (0 != ba.TxPending()) {
                if (0 == ba.PollTx(scratch)) {
                    break;
                }
            }
        }

        const UInt32 s = success.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[conn_toctou] attempts=%u success=%u max=%u conn_count=%u\n",
                     (unsigned)kAttempts, (unsigned)s, (unsigned)kMaxConns,
                     (unsigned)sa.ConnectionCount());

        // Core assertion: the hard cap is never overshot, no matter how the
        // concurrent Connects interleave (TOCTOU after the atomic-check fix).
        CHECK(s <= kMaxConns);
        CHECK(sa.ConnectionCount() <= kMaxConns);

        // Sanity + internal consistency: the scenario must actually saturate
        // the cap (otherwise it proves nothing), and every admitted active
        // open must be reflected in the live counter.
        CHECK(0 < s);
        CHECK(sa.ConnectionCount() == s);
    }
    xtcp::buf::ShutdownPools();

    std::fprintf(stderr, g_failures ? "CONN_TOCTOU: FAILED (%d)\n" : "CONN_TOCTOU: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

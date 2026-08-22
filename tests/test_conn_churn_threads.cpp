/**
 * @file test_conn_churn_threads.cpp
 * @brief Multi-threaded connect/close churn: the connection slab (perf #4)
 *        and the flat flow table (perf #3) are documented as safe under
 *        the owning shard's lock, but were never stress-tested under TRUE
 *        cross-thread contention - several threads simultaneously allocate
 *        and reclaim connections (slab slots, free lists, flow routes,
 *        tombstones) while a single pump thread drives the wire.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
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
    for (UInt32 round = 0; round < 5000; ++round) {
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
        constexpr UInt32 kThreads = 4;
        constexpr UInt32 kCycles = 150;  // 600 connections total
        constexpr UInt32 kBasePort = 9200;

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

        // kThreads listeners (one per worker) so every worker's connects
        // spread across shards. Short 2MSL so TIME-WAIT reaps fast (the
        // churn is the target, not 120 s of lingering).
        stack_a.SetTwoMsl(100000);
        stack_b.SetTwoMsl(100000);
        // B closes its side when A's FIN arrives (CLOSE-WAIT): without it
        // B's connections linger in CLOSE-WAIT forever and A's linger in
        // FIN-WAIT-2 until the 60 s timeout.
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                // Reentrant Close: the handler runs under the shard/conn
                // locks, both recursive - safe.
                stack_b.Close(id);
            }
        });
        for (UInt32 i = 0; i < kThreads; ++i) {
            xtcp::core::Endpoint ep;
            ep.family = 4;
            ep.addr[0] = 0x0A000002;
            ep.port = static_cast<UInt16>(kBasePort + i);
            CHECK(stack_b.Listen(ep));
        }

        std::atomic<bool> stop{false};
        std::atomic<UInt32> errors{0};
        std::atomic<UInt32> done_workers{0};  // workers finished: pump may exit early
        std::vector<std::thread> workers;
        for (UInt32 w = 0; w < kThreads; ++w) {
            workers.emplace_back([&, w]() {
                for (UInt32 c = 0; c < kCycles && !stop.load(std::memory_order_relaxed); ++c) {
                    xtcp::core::Endpoint local, remote;
                    local.family = 4;
                    local.addr[0] = 0x0A000001;
                    local.port = static_cast<UInt16>(40000 + w * 1000 + c);
                    remote.family = 4;
                    remote.addr[0] = 0x0A000002;
                    remote.port = static_cast<UInt16>(kBasePort + w);
                    const UInt64 conn = stack_a.Connect(local, remote);
                    if (0 == conn) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    // Wait for Established (the pump thread drives it).
                    UInt32 est_spins = 0;
                    for (UInt32 spin = 0; spin < 2000; ++spin) {
                        if (xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn)) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        ++est_spins;
                    }
                    if (est_spins > 50) {
                        std::fprintf(stderr, "[churn] est slow %u ms\n", est_spins);
                    }
                    if (xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn)) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        stack_a.Abort(conn);
                        continue;
                    }
                    // Half-close exchange, then reap.
                    stack_a.Close(conn);
                    UInt32 reap_spins = 0;
                    for (UInt32 spin = 0; spin < 2000; ++spin) {
                        if (!stack_a.ConnectionExists(conn)) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        ++reap_spins;
                    }
                    if (reap_spins > 50) {
                        std::fprintf(stderr, "[churn] reap slow %u ms\n", reap_spins);
                    }
                    if (stack_a.ConnectionExists(conn)) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                done_workers.fetch_add(1, std::memory_order_relaxed);
            });
        }

        // Pump driver: moves all traffic until every worker finishes. The
        // loop exits as soon as done_workers == kThreads (the workers are
        // done; a fixed 20000-round cap would otherwise run ~40s of idle
        // pumping - and on Windows each 2ms sleep is ~15.6ms of clock
        // granularity, i.e. ~5 minutes of pure waiting).
        UInt64 pump_rounds = 0;
        for (UInt32 round = 0; round < 20000 && !stop.load(std::memory_order_relaxed) &&
             done_workers.load(std::memory_order_relaxed) < kThreads; ++round) {
            const auto p0 = std::chrono::steady_clock::now();
            Pump(backend_a, backend_b, stack_a, stack_b);
            const auto p1 = std::chrono::steady_clock::now();
            const auto pump_us = std::chrono::duration_cast<std::chrono::microseconds>(p1 - p0).count();
            if (pump_us > 5000) {
                std::fprintf(stderr, "[churn] pump round %u slow: %lld us\n", round, (long long)pump_us);
            }
            ++pump_rounds;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        std::fprintf(stderr, "[churn] pump rounds=%llu\n", (unsigned long long)pump_rounds);
        stop.store(true, std::memory_order_relaxed);
        for (auto& t : workers) {
            t.join();
        }
        // Final drain.
        for (UInt32 i = 0; i < 200 && (0 != stack_a.ConnectionCount() || 0 != stack_b.ConnectionCount()); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        std::fprintf(stderr, "[conn-churn-threads] errors=%u A_conns=%u B_conns=%u\n",
                     errors.load(std::memory_order_relaxed),
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount());
        CHECK(0 == errors.load(std::memory_order_relaxed));
        CHECK(0 == stack_a.ConnectionCount());  // every connection reaped
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CONN_CHURN_THREADS: FAILED (%d)\n" : "CONN_CHURN_THREADS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

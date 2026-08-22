/**
 * @file test_bufref_starvation.cpp
 * @brief Tier-2 (32KB) pool starvation regression: with per-thread hoarding,
 *        released blocks sit in the RELEASING thread's cache while other
 *        threads see an empty global pool and Acquire returns empty (silent
 *        packet loss). The root fix disables hoarding for tier-2 (cap 0):
 *        every tier-2 block returns to the global free list, so any thread
 *        can reuse it.
 *
 * Deterministic scenario: 32 threads each hold 4 tier-2 blocks (128 = the
 * entire tier-2 pool -> global list empty). Thread 0 releases one block;
 * thread 1 must then Acquire it successfully. Pre-fix this fails (the
 * released block is hoarded in thread 0's cache).
 */

#include <xtcp/buf/bufref.h>

#include <cstdio>
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

namespace {
    constexpr UInt32 kThreads = 32;
    constexpr UInt32 kPerThread = 4;  // 32 x 4 = 128 = tier-2 capacity
}

int main() {
    xtcp::buf::InitPools();
    {
        // Phase 1: every thread hoards kPerThread tier-2 blocks (in use).
        std::vector<std::vector<xtcp::buf::BufRef>> held(kThreads);
        std::vector<std::thread> threads;
        for (UInt32 t = 0; t < kThreads; ++t) {
            threads.emplace_back([&held, t]() {
                held[t].reserve(kPerThread);
                for (UInt32 i = 0; i < kPerThread; ++i) {
                    xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(32752);
                    if (!b.IsEmpty()) {
                        held[t].push_back(std::move(b));
                    }
                }
            });
        }
        for (auto& th : threads) {
            th.join();
        }
        UInt32 acquired = 0;
        for (UInt32 t = 0; t < kThreads; ++t) {
            acquired += static_cast<UInt32>(held[t].size());
        }
        std::fprintf(stderr, "[starvation] threads held %u/%u tier-2 blocks\n",
                     acquired, kThreads * kPerThread);
        CHECK(kThreads * kPerThread == acquired);  // the whole pool is in use

        // Phase 2: thread 0 releases ONE block; thread 1 must be able to
        // Acquire it (it returned to the global free list, not thread 0's
        // cache). The moved-out ref must be destroyed NOW (not at scope
        // end) so the block actually returns.
        xtcp::buf::BufRef released = std::move(held[0].back());
        held[0].pop_back();
        released = xtcp::buf::BufRef();  // block returns to thread 0's cache (or global post-fix)

        bool got = false;
        std::thread t1([&got]() {
            xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(32752);
            got = !b.IsEmpty();
        });
        t1.join();
        CHECK(got);  // pre-fix: false (block hoarded in thread 0's cache)

        // Phase 3: the re-acquired block returns to the global list again.
        for (UInt32 t = 1; t < kThreads; ++t) {
            held[t].clear();  // release everything
        }
        held[0].clear();
        xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(32752);
        CHECK(!b.IsEmpty());  // post-drain the pool is fully reusable
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "BUFREF_STARVATION: FAILED (%d)\n" : "BUFREF_STARVATION: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

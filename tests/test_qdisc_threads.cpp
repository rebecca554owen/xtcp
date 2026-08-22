/**
 * @file test_qdisc_threads.cpp
 * @brief Qdisc thread safety: the stack enqueues from worker threads while
 *        the pacing clock drains from another. Concurrent enqueue/dequeue
 *        must not corrupt the flow tables (FQ instance lock).
 */

#include <xtcp/qdisc/qdisc.h>
#include <xtcp/buf/bufref.h>

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

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::qdisc::RegisterFqDefault();
        xtcp::qdisc::QdiscParams params;
        params.pacing_enabled = false;     // immediate drain, deterministic
        params.max_flow_queue = 100;       // 10 packets per flow: fits
        params.max_global_queue = 100000;  // all 40000 packets fit
        xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
        CHECK(NULLPTR != fq);

        static constexpr UInt32 kThreads = 4;
        static constexpr UInt32 kPerThread = 10000;
        static constexpr UInt32 kTotalPackets = kThreads * kPerThread;
        std::atomic<UInt64> enqueued{0};
        std::atomic<UInt64> drained{0};
        std::atomic<bool>   done{false};

        // Draining thread: frees a pool block on every successful dequeue,
        // which is what lets the enqueuers below ever Acquire again. The
        // loop target is "drained == enqueued" (not kTotalPackets) so a
        // silent drop by the qdisc under test fails the CHECK below instead
        // of hanging the test forever. yield() on an empty queue gives the
        // enqueue threads CPU time to refill it.
        std::thread drainer([&]() {
            for (;;) {
                xtcp::core::TimePoint next = 0;
                xtcp::buf::BufRef pkt = fq->ops->dequeue(fq, 0, &next);
                if (!pkt.IsEmpty()) {
                    drained.fetch_add(1, std::memory_order_relaxed);
                } else {
                    if (done.load(std::memory_order_acquire) &&
                        drained.load(std::memory_order_relaxed) >=
                            enqueued.load(std::memory_order_relaxed)) {
                        break;
                    }
                    std::this_thread::yield();
                }
            }
        });

        // Enqueueing threads: many distinct flows (per-flow queue caps hold).
        // The 2KB tier has 1024 blocks but 40000 packets are pushed, so the
        // pool saturates by design: Acquire only fails transiently, until the
        // drainer releases a block. Wait unconditionally (yield + retry);
        // a fixed retry cap lets a worker give up and permanently drop a
        // packet, which then keeps the drained count short forever.
        std::vector<std::thread> workers;
        for (UInt32 t = 0; t < kThreads; ++t) {
            workers.emplace_back([fq, t, &enqueued]() {
                for (UInt32 i = 0; i < kPerThread; ++i) {
                    xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(64);
                    while (b.IsEmpty()) {
                        std::this_thread::yield();
                        b = xtcp::buf::BufRef::Acquire(64);
                    }
                    b.SetLen(64);
                    if (0 == fq->ops->enqueue(fq, 1000 + t * 100000 + (i % 1000), std::move(b))) {
                        enqueued.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }
        for (auto& w : workers) {
            w.join();
        }
        done.store(true, std::memory_order_release);
        drainer.join();

        const UInt64 totalDrained = drained.load(std::memory_order_relaxed);
        const UInt64 totalEnqueued = enqueued.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[qdisc-thread] enqueued=%llu drained=%llu\n",
                     (unsigned long long)totalEnqueued, (unsigned long long)totalDrained);
        CHECK(kTotalPackets == totalEnqueued);
        CHECK(kTotalPackets == totalDrained);
        xtcp::qdisc::DestroyQdisc(fq);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QDISC_THREADS: FAILED (%d)\n" : "QDISC_THREADS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

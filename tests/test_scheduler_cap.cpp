/**
 * @file test_scheduler_cap.cpp
 * @brief Multi-producer boundedness of the scheduler's MPSC inbox queue.
 *
 * The scheduler's cross-shard inbox is a bounded MpscQueue. Push() must never
 * let the in-queue item count exceed its capacity even when many producers
 * push concurrently. The fixed implementation reserves a slot with an atomic
 * fetch_add and rolls it back (fetch_sub) when the reserved slot is beyond
 * capacity, so a multi-producer burst can never overfill the queue.
 *
 * Scenario 1 (boundedness): a small-capacity MpscQueue is driven by 8
 * producers pushing far beyond capacity. Assert accepted pushes <= capacity,
 * queue occupancy <= capacity, and every accepted packet is readable. This
 * queue is the exact object Scheduler::Deliver pushes into (the Scheduler
 * class hardcodes inbox capacity to 4096 in its constructor, so the small-
 * capacity variant of the same queue is constructed directly to make the
 * bound reachable in a test).
 *
 * Scenario 2 (scheduler path): the full Scheduler::Deliver -> Push path under
 * concurrent producers, with a single consumer draining. Verifies no crash
 * and that every accepted packet arrives intact exactly once.
 */

#include <xtcp/core/scheduler.h>

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
    constexpr UInt32 kCapacity    = 32;    // small queue: burst must not exceed this
    constexpr UInt32 kProducers   = 8;
    constexpr UInt32 kPerProducer = 1000;  // 8000 attempts vs 32 capacity
    constexpr UInt32 kDeliverPer  = 2000;  // scheduler Deliver scenario
    constexpr UInt32 kFlows       = 4;
}

static xtcp::core::FlowKey MakeKey(UInt32 src, UInt16 sport) noexcept {
    xtcp::core::FlowKey key;
    key.addr_family = 4;
    key.saddr[0] = src;
    key.daddr[0] = 0x0A000001;
    key.sport = sport;
    key.dport = 443;
    return key;
}

/** Scenario 1: 8 producers concurrently overfill a capacity-32 queue. */
static void TestMpscBoundedPush() {
    xtcp::core::MpscQueue q(kCapacity);
    CHECK(q.IsEmpty());

    std::atomic<UInt32> success{0};
    std::atomic<UInt32> failed{0};
    std::vector<std::thread> threads;
    for (UInt32 t = 0; t < kProducers; ++t) {
        threads.emplace_back([&q, &success, &failed]() {
            UInt32 ok = 0, no = 0;
            for (UInt32 i = 0; i < kPerProducer; ++i) {
                xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(64);
                while (p.IsEmpty()) {  // pool pressure: wait, never skip
                    p = xtcp::buf::BufRef::Acquire(64);
                    std::this_thread::yield();
                }
                p.SetLen(1);
                p.Data()[0] = 0x5A;
                if (q.Push(std::move(p))) {
                    ++ok;
                } else {
                    ++no;
                }
            }
            success += ok;
            failed += no;
        });
    }
    for (auto& th : threads) {
        th.join();
    }

    // With the reservation+rollback fix, at most kCapacity pushes can ever
    // succeed while nothing is popped; the queue saturates exactly at the
    // capacity (>= kCapacity attempts guarantee the fill completes).
    CHECK(success.load() <= kCapacity);
    CHECK(kCapacity == success.load());
    CHECK(kProducers * kPerProducer == success.load() + failed.load());
    CHECK(q.Size() <= kCapacity);

    UInt32 popped = 0;
    while (!q.IsEmpty()) {
        xtcp::buf::BufRef p = q.Pop();
        CHECK(!p.IsEmpty());
        CHECK(1 == p.Len());
        CHECK(0x5A == p.Data()[0]);
        ++popped;
    }
    CHECK(popped == success.load());
    CHECK(q.IsEmpty());
}

/** Scenario 2: concurrent Scheduler::Deliver -> Push with one draining consumer. */
static void TestSchedulerDeliverConcurrent() {
    xtcp::core::Scheduler sched(1, 64, 64);
    std::vector<xtcp::core::FlowKey> keys;
    for (UInt32 i = 0; i < kFlows; ++i) {
        keys.push_back(MakeKey(0xC0A80001 + i, static_cast<UInt16>(20000 + i)));
        sched.RegisterFlow(keys.back(), 0);
    }

    std::atomic<bool> done{false};
    std::atomic<UInt32> accepted{0};
    std::atomic<UInt32> rejected{0};
    int bad = 0;
    UInt32 popped = 0;

    std::thread consumer([&]() {
        int bad_local = 0;
        UInt32 local_popped = 0;
        while (!done.load() || local_popped < accepted.load()) {
            xtcp::buf::BufRef p = sched.Poll(0);
            if (p.IsEmpty()) {
                std::this_thread::yield();
                continue;
            }
            if (1 != p.Len() || static_cast<UInt32>(p.Data()[0]) >= kProducers) {
                ++bad_local;
            }
            ++local_popped;
        }
        bad = bad_local;
        popped = local_popped;
    });

    std::vector<std::thread> producers;
    for (UInt32 t = 0; t < kProducers; ++t) {
        producers.emplace_back([&, t]() {
            UInt32 ok = 0, no = 0;
            const xtcp::core::FlowKey& key = keys[t % kFlows];
            for (UInt32 i = 0; i < kDeliverPer; ++i) {
                xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(64);
                while (p.IsEmpty()) {
                    p = xtcp::buf::BufRef::Acquire(64);
                    std::this_thread::yield();
                }
                p.SetLen(1);
                p.Data()[0] = static_cast<Byte>(t);
                if (sched.Deliver(key, std::move(p))) {
                    ++ok;
                } else {
                    ++no;
                }
            }
            accepted += ok;
            rejected += no;
        });
    }
    for (auto& th : producers) {
        th.join();
    }
    done.store(true);
    consumer.join();

    CHECK(0 < accepted.load());
    CHECK(kProducers * kDeliverPer == accepted.load() + rejected.load());
    CHECK(popped == accepted.load());  // every accepted packet arrives exactly once
    CHECK(0 == bad);                   // payload intact, no corruption
}

int main() {
    xtcp::buf::InitPools();
    std::fprintf(stderr, "cap: bounded push\n");
    TestMpscBoundedPush();
    std::fprintf(stderr, "cap: scheduler deliver concurrent\n");
    TestSchedulerDeliverConcurrent();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_scheduler_cap: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_scheduler_cap: all passed (bounded push, no crash)\n");
    return 0;
}

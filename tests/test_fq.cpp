/**
 * @file test_fq.cpp
 * @brief Pluggable qdisc tests: registry, FQ fairness/ordering/pacing/GSO
 *        counting, FIFO sample.
 */

#include <xtcp/qdisc/qdisc.h>

#include <cstdio>
#include <cstring>

using xtcp::core::TimePoint;

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static xtcp::buf::BufRef MakePacket(UInt32 len, UInt16 segs = 0) noexcept {
    xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(len);
    if (!p.IsEmpty()) {
        p.SetLen(len);
        if (0 < segs) {
            p.Meta().segs = segs;
            p.Meta().mss = 1460;
            p.Meta().gso_size = len / segs;
        }
    }
    return p;
}

static void TestRegistry() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::RegisterFifoSample();

    CHECK(NULLPTR != xtcp::qdisc::FindQdisc("fq"));
    CHECK(NULLPTR != xtcp::qdisc::FindQdisc("fifo"));
    CHECK(NULLPTR == xtcp::qdisc::FindQdisc("nonexistent"));

    xtcp::qdisc::QdiscParams params;
    xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != fq);
    xtcp::qdisc::XtcpQdisc* fifo = xtcp::qdisc::CreateQdisc("fifo", params);
    CHECK(NULLPTR != fifo);
    CHECK(NULLPTR == xtcp::qdisc::CreateQdisc("nonexistent", params));

    xtcp::qdisc::DestroyQdisc(fq);
    xtcp::qdisc::DestroyQdisc(fifo);
}

static void TestFqOrdering() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    for (UInt32 i = 0; i < 5; ++i) {
        xtcp::buf::BufRef p = MakePacket(100);
        std::memcpy(p.Data(), &i, sizeof(i));
        CHECK(0 == q->ops->enqueue(q, 7, std::move(p)));
    }
    for (UInt32 i = 0; i < 5; ++i) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, 1000, NULLPTR);
        CHECK(!out.IsEmpty());
        UInt32 v = 0;
        std::memcpy(&v, out.Data(), sizeof(v));
        CHECK(i == v);  // strict per-flow ordering
    }
    CHECK(!q->ops->has_backlog(q));
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqFairness() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    // 10 flows, 100 packets each of 100 bytes; deficit quantum 1500 -> each
    // flow serves up to 15 packets per round; service counts must be balanced.
    for (UInt64 flow = 1; flow <= 10; ++flow) {
        for (UInt32 i = 0; i < 100; ++i) {
            CHECK(0 == q->ops->enqueue(q, flow, MakePacket(100)));
        }
    }

    UInt64 served[11] = { 0 };
    TimePoint now = 1000;
    UInt32 total = 0;
    UInt32 guard = 0;
    while (q->ops->has_backlog(q)) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, now, NULLPTR);
        if (!out.IsEmpty()) {
            ++total;
            guard = 0;
            continue;
        }
        // Deficit may be exhausted for the round; advance time and retry.
        now += 1;
        if (100000 < ++guard) {
            break;  // safety guard
        }
    }
    CHECK(1000 == total);  // all packets drained

    // Per-flow queue length balance: enqueue again and drain per-flow.
    for (UInt64 flow = 1; flow <= 10; ++flow) {
        for (UInt32 i = 0; i < 30; ++i) {
            CHECK(0 == q->ops->enqueue(q, flow, MakePacket(100)));
        }
    }
    now = 2000;
    // Serve 30 packets per flow round-robin: after 30 full rotations each
    // flow was served equally; DRR deficit may delay some rotations, so
    // drain in rotations of 10 until each flow has served 30 times.
    UInt32 served_rounds = 0;
    guard = 0;
    while (served_rounds < 30) {
        bool progressed = false;
        for (UInt32 f = 0; f < 10; ++f) {
            xtcp::buf::BufRef out = q->ops->dequeue(q, now, NULLPTR);
            if (!out.IsEmpty()) {
                ++served[f + 1];
                progressed = true;
            }
        }
        if (progressed) {
            ++served_rounds;
            guard = 0;
        } else {
            now += 1;
            if (100000 < ++guard) {
                break;
            }
        }
    }
    UInt64 min_s = ~0ull, max_s = 0;
    for (UInt64 f = 1; f <= 10; ++f) {
        if (served[f] < min_s) min_s = served[f];
        if (served[f] > max_s) max_s = served[f];
    }
    CHECK(30 == served_rounds);
    CHECK((max_s - min_s) <= 2);  // DRR balance within 2 packets
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqManyFlows() {
    // rigorous per-bucket fairness with 100 flows.
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    constexpr UInt32 kFlows = 50;
    constexpr UInt32 kPktsPerFlow = 10;
    for (UInt32 flow = 1; flow <= kFlows; ++flow) {
        for (UInt32 i = 0; i < kPktsPerFlow; ++i) {
            xtcp::buf::BufRef p = MakePacket(100);
            std::memcpy(p.Data(), &flow, sizeof(flow));
            CHECK(0 == q->ops->enqueue(q, flow, std::move(p)));
        }
    }

    UInt32 served[kFlows + 1] = {};
    TimePoint now = 5000;
    UInt32 total = 0;
    UInt32 guard = 0;
    while (q->ops->has_backlog(q)) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, now, NULLPTR);
        if (!out.IsEmpty()) {
            UInt32 fid = 0;
            std::memcpy(&fid, out.Data(), sizeof(fid));
            if (1 <= fid && fid <= kFlows) {
                ++served[fid];
            }
            ++total;
            guard = 0;
        } else {
            now += 1;
            if (1000000 < ++guard) {
                break;
            }
        }
    }
    CHECK(total == kFlows * kPktsPerFlow);

    UInt32 min_s = ~0u, max_s = 0;
    for (UInt32 f = 1; f <= kFlows; ++f) {
        if (served[f] < min_s) min_s = served[f];
        if (served[f] > max_s) max_s = served[f];
    }
    CHECK((max_s - min_s) <= 3);
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqPacing() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = true;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    // One flow at 1 Gbps; small packets keep deficit out of the way.
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(0 == q->ops->set_pacing_rate(q, 1, 1000000000ull));

    TimePoint next = 0;
    xtcp::buf::BufRef out = q->ops->dequeue(q, 100000, &next);
    CHECK(!out.IsEmpty());
    CHECK(next >= 100000);  // 100 bytes at 1Gbps = 0.8us, rounds to 0

    // Second packet must wait until next_time.
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    out = q->ops->dequeue(q, next - 1, &next);
    CHECK(out.IsEmpty());
    out = q->ops->dequeue(q, next, &next);
    CHECK(!out.IsEmpty());
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqPacingRateChange() {
    // Audit m2: raising the rate must clear the stale (slow) pacing
    // deadline - otherwise the next packet is gated for up to len*8/old_rate
    // (a 100-byte packet at 1 B/s = 800 s of spurious stall).
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = true;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));  // flow created here
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));  // this one gets paced
    CHECK(0 == q->ops->set_pacing_rate(q, 1, 1));  // 1 B/s: deadly slow
    TimePoint next = 0;
    xtcp::buf::BufRef out = q->ops->dequeue(q, 100000, &next);
    CHECK(!out.IsEmpty());      // first packet: no prior deadline, sends now
    CHECK(next > 100000);       // its deadline (100 bytes at 1 B/s)
    out = q->ops->dequeue(q, next - 1, &next);
    CHECK(out.IsEmpty());       // second packet paced by the slow deadline
    CHECK(next > 100000);       // the (old, slow) deadline is reported

    // Raise the rate: the stale deadline must not gate the packet.
    CHECK(0 == q->ops->set_pacing_rate(q, 1, 1000000000ull));
    out = q->ops->dequeue(q, next - 1, &next);  // BEFORE the old deadline
    CHECK(!out.IsEmpty());  // CORE: the stale slow-rate deadline was cleared
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqDeficitRotation() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    // Deficit quantum is 1500 bytes; a 1000-byte packet leaves 500 credit,
    // so a second 1000-byte packet needs one rotation (deficit += quantum).
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(1000)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(1000)));

    xtcp::buf::BufRef out = q->ops->dequeue(q, 1000, NULLPTR);
    CHECK(!out.IsEmpty());  // first packet: deficit 1500 -> 500

    out = q->ops->dequeue(q, 1001, NULLPTR);
    CHECK(out.IsEmpty());   // deficit 500 < 1000: rotate, no packet

    out = q->ops->dequeue(q, 1002, NULLPTR);
    CHECK(!out.IsEmpty());  // deficit now 2000 >= 1000
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqLimits() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.max_flow_queue = 3;
    params.max_global_queue = 1000;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100)));  // flow limit

    // Other flows are unaffected.
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100)));
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqChange() {
    // Audit m3: FqChange applies new limits to NEW enqueues only -
    // already-queued segments above a shrunken limit stay until drained.
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.max_flow_queue = 3;
    params.max_global_queue = 1000;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));

    // Shrink the flow limit below the already-queued count.
    params.max_flow_queue = 1;
    CHECK(0 == q->ops->change(q, &params));
    // New enqueues are gated by the NEW limit...
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100)));
    // ...but the 3 queued segments remain and drain normally (not trimmed).
    for (UInt32 i = 0; i < 3; ++i) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, 1000 + i, NULLPTR);
        CHECK(!out.IsEmpty());
    }
    // After the drain, the new limit admits one more.
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100)));
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100)));
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFqGsoCounts() {
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.max_flow_queue = 6;  // exactly one GSO super-segment of 6
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != q);

    // A GSO super-segment of 6 sub-segments counts as 6 against the limit.
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(8760, 6)));
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100)));  // 6 + 1 > 6
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100)));   // other flow fine
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFifoSample() {
    xtcp::qdisc::RegisterFifoSample();
    xtcp::qdisc::QdiscParams params;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fifo", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(10)));
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(20)));
    CHECK(q->ops->has_backlog(q));
    xtcp::buf::BufRef out = q->ops->dequeue(q, 0, NULLPTR);
    CHECK(!out.IsEmpty());
    CHECK(10 == out.Len());
    xtcp::qdisc::DestroyQdisc(q);
}

int main() {
    xtcp::buf::InitPools();
    TestRegistry();
    TestFqOrdering();
    TestFqFairness();
    TestFqManyFlows();
    TestFqPacing();
    TestFqPacingRateChange();
    TestFqDeficitRotation();
    TestFqLimits();
    TestFqChange();
    TestFqGsoCounts();
    TestFifoSample();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_fq: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_fq: all passed\n");
    return 0;
}

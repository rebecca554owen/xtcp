/**
 * @file test_qdisc_cake.cpp
 * @brief cake qdisc semantics (sch_cake core subset): per-flow FIFO queues
 *        with DRR rotation (flow fairness), Cobalt AQM (Blue probability +
 *        CoDel control-law drops when sojourn stays above target for one
 *        interval), and backpressure (per-flow + global caps).
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

static xtcp::buf::BufRef MakePacket(UInt32 len, UInt32 tag) noexcept {
    xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(len);
    if (!p.IsEmpty()) {
        p.SetLen(len);
        std::memcpy(p.Data(), &tag, sizeof(tag));
    }
    return p;
}

static UInt32 ReadTag(const xtcp::buf::BufRef& p) {
    UInt32 v = 0;
    std::memcpy(&v, p.Data(), sizeof(v));
    return v;
}

/** DRR: interleaved flows drain in round-robin order (per-flow FIFO kept). */
static void TestCakeFairness() {
    xtcp::qdisc::RegisterCake();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("cake", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 10)));
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 20)));
    CHECK(0 == q->ops->enqueue(q, 3, MakePacket(100, 30)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 11)));
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 21)));
    CHECK(0 == q->ops->enqueue(q, 3, MakePacket(100, 31)));

    UInt32 expect[6] = {10, 20, 30, 11, 21, 31};
    for (UInt32 i = 0; i < 6; ++i) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, 0, NULLPTR);
        CHECK(!out.IsEmpty());
        CHECK(expect[i] == ReadTag(out));
    }
    CHECK(!q->ops->has_backlog(q));
    xtcp::qdisc::DestroyQdisc(q);
}

/** Cobalt: once sojourn has stayed above target for one interval, the
 *  over-target dequeue drops the head (Blue probability also ramps). */
static void TestCakeCobaltDrop() {
    xtcp::qdisc::RegisterCake();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    params.target_us = 5000;
    params.interval_us = 20000;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("cake", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 10)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 11)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 12)));
    const TimePoint t0 = xtcp::qdisc::NowUs();

    // t0: sojourn ~ 0 -> normal emit.
    xtcp::buf::BufRef out = q->ops->dequeue(q, t0, NULLPTR);
    CHECK(!out.IsEmpty());
    CHECK(10 == ReadTag(out));

    // t0 + 26ms: first over-target dequeue records first_above, emits.
    out = q->ops->dequeue(q, t0 + 26000, NULLPTR);
    CHECK(!out.IsEmpty());
    CHECK(11 == ReadTag(out));

    // t0 + 52ms: over target for >= one interval -> Cobalt drops the head.
    out = q->ops->dequeue(q, t0 + 52000, NULLPTR);
    CHECK(out.IsEmpty());
    CHECK(!q->ops->has_backlog(q));
    xtcp::qdisc::DestroyQdisc(q);
}

/** Backpressure: per-flow and global caps reject; remove_flow reclaims. */
static void TestCakeBackpressure() {
    xtcp::qdisc::RegisterCake();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    params.max_flow_queue = 3;
    params.max_global_queue = 5;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("cake", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 0)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 1)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 2)));  // flow cap 3: fits
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100, 3))); // flow cap exceeded
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 4)));  // total 4
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 5)));  // total 5 = global cap
    CHECK(-1 == q->ops->enqueue(q, 2, MakePacket(100, 6))); // global cap exceeded

    // remove_flow reclaims queued segments (drop count returned).
    const int dropped = q->ops->remove_flow(q, 1);
    CHECK(3 == dropped);  // flow 1 held 3 packets (tags 0,1,2)
    xtcp::qdisc::DestroyQdisc(q);
}

/** Single flow keeps FIFO order. */
static void TestCakeFifoPerFlow() {
    xtcp::qdisc::RegisterCake();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("cake", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 9, MakePacket(100, 100)));
    CHECK(0 == q->ops->enqueue(q, 9, MakePacket(100, 101)));
    CHECK(0 == q->ops->enqueue(q, 9, MakePacket(100, 102)));
    for (UInt32 i = 0; i < 3; ++i) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, 0, NULLPTR);
        CHECK(!out.IsEmpty());
        CHECK(100u + i == ReadTag(out));
    }
    xtcp::qdisc::DestroyQdisc(q);
}

int main() {
    xtcp::buf::InitPools();
    TestCakeFairness();
    TestCakeCobaltDrop();
    TestCakeBackpressure();
    TestCakeFifoPerFlow();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_qdisc_cake: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_qdisc_cake: all passed\n");
    return 0;
}

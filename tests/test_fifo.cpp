/**
 * @file test_fifo.cpp
 * @brief FIFO qdisc semantics: strict enqueue/dequeue order (FIFO, flow
 *        agnostic), backpressure (global cap rejection), and contrast with
 *        the default FQ (per-flow separation/rotation vs a single shared
 *        queue). Only a smoke test existed before.
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

static void TestFifoOrdering() {
    xtcp::qdisc::RegisterFifoSample();
    xtcp::qdisc::QdiscParams params;
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fifo", params);
    CHECK(NULLPTR != q);

    // Enqueue interleaved flows; FIFO must preserve global arrival order.
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 0)));
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 1)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 2)));
    CHECK(0 == q->ops->enqueue(q, 3, MakePacket(100, 3)));
    CHECK(q->ops->has_backlog(q));

    for (UInt32 i = 0; i < 4; ++i) {
        xtcp::buf::BufRef out = q->ops->dequeue(q, 0, NULLPTR);
        CHECK(!out.IsEmpty());
        CHECK(i == ReadTag(out));
    }
    CHECK(!q->ops->has_backlog(q));
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFifoBackpressure() {
    xtcp::qdisc::RegisterFifoSample();
    xtcp::qdisc::QdiscParams params;
    params.max_global_queue = 2;  // tiny cap
    xtcp::qdisc::XtcpQdisc* q = xtcp::qdisc::CreateQdisc("fifo", params);
    CHECK(NULLPTR != q);

    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 0)));
    CHECK(0 == q->ops->enqueue(q, 1, MakePacket(100, 1)));
    CHECK(-1 == q->ops->enqueue(q, 1, MakePacket(100, 2)));  // full -> reject
    CHECK(-1 == q->ops->enqueue(q, 2, MakePacket(100, 3)));  // other flow also rejected

    // Draining restores capacity.
    xtcp::buf::BufRef out = q->ops->dequeue(q, 0, NULLPTR);
    CHECK(!out.IsEmpty());
    CHECK(0 == ReadTag(out));
    CHECK(0 == q->ops->enqueue(q, 2, MakePacket(100, 4)));

    // Reset empties the queue.
    q->ops->reset(q);
    CHECK(!q->ops->has_backlog(q));
    xtcp::qdisc::DestroyQdisc(q);
}

static void TestFifoVsFq() {
    xtcp::qdisc::RegisterFifoSample();
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;

    xtcp::qdisc::XtcpQdisc* fifo = xtcp::qdisc::CreateQdisc("fifo", params);
    xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != fifo && NULLPTR != fq);

    // Same arrival pattern (two flows, one packet each): FQ keeps flows
    // separate (per-flow ordering), FIFO shares a single queue. With equal
    // single packets the drain order is identical; the difference is the
    // per-flow cap: FIFO has no per-flow limit, FQ honors max_flow_queue.
    xtcp::qdisc::QdiscParams strict_params;
    strict_params.max_flow_queue = 1;
    strict_params.max_global_queue = 1000;
    strict_params.pacing_enabled = false;
    xtcp::qdisc::XtcpQdisc* fq_strict = xtcp::qdisc::CreateQdisc("fq", strict_params);
    CHECK(NULLPTR != fq_strict);

    CHECK(0 == fifo->ops->enqueue(fifo, 1, MakePacket(100, 10)));
    CHECK(0 == fifo->ops->enqueue(fifo, 1, MakePacket(100, 11)));
    CHECK(0 == fifo->ops->enqueue(fifo, 1, MakePacket(100, 12)));  // FIFO: no per-flow cap

    CHECK(0 == fq_strict->ops->enqueue(fq_strict, 1, MakePacket(100, 20)));
    CHECK(-1 == fq_strict->ops->enqueue(fq_strict, 1, MakePacket(100, 21)));  // flow cap hit
    CHECK(0 == fq_strict->ops->enqueue(fq_strict, 2, MakePacket(100, 22)));   // other flow fine

    // FIFO global cap, by contrast, spans all flows (tested above).
    xtcp::qdisc::DestroyQdisc(fifo);
    xtcp::qdisc::DestroyQdisc(fq);
    xtcp::qdisc::DestroyQdisc(fq_strict);
}

int main() {
    xtcp::buf::InitPools();
    TestFifoOrdering();
    TestFifoBackpressure();
    TestFifoVsFq();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_fifo: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_fifo: all passed\n");
    return 0;
}

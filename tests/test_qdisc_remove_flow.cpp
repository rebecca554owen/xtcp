/**
 * @file test_qdisc_remove_flow.cpp
 * @brief remove_flow coverage (qdisc audit gap: the path had ZERO tests):
 *        with an FQ mounted, a closed connection's still-queued segments
 *        must be dropped by the stack's reclaim (remove_flow) - the FQ's
 *        backlog must clear and the stack's tx counter must decrease by the
 *        dropped count. Idempotent double-remove returns 0.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

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
    for (UInt32 round = 0; round < 3000; ++round) {
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
    xtcp::qdisc::XtcpQdisc* fq = NULLPTR;
    {
        xtcp::qdisc::RegisterFqDefault();
        xtcp::qdisc::QdiscParams params;
        params.pacing_enabled = true;  // paced: segments stay queued
        fq = xtcp::qdisc::CreateQdisc("fq", params);
        CHECK(NULLPTR != fq);

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
        stack_b.SetTxQdisc(fq);

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40199;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9099;
        CHECK(stack_b.Listen(b_local));
        UInt64 conn_b = 0;
        stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            conn_b = id;
            return true;
        });
        std::atomic<UInt64> b_recv{0};
        stack_b.SetRecvHandler([&stack_b, &b_recv](UInt64 id, const Byte* d, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            stack_b.Send(id, d, len);  // echo
        });

        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);

        // Pace B's flow very slowly (1 KB/s): the echoed segments stay
        // queued in the FQ for the duration of the test.
        CHECK(0 == fq->ops->set_pacing_rate(fq, conn_b, 1000));

        // A sends 32 KB; B echoes it into the paced FQ (1 KB/s: the echo
        // segments stay queued for the duration of the test).
        Byte payload[32768];
        std::memset(payload, 0x5A, sizeof(payload));
        CHECK(stack_a.Send(conn_a, payload, sizeof(payload)));
        // The flush emits on the first PollAckTimers round; a second pump
        // round delivers the emitted segments (a single Pump returns as soon
        // as nothing moved - which is BEFORE the flush segments appear).
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        stack_b.PollAckTimers();
        const bool backlog_before = (NULLPTR != fq->ops->has_backlog) && fq->ops->has_backlog(fq);
        std::fprintf(stderr, "[qdisc-remove-flow] backlog before close=%d\n", backlog_before ? 1 : 0);
        CHECK(backlog_before);  // the echo is genuinely queued
        const UInt64 tx_before = stack_b.TxCount();

        // A aborts (RST - no FIN needed, so nothing must reach A through
        // the paced FQ): B's connection closes on the valid RST and the
        // PollAckTimers reclaim must drop B's queued echo segments via
        // remove_flow (a graceful FIN exchange would deadlock the test -
        // B's FIN would queue behind the paced echo backlog).
        stack_a.Abort(conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_b.PollAckTimers();
        stack_b.PollAckTimers();
        const bool backlog_after = (NULLPTR != fq->ops->has_backlog) && fq->ops->has_backlog(fq);
        const UInt64 tx_after = stack_b.TxCount();
        std::fprintf(stderr, "[qdisc-remove-flow] backlog after close=%d tx %llu -> %llu\n",
                     backlog_after ? 1 : 0,
                     (unsigned long long)tx_before, (unsigned long long)tx_after);
        CHECK(!backlog_after);        // CORE: queued segments dropped by remove_flow
        CHECK(tx_after < tx_before);  // CORE: tx counter subtracted (M4)
        CHECK(0 == stack_b.ConnectionCount());

        // Idempotent double-remove returns 0 (unknown flow).
        CHECK(0 == fq->ops->remove_flow(fq, conn_b));
    }
    // The qdisc is owned by the test, not the stack: destroy it before pool
    // shutdown so ASan sees no outstanding FqPrivate allocation.
    if (NULLPTR != fq) {
        xtcp::qdisc::DestroyQdisc(fq);
        fq = NULLPTR;
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QDISC_REMOVE_FLOW: FAILED (%d)\n" : "QDISC_REMOVE_FLOW: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

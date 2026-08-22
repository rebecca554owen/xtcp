/**
 * @file test_pacing_flush.cpp
 * @brief Regression: FlushPendingSend must respect the pacing gate.
 *
 * Bug (tcp_fsm.cpp:1440-1504): SendData checks `0 < pacing_rate &&
 * now < pacing_deadline_` before sending (1252-1253), but FlushPendingSend
 * only SETS pacing_deadline_ after each segment (1499-1501) and never checks
 * it. Buffered data (pending_send_) is flushed on every ACK/poll round
 * (OnAckReceived 1076, OnPoll 1375), so a rate-based CC's pacing limit is
 * bypassed entirely: the flush bursts a full congestion window per round.
 *
 * The pacing gate is made deterministically observable by plugging a custom
 * CC whose init fixes pacing_rate to a low value. Reno's derived rate
 * (cwnd_bytes*1e6/srtt_) on a zero-latency manual backend is astronomically
 * high, so the deadline never binds - not observable. With a fixed low rate
 * the first FlushPendingSend call must emit exactly one MSS (the pacing
 * deadline for the next segment is still in the future); before the fix it
 * emits the whole cwnd (10 MSS).
 *
 * Simplified integrity scenario (default Reno): a single large send is
 * buffered whole (len > payload_cap), then drained on the ACK/poll clock;
 * every byte must arrive intact under window sliding (no loss, no overshoot).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/cc/cc.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, 0x0800);
        if (2000 < ++guard) {
            break;
        }
    }
}

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

namespace {
    /** Fixed low pacing rate so the flush gate binds deterministically. */
    constexpr UInt64 kPacingRate = 1000;  // bytes/sec -> 1460B segment = 1.46 s

    void PacedFlushInit(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->pacing_rate = kPacingRate;
    }

    /** Minimal CC: only fixes pacing_rate; leaves cwnd/window defaults. */
    const xtcp::cc::XtcpCongestionOps kPacedFlush = {
        "paced_flush",   // name
        PacedFlushInit,  // init
        NULLPTR,         // release
        NULLPTR,         // ssthresh
        NULLPTR,         // cong_avoid
        NULLPTR,         // set_state
        NULLPTR,         // cwnd_event
        NULLPTR,         // pkts_acked
        NULLPTR,         // undo_cwnd
        NULLPTR,         // cong_control
        NULLPTR,         // reinit_ssthresh
        0,               // flags
    };
}

/**
 * @brief The pacing gate: one flush round must emit exactly one MSS.
 *
 * A single 60 KB send is buffered whole into pending_send_ (len > MSS).
 * After ONE PollAckTimers round the first FlushPendingSend call fires.
 *   - fixed: pacing_deadline_ is set for the first segment and is still in
 *     the future -> the loop re-queues the remainder, one MSS emitted.
 *   - buggy: pacing is never checked -> a full cwnd (10 MSS) bursts out.
 *
 * The pacing rate itself is observable via XtcpStack::ConnPacingRate.
 */
static void TestPacingGate() {
    constexpr UInt32 kTotal = 60 * 1024;
    constexpr UInt32 kMss = 1460;

    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    CHECK(stack_a.SetCongestionControl(conn, "paced_flush"));
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);

    // pacing_rate is observable via ConnPacingRate (ConnStats-family).
    CHECK(kPacingRate == stack_a.ConnPacingRate(conn));

    std::string payload(kTotal, 0);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<char>((i * 13 + 5) & 0xFF);
    }
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()), kTotal));

    // One flush round, no ACK pumped back, no wall-clock sleep: the pacing
    // deadline for the first segment (1.46 s) cannot have elapsed.
    stack_a.PollAckTimers();
    Pump(backend_a, backend_b);

    // Exactly one MSS may leave under the pacing gate; the rest re-queues.
    CHECK(received.size() == kMss);
    std::fprintf(stderr, "[pacing_flush] gate: one flush emitted %u bytes (expect %u = 1 MSS)\n",
                 (UInt32)received.size(), kMss);
}

/**
 * @brief Simplified integrity check (default Reno): a large buffered send is
 *        fully delivered under window sliding, with no loss or overshoot.
 */
static void TestLargeFlushIntegrity() {
    constexpr UInt32 kTotal = 60 * 1024;

    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);

    std::string payload(kTotal, 0);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<char>((i * 13 + 5) & 0xFF);
    }
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()), kTotal));

    // Drain on the ACK/poll clock: buffered flush rides the freed window.
    for (UInt32 i = 0; i < 500 && received.size() < kTotal; ++i) {
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_b.PollAckTimers();
        stack_a.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(kTotal == received.size());
    CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
    std::fprintf(stderr, "[pacing_flush] integrity: %u/%u bytes, %s\n",
                 (UInt32)received.size(), kTotal,
                 (kTotal == received.size() && 0 == std::memcmp(received.data(), payload.data(), kTotal))
                     ? "OK" : "MISMATCH");
}

int main() {
    xtcp::buf::InitPools();
    CHECK(xtcp::cc::RegisterCongestionControl(kPacedFlush));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("paced_flush"));

    TestPacingGate();
    TestLargeFlushIntegrity();

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PACING_FLUSH: FAILED (%d)\n" : "PACING_FLUSH: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

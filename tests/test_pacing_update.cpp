/**
 * @file test_pacing_update.cpp
 * @brief Regression: a stale pacing deadline must not gate sends after the
 *        CC raises pacing_rate.
 *
 * Bug (fixed at tcp_fsm.cpp:1118-1121): OnAckReceived applies the ACK/rate
 * sample to the connection CC (cc_ops_ branch) and then resets
 * pacing_deadline_ = 0. Before the fix, the deadline set under the OLD (small)
 * pacing_rate survived the rate update: with a 100 B/s CC, one 1460 B segment
 * arms pacing_deadline_ = now + 14.6 s, and every FlushPendingSend re-check
 * (tcp_fsm.cpp:1479, `now < pacing_deadline_`) re-queues the buffer for the
 * whole stale window - the flow stalls for ~14.6 s PER SEGMENT (minutes for
 * a 60 KB send) even though the CC has raised the rate to 10 MB/s.
 *
 * Deterministic observation: a self-registered CC whose init fixes pacing_rate
 * to 100 B/s, and whose cong_control hook (called on every ACK rate sample)
 * raises it to 10 MB/s. A first small send goes direct and arms the far
 * deadline; the rest is buffered behind it. On the ACK the CC updates the rate
 * and the (fixed) cc_ops_ branch clears the stale deadline, so the buffered
 * data drains on the poll/ACK clock instead of waiting out 14.6 s/segment.
 *
 * Core assertions: the transmission completes (bytes + content intact) and is
 * NOT stalled by the stale deadline (bounded wall-clock budget far below the
 * old 14.6 s/segment window).
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
    /** Low rate: one 1460 B segment arms a 14.6 s pacing deadline. */
    constexpr UInt64 kPacingLow  = 100;  // bytes/sec
    /** High rate: 10 MB/s -> a 1460 B segment needs only 146 us. */
    constexpr UInt64 kPacingHigh = 10 * 1000 * 1000;

    void PacedUpdateInit(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->pacing_rate = kPacingLow;
    }

    /** Every ACK rate sample raises the rate to the high value. */
    void PacedUpdateCongControl(xtcp::cc::XtcpConnCc* sk,
                                const xtcp::cc::RateSample* rs) noexcept {
        (void)rs;
        sk->pacing_rate = kPacingHigh;
    }

    /** Minimal rate-based CC: low on init, high after the first ACK. */
    const xtcp::cc::XtcpCongestionOps kPacedUpdate = {
        "paced_update",        // name
        PacedUpdateInit,       // init
        NULLPTR,               // release
        NULLPTR,               // ssthresh
        NULLPTR,               // cong_avoid
        NULLPTR,               // set_state
        NULLPTR,               // cwnd_event
        NULLPTR,               // pkts_acked
        NULLPTR,               // undo_cwnd
        PacedUpdateCongControl,  // cong_control (rate-based path)
        NULLPTR,               // reinit_ssthresh
        0,                     // flags
    };
}

/**
 * @brief A stale (low-rate) pacing deadline must not gate a raised rate.
 *
 *  1. CC init fixes pacing_rate = 100 B/s.
 *  2. A first 1460 B send goes direct and arms pacing_deadline_ = now + 14.6 s.
 *  3. The remaining 60 KB is buffered behind that deadline.
 *  4. The ACK for the first segment reaches OnAckReceived: cong_control raises
 *     pacing_rate to 10 MB/s and the cc_ops_ branch resets pacing_deadline_.
 *  5. The buffered data drains on the poll/ACK clock.
 *
 * Before the fix the stale 14.6 s deadline gates the flush on every round
 * (tcp_fsm.cpp:1479) - only the first 1460 B ever arrives inside the bounded
 * drain budget. After the fix the whole 60 KB arrives in well under a second.
 */
static void TestStaleDeadlineReset() {
    constexpr UInt32 kFirst = 1460;         // direct send -> arms far deadline
    constexpr UInt32 kTotal = 60 * 1024;    // rest buffers behind the deadline
    constexpr UInt32 kMaxIterations = 100;  // ~1.6 s wall clock (<< 14.6 s)
    constexpr double kMaxElapsedSec = 5.0;  // "not gated for minutes" bound

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
    local.port = 40180;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 9130;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    CHECK(stack_a.SetCongestionControl(conn, "paced_update"));
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);

    // The CC's init fixed the low rate; it is observable via ConnPacingRate.
    CHECK(kPacingLow == stack_a.ConnPacingRate(conn));

    std::string payload(kTotal, 0);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<char>((i * 13 + 5) & 0xFF);
    }

    // First chunk: direct send (window open, no deadline yet) -> the 100 B/s
    // rate arms pacing_deadline_ = now + 14.6 s for the NEXT segment.
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()), kFirst));
    // Rest: now < pacing_deadline_ (and cwnd), so it buffers whole.
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()) + kFirst,
                       kTotal - kFirst));

    const auto t0 = std::chrono::steady_clock::now();
    for (UInt32 i = 0; i < kMaxIterations && received.size() < kTotal; ++i) {
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_b.PollAckTimers();  // fire B's delayed ACK for the first segment
        stack_a.PollAckTimers();  // poll clock also flushes buffered data
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double elapsed_s = std::chrono::duration<double>(t1 - t0).count();

    // The CC saw the ACK and raised the rate to the high value.
    CHECK(kPacingHigh == stack_a.ConnPacingRate(conn));
    // Transmission recovered: every byte arrived, nothing is gated.
    CHECK(kTotal == received.size());
    CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
    // Explicit "not stuck for minutes" bound: the stale 14.6 s/segment window
    // would blow this budget by an order of magnitude.
    CHECK(elapsed_s < kMaxElapsedSec);

    std::fprintf(stderr,
                 "[pacing_update] stale deadline: %u/%u bytes in %.3f s, rate=%llu B/s\n",
                 (UInt32)received.size(), kTotal, elapsed_s,
                 (unsigned long long)stack_a.ConnPacingRate(conn));
}

int main() {
    xtcp::buf::InitPools();
    CHECK(xtcp::cc::RegisterCongestionControl(kPacedUpdate));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("paced_update"));

    TestStaleDeadlineReset();

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PACING_UPDATE: FAILED (%d)\n" : "PACING_UPDATE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

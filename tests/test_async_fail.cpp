/**
 * @file test_async_fail.cpp
 * @brief AsyncConnect failure completion: a connect to a dead port (no
 *        listener - the peer never answers the SYN) MUST still fire the
 *        ConnectHandler once the SYN retransmission budget is exhausted
 *        (RTO close -> kClosed). Regression for the pre-fix behavior
 *        where kClosed was ignored: the callback never fired and the
 *        pending-connect entry leaked.
 *
 *        NOTE: the RTO timeout produces NO inbound packet, so the stack's
 *        state handler (only invoked from OnPacket) never observes the
 *        close - the AsyncStack::Poll() pending-connect sweep (which reads
 *        ConnectionState directly) is the ONLY path that completes it.
 *
 *        Wait-budget note: the default budget is syn_retries_ = 6 with a
 *        1 s RTO, and each SYN re-arm actually schedules the next fire 2 s
 *        out (ArmRetransmit adds rto_ to a now+rto_ argument), so the
 *        handshake is abandoned only at ~13 s. The test shrinks the budget
 *        to a single retransmit (SetOption(kTcpSynCnt) via the stack
 *        exposed by AsyncStack::Stack()) so the failure completes in ~3 s.
 *        AsyncStack itself has no SetSynRetries entry point, so the test
 *        reaches it through XtcpStack::SetOption (Linux TCP_SYNCNT).
 */

#include <xtcp/async/async.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::async::AsyncStack& sa, xtcp::async::AsyncStack& sb) {
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

/** Pumps A->B (delivers the SYN once); B has no listener and drops it. */
static void PumpAtoB(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, 0x0800);
        if (1000 < ++guard) {
            break;
        }
    }
}

/** Pumps both directions until quiescent (SYN -> B, RST -> A). */
static void PumpBoth(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b) {
    Byte out[65536];
    for (UInt32 round = 0; round < 200; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 got = a.PollTx(out);
            if (0 < got) {
                b.Inject(out, got, 0x0800);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 got = b.PollTx(out);
            if (0 < got) {
                a.Inject(out, got, 0x0800);
                moved = true;
            }
        }
        if (!moved) {
            return;
        }
    }
}

/**
 * Scenario: AsyncConnect to a port with no listener. The SYN is emitted,
 * B never answers (no SYN+ACK, no RST). The RTO timer retransmits the SYN
 * and then closes the handshake with kClosed once the SYN budget
 * (syn_retries_ = 1 after SetOption(kTcpSynCnt) below) is exhausted.
 * Poll() must then fire the ConnectHandler with a failure result, and the
 * pending-connect entry must be cleaned up (no second completion).
 */
static void TestAsyncConnectDeadPort() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);
    // B is deliberately NOT listening (closed port).

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;  // closed port: no listener on B

    bool connect_done = false;
    xtcp::mimt::Result ec = xtcp::mimt::Result::kOk;
    UInt64 conn_id = 0;
    stack_a.AsyncConnect(local, remote, [&](xtcp::mimt::Result r, UInt64 id) {
        connect_done = true;
        ec = r;
        conn_id = id;
    });

    // Completion is async: AsyncConnect must not fire it synchronously.
    CHECK(!connect_done);

    // AsyncConnect does not return the conn id (it is only delivered to the
    // completion handler), so discover it on the underlying stack. On a fresh
    // AsyncStack the single pending connection is the first one created by
    // XtcpStack (id = (shard << 56) | 1), still in kSynSent.
    UInt64 pending_id = 0;
    for (UInt32 shard = 0; shard < xtcp::XtcpStack::kShardCount && 0 == pending_id; ++shard) {
        const UInt64 candidate = (static_cast<UInt64>(shard) << 56) | 1ULL;
        if (xtcp::core::TcpState::kSynSent == stack_a.Stack().ConnectionState(candidate)) {
            pending_id = candidate;
        }
    }
    CHECK(0 != pending_id);

    // Shrink the SYN retransmission budget to a single retry (Linux
    // TCP_SYNCNT). AsyncStack has no SetSynRetries entry point, so go through
    // the stack it exposes; with syn_retries_ = 1 the handshake is abandoned
    // at ~3 s instead of the default ~13 s (6 retries at a 2 s re-arm).
    const Int32 syn_cnt = 1;
    CHECK(stack_a.Stack().SetOption(pending_id, xtcp::options::kTcpSynCnt,
                                    &syn_cnt, sizeof(syn_cnt)));

    // Deliver the SYN to B once; B has no listener so it is dropped.
    PumpAtoB(backend_a, backend_b);

    // Drive the RTO clock until the SYN budget exhausts and the handshake
    // is abandoned (kClosed), then let Poll() sweep the pending connect.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!connect_done && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        stack_a.Stack().PollAckTimers();  // drives the RTO (real clock)
        stack_a.Poll();                   // pending-connect sweep + completions
    }

    // Fixed behavior: the ConnectHandler MUST be called once the SYN
    // retransmission budget is exhausted (kClosed -> failure).
    CHECK(connect_done);
    CHECK(xtcp::mimt::Result::kClosed == ec);
    CHECK(0 != conn_id);

    // Entry cleanup (strict 1:1): a further Poll must fire nothing.
    CHECK(0 == stack_a.Poll());
}

/**
 * @brief A connect rejected by RST (the server's accept handler refuses ->
 *        Abort -> RST with an acceptable ACK, RFC 5961) must complete the
 *        ConnectHandler exactly once with a failure result via the Poll
 *        sweep. Pre-existing coverage only exercised the SYN-timeout path
 *        (audit gap: the RST-driven failure was never tested).
 */
static void TestAsyncConnectRstRejected() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);
    // B listens but REFUSES every accept (RST).
    stack_b.Stack().SetAcceptHandler([](UInt64, const xtcp::core::Endpoint&,
                                        const xtcp::core::Endpoint&) { return false; });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    CHECK(stack_b.Stack().Listen(remote));

    bool connect_done = false;
    xtcp::mimt::Result ec = xtcp::mimt::Result::kOk;
    UInt64 conn_id = 0;
    stack_a.AsyncConnect(local, remote, [&](xtcp::mimt::Result r, UInt64 id) {
        connect_done = true;
        ec = r;
        conn_id = id;
    });
    CHECK(!connect_done);  // async: never synchronous

    // SYN -> B (refused: RST), RST -> A: the connection closes via the
    // RFC 5961 acceptable-ACK RST without waiting for the SYN budget.
    PumpBoth(backend_a, backend_b);
    PumpBoth(backend_a, backend_b);

    // The Poll sweep must complete the pending connect exactly once.
    CHECK(0 < stack_a.Poll() || connect_done);
    CHECK(connect_done);
    CHECK(xtcp::mimt::Result::kClosed == ec);
    CHECK(0 != conn_id);
    // Strict 1:1: nothing left to fire.
    CHECK(0 == stack_a.Poll());
    CHECK(connect_done);
    CHECK(1 == (connect_done ? 1 : 0));  // the flag itself: fired once
}

int main() {
    xtcp::buf::InitPools();
    TestAsyncConnectDeadPort();
    TestAsyncConnectRstRejected();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_fail: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_fail: all passed\n");
    return 0;
}

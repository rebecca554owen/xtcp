/**
 * @file test_retries_cap.cpp
 * @brief Data-segment retransmission cap (Linux tcp_retries2 equivalent):
 *        when the peer is permanently unresponsive, the connection gives up
 *        (Transitions Closed) after kMaxDataRetries (15) RTO retransmissions
 *        instead of retransmitting forever at the 60 s backoff ceiling.
 *
 * Two layers:
 *   1. Unit (deterministic): a raw TcpConn with a 1 ms RTO (SetRto) is
 *      driven with synthetic timer timestamps. After exactly 15 retransmits
 *      the 16th timer fire transitions the connection to Closed and the
 *      timer is disarmed - proving the retransmission-cap code path exists
 *      and fires (tcp_fsm.cpp RetransmitFront).
 *   2. Stack (end-to-end): a dual-stack A<->B link transfers partial data,
 *      then B's RxHandler is dropped (peer death). A keeps sending until its
 *      send buffer fills (Send returns false), and the RTO retransmission
 *      counter climbs while the connection is NOT prematurely closed.
 */

#include <xtcp/core/tcp.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/buf/bufref.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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

typedef std::vector<xtcp::buf::BufRef> TxLog;

static xtcp::core::TxSink MakeSink(TxLog& log) noexcept {
    return [&log](xtcp::buf::BufRef&& packet) { log.push_back(std::move(packet)); };
}

static xtcp::core::TcpConn MakeEstablishedConn(TxLog& log, UInt32 iss = 100, UInt32 irs = 200) noexcept {
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    return xtcp::core::TcpConn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
}

/**
 * @brief Deterministic unit proof of the cap: with a 1 ms RTO the connection
 *        gives up exactly at kMaxDataRetries (15) retransmissions.
 */
static void TestDataRetriesCapUnit() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeEstablishedConn(log);
    conn.SetRto(1000);  // 1 ms initial RTO (SetRto lives on TcpConn)
    const Byte data[] = { 1, 2, 3 };
    CHECK(conn.SendData(data, 3, 1000));
    CHECK(1 == log.size());               // original emission
    CHECK(0 == conn.RetransmitCount());

    // Drive the RTO timer with synthetic timestamps (deadline+1): each fire
    // is one retransmission; the 16th fire (retries already == 15) is the
    // give-up transition. No real-time waits.
    for (UInt32 i = 0; i < 40; ++i) {
        const xtcp::core::TimePoint deadline = conn.NextRetransmitTime();
        if (0 == deadline) {
            break;
        }
        conn.OnRetransmitTimer(deadline + 1);
        if (xtcp::core::TcpState::kClosed == conn.State()) {
            break;
        }
    }
    CHECK(xtcp::core::TcpState::kClosed == conn.State());
    CHECK(15 == conn.RetransmitCount());  // exactly kMaxDataRetries (15)
    CHECK(16 == log.size());              // 1 original + 15 retransmits
    CHECK(0 == conn.NextRetransmitTime());  // timer disarmed after give-up

    // The infinite-retransmit guard: nothing is emitted after Closed.
    const UInt32 before = static_cast<UInt32>(log.size());
    conn.OnRetransmitTimer(999999999);
    CHECK(static_cast<UInt32>(log.size()) == before);
    std::fprintf(stderr, "[retries-cap] unit: Closed after %u retransmits, %zu emissions\n",
                 conn.RetransmitCount(), log.size());
}

/** Pumps both directions until quiet, advancing both stacks' timers. */
static void PumpBothWays(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                         xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 500; ++round) {
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

/**
 * @brief End-to-end dead-peer scenario: partial data flows, then B's RxHandler
 *        is dropped, A keeps sending until the buffer fills (Send returns
 *        false), and the RTO retransmission counter climbs while the
 *        connection stays alive (the cap is 15, not a premature 1-retry close).
 */
static void TestDualStackDeadPeer() {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    std::string recv_b;

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
    stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 n) {
        recv_b.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8080;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    PumpBothWays(backend_a, backend_b, stack_a, stack_b);
    CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());

    // Partial data transferred before the peer dies.
    const char partial[] = "partial-transfer-before-death";
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(partial), sizeof(partial) - 1));
    for (UInt32 i = 0; i < 8; ++i) {
        PumpBothWays(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK(recv_b == partial);

    // Peer death: B's RxHandler is replaced with a drop, so A's packets are
    // never delivered to stack_b and no ACK ever returns.
    backend_b.SetRxHandler([](xtcp::ndi::Packet&&) {});

    // A keeps sending; the send buffer eventually fills (Send returns false).
    Byte chunk[4096];
    std::memset(chunk, 0xAA, sizeof(chunk));
    bool saw_full = false;
    UInt32 sent_ok = 0;
    Byte out[65536];
    for (UInt32 i = 0; i < 64; ++i) {
        if (stack_a.Send(conn, chunk, sizeof(chunk))) {
            ++sent_ok;
        } else {
            saw_full = true;
            break;  // send buffer full: further sends keep failing
        }
        // Pump A->B (dropped at the dead B) and advance A's timers.
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                backend_b.Inject(out, n, 0x0800);
            }
        }
        stack_a.PollAckTimers();
    }
    CHECK(saw_full);  // buffer-full behavior: Send returns false

    // Advance real time so A's RTO fires a few times on the dead peer.
    UInt32 retx = 0;
    for (UInt32 i = 0; i < 30; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                backend_b.Inject(out, n, 0x0800);
            }
        }
        stack_a.PollAckTimers();
        UInt32 infl = 0, cwnd = 0, ssth = 0, wnd = 0, retx_t = 0, dup = 0, fr = 0, fseq = 0, una = 0;
        UInt16 lp = 0, rp = 0;
        UInt64 rto = 0;
        stack_a.ConnStats(conn, infl, cwnd, ssth, wnd, retx_t, rto, dup, fr, fseq, una, lp, rp);
        if (0 < retx_t) {
            retx = retx_t;
            break;
        }
    }
    CHECK(0 < retx);  // RTO retransmission engaged on the dead peer

    // The cap is 15 retries: after only a few retransmissions the connection
    // must NOT have closed (a 1-retry give-up would be the bug the cap fixes).
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
    std::fprintf(stderr, "[retries-cap] stack: buffer full=%d sent_ok=%u retx=%u\n",
                 saw_full ? 1 : 0, sent_ok, retx);
}

int main() {
    xtcp::buf::InitPools();
    std::fprintf(stderr, "T: retries-cap-unit\n");
    TestDataRetriesCapUnit();
    std::fprintf(stderr, "T: retries-cap-stack\n");
    TestDualStackDeadPeer();
    std::fprintf(stderr, "T: shutdown\n");
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_retries_cap: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_retries_cap: all passed\n");
    return 0;
}

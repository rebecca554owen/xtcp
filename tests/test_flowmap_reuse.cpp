/**
 * @file test_flowmap_reuse.cpp
 * @brief Same-4-tuple reconnect with flow-map reuse: connection #2 overwrites
 *        flow_map_[key] = conn2 while connection #1 still lingers in
 *        TIME-WAIT. When the old entry is reclaimed after its 2MSL deadline,
 *        the reclamation must NOT erase conn2's routing entry - otherwise the
 *        live connection silently loses its route and every inbound segment
 *        (data AND ACK) is dropped.
 *
 *        Regression for the stack.cpp guard: the reclamation path may only
 *        erase flow_map_[key] when the entry still points at the connection
 *        being reclaimed (self-check), never blindly.
 *
 *        Scenario:
 *          1. conn1 establishes on the fixed tuple, closes into TIME-WAIT.
 *          2. conn2 establishes on the exact same tuple (flow_map overwrite).
 *          3. conn2 transfers data - B receives it all (route intact).
 *          4. The old conn1 TIME-WAIT entry is reclaimed after a short 2MSL.
 *          5. conn2 keeps transferring in BOTH directions - every segment
 *             must still be routed to conn2 (route survived the reclaim).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <unordered_set>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kClientV4  = 0x0A000001;
    constexpr UInt32 kServerV4  = 0x0A000002;
    constexpr UInt16 kClientPort = 40202;
    constexpr UInt16 kServerPort = 9101;
    // 800 ms: phases 1-3 (handshake + close + first transfer) complete well
    // before reclamation, so the conflict window is exercised deterministically.
    constexpr UInt32 kTwoMslUs  = 800000;
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

/** Drains both tx queues and polls timers; sleep_ms > 0 lets delayed-ACK
 *  (40 ms) and the 2MSL clock actually elapse. */
static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32 rounds, UInt32 sleep_ms) {
    Byte out[65536];
    for (UInt32 round = 0; round < rounds; ++round) {
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
        if (0 < sleep_ms) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
        } else if (!moved) {
            return;
        }
    }
}

/** Pumps until done() is true or max_ms of real time has elapsed. */
template <typename Fn>
static bool DrainUntil(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                       xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, Fn done, UInt32 max_ms) {
    for (UInt32 i = 0; i < max_ms; ++i) {
        Pump(a, b, sa, sb, 1, 1);
        if (done()) {
            return true;
        }
    }
    return done();
}

/** Sends len bytes on st/id in <=2048-byte chunks, pumping while the send
 *  path is window/buffer throttled. */
static bool SendAll(xtcp::XtcpStack& st, UInt64 id, const Byte* data, UInt32 len,
                    xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                    xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    UInt32 sent = 0;
    UInt32 round = 0;
    while (sent < len && 400 > round++) {
        UInt32 n = len - sent;
        if (n > 2048) {
            n = 2048;
        }
        if (!st.Send(id, data + sent, n)) {
            Pump(a, b, sa, sb, 1, 1);
            continue;
        }
        sent += n;
    }
    return sent == len;
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(kTwoMslUs);
        stack_b.SetTwoMsl(kTwoMslUs);
        Wire(backend_a, backend_b, stack_a, stack_b);

        UInt64 bytes_b = 0;  // A -> B payload delivered on B
        UInt64 bytes_a = 0;  // B -> A payload delivered on A
        stack_a.SetRecvHandler([&bytes_a](UInt64, const Byte*, UInt32 len) { bytes_a += len; });
        stack_b.SetRecvHandler([&bytes_b](UInt64, const Byte*, UInt32 len) { bytes_b += len; });

        std::vector<UInt64> b_est;
        std::unordered_set<UInt64> b_est_seen;
        stack_b.SetStateHandler([&stack_b, &b_est, &b_est_seen](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st && b_est_seen.insert(id).second) {
                b_est.push_back(id);
            }
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = kClientPort;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kServerPort;
        CHECK(stack_b.Listen(remote));

        // ---- Phase 1: conn1 on the fixed tuple, closed into TIME-WAIT. ----
        UInt64 conn1 = stack_a.Connect(local, remote);
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b, 10, 0);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));
        CHECK(1 == b_est.size());
        const UInt64 conn_b1 = b_est[0];
        stack_a.Close(conn1);
        // B's CLOSE-WAIT handler above closes conn_b1, which lets A consume
        // B's FIN and reach TIME-WAIT. The close handshake is purely
        // packet-driven, so it needs no wall-clock sleep - keep the 2MSL
        // budget (kTwoMslUs) intact for phase 4 by not over-pumping here:
        // each 1 ms sleep actually costs ~15 ms on Windows, and the previous
        // 200 rounds expired the 800 ms TIME-WAIT before the check below.
        Pump(backend_a, backend_b, stack_a, stack_b, 10, 0);
        std::fprintf(stderr, "[flowmap-reuse] phase1 conn1=%d B-count=%u\n",
                     (int)stack_a.ConnectionState(conn1), (UInt32)stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn1));
        // B's conn closed in CLOSE-WAIT and PollAckTimers reclaims closed
        // connections immediately (stack.cpp), so B-count is already 0 here.
        // Assert conn_b1's state (kClosed both while it lingers in CLOSED and
        // after it is reclaimed) rather than the count, which is robust to
        // whether the reclamation pass has run yet.
        CHECK(xtcp::core::TcpState::kClosed == stack_b.ConnectionState(conn_b1));

        // ---- Phase 2: reconnect on the exact same tuple. The new flow
        //      overwrites flow_map_[key] = conn2 while the old TIME-WAIT
        //      entry is still alive. ----
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn1));
        UInt64 conn2 = stack_a.Connect(local, remote);
        CHECK(0 != conn2);
        CHECK(conn1 != conn2);
        // Packet-driven handshake: no sleep needed, and over-pumping would
        // burn the 800 ms 2MSL window while conn1 still sits in TIME-WAIT.
        Pump(backend_a, backend_b, stack_a, stack_b, 10, 0);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn2));
        CHECK(2 == b_est.size());
        const UInt64 conn_b2 = b_est[1];
        CHECK(0 != conn_b2);
        CHECK(conn_b1 != conn_b2);
        CHECK(1 == stack_b.ConnectionCount());
        // Old entry must still be in TIME-WAIT so the reclaim/overwrite
        // conflict is genuinely exercised in phase 4.
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn1));

        // ---- Phase 3: transfer on conn2 BEFORE reclamation (route intact). ----
        constexpr UInt32 kChunk1 = 4096;
        std::vector<Byte> payload1(kChunk1);
        for (UInt32 i = 0; i < kChunk1; ++i) {
            payload1[i] = static_cast<Byte>((i * 7 + i / 3) & 0xFF);
        }
        CHECK(SendAll(stack_a, conn2, payload1.data(), kChunk1, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainUntil(backend_a, backend_b, stack_a, stack_b,
                         [&bytes_b, want = kChunk1]() { return bytes_b >= want; }, 3000));
        std::fprintf(stderr, "[flowmap-reuse] phase3 bytes_b=%llu (expect %u)\n",
                     (unsigned long long)bytes_b, kChunk1);
        CHECK(kChunk1 == bytes_b);

        // ---- Phase 4: old conn1 reaches its 2MSL deadline and is reclaimed.
        //      With the bug, reclamation blindly erases flow_map_[key] and
        //      kills conn2's route; with the fix, the self-check keeps it. ----
        const UInt64 deadline = stack_a.ConnTimeWaitDeadline(conn1);
        std::fprintf(stderr, "[flowmap-reuse] phase4 old TW deadline=%llu us\n",
                     (unsigned long long)deadline);
        bool reclaimed = false;
        for (UInt32 i = 0; i < 3000; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b, 1, 1);
            if (xtcp::core::TcpState::kTimeWait != stack_a.ConnectionState(conn1)) {
                reclaimed = true;
                break;
            }
        }
        CHECK(reclaimed);
        std::fprintf(stderr, "[flowmap-reuse] phase4 conn1=%d conn2=%d\n",
                     (int)stack_a.ConnectionState(conn1), (int)stack_a.ConnectionState(conn2));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn1));  // old entry gone
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn2));  // route survived

        // ---- Phase 5: conn2 keeps transferring AFTER the reclaim. ----
        // A -> B: B's routing delivers data, and B's ACKs must still route
        //         through A's flow_map_ back to conn2 (reclaim must not
        //         have broken this).
        constexpr UInt32 kChunk2 = 4096;
        std::vector<Byte> payload2(kChunk2);
        for (UInt32 i = 0; i < kChunk2; ++i) {
            payload2[i] = static_cast<Byte>((i * 13 + i / 5) & 0xFF);
        }
        CHECK(SendAll(stack_a, conn2, payload2.data(), kChunk2, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainUntil(backend_a, backend_b, stack_a, stack_b,
                         [&bytes_b, want = kChunk1 + kChunk2]() { return bytes_b >= want; }, 3000));
        CHECK(kChunk1 + kChunk2 == bytes_b);

        // B -> A: every inbound segment on A must be routed by A's flow_map_
        //         to conn2. This is the most direct proof the reclaim did not
        //         delete conn2's routing entry.
        constexpr UInt32 kChunk3 = 4096;
        std::vector<Byte> payload3(kChunk3);
        for (UInt32 i = 0; i < kChunk3; ++i) {
            payload3[i] = static_cast<Byte>((i * 3 + i / 7) & 0xFF);
        }
        CHECK(SendAll(stack_b, conn_b2, payload3.data(), kChunk3, backend_a, backend_b, stack_a, stack_b));
        CHECK(DrainUntil(backend_a, backend_b, stack_a, stack_b,
                         [&bytes_a, want = kChunk3]() { return bytes_a >= want; }, 3000));
        std::fprintf(stderr, "[flowmap-reuse] phase5 A->B=%llu (expect %u) B->A=%llu (expect %u)\n",
                     (unsigned long long)bytes_b, kChunk1 + kChunk2,
                     (unsigned long long)bytes_a, kChunk3);
        CHECK(kChunk3 == bytes_a);

        // ---- Teardown: A closes conn2; B's CLOSE-WAIT handler closes conn_b2. ----
        stack_a.Close(conn2);
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b, 1, 1);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FLOWMAP_REUSE: FAILED (%d)\n" : "FLOWMAP_REUSE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

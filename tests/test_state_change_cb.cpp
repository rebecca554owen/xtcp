/**
 * @file test_state_change_cb.cpp
 * @brief Audit of XtcpStack::SetStateHandler trigger semantics.
 *
 * The API documents a "Connection-state-change callback" (stack.h:35) - one
 * invocation per actual TCP state transition. This test probes the real
 * implementation and records the divergence.
 *
 * Implementation facts (verified by reading the source):
 *   - stack.cpp:979-981: state_handler_ is invoked exactly once per received
 *     packet that hits an established flow, AFTER OnSegment, reporting
 *     entry->conn->State() - the CURRENT state at packet arrival time.
 *   - stack.cpp:899: the passive-open SYN path (which creates the server
 *     connection in kSynRcvd and answers SYN+ACK) returns before reaching
 *     the handler call, so kSynRcvd is NEVER reported even though the
 *     connection passes through that state.
 *   - Timer-driven transitions (RTO -> kClosed, FIN-WAIT-2 timeout, TIME-WAIT
 *     reclaim) never invoke the handler: grep shows the only call site of
 *     state_handler_ is stack.cpp:979-980.
 *
 * Expected observation (dual stack, server-side handler):
 *   - B receives 3 packets total (SYN, handshake ACK, one 100-byte data
 *     segment). The handler fires on the 2 packets that hit the established
 *     flow: handshake ACK + data segment = 2 calls, both reporting
 *     kEstablished.
 *   - Real state changes on B: kSynRcvd -> kEstablished = 1 change.
 *   => handler_calls (2) == packets received by the established flow (2),
 *      which is > state changes (1): per-packet semantics, not per-state.
 *      The kSynRcvd transition is never reported (smoking gun).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kClientV4 = 0x0A000001;   // 10.0.0.1
    constexpr UInt32 kServerV4 = 0x0A000002;   // 10.0.0.2
    constexpr UInt16 kLocalPort = 41050;
    constexpr UInt16 kPort     = 9305;
    constexpr UInt32 kPayloadLen = 100;

    std::atomic<UInt32> g_b_packets{0};      // packets received by B's backend
    std::atomic<UInt32> g_handler_calls{0};  // state-handler invocations
    std::atomic<UInt32> g_state_counts[11] = {};  // per-state report histogram
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            g_b_packets.fetch_add(1, std::memory_order_relaxed);
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });

        UInt64 conn_b = 0;
        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });
        // The handler under audit: count every invocation and the reported
        // (current) state at that moment.
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            g_handler_calls.fetch_add(1, std::memory_order_relaxed);
            g_state_counts[static_cast<int>(st)].fetch_add(1, std::memory_order_relaxed);
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        // Captures conn_b as early as the SYN path (fires before the state
        // handler) so the test can poll B's state per pump round.
        stack_b.SetAcceptHandler([&conn_b](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            conn_b = id;
            return true;
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = kLocalPort;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);

        // Per-round pump that also counts real state changes on B by polling
        // ConnectionState(conn_b) after every round.
        UInt32 state_changes = 0;
        bool prev_set = false;
        xtcp::core::TcpState prev_state = xtcp::core::TcpState::kClosed;
        auto pollState = [&]() {
            if (0 == conn_b) {
                return;
            }
            const xtcp::core::TcpState cur = stack_b.ConnectionState(conn_b);
            if (!prev_set) {
                prev_state = cur;  // baseline right after the SYN round
                prev_set = true;
                return;
            }
            if (cur != prev_state) {
                ++state_changes;
                prev_state = cur;
            }
        };
        auto pump = [&]() -> bool {
            bool moved = false;
            Byte out[65536];
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    backend_b.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            pollState();
            return moved;
        };

        // Handshake: SYN -> B (SynRcvd, no handler call), SYN+ACK -> A,
        // ACK -> B (SynRcvd->Established, handler call #1).
        for (UInt32 round = 0; round < 500; ++round) {
            if (!pump()) {
                break;
            }
        }
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // Transfer 100 bytes: one segment -> B, handler call #2 (no state
        // change, still kEstablished).
        Byte payload[kPayloadLen];
        for (UInt32 i = 0; i < kPayloadLen; ++i) {
            payload[i] = static_cast<Byte>(i);
        }
        CHECK(stack_a.Send(conn_a, payload, kPayloadLen));
        for (UInt32 round = 0; round < 200 && received.size() < kPayloadLen; ++round) {
            pump();
        }

        const UInt32 b_packets = g_b_packets.load(std::memory_order_relaxed);
        const UInt32 calls = g_handler_calls.load(std::memory_order_relaxed);
        const UInt32 synrcvd = g_state_counts[static_cast<int>(xtcp::core::TcpState::kSynRcvd)].load(std::memory_order_relaxed);
        const UInt32 estab = g_state_counts[static_cast<int>(xtcp::core::TcpState::kEstablished)].load(std::memory_order_relaxed);
        const UInt32 closed = g_state_counts[static_cast<int>(xtcp::core::TcpState::kClosed)].load(std::memory_order_relaxed);

        std::fprintf(stderr,
                     "[state-cb] B packets=%u handler_calls=%u state_changes=%u "
                     "reported{SynRcvd=%u Established=%u Closed=%u}\n",
                     b_packets, calls, state_changes, synrcvd, estab, closed);

        // Recorded behavior: handler fires once per established-flow packet,
        // reporting the current state (always kEstablished here) - NOT once
        // per state change. kSynRcvd was visited but never reported.
        CHECK(0 < calls);
        CHECK(calls == b_packets - 1);   // every post-SYN packet -> exactly 1 call
        CHECK(1 == state_changes);       // the one real transition: SynRcvd -> Established
        CHECK(state_changes < calls);    // per-packet count exceeds per-state count
        CHECK(0 == synrcvd);             // the SynRcvd transition was never reported
        CHECK(estab == calls);           // every report carries the current state
        CHECK(0 == closed);
        CHECK(kPayloadLen == received.size());  // 100-byte transfer completed
        CHECK(0 == std::memcmp(payload, received.data(), kPayloadLen));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "STATE_CB: FAILED (%d)\n" : "STATE_CB: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

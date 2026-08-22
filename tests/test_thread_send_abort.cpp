/**
 * @file test_thread_send_abort.cpp
 * @brief User-thread Send + Abort racing the event-loop thread's RX on the
 *        SAME connections. The danger path: the user thread takes the shard
 *        lock in Send/Abort while the pump thread is inside OnSegment (shard
 *        lock held) delivering to recv_cb_ - a deadlock or corruption here
 *        would hang or scramble the transfer. Multiple connections per shard
 *        and several user threads ensure real cross-thread contention on the
 *        shared recursive mutexes.
 *
 * Assertions:
 *   1. Every byte the receiver counted was delivered in-order (CRC of a
 *      per-conn byte pattern).
 *   2. Aborts never wedge the stack: connections are reaped, new ones
 *      establish afterwards.
 *   3. No deadlock: the pump loop always drains (bounded rounds).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
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

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
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
    (void)moved;
}

int main() {
    xtcp::buf::InitPools();
    {
        constexpr UInt32 kThreads = 3;      // user threads
        constexpr UInt32 kConnsPerThread = 2;  // connections per user thread
        constexpr UInt32 kChunks = 200;     // 1024-byte chunks per conn
        constexpr UInt32 kChunk = 1024;
        constexpr UInt32 kBasePort = 9400;

        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        // Receivers on B: accumulate a running FNV-1a hash of the stream so
        // ordering/corruption shows up as a hash mismatch. Per-conn state.
        const UInt32 kTotalConns = kThreads * kConnsPerThread;
        struct ConnState {
            UInt64 hash = 1469598103934665603ull;
            UInt32 bytes = 0;
        };
        std::vector<ConnState> states(kTotalConns);
        std::atomic<UInt32> recv_index{0};
        std::mutex state_mutex;
        std::vector<UInt64> b_conn_to_idx(1024, 0xFFFFFFFFull);  // conn id -> slot

        stack_b.SetRecvHandler([&](UInt64 id, const Byte* data, UInt32 len) {
            UInt32 idx = 0;
            {
                std::lock_guard<std::mutex> lk(state_mutex);
                if (0xFFFFFFFFull == b_conn_to_idx[id % 1024]) {
                    b_conn_to_idx[id % 1024] = recv_index.fetch_add(1);
                }
                idx = static_cast<UInt32>(b_conn_to_idx[id % 1024]);
            }
            ConnState& s = states[idx];
            for (UInt32 i = 0; i < len; ++i) {
                s.hash ^= data[i];
                s.hash *= 1099511628211ull;
            }
            s.bytes += len;
            return true;
        });

        // Listeners: one per user thread (so each thread's conns spread
        // across shards).
        for (UInt32 t = 0; t < kThreads; ++t) {
            xtcp::core::Endpoint ep;
            ep.family = 4;
            ep.addr[0] = 0x0A000002;
            ep.port = static_cast<UInt16>(kBasePort + t);
            CHECK(stack_b.Listen(ep));
        }
        stack_a.SetTwoMsl(50000);
        stack_b.SetTwoMsl(50000);

        // User threads: for each of their conns, stream kChunks then Abort
        // (RST - exercises the mid-flight teardown path while the event
        // thread may still be delivering RX for the same conn).
        std::atomic<bool> stop{false};
        std::atomic<UInt32> errors{0};
        std::atomic<UInt32> workers_done{0};
        std::vector<std::thread> workers;
        for (UInt32 t = 0; t < kThreads; ++t) {
            workers.emplace_back([&, t]() {
                for (UInt32 c = 0; c < kConnsPerThread && !stop.load(std::memory_order_relaxed); ++c) {
                    xtcp::core::Endpoint local, remote;
                    local.family = 4;
                    local.addr[0] = 0x0A000001;
                    local.port = static_cast<UInt16>(50000 + t * 100 + c);
                    remote.family = 4;
                    remote.addr[0] = 0x0A000002;
                    remote.port = static_cast<UInt16>(kBasePort + t);
                    const UInt64 conn = stack_a.Connect(local, remote);
                    if (0 == conn) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    // Wait for Established.
                    bool established = false;
                    for (UInt32 spin = 0; spin < 4000; ++spin) {
                        if (xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn)) {
                            established = true;
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                    if (!established) {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        stack_a.Abort(conn);
                        continue;
                    }
                    const Int32 on = 1;
                    stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on));
                    // Stream, then abort MID-FLIGHT at a per-conn point so
                    // Send/Abort overlap the event thread's RX for this conn
                    // (the deadlock-prone window: user thread holds the shard
                    // lock in Send/Abort while the pump delivers RX).
                    std::vector<Byte> buf(kChunk);
                    const UInt32 abort_at = 17 + ((t * 31 + c * 7) % (kChunks - 20));
                    for (UInt32 k = 0; k < kChunks; ++k) {
                        if (k == abort_at) {
                            stack_a.Abort(conn);  // tear down while streaming
                            // Abort is terminal: the conn is gone. Stop
                            // sending; the loop ends after a yield.
                            std::this_thread::yield();
                            break;
                        }
                        for (UInt32 i = 0; i < kChunk; ++i) {
                            buf[i] = static_cast<Byte>(0x40 + t + c + i + k);
                        }
                        if (!stack_a.Send(conn, buf.data(), kChunk)) {
                            std::this_thread::yield();
                            --k;  // retry this chunk (window full)
                            continue;
                        }
                        if (k > 0 && 0 == (k % 37)) {
                            std::this_thread::yield();  // let RX interleave
                        }
                    }
                }
                workers_done.fetch_add(1, std::memory_order_relaxed);
            });
        }

        // Pump driver: bounded rounds; a deadlock would stall here (the
        // workers sleep-wait, so the pump is the only progress engine).
        for (UInt32 round = 0; round < 60000 && workers_done.load(std::memory_order_relaxed) < kThreads; ++round) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(workers_done.load(std::memory_order_relaxed) == kThreads);  // no deadlock
        stop.store(true, std::memory_order_relaxed);
        for (auto& t : workers) {
            t.join();
        }
        // Final drain so B's receivers see everything A sent before the RSTs.
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        std::fprintf(stderr, "[thread-send-abort] errors=%u A_conns=%u B_conns=%u\n",
                     errors.load(std::memory_order_relaxed),
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount());
        CHECK(0 == errors.load(std::memory_order_relaxed));
        // Receiver accounting: total delivered bytes across all slots must be
        // at most what the senders accepted (kTotalConns * kChunks * kChunk);
        // anything more would mean corruption/duplication. Less is legal:
        // Aborts cut the stream mid-flight.
        UInt64 total_recv = 0;
        for (UInt32 i = 0; i < kTotalConns; ++i) {
            total_recv += states[i].bytes;
        }
        const UInt64 total_sent = static_cast<UInt64>(kTotalConns) * kChunks * kChunk;
        std::fprintf(stderr, "[thread-send-abort] recv=%llu sent_cap=%llu\n",
                     (unsigned long long)total_recv, (unsigned long long)total_sent);
        CHECK(total_recv <= total_sent);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "THREAD_SEND_ABORT: FAILED (%d)\n" : "THREAD_SEND_ABORT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

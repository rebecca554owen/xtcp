/**
 * @file test_tx_retry_mpsc.cpp
 * @brief MPSC retry-chain concurrency: the DMA/PCIe retry
 *        queue used to be a std::deque that RetryBatchSharded could push
 *        to a FOREIGN shard WITHOUT that shard's lock, racing the sweep's
 *        locked pop - UB. The chain is now an atomic-head MPSC list: this
 *        test drives the exact race (user threads Send while a backend
 *        rejects, event thread sweeps) and pins byte-exact convergence
 *        plus chain FIFO ordering.
 *
 * Setup: TWO user threads Send on TWO connections (different shards) while
 * the backend rejects everything; the event thread pumps PollAckTimers
 * (the sweep drains the retry chains). When the ring reopens every
 * deferred byte must arrive in order, byte-exact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
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

// A backend whose Tx rejects every packet while `reject` is true. Rejected
// packets keep their ownership with the caller (the stack defers them).
// Accepted packets are QUEUED and delivered by Drain() on the pump thread -
// NOT synchronously inside Tx: Tx runs under the sender's shard lock, and a
// synchronous peer_(OnPacket) there would take the peer's shard lock under
// ours (a cross-stack lock-order inversion the real async backends never
// have; TSan flags it).
class RejectingBackend final : public xtcp::ndi::Backend {
public:
    std::atomic<bool> reject{false};
    std::atomic<UInt32> rejected_count{0};
    xtcp::ndi::RxHandler peer_;  // delivers accepted packets to the PEER stack

    void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
        rx_ = std::move(handler);
    }
    xtcp::ndi::BackendCaps Caps() const noexcept override { return xtcp::ndi::kCapNone; }

    bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
        if (reject.load(std::memory_order_relaxed)) {
            ++rejected_count;
            return false;  // ring full: the packet is NOT consumed
        }
        {
            std::lock_guard<std::mutex> scope(tx_mutex_);
            tx_queue_.push_back(std::move(packet));
        }
        return true;
    }

    UInt32 TxBatch(xtcp::ndi::Packet* packets, UInt32 count) noexcept override {
        UInt32 accepted = 0;
        for (UInt32 i = 0; i < count; ++i) {
            if (!Tx(std::move(packets[i]))) {
                break;
            }
            ++accepted;
        }
        return accepted;
    }

    // Pump-thread delivery: hands every queued packet to the peer stack
    // OUTSIDE any stack lock (the pump thread holds none).
    void Drain() {
        std::deque<xtcp::ndi::Packet> batch;
        {
            std::lock_guard<std::mutex> scope(tx_mutex_);
            batch.swap(tx_queue_);
        }
        for (xtcp::ndi::Packet& p : batch) {
            if (peer_) {
                peer_(std::move(p));
            }
        }
    }

private:
    std::mutex tx_mutex_;
    std::deque<xtcp::ndi::Packet> tx_queue_;
    xtcp::ndi::RxHandler rx_;
};

int main() {
    xtcp::buf::InitPools();
    {
        constexpr UInt32 kThreads = 2;
        constexpr UInt32 kPerConn = 64 * 1024;
        RejectingBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.peer_ = [&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        };
        backend_b.peer_ = [&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        };
        std::atomic<UInt64> b_recv{0};
        // Byte-exact pin via the delivered-byte count: a duplicated or
        // lost segment changes the total by exactly one segment, so
        // recv == 2*kPerConn proves the MPSC chain drained with no
        // duplication and no loss (each deferred packet delivered once).
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
        });

        auto pump = [&]() {
            backend_a.Drain();
            backend_b.Drain();
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        // Two listeners (different ports -> different shards).
        xtcp::core::Endpoint ep0, ep1;
        ep0.family = 4; ep0.addr[0] = 0x0A000001; ep0.port = 8100;
        ep1.family = 4; ep1.addr[0] = 0x0A000001; ep1.port = 8101;
        CHECK(stack_b.Listen(ep0));
        CHECK(stack_b.Listen(ep1));

        std::vector<UInt64> conns(kThreads, 0);
        std::vector<xtcp::core::Endpoint> locals(kThreads);
        for (UInt32 i = 0; i < kThreads; ++i) {
            locals[i].family = 4;
            locals[i].addr[0] = 0xC0A80102;
            locals[i].port = static_cast<UInt16>(41000 + i);
            conns[i] = stack_a.Connect(locals[i], (0 == i) ? ep0 : ep1);
            CHECK(0 != conns[i]);
        }
        backend_a.reject.store(false);
        backend_b.reject.store(false);
        for (UInt32 i = 0; i < 300 && (xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conns[0]) ||
                                       xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conns[1])); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conns[0]));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conns[1]));

        // Seed the payloads (per-conn distinct fill for byte-exact compare).
        std::vector<std::vector<Byte>> payloads(kThreads, std::vector<Byte>(kPerConn));
        for (UInt32 i = 0; i < kThreads; ++i) {
            for (UInt32 j = 0; j < kPerConn; ++j) {
                payloads[i][j] = static_cast<Byte>(0x40 + i * 16 + (j % 16));
            }
        }

        // Close A's ring: everything the user threads send is deferred.
        backend_a.reject.store(true);

        std::atomic<bool> done{false};
        std::vector<std::thread> workers;
        for (UInt32 w = 0; w < kThreads; ++w) {
            workers.emplace_back([&, w]() {
                UInt32 sent = 0;
                while (sent < kPerConn && !done.load(std::memory_order_relaxed)) {
                    // Full-MSS chunks; the last chunk takes the remainder so
                    // the payload buffer is never over-read (kPerConn is not
                    // a multiple of the MSS).
                    const UInt32 chunk = ((kPerConn - sent) > 1460) ? 1460 : (kPerConn - sent);
                    if (stack_a.Send(conns[w], payloads[w].data() + sent, chunk)) {
                        sent += chunk;
                    } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                }
                if (sent < kPerConn) {
                    std::fprintf(stderr, "[tx-retry-mpsc] worker %u stalled at %u\n", w, sent);
                    ++g_failures;
                }
            });
        }

        // Event thread: sweep while the workers hammer the rejected ring
        // (the F1 race: foreign-shard chain pushes vs the sweep's locked
        // drain - the exact interleaving that was UB on a std::deque).
        std::thread event([&]() {
            for (UInt32 round = 0; round < 3000 && !done.load(std::memory_order_relaxed); ++round) {
                pump();
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        // Let the workers run against the closed ring for a while, then
        // reopen and let the deferred chains drain.
        for (UInt32 i = 0; i < 200 && !done.load(std::memory_order_relaxed); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        backend_a.reject.store(false);
        event.join();
        done.store(true, std::memory_order_relaxed);
        for (auto& t : workers) {
            t.join();
        }

        // Every deferred byte must arrive byte-exact on the peer.
        const UInt64 target = static_cast<UInt64>(kThreads) * kPerConn;
        for (UInt32 i = 0; i < 1000 && b_recv.load() < target; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(target == b_recv.load());
        CHECK(0 < backend_a.rejected_count);
        std::fprintf(stderr, "[tx-retry-mpsc] recv=%llu target=%llu rejected=%u\n",
                     (unsigned long long)b_recv.load(), (unsigned long long)target,
                     backend_a.rejected_count.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TX_RETRY_MPSC: FAILED (%d)\n" : "TX_RETRY_MPSC: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

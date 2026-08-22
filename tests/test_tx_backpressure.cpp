/**
 * @file test_tx_backpressure.cpp
 * @brief DMA/PCIe TX backpressure (ndi Tx acceptance): when the backend's
 *        transmit ring is full (Tx returns false / TxBatch accepts only
 *        part), the stack must DEFER the rejected packets (per-shard retry
 *        queue, drained on the next PollAckTimers) - never drop them. The
 *        peer must receive the complete stream byte-exact once the ring
 *        reopens, and the retry must not reorder segments.
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

// A backend whose Tx rejects every packet until the ring reopens. A
// rejected packet is NOT consumed: the caller (the stack) keeps ownership.
class RejectingBackend final : public xtcp::ndi::Backend {
public:
    xtcp::ndi::RxHandler peer_;  // delivers accepted packets to the PEER stack
public:
    std::atomic<bool> reject{true};
    std::atomic<UInt32> rejected_count{0};

    void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
        rx_ = std::move(handler);
    }
    xtcp::ndi::BackendCaps Caps() const noexcept override { return xtcp::ndi::kCapNone; }

    bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
        
        if (reject.load(std::memory_order_relaxed)) {
            ++rejected_count;
            return false;  // ring full: the packet is NOT consumed
        }
        // Accepted: deliver to the peer (adopt the owned ref).
        if (peer_) {
            peer_(std::move(packet));
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

private:
    xtcp::ndi::RxHandler rx_;
};

int main() {
    xtcp::buf::InitPools();
    {
        RejectingBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // Backpressure accounting test on a manual clock: pin Reno so the
        // rate-based KCC default does not pace the send/reject pattern.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
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
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
        });

        auto pump = [&]() {
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = 40000;
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = 443;
        stack_b.Listen(remote_a);

        // Handshake with the ring OPEN (the SYN/SYN-ACK must flow).
        backend_a.reject.store(false);
        backend_b.reject.store(false);
        const UInt64 conn = stack_a.Connect(local_a, remote_a);
        CHECK(0 != conn);
        
        for (UInt32 i = 0; i < 200 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        

        // Send the payload while the ring is open.
        const UInt32 kTotal = 64 * 1024;
        std::vector<Byte> payload(kTotal, 0x7A);
        UInt32 sent = 0;
        while (sent < kTotal) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTotal == b_recv.load());
        

        // Close A's ring: A's next sends must be DEFERRED, not dropped.
        // Send 4KB more (the window/cwnd allow it), with the ring closed.
        backend_a.reject.store(true);
        sent = 0;
        UInt32 send_guard = 0;
        while (sent < 4 * 1024 && 2000 > ++send_guard) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(0 < backend_a.rejected_count.load());  // the backpressure was exercised

        // Reopen A's ring: the deferred packets must drain and the peer
        // must receive everything (64KB + 4KB) byte-exact.
        backend_a.reject.store(false);
        const UInt64 target = kTotal + 4 * 1024;
        for (UInt32 i = 0; i < 200 && b_recv.load() < target; ++i) {
            pump();
        }
        CHECK(target == b_recv.load());
    }

    // Phase 2: the same backpressure through a mounted FQ qdisc. The sender's
    // segments go enqueue -> DrainTxQdisc -> TxBatch; a partial acceptance
    // must defer the rejected segments on THEIR connections' shards
    // (RetryBatchSharded) and drain byte-exact once the ring reopens.
    {
        xtcp::qdisc::RegisterFqDefault();
        xtcp::qdisc::QdiscParams params;
        params.pacing_enabled = false;
        xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
        CHECK(NULLPTR != fq);
        RejectingBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTxQdisc(fq);
        // Manual-clock backpressure test: pin Reno (KCC's pacing would
        // change the reject/retry pattern).
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
        std::atomic<bool> attribution_ok{true};
        std::atomic<UInt64> conn_id_seen{0};
        backend_a.peer_ = [&stack_a, &stack_b, &attribution_ok, &conn_id_seen](xtcp::ndi::Packet&& p) {
            // Attribution pin: every packet the sender emits must resolve to
            // the connection's shard via ShardOfPacket - the retry path
            // attributes rejected segments by their 5-tuple, and a wrong
            // shard would put the connection's deferred segments on a
            // foreign retry queue.
            const xtcp::ndi::Packet& pc = p;
            const UInt64 cid = conn_id_seen.load();
            if (0 != cid) {
                const auto s = stack_a.ShardOfPacket(pc);
                const auto c = stack_a.ShardOf(cid);
                if (NULLPTR == s || s != c) {
                    attribution_ok.store(false);
                }
            }
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
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
        });

        auto pump = [&]() {
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80202;
        local_a.port = 40001;
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000002;
        remote_a.port = 444;
        stack_b.Listen(remote_a);

        backend_a.reject.store(false);
        backend_b.reject.store(false);
        const UInt64 conn = stack_a.Connect(local_a, remote_a);
        CHECK(0 != conn);
        conn_id_seen.store(conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(attribution_ok.load());

        const UInt32 kTotal = 32 * 1024;
        std::vector<Byte> payload(kTotal, 0x9B);
        UInt32 sent = 0;
        while (sent < kTotal) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTotal == b_recv.load());

        // Close A's ring mid-stream: the qdisc-drained segments must defer,
        // never drop. The qdisc is paced-off, so DrainTxQdisc drives the
        // batches straight into the rejecting backend.
        backend_a.reject.store(true);
        sent = 0;
        UInt32 send_guard = 0;
        while (sent < 4 * 1024 && 2000 > ++send_guard) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(0 < backend_a.rejected_count.load());

        backend_a.reject.store(false);
        const UInt64 target = kTotal + 4 * 1024;
        for (UInt32 i = 0; i < 300 && b_recv.load() < target; ++i) {
            pump();
        }
        CHECK(target == b_recv.load());
        xtcp::qdisc::DestroyQdisc(fq);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TX_BACKPRESSURE: FAILED (%d)\n" : "TX_BACKPRESSURE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

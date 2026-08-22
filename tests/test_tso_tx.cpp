/**
 * @file test_tso_tx.cpp
 * @brief TSO TX passthrough: a backend with kCapTsoTx tells the stack the
 *        NIC (or the backend itself) segments. The stack must hand the
 *        whole super-segment to the backend in ONE Tx call - no software
 *        GSO - and the peer must still receive the complete stream
 *        byte-exact (the NIC's segmentation is invisible to the receiver's
 *        stack; the wire is identical). Also covers the DMA backpressure
 *        interplay: a rejected super-segment is deferred whole and drained
 *        once the ring reopens (never segmented, never dropped).
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

// A TSO-capable backend: Caps() advertises kCapTsoTx; the stack must send
// the whole super-segment in ONE Tx call (never software-GSO it). The
// "NIC" segmentation is emulated by the pump: the super-segment is
// re-delivered to the peer as-is (the receiver's stack handles a 64KB
// segment - the GRO-validated path).
class TsoBackend final : public xtcp::ndi::Backend {
public:
    xtcp::ndi::RxHandler peer_;
    std::atomic<UInt64> tx_calls{0};
    std::atomic<UInt64> tx_bytes{0};
    std::atomic<bool> reject{false};

    void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
        rx_ = std::move(handler);
    }
    xtcp::ndi::BackendCaps Caps() const noexcept override { return xtcp::ndi::kCapTsoTx; }

    bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
        if (reject.load(std::memory_order_relaxed)) {
            return false;  // ring full: the packet is NOT consumed
        }
        tx_calls.fetch_add(1, std::memory_order_relaxed);
        tx_bytes.fetch_add(packet.len, std::memory_order_relaxed);
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
        TsoBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // TSO passthrough must keep the super-segment in ONE Tx call; pin
        // Reno so the rate-based KCC default does not split it via pacing.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
        backend_a.peer_ = [&stack_b](xtcp::ndi::Packet&& p) {
            // The NIC segments the super-segment on the wire; the receiver
            // sees normal segments. The pump emulates this by re-delivering
            // the super-segment directly (the receiver's stack handles it -
            // the GRO-validated path), byte-identical to the NIC's output.
            stack_b.OnPacket(std::move(p.owned));
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
            return true;
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

        const UInt64 conn = stack_a.Connect(local_a, remote_a);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 200 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Grow the congestion window first (slow start needs a few ACK
        // rounds before the cwnd admits a super-segment), then send the
        // pool's largest zero-copy super-segment (32712 = the 32KB class
        // minus headers) in ONE Send call. The TSO cap must make the stack
        // hand it to the backend whole (ONE Tx call - no software GSO
        // segmentation).
        const UInt32 kTotal = 32712;
        std::vector<Byte> payload(kTotal, 0x6E);
        // Grow the congestion window past the super-segment size (slow
        // start: 10 + 1 per ACK - 15KB of small sends reach ~25 segments
        // = 36500 bytes, admitting the 32712-byte super-segment).
        for (UInt32 i = 0; i < 15; ++i) {
            if (stack_a.Send(conn, payload.data() + i * 1024, 1024)) {
                pump();
            }
        }
        // Drain until the growth's bytes are fully delivered AND the ACKs
        // have released the sender's retransmission queue (the TSO-direct
        // gate requires an empty queue). The peer's delayed-ACK fires on a
        // 40ms timer, so the drain must span real time.
        for (UInt32 i = 0; i < 500 && b_recv.load() < 15 * 1024; ++i) {
            pump();
        }
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        UInt32 sent = 0;
        const UInt64 calls_before = backend_a.tx_calls.load();
        for (UInt32 i = 0; i < 2000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, kTotal - sent)) {
                sent = kTotal;
            }
            pump();
        }
        CHECK(kTotal == sent);
        CHECK(kTotal + 15 * 1024 == b_recv.load());  // growth + the super-segment
        // TSO proof: the whole super-segment went out in ONE Tx call (the
        // handshake + the cwnd-growth sends add a handful; the super-segment
        // itself is a single call, never the ~22 MSS-sized GSO segments).
        const UInt64 tso_calls = backend_a.tx_calls.load() - calls_before;
        CHECK(1 == tso_calls);
        // Reap the super-segment's ACK (the delayed-ACK fires on a 40ms
        // timer) so the next super-send finds an empty retransmission queue.
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        std::fprintf(stderr, "[tso] tx_calls=%llu tx_bytes=%llu recv=%llu\n",
                     (unsigned long long)backend_a.tx_calls.load(),
                     (unsigned long long)backend_a.tx_bytes.load(),
                     (unsigned long long)b_recv.load());

        // The TLP/reentrant-ACK path reaps the super instantly, so the
        // second send can arrive INSIDE the first super's ACK-clock pacing
        // window (len/rate). The pacing gate would then hold the second
        // TSO-direct in pending_send_ (flushed in MSS segments) instead of
        // deferring the whole super via the retry queue - the very path
        // this phase tests. Wait out the pacing window (the delayed-ACK
        // reap used to provide this elapsed time).
        for (UInt32 i = 0; i < 100; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        // DMA backpressure interplay: with the ring closed, a SECOND 32KB
        // super-segment must be deferred WHOLE (never segmented, never
        // dropped), then drained when the ring reopens.
        backend_a.reject.store(true);
        const UInt64 calls_before2 = backend_a.tx_calls.load();
        sent = 0;
        for (UInt32 i = 0; i < 2000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, kTotal - sent)) {
                sent = kTotal;
            }
            pump();
        }
        CHECK(kTotal == sent);
        CHECK(0 == backend_a.tx_calls.load() - calls_before2);  // nothing accepted while closed
        backend_a.reject.store(false);
        const UInt64 target = 2 * kTotal + 15 * 1024;
        for (UInt32 i = 0; i < 500 && b_recv.load() < target; ++i) {
            pump();
        }
        CHECK(target == b_recv.load());
        // The drained super-segment was ONE deferred packet, re-emitted as
        // one Tx call (the retry queue holds it whole).
        CHECK(1 == backend_a.tx_calls.load() - calls_before2);
        std::fprintf(stderr, "[tso] backpressure: recv=%llu drain_calls=%llu\n",
                     (unsigned long long)b_recv.load(),
                     (unsigned long long)(backend_a.tx_calls.load() - calls_before2));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TSO_TX: FAILED (%d)\n" : "TSO_TX: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

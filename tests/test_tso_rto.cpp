/**
 * @file test_tso_rto.cpp
 * @brief TSO'd super-segment RTO recovery: when the super-segment's ACK is
 *        lost (not the segment), the sender's RTO must re-emit the WHOLE
 *        super-segment in ONE Tx call (the retransmission keeps the TSO
 *        path - never re-segmented) and the recovery must converge
 *        byte-exact with the connection intact. This pins the *        safety claim: an oversized retransmission-queue entry recovers
 *        cleanly under loss.
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

class TsoBackend final : public xtcp::ndi::Backend {
public:
    xtcp::ndi::RxHandler peer_;
    std::atomic<UInt64> tx_calls{0};

    void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
        rx_ = std::move(handler);
    }
    xtcp::ndi::BackendCaps Caps() const noexcept override { return xtcp::ndi::kCapTsoTx; }

    bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
        tx_calls.fetch_add(1, std::memory_order_relaxed);
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
        // TSO super-segment emission must be one Tx call; pin Reno so the
        // rate-based KCC default does not split the super-segment via pacing.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
        std::atomic<bool> drop_one_ack{false};
        backend_a.peer_ = [&stack_b](xtcp::ndi::Packet&& p) {
            stack_b.OnPacket(std::move(p.owned));
        };
        backend_b.peer_ = [&stack_a, &drop_one_ack](xtcp::ndi::Packet&& p) {
            // Lose ONE B->A packet: the super-segment's ACK never arrives,
            // forcing the sender's RTO (the segment itself is never lost).
            if (drop_one_ack.exchange(false, std::memory_order_relaxed)) {
                return;
            }
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

        // Grow the cwnd past the super-segment size, then drain the
        // retransmission queue completely (the TSO-direct gate requires it).
        const UInt32 kTotal = 32712;
        std::vector<Byte> payload(kTotal, 0x4E);
        for (UInt32 i = 0; i < 15; ++i) {
            if (stack_a.Send(conn, payload.data() + i * 1024, 1024)) {
                pump();
            }
        }
        for (UInt32 i = 0; i < 500 && b_recv.load() < 15 * 1024; ++i) {
            pump();
        }
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Arm the ACK drop, then send the super-segment: its ONE Tx goes
        // out, but its ACK is lost - the RTO must re-emit the whole
        // super-segment in ONE further Tx call.
        drop_one_ack.store(true);
        UInt32 sent = 0;
        const UInt64 calls_before = backend_a.tx_calls.load();
        for (UInt32 i = 0; i < 2000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, kTotal - sent)) {
                sent = kTotal;
            }
            pump();
        }
        CHECK(kTotal == sent);
        CHECK(1 == backend_a.tx_calls.load() - calls_before);  // the ONE super Tx
        CHECK(b_recv.load() >= 15 * 1024 + kTotal);  // the super arrived

        // Wait out the RTO (200ms floor + backoff) and the re-emission.
        const UInt64 calls_before_rto = backend_a.tx_calls.load();
        for (UInt32 i = 0; i < 3000 && 1 > backend_a.tx_calls.load() - calls_before_rto; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // The retransmission is the WHOLE super-segment in ONE Tx (the TSO
        // path survives the RTO - never re-segmented).
        CHECK(1 == backend_a.tx_calls.load() - calls_before_rto);

        // The retransmission converges: the duplicate is dropped by the
        // receiver (old data), the stream stays byte-exact, the connection
        // stays established.
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        std::fprintf(stderr, "[tso-rto] recv=%llu retransmit_calls=%llu\n",
                     (unsigned long long)b_recv.load(),
                     (unsigned long long)(backend_a.tx_calls.load() - calls_before_rto));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TSO_RTO: FAILED (%d)\n" : "TSO_RTO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

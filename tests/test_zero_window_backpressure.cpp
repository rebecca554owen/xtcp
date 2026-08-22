/**
 * @file test_zero_window_backpressure.cpp
 * @brief RFC 1122 s4.2.3.4: under app backpressure (recv_cb_ rejects), the
 *        receiver advertises window 0 - the sender stops sending and
 *        persists instead of retransmitting into an unusable window. When
 *        the app accepts again, the window reopens and the stream resumes.
 *        (Pre-fix the advertised window stayed constant 65535 and the
 *        sender RTO-retransmitted into backpressure.)
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
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
    for (UInt32 round = 0; round < 2000; ++round) {
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

// Regression pin: a rejection must
// produce a window-0 ACK EVEN WHEN the sender sends nothing further. The
// pre-fix code armed nothing after a rejection, so with no subsequent
// accepted segment the win-0 advertisement never went out (the peer kept
// RTO-retransmitting into a window that looked open). Deterministic: one
// rejected segment, then only B's timers pump - a win-0 ACK must appear.
static void TestRejectionAloneAdvertisesWindowZero() {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
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
    xtcp::core::Endpoint a_local, b_local;
    a_local.family = 4;
    a_local.addr[0] = 0x0A000001;
    a_local.port = 40240;
    b_local.family = 4;
    b_local.addr[0] = 0x0A000002;
    b_local.port = 9140;
    CHECK(stack_b.Listen(b_local));
    // Backpressure from the start: every segment is rejected.
    stack_b.SetRecvHandlerChecked([](UInt64, const Byte*, UInt32) { return false; });

    const UInt64 conn_a = stack_a.Connect(a_local, b_local);
    CHECK(0 != conn_a);
    // Handshake (the recv handler is not involved).
    for (UInt32 i = 0; i < 500 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn_a); ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

    // A sends exactly ONE segment; B rejects it.
    Byte payload[1460];
    std::memset(payload, 0x5A, sizeof(payload));
    CHECK(stack_a.Send(conn_a, payload, sizeof(payload)));
    // Deliver A->B only (the rejection must arm the window-0 ACK).
    {
        Byte out[65536];
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                backend_b.Inject(out, n, 0x0800);
            }
        }
    }
    // Pump ONLY B's timers: the armed window-update ACK must fire with
    // window 0 - without ANY further sender traffic.
    bool saw_zero = false;
    bool saw_nonzero = false;
    for (UInt32 round = 0; round < 100; ++round) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));  // let the delayed ACK deadline pass
        stack_b.PollAckTimers();
        Byte out[65536];
        while (0 != backend_b.TxPending()) {
            const UInt32 n = backend_b.PollTx(out);
            if (0 == n) {
                continue;
            }
            const UInt32 tcp_off = static_cast<UInt32>(out[0] & 0x0F) * 4;
            if (tcp_off + 20 <= n) {
                const UInt16 win = (static_cast<UInt16>(out[tcp_off + 14]) << 8) | out[tcp_off + 15];
                if (0 == win) {
                    saw_zero = true;
                } else {
                    saw_nonzero = true;
                }
            }
        }
        if (saw_zero) {
            break;
        }
    }
    std::fprintf(stderr, "[zero-window] rejection-alone: zero=%d nonzero=%d\n",
                 saw_zero ? 1 : 0, saw_nonzero ? 1 : 0);
    CHECK(saw_zero);  // CORE: a lone rejection advertises window 0 promptly
}

int main() {
    xtcp::buf::InitPools();
    TestRejectionAloneAdvertisesWindowZero();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
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

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40230;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9130;
        CHECK(stack_b.Listen(b_local));

        std::atomic<bool> accept_data{false};  // app backpressure ON initially
        std::atomic<UInt64> b_recv{0};
        stack_b.SetRecvHandlerChecked([&](UInt64, const Byte*, UInt32 len) {
            if (!accept_data.load(std::memory_order_relaxed)) {
                return false;  // backpressure: reject
            }
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });

        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // A sends a large stream while B backpressures.
        constexpr UInt32 kTotal = 65536;
        std::vector<Byte> payload(kTotal, 0x4D);
        for (UInt32 i = 0; i < 4; ++i) {
            stack_a.Send(conn_a, payload.data() + i * 16384, 16384);
        }
        // Blocked phase: pump A->B, but B's outbound traffic is inspected on
        // the wire BEFORE it reaches A. While the app backpressures, every ACK
        // must advertise window 0 (RFC 1122 s4.2.3.4) - the pre-fix behavior
        // advertised the full 65535 and A kept retransmitting into it.
        bool saw_zero = false;
        bool saw_nonzero = false;
        {
            Byte out[65536];
            for (UInt32 round = 0; round < 2000; ++round) {
                bool moved = false;
                auto drain_a = [&]() {
                    while (0 != backend_a.TxPending()) {
                        const UInt32 n = backend_a.PollTx(out);
                        if (0 < n) {
                            backend_b.Inject(out, n, 0x0800);
                            moved = true;
                        }
                    }
                };
                auto drain_b = [&]() {
                    while (0 != backend_b.TxPending()) {
                        const UInt32 n = backend_b.PollTx(out);
                        if (0 == n) {
                            continue;
                        }
                        const UInt32 tcp_off = static_cast<UInt32>(out[0] & 0x0F) * 4;
                        if (tcp_off + 20 <= n) {
                            const UInt16 win = (static_cast<UInt16>(out[tcp_off + 14]) << 8) | out[tcp_off + 15];
                            if (0 == win) {
                                saw_zero = true;
                            } else {
                                saw_nonzero = true;
                            }
                        }
                        backend_a.Inject(out, n, 0x0800);  // forward B's ACKs to A
                        moved = true;
                    }
                };
                drain_a();
                drain_b();
                stack_a.PollAckTimers();
                stack_b.PollAckTimers();
                drain_a();  // the flush may emit from PollAckTimers
                drain_b();
                if (!moved) {
                    break;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[zero-window] blocked: zero=%d nonzero=%d b_recv=%llu\n",
                     saw_zero ? 1 : 0, saw_nonzero ? 1 : 0,
                     (unsigned long long)b_recv.load());
        CHECK(saw_zero);  // CORE: window 0 advertised under backpressure

        // A must NOT have completed the stream while blocked (its window is
        // 0): the bytes sit in A's pending buffer.
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto;
        UInt32 fseq, snd_una;
        UInt16 lp, rp;
        stack_a.ConnStats(conn_a, inflight, cwnd, ssthresh, snd_wnd, retx, rto, dup, fast, fseq, snd_una, lp, rp);
        std::fprintf(stderr, "[zero-window] A snd_wnd=%u (expect 0 while blocked)\n", snd_wnd);
        CHECK(0 == snd_wnd);  // CORE: the peer sees the zero window

        // The app recovers: the window reopens and the stream completes.
        accept_data.store(true, std::memory_order_relaxed);
        for (UInt32 i = 0; i < 800 && b_recv.load(std::memory_order_relaxed) < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::fprintf(stderr, "[zero-window] recovered b_recv=%llu (expect %u)\n",
                     (unsigned long long)b_recv.load(), kTotal);
        CHECK(kTotal == b_recv.load(std::memory_order_relaxed));  // CORE: stream resumed
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ZERO_WINDOW_BACKPRESSURE: FAILED (%d)\n" : "ZERO_WINDOW_BACKPRESSURE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

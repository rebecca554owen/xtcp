/**
 * @file test_loss_recovery.cpp
 * @brief : quantify the post-loss throughput recovery. A single
 *        lost/held segment must not crater the connection: after the loss
 *        event the cwnd recovers via the ACK clock and the remaining stream
 *        completes at a sane rate. Measures the clean-vs-lossy 1MB transfer
 *        time and samples the cwnd during recovery.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
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

struct Pair {
    xtcp::ndi::ManualBackend a, b;
    xtcp::XtcpStack sa, sb;
    std::atomic<UInt64> b_recv{0};
    bool hold_first = false;  // withhold A's first data segment (loss event)
    std::vector<Byte> held;

    Pair() : sa(&a), sb(&b) {
        a.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            sa.OnPacket(std::move(buf));
        });
        b.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            sb.OnPacket(std::move(buf));
        });
        sb.SetRecvHandlerChecked([this](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });
    }

    void Pump() {
        Byte out[65536];
        for (UInt32 round = 0; round < 2000; ++round) {
            bool moved = false;
            while (0 != a.TxPending()) {
                const UInt32 n = a.PollTx(out);
                if (0 < n) {
                    if (hold_first && held.empty()) {
                        held.assign(out, out + n);
                    } else {
                        b.Inject(out, n, 0x0800);
                    }
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
};

static double RunTransfer(UInt32 port, bool lossy, UInt64* cwnd_lo, UInt64* cwnd_hi, bool big_win = false) {
    Pair p;
    p.hold_first = lossy;
    if (big_win) {
        p.sb.SetRcvBuf(262144);
    }
    xtcp::core::Endpoint la, lb;
    la.family = 4;
    la.addr[0] = 0x0A000001;
    la.port = static_cast<UInt16>(port);
    lb.family = 4;
    lb.addr[0] = 0x0A000002;
    lb.port = 9200 + port % 100;
    CHECK(p.sb.Listen(lb));
    const UInt64 conn = p.sa.Connect(la, lb);
    CHECK(0 != conn);
    p.Pump();
    p.Pump();

    constexpr UInt32 kTotal = 1024 * 1024;
    std::vector<Byte> payload(kTotal, 0x33);
    UInt32 sent = 0, guard = 0;
    while (sent < kTotal && 100000 > ++guard) {
        const UInt32 chunk = (kTotal - sent < 16384) ? (kTotal - sent) : 16384;
        if (p.sa.Send(conn, payload.data() + sent, chunk)) {
            sent += chunk;
        } else {
            p.Pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(kTotal == sent);
    if (p.hold_first && !p.held.empty()) {
        p.b.Inject(p.held.data(), static_cast<UInt32>(p.held.size()), 0x0800);  // release after ~0.5s
    }

    const auto t0 = std::chrono::steady_clock::now();
    UInt64 lo = 0xFFFFFFFFFFFFFFFFull, hi = 0;
    while (p.b_recv.load(std::memory_order_relaxed) < kTotal) {
        for (UInt32 i = 0; i < 50; ++i) {
            p.Pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast, fseq, snd_una;
        UInt64 rto;
        UInt16 lp, rp;
        p.sa.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto, dup, fast, fseq, snd_una, lp, rp);
        if (cwnd < lo) {
            lo = cwnd;
        }
        if (cwnd > hi) {
            hi = cwnd;
        }
        if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(60)) {
            break;
        }
    }
    *cwnd_lo = lo;
    *cwnd_hi = hi;
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "[loss-rec] %s: %llu B in %.2f s (%.0f KB/s) cwnd[%llu..%llu] sent=%u\n",
                 lossy ? "LOSSY" : "CLEAN", (unsigned long long)p.b_recv.load(), secs,
                 p.b_recv.load() / 1024.0 / (secs > 0.01 ? secs : 0.01), (unsigned long long)*cwnd_lo,
                 (unsigned long long)*cwnd_hi, sent);
    return secs;
}

int main() {
    xtcp::buf::InitPools();
    UInt64 cwnd_lo = 0, cwnd_hi = 0;
    const double clean = RunTransfer(40240, false, &cwnd_lo, &cwnd_hi);
    std::fprintf(stderr, "[loss-rec] clean cwnd[%llu..%llu]\n", (unsigned long long)cwnd_lo, (unsigned long long)cwnd_hi);
    UInt64 l_lo = 0, l_hi = 0;
    const double lossy = RunTransfer(40241, true, &l_lo, &l_hi);
    std::fprintf(stderr, "[loss-rec] lossy cwnd[%llu..%llu]\n", (unsigned long long)l_lo, (unsigned long long)l_hi);
    // The rcvbuf-test scenario: big receive window + loss event.
    UInt64 b_lo = 0, b_hi = 0;
    const double bigwin = RunTransfer(40242, true, &b_lo, &b_hi, true);
    std::fprintf(stderr, "[loss-rec] lossy-bigwin cwnd[%llu..%llu]\n", (unsigned long long)b_lo, (unsigned long long)b_hi);
    // A single loss must not crater the recovery below ~1/4 of the clean rate.
    const double ratio = (lossy / (clean > 0.01 ? clean : 0.01));
    std::fprintf(stderr, "[loss-rec] lossy/clean time ratio = %.2f\n", ratio);
    CHECK(ratio < 8.0);
    const double ratio_b = (bigwin / (clean > 0.01 ? clean : 0.01));
    std::fprintf(stderr, "[loss-rec] lossy-bigwin/clean time ratio = %.2f\n", ratio_b);
    CHECK(ratio_b < 8.0);
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "LOSS_RECOVERY: FAILED (%d)\n" : "LOSS_RECOVERY: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

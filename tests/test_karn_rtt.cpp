/**
 * @file test_karn_rtt.cpp
 * @brief Karn algorithm (RFC 6298): a retransmitted segment must NOT be
 *        sampled for RTT. A 64 KiB transfer crosses a lossy link that drops
 *        1 in 8 A->B segments, forcing multiple RTO/fast-retransmit
 *        recoveries. If the RTO backoff polluted srtt/rto, the RTO would
 *        blow toward the 60 s ceiling and the rto_deadline would sit at
 *        now+60s while segments were outstanding; a healthy connection
 *        finishes the transfer and clears rto_deadline (no pending
 *        retransmit timer), proving the estimate never exploded.
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

static UInt32 g_drop_every = 0;
static UInt32 g_drop_count = 0;
static UInt32 g_tx_seen = 0;

static UInt64 NowUs() noexcept {
    return static_cast<UInt64>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// Lossy pump: 1 in g_drop_every A->B segments is dropped (the RTO/retransmit
// path runs on stack_a); B->A ACKs pass untouched so recovery feedback is
// never lost.
static void PumpLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                if (0 != g_drop_every && 0 == (g_tx_seen % g_drop_every)) {
                    ++g_drop_count;
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

int main() {
    xtcp::buf::InitPools();
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
        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40131;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9100;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        PumpLossy(backend_a, backend_b, stack_a, stack_b);

        // 64 KiB transfer with 1-in-8 loss (~12.5%). ~45 MSS segments ->
        // several drops, so the recovery path is exercised multiple times.
        const UInt32 kTotal = 65536;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
        }
        UInt32 accepted = 0;
        g_drop_every = 8;
        UInt32 guard = 0;
        const UInt64 t0 = NowUs();
        while (accepted < kTotal && 400000 > ++guard) {
            UInt32 n = kTotal - accepted;
            if (n > 4096) {
                n = 4096;
            }
            UInt32 tries = 0;
            while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
                PumpLossy(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            accepted += n;
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == accepted);

        // Drain + observe the RTO deadline while segments are still being
        // recovered. Both stack and test read the same steady_clock in us,
        // so (rto_deadline - now) is the armed RTO wait. A Karn-polluted
        // rto_ pins this at ~60 s; a healthy estimate stays far below.
        UInt64 max_deadline_gap = 0;
        for (UInt32 i = 0; i < 3000 && bytes_recv < kTotal; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
            UInt64 rto_deadline = 0;
            UInt32 front_seq = 0, snd_una = 0;
            UInt16 lp = 0, rp = 0;
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
            const UInt64 now_us = NowUs();
            if (0 != rto_deadline && rto_deadline > now_us) {
                const UInt64 gap = rto_deadline - now_us;
                if (gap > max_deadline_gap) {
                    max_deadline_gap = gap;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const UInt64 elapsed_us = NowUs() - t0;

        // Settle: let the final ACK land so stack_a's retransmit timer and
        // inflight are fully drained before the terminal stats read.
        for (UInt32 i = 0; i < 100; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }

        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto_deadline = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt64 now_us = NowUs();
        std::fprintf(stderr,
                     "[karn-rtt] dropped=%u retx=%u fast=%u inflight=%u "
                     "rto_deadline=%llu max_rto_gap_ms=%llu elapsed_s=%.3f\n",
                     g_drop_count, retx, fast, inflight,
                     (unsigned long long)rto_deadline,
                     (unsigned long long)(max_deadline_gap / 1000),
                     static_cast<double>(elapsed_us) / 1000000.0);

        // 1. The transfer completed and delivered the exact bytes.
        CHECK(kTotal == bytes_recv);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_recv);
        std::fprintf(stderr, "[karn-rtt] crc recv=%u exp=%u\n", crc_recv, crc_expect);

        // 2. Loss was actually injected and recovered: multiple drop events
        //    forced RTO/retransmit, and the connection stayed healthy.
        CHECK(0 < g_drop_count);
        CHECK(0 < retx);

        // 3. Karn: RTO backoff never polluted srtt/rto. The armed RTO wait
        //    stayed far below the 60 s ceiling (a polluted estimate pins
        //    it at ~60 s), and the terminal rto_deadline is cleared with
        //    nothing outstanding (no retransmit timer stuck at the cap).
        CHECK(max_deadline_gap < 30ull * 1000000ull);
        CHECK(0 == rto_deadline || rto_deadline <= now_us + 30ull * 1000000ull);
        // Settle: drain the last ACKs so nothing is left outstanding.
        for (UInt32 i = 0; i < 200; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
            if (0 == inflight) {
                break;
            }
        }
        CHECK(0 == inflight);

        // 4. Recovery completed promptly: no 60 s RTO stall ever fired.
        CHECK(elapsed_us < 30ull * 1000000ull);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KARN_RTT: FAILED (%d)\n" : "KARN_RTT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

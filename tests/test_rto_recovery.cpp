/**
 * @file test_rto_recovery.cpp
 * @brief RTO recovery boundary test: two back-to-back stacks transfer 64 KiB
 *        across a lossy link that drops 1 in 8 first-seen data segments.
 *        The loss forces retransmission (RTO and/or fast-retransmit) and a
 *        window cut+recovery, and ConnStats proves the armed RTO wait stays
 *        inside the stack's hard bounds:
 *          - upper bound: never above the 60 s ceiling (kMaxRto,
 *            tcp_fsm.cpp:32) - a Karn-polluted estimate pins it there;
 *          - lower bound: a freshly-armed wait (right after a retransmit
 *            event, when RetransmitFront / RetransmitEarliestMissing /
 *            OnAckReceived re-arm the deadline) never dips below the
 *            Linux TCP_RTO_MIN parity floor of 200 ms
 *            (tcp_fsm.cpp:1000-1008) once the RTT has been sampled.
 *        Reference: test_karn_rtt.cpp (RTO deadline bound + transfer shape).
 *        Data integrity is verified by byte count + rolling CRC (a duplicated
 *        retransmit delivery would inflate the CRC).
 *
 *        The window-cut observation is split into two phases:
 *          - Phase A (64 KiB, 1-in-8 loss): bounds the armed RTO wait and
 *            verifies recovery + data integrity. On a fast machine the
 *            recovery can complete entirely through RFC 8985 TLP probes,
 *            which are NOT loss verdicts and never cut the window, so the
 *            cut itself is not asserted here (it would be machine-speed
 *            dependent - the observed CI flake).
 *          - Phase B (4 KiB, first two first-seen segments blackholed):
 *            forces the window cut deterministically. The two leading
 *            segments of a fresh burst are blackholed while the trailing
 *            segments are delivered, so the peer's SACKs expose a REAL gap
 *            and the RFC 5681 fast-retransmit entry (or the 200 ms RTO
 *            backstop) cuts ssthresh. Because the loss is real, the peer
 *            never held the data: neither the RFC 2883 D-SACK undo nor the
 *            no-SACK clean-exit undo can restore the pre-cut window, so the
 *            cut persists and is observable at every machine speed.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <algorithm>
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

static UInt64 NowUs() noexcept {
    return static_cast<UInt64>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// Lossy pump: every `drop_every`-th FIRST-seen A->B data segment (identified
// by its TCP sequence number) is blackholed; retransmissions of a dropped
// sequence pass through. B->A ACKs are never dropped so recovery feedback is
// never lost. The RTO/retransmit path runs on stack_a.
static void PumpLossy(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                      UInt32 drop_every, UInt32& dropped_out, UInt32& first_seen_out,
                      std::vector<UInt32>& dropped_seqs) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        // Parse: IPv4 (20B) + TCP (>=20B). flags at tcp offset 13, seq at 4.
        const UInt32 tcp_off = 20;
        const bool data = (got > tcp_off + 13) && (0 != (out[tcp_off + 13] & 0x08));  // PSH
        bool drop = false;
        if (data) {
            const UInt32 seq = (static_cast<UInt32>(out[tcp_off + 4]) << 24) |
                               (static_cast<UInt32>(out[tcp_off + 5]) << 16) |
                               (static_cast<UInt32>(out[tcp_off + 6]) << 8) |
                               static_cast<UInt32>(out[tcp_off + 7]);
            const bool is_retransmit =
                std::find(dropped_seqs.begin(), dropped_seqs.end(), seq) != dropped_seqs.end();
            if (!is_retransmit) {
                ++first_seen_out;
                if (0 != drop_every && 0 == (first_seen_out % drop_every)) {
                    drop = true;
                }
            }
            if (drop) {
                dropped_seqs.push_back(seq);
            }
        }
        if (drop) {
            ++dropped_out;
            continue;  // silently drop (like a blackhole)
        }
        to.Inject(out, got, 0x0800);
        if (20000 < ++guard) {
            break;
        }
    }
    // Drive flush + retransmit timers each pump (test_karn_rtt.cpp:69-70):
    // super-MSS Send data buffers in pending_send_ and is only flushed by
    // OnPoll (via PollAckTimers); without this nothing reaches the wire.
    sa.PollAckTimers();
    sb.PollAckTimers();
}

// Phase-B pump: blackholes the first two FIRST-seen A->B data segments (by
// TCP sequence number); retransmissions of a dropped sequence pass through.
// B->A carries only ACKs and is never dropped. The loss is REAL - the peer
// never receives these segments - so the window cut they trigger can never
// be undone (RFC 2883 D-SACK undo needs the peer to have received the data
// already; the no-SACK clean-exit undo needs undo_marker_).
static void PumpDropFirstTwo(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                             xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32& dropped_out,
                             std::vector<UInt32>& dropped_seqs) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        const UInt32 tcp_off = 20;
        const bool data = (got > tcp_off + 13) && (0 != (out[tcp_off + 13] & 0x08));  // PSH
        bool drop = false;
        if (data) {
            const UInt32 seq = (static_cast<UInt32>(out[tcp_off + 4]) << 24) |
                               (static_cast<UInt32>(out[tcp_off + 5]) << 16) |
                               (static_cast<UInt32>(out[tcp_off + 6]) << 8) |
                               static_cast<UInt32>(out[tcp_off + 7]);
            const bool is_retransmit =
                std::find(dropped_seqs.begin(), dropped_seqs.end(), seq) != dropped_seqs.end();
            if (!is_retransmit && dropped_out < 2) {
                dropped_seqs.push_back(seq);
                ++dropped_out;
                drop = true;
            }
        }
        if (drop) {
            continue;
        }
        to.Inject(out, got, 0x0800);
        if (20000 < ++guard) {
            break;
        }
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
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

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        Wire(backend_a, backend_b, stack_a, stack_b);

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
        local.port = 40350;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9160;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        // RFC 5681/6675 recovery is CC-independent; Reno exercises the
        // documented retransmit/window-recovery path deterministically.
        CHECK(stack_a.SetCongestionControl(conn, ""));

        UInt32 drop = 0, seen = 0;
        std::vector<UInt32> dropped_seqs;
        // Handshake (no drops).
        PumpLossy(backend_a, backend_b, stack_a, stack_b, 0, drop, seen, dropped_seqs);
        PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
        PumpLossy(backend_a, backend_b, stack_a, stack_b, 0, drop, seen, dropped_seqs);

        constexpr UInt32 kTotal = 65536;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
        }
        UInt64 accepted = 0;
        const UInt32 kDropEvery = 8;  // 1 in 8 data segments (~12.5%)
        UInt32 guard = 0;
        const UInt64 t0 = NowUs();
        while (accepted < kTotal && 400000 > ++guard) {
            UInt32 n = static_cast<UInt32>(kTotal - accepted);
            if (n > 4096) {
                n = 4096;
            }
            UInt32 tries = 0;
            while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
                PumpLossy(backend_a, backend_b, stack_a, stack_b, kDropEvery, drop, seen, dropped_seqs);
                PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            accepted += n;
            PumpLossy(backend_a, backend_b, stack_a, stack_b, kDropEvery, drop, seen, dropped_seqs);
            PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
        }
        CHECK(kTotal == accepted);

        // Drain + observe the RTO deadline while segments are still being
        // recovered. Both stack and test read the same steady_clock in us, so
        // (rto_deadline - now) is the armed RTO wait.
        UInt64 max_gap = 0;         // upper bound: closest any armed wait came to the ceiling
        UInt64 min_fresh_gap = 0;   // lower bound: smallest freshly-armed wait after a retransmit
        UInt32 fresh_samples = 0;
        UInt32 prev_retx = 0;
        UInt32 min_ssthresh = 0xFFFFFFFFu;
        UInt32 max_inflight = 0;
        for (UInt32 i = 0; i < 3000 && bytes_recv < kTotal; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, kDropEvery, drop, seen, dropped_seqs);
            PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
            UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
            UInt64 rto_deadline = 0;
            UInt32 front_seq = 0, snd_una = 0;
            UInt16 lp = 0, rp = 0;
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
            const UInt64 now_us = NowUs();
            if (inflight > max_inflight) {
                max_inflight = inflight;
            }
            if (ssthresh < min_ssthresh) {
                min_ssthresh = ssthresh;
            }
            if (0 != rto_deadline && rto_deadline > now_us) {
                const UInt64 gap = rto_deadline - now_us;
                if (gap > max_gap) {
                    max_gap = gap;
                }
                // A retransmit (RTO timer -> RetransmitFront, or SACK/fast
                // retransmit -> RetransmitEarliestMissing) re-arms the deadline
                // to now+rto_; this snapshot taken right after the retx counter
                // moved is the freshly-armed RTO wait.
                if (retx > prev_retx && (0 == min_fresh_gap || gap < min_fresh_gap)) {
                    min_fresh_gap = gap;
                    ++fresh_samples;
                }
            }
            prev_retx = retx;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const UInt64 elapsed_us = NowUs() - t0;

        // Settle: deliver the final ACKs so the retransmit timer and inflight
        // fully drain before the terminal stats read. The delayed ACK needs
        // real time to fire (test_karn_rtt.cpp:208-216 pattern).
        for (UInt32 i = 0; i < 200; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, kDropEvery, drop, seen, dropped_seqs);
            PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            UInt32 inflight_i = 0, cwnd_i = 0, ssthresh_i = 0, snd_wnd_i = 0, retx_i = 0, dup_i = 0, fast_i = 0;
            UInt64 rto_deadline_i = 0;
            UInt32 front_seq_i = 0, snd_una_i = 0;
            UInt16 lp_i = 0, rp_i = 0;
            stack_a.ConnStats(conn, inflight_i, cwnd_i, ssthresh_i, snd_wnd_i, retx_i, rto_deadline_i,
                              dup_i, fast_i, front_seq_i, snd_una_i, lp_i, rp_i);
            if (0 == inflight_i) {
                break;
            }
        }

        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto_deadline = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt64 now_us = NowUs();
        std::fprintf(stderr,
                     "[rto-recovery] dropped=%u retx=%u fast=%u inflight=%u "
                     "rto_deadline=%llu max_gap_ms=%llu min_fresh_gap_ms=%llu "
                     "fresh_samples=%u cwnd=%u ssthresh=%u min_ssthresh=%u "
                     "max_inflight=%u elapsed_s=%.3f\n",
                     drop, retx, fast, inflight,
                     (unsigned long long)rto_deadline,
                     (unsigned long long)(max_gap / 1000),
                     (unsigned long long)(min_fresh_gap / 1000),
                     fresh_samples, cwnd, ssthresh, min_ssthresh, max_inflight,
                     static_cast<double>(elapsed_us) / 1000000.0);

        // 1. RTO recovery: loss was injected and recovered via retransmission.
        CHECK(0 < drop);
        CHECK(0 < retx);

        // 2. Data integrity: exact byte count + rolling CRC (a duplicated
        //    retransmit delivery would inflate the CRC).
        CHECK(kTotal == bytes_recv);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_recv);
        std::fprintf(stderr, "[rto-recovery] crc recv=%u exp=%u\n", crc_recv, crc_expect);

        // 3. RTO upper bound: no armed RTO wait ever exceeded the 60 s ceiling
        //    (kMaxRto) - a Karn-polluted srtt/rto would pin the wait there.
        CHECK(max_gap <= 60ull * 1000000ull);

        // 4. RTO lower bound: every freshly-armed retransmit wait sat at/above
        //    the 200 ms floor (with measurement latency tolerance); a deadline
        //    armed below the floor would violate RFC 6298's rto_min.
        CHECK(0 < fresh_samples);
        CHECK(min_fresh_gap >= 150ull * 1000ull);

        // 5. Window recovery: the Phase-A recovery may complete via RFC 8985
        //    TLP probes alone on a fast machine - a probe is not a loss
        //    verdict and does not cut the window - so the cut is NOT asserted
        //    here (it would be machine-speed dependent). Phase B below forces
        //    a real loss whose window cut cannot be undone and verifies the
        //    cut deterministically. Terminal cwnd/ssthresh are non-zero and
        //    all Phase-A data drained out of flight.
        CHECK(0 < cwnd);
        CHECK(0 < ssthresh);
        CHECK(0 == inflight);

        // 6. No stuck 60 s retransmit timer: nothing is outstanding, and the
        //    recovery completed promptly (no 60 s RTO stall ever fired).
        CHECK(0 == rto_deadline || rto_deadline <= now_us + 30ull * 1000000ull);
        CHECK(elapsed_us < 30ull * 1000000ull);

        // ---- Phase B: deterministic window-cut verification (RFC 5681).
        // A fresh 4-KiB burst; its first two first-seen segments are
        // blackholed while the trailing segments are delivered. The peer's
        // SACKs then expose a REAL gap, so the RFC 5681 fast-retransmit
        // entry (or the 200 ms RTO backstop) cuts ssthresh - and because the
        // loss is real (the peer never held the data), neither the RFC 2883
        // D-SACK undo nor the no-SACK clean-exit undo can restore it: the
        // cut persists and is observable at any machine speed.
        constexpr UInt32 kPhaseB = 4096;
        std::vector<Byte> payload_b(kPhaseB);
        for (UInt32 i = 0; i < kPhaseB; ++i) {
            payload_b[i] = static_cast<Byte>((i * 13 + i / 7) & 0xFF);
        }
        UInt32 dropped_b = 0;
        std::vector<UInt32> dropped_seqs_b;
        UInt32 tries_b = 0;
        while (!stack_a.Send(conn, payload_b.data(), kPhaseB) && 500 > ++tries_b) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, 0, dropped_b, seen,
                      dropped_seqs_b);
            PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, dropped_b, seen,
                      dropped_seqs_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(500 > tries_b);
        const UInt64 recv_b_before = bytes_recv;
        UInt32 min_ssthresh_b = 0xFFFFFFFFu;
        UInt32 inflight_b = 0, cwnd_b = 0, ssthresh_b = 0, snd_wnd_b = 0, retx_b = 0;
        UInt32 dup_b = 0, fast_b = 0;
        UInt64 rto_deadline_b = 0;
        UInt32 front_seq_b = 0, snd_una_b = 0;
        UInt16 lp_b = 0, rp_b = 0;
        for (UInt32 i = 0; i < 3000 && bytes_recv - recv_b_before < kPhaseB; ++i) {
            PumpDropFirstTwo(backend_a, backend_b, stack_a, stack_b, dropped_b, dropped_seqs_b);
            PumpDropFirstTwo(backend_b, backend_a, stack_a, stack_b, dropped_b, dropped_seqs_b);
            stack_a.ConnStats(conn, inflight_b, cwnd_b, ssthresh_b, snd_wnd_b, retx_b,
                              rto_deadline_b, dup_b, fast_b, front_seq_b, snd_una_b, lp_b, rp_b);
            if (ssthresh_b < min_ssthresh_b) {
                min_ssthresh_b = ssthresh_b;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (UInt32 i = 0; i < 200; ++i) {
            PumpDropFirstTwo(backend_a, backend_b, stack_a, stack_b, dropped_b, dropped_seqs_b);
            PumpDropFirstTwo(backend_b, backend_a, stack_a, stack_b, dropped_b, dropped_seqs_b);
            stack_a.ConnStats(conn, inflight_b, cwnd_b, ssthresh_b, snd_wnd_b, retx_b,
                              rto_deadline_b, dup_b, fast_b, front_seq_b, snd_una_b, lp_b, rp_b);
            if (0 == inflight_b) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        stack_a.ConnStats(conn, inflight_b, cwnd_b, ssthresh_b, snd_wnd_b, retx_b,
                          rto_deadline_b, dup_b, fast_b, front_seq_b, snd_una_b, lp_b, rp_b);
        std::fprintf(stderr,
                     "[rto-recovery] phaseB dropped=%u retx_b=%u min_ssthresh_b=%u "
                     "cwnd_b=%u ssthresh_b=%u inflight_b=%u recv_b=%llu\n",
                     dropped_b, retx_b, min_ssthresh_b, cwnd_b, ssthresh_b, inflight_b,
                     (unsigned long long)(bytes_recv - recv_b_before));
        CHECK(0 < dropped_b);
        CHECK(0 < retx_b - retx);
        CHECK(kPhaseB == bytes_recv - recv_b_before);
        CHECK(min_ssthresh_b < 1000u);
        CHECK(0 == inflight_b);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, kDropEvery, drop, seen, dropped_seqs);
            PumpLossy(backend_b, backend_a, stack_a, stack_b, 0, drop, seen, dropped_seqs);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RTO_RECOVERY: FAILED (%d)\n" : "RTO_RECOVERY: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

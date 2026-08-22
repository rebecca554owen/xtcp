/**
 * @file cc_bbrv1.cpp
 * @brief BBRv1 port as an XtcpCongestionOps module (independent C++
 *        implementation, fidelity-verified against plugins/ref/bbr_core.c).
 */

#include <xtcp/cc/cc.h>

#include <new>

namespace {
    using namespace xtcp;
    using namespace xtcp::cc;

    constexpr UInt32 kUnit = 1000000;
    constexpr UInt32 kCycleLen = 8;
    constexpr UInt32 kBwWindow = 10;       /* rounds */
    constexpr UInt32 kMinRttWinSec = 10;
    constexpr UInt32 kCwndMinTarget = 4;
    constexpr UInt32 kHighGain = kUnit * 2885 / 1000 + 1;
    constexpr UInt32 kCwndGain = kUnit * 2;
    constexpr UInt32 kFullBwThresh = kUnit * 5 / 4;

    constexpr UInt32 kPacingGain[kCycleLen] = {
        kUnit * 5 / 4, kUnit * 3 / 4,
        kUnit, kUnit, kUnit, kUnit, kUnit, kUnit,
    };

    enum class BbrMode : Byte {
        kStartup = 0,
        kDrain = 1,
        kProbeBw = 2,
        kProbeRtt = 3,
    };

    /**
     * @brief BBR private state (per connection, ca_priv).
     */
    struct BbrState {
        UInt32  min_rtt_us = 0;
        UInt32  min_rtt_stamp = 0;   /**< Elapsed-clock time of the last min_rtt sample */
        UInt32  now_us = 0;          /**< Accumulated elapsed clock (rs.interval_us sums) */
        UInt32  probe_rtt_enter = 0; /**< Elapsed-clock time PROBE_RTT began */
        UInt32  saved_pacing_gain = 0; /**< Cycle gain to resume after PROBE_RTT */
        Byte    saved_cycle_idx = 0;
        UInt32  bw_window[kBwWindow] = { 0 };
        UInt32  bw_next = 0;
        UInt32  bw_count = 0;
        UInt32  full_bw = 0;
        UInt32  full_bw_cnt = 0;
        UInt32  pacing_gain = kHighGain;
        UInt32  cwnd_gain = kHighGain;
        UInt32  prior_cwnd = 0;
        Byte    mode = static_cast<Byte>(BbrMode::kStartup);
        Byte    full_bw_reached = 0;
        Byte    cycle_idx = 0;

        UInt32 MaxBw() const noexcept {
            UInt32 best = 0;
            for (UInt32 i = 0; i < bw_count; ++i) {
                if (bw_window[i] > best) {
                    best = bw_window[i];
                }
            }
            return best;
        }
        void AddBw(UInt32 bw) noexcept {
            bw_window[bw_next] = bw;
            bw_next = (bw_next + 1) % kBwWindow;
            if (bw_count < kBwWindow) {
                ++bw_count;
            }
        }
    };

    BbrState* Priv(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return NULLPTR;
        }
        if (NULLPTR == sk->ca_priv) {
            sk->ca_priv = new (std::nothrow) BbrState();
        }
        return static_cast<BbrState*>(sk->ca_priv);
    }

    void BbrInit(XtcpConnCc* sk) noexcept {
        BbrState* b = Priv(sk);
        if (NULLPTR == b) {
            return;
        }
        b->mode = static_cast<Byte>(BbrMode::kStartup);
        b->pacing_gain = kHighGain;
        b->cwnd_gain = kHighGain;
        // Initial pacing from cwnd and min RTT (bytes/sec).
        UInt64 rate = static_cast<UInt64>(sk->snd_cwnd) * sk->mss;
        if (0 != sk->rtt_min_us) {
            rate = rate * 1000000ull / sk->rtt_min_us;
        } else {
            rate = rate * 1000;  // assume 1ms
        }
        sk->pacing_rate = rate;
    }

    void BbrRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != sk) {
            delete static_cast<BbrState*>(sk->ca_priv);
            sk->ca_priv = NULLPTR;
        }
    }

    UInt32 BbrSsthresh(XtcpConnCc* sk) noexcept {
        BbrState* b = Priv(sk);
        if (NULLPTR != b) {
            b->prior_cwnd = sk->snd_cwnd;
        }
        sk->snd_cwnd = kCwndMinTarget;
        return kCwndMinTarget;
    }

    void BbrSetState(XtcpConnCc* sk, Byte new_state) noexcept {
        (void)sk;
        (void)new_state;
    }

    void BbrCwndEvent(XtcpConnCc* sk, CaEvent ev) noexcept {
        BbrState* b = Priv(sk);
        if (NULLPTR == b) {
            return;
        }
        if (kCaEventLoss == ev) {
            // The prior_cwnd save belongs to BbrSsthresh (which CutCwnd
            // dispatches FIRST): overwriting it here with the ALREADY-cut
            // value would make a future undo restore the collapsed window
            // instead of the pre-loss one.
            sk->snd_cwnd = kCwndMinTarget;
        }
    }

    UInt32 BbrUndoCwnd(XtcpConnCc* sk) noexcept {
        BbrState* b = Priv(sk);
        if (NULLPTR != b && 0 != b->prior_cwnd) {
            sk->snd_cwnd = b->prior_cwnd;
        }
        return sk->snd_cwnd;
    }

    void BbrMain(XtcpConnCc* sk, const RateSample* rs) noexcept {
        BbrState* b = Priv(sk);
        if (NULLPTR == b) {
            return;
        }
        // Model update: bandwidth.
        if (0 != rs->interval_us) {
            b->now_us += rs->interval_us;  // elapsed clock for PROBE_RTT timing
            const UInt64 bw64 =
                (static_cast<UInt64>(rs->delivered) * kUnit) / rs->interval_us;
            const UInt32 bw = (bw64 > 0xFFFFFFFFu) ? 0xFFFFFFFFu : static_cast<UInt32>(bw64);
            b->AddBw(bw);
            // Full-bw detection: exit STARTUP after 3 rounds WITHOUT >1.25x
            // gain (BBR paper Fig. 3 - growth RESETS the plateau counter).
            // The pre-fix code counted growth rounds (bw >= 1.25x full_bw
            // incremented the counter): under the 2.885x STARTUP ramp it
            // fired every round (exiting mid-ramp, before the pipe fills)
            // and under a plateau it reset forever (never exiting - a
            // permanent 2.885x pacing regime, same pathology as the KCC
            // bug). Compare against the OLD full_bw, then update full_bw -
            // order mirrors bbr_core.c:223-234.
            if (bw >= (static_cast<UInt64>(b->full_bw) * kFullBwThresh / kUnit)) {
                b->full_bw_cnt = 0;  // still growing >= 25%/round: keep probing
            } else {
                ++b->full_bw_cnt;    // plateau round
            }
            if (3 <= b->full_bw_cnt) {
                b->full_bw_reached = 1;
            }
            if (bw > b->full_bw) {
                b->full_bw = bw;
            }
        }
        // Model update: min RTT (stamped for the 10 s PROBE_RTT expiry).
        if (0 != rs->rtt_us && (0 == b->min_rtt_us || rs->rtt_us < b->min_rtt_us)) {
            b->min_rtt_us = rs->rtt_us;
            b->min_rtt_stamp = b->now_us;
        }
        // State machine.
        switch (static_cast<BbrMode>(b->mode)) {
        case BbrMode::kStartup:
            if (b->full_bw_reached) {
                // BBR paper Fig. 3: STARTUP -> DRAIN (gain 1/2.885) drains
                // the queue built during STARTUP before probing resumes
                // (audit M2). The pre-fix code jumped straight to PROBE_BW,
                // probing on top of a standing queue.
                b->mode = static_cast<Byte>(BbrMode::kDrain);
                b->pacing_gain = static_cast<UInt32>(kUnit * 1000ull / 2885);
                b->cwnd_gain = kHighGain;
            }
            break;
        case BbrMode::kDrain: {
            // Exit when the STARTUP queue has drained: inflight <= BDP
            // (bytes). Use the REAL pipe occupancy (audit M3).
            const UInt32 bw = b->MaxBw();
            const UInt64 bdp = (0 != b->min_rtt_us)
                ? static_cast<UInt64>(bw) * b->min_rtt_us / kUnit
                : 0;
            if (0 == bdp || static_cast<UInt64>(sk->inflight) <= bdp) {
                b->mode = static_cast<Byte>(BbrMode::kProbeBw);
                b->cycle_idx = 0;
                b->pacing_gain = kPacingGain[0];
                b->cwnd_gain = kCwndGain;
            }
            break;
        }
        case BbrMode::kProbeBw: {
            // PROBE_RTT (audit M2): refresh the min-RTT filter every 10 s
            // with a 4-packet window (the paper's BBR_MIN_RTT_WIN_SEC).
            // Without it min_rtt only ratchets down, pinning BDP to the
            // all-time-best RTT after a path change.
            if (0 != b->min_rtt_stamp &&
                b->now_us - b->min_rtt_stamp >= kMinRttWinSec * 1000000ull) {
                b->saved_cycle_idx = b->cycle_idx;
                b->saved_pacing_gain = b->pacing_gain;
                b->probe_rtt_enter = b->now_us;
                b->mode = static_cast<Byte>(BbrMode::kProbeRtt);
            }
            // Cycle phase advance: probe (>1.0 gain) until inflight >=
            // target, drain (<1.0) until inflight <= target. Uses the REAL
            // bytes-in-flight (audit M3) - the pre-fix snd_cwnd (always
            // 2x BDP) made the probe condition true immediately and the
            // drain false, collapsing the cycle to ~2 samples.
            const UInt32 bw = b->MaxBw();
            const UInt64 inflight = static_cast<UInt64>(sk->inflight);
            UInt64 target = inflight;  // fallback: no advance
            if (0 != b->min_rtt_us && 0 != bw) {
                target = static_cast<UInt64>(bw) * b->min_rtt_us / kUnit;
                target = target * b->pacing_gain / kUnit;
            }
            bool advance = false;
            if (b->pacing_gain > kUnit) {
                advance = inflight >= target;
            } else if (b->pacing_gain < kUnit) {
                advance = inflight <= target;
            }
            if (advance) {
                b->cycle_idx = (b->cycle_idx + 1) % kCycleLen;
                b->pacing_gain = kPacingGain[b->cycle_idx];
            }
            break;
        }
        case BbrMode::kProbeRtt:
            // 200 ms of 4-packet probing refreshes min_rtt, then resume
            // the saved PROBE_BW cycle. Pacing gain forced to 1.0 for the
            // whole probe (reference bbr_core.c:329-331: the probe must not
            // inflate the queue).
            b->pacing_gain = kUnit;
            if (b->now_us - b->probe_rtt_enter >= 200000) {
                b->cycle_idx = b->saved_cycle_idx;
                b->pacing_gain = b->saved_pacing_gain;
                b->mode = static_cast<Byte>(BbrMode::kProbeBw);
            }
            break;
        default:
            break;
        }
        // Control outputs.
        const UInt32 bw = b->MaxBw();
        if (0 != bw) {
            // bw is bytes/sec (delivered*UNIT/interval cancels to /s). The
            // pacing rate is bw * gain, where gain is scaled by kUnit:
            //   rate = bw * gain / kUnit
            // (a previous "bw/kUnit * gain/kUnit" divided twice and shrank the
            // pacing by 1e6, stalling large transfers). PROBE_RTT's gain-1.0
            // is applied in the mode case above (mirror of the reference).
            UInt64 rate = static_cast<UInt64>(bw) * b->pacing_gain / kUnit;
            if (0 == rate) {
                rate = 1;
            }
            sk->pacing_rate = rate;
        }
            if (0 != b->min_rtt_us && 0 != bw) {
                UInt64 target = static_cast<UInt64>(bw) * b->min_rtt_us / kUnit;
                if (static_cast<Byte>(BbrMode::kProbeRtt) == b->mode) {
                    // PROBE_RTT: the 4-packet window forces the queue to
                    // drain so the RTT sample measures the true empty-path
                    // RTT (paper Fig. 5).
                    sk->snd_cwnd = kCwndMinTarget;
                } else {
                    // bdp: bw(bytes/sec) * min_rtt(us) / kUnit = bytes -> packets.
                    target = target * b->cwnd_gain / kUnit;
                    if (0 != sk->mss) {
                        target = target / sk->mss + 1;
                    }
                    // Clamp (m3): a poisoned min_rtt sample (first ACK after a
                    // long stall) can inflate the BDP target past UInt32; the
                    // cast must not wrap into a garbage window.
                    sk->snd_cwnd = (target > 0x7FFFFFFFull)
                        ? 0x7FFFFFFFu
                        : static_cast<UInt32>(target);
                }
            }
    }

    const XtcpCongestionOps& BbrOps() noexcept {
        static const XtcpCongestionOps ops = {
            "bbr",
            BbrInit,
            BbrRelease,
            BbrSsthresh,
            NULLPTR,          /* cong_avoid */
            BbrSetState,
            BbrCwndEvent,
            NULLPTR,          /* pkts_acked */
            BbrUndoCwnd,
            BbrMain,          /* cong_control */
            NULLPTR,
            0,
        };
        return ops;
    }
}

namespace xtcp {
    namespace cc {
        /**
         * @brief Registers the BBRv1 port (default: KCC; BBR is a reference).
         */
        void RegisterBbrv1() noexcept {
            RegisterCongestionControl(BbrOps());
        }
    }
}

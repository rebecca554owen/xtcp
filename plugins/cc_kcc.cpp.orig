/**
 * @file cc_kcc.cpp
 * @brief KCC v2.0 (Geodesic) port as an XtcpCongestionOps module.
 *
 * Independent C++ implementation of the KCC core (three-component RTT
 * decomposition: T_prop/T_queue/T_noise; geodesic G1/G2/G3 estimator;
 * STARTUP->DRAIN->PROBE_BW FSM). Constants verbatim from ucp_constants.h
 * and tcp_kcc.c. Fidelity-verified against plugins/ref/kcc_core.c.
 */

#include <xtcp/cc/cc.h>

#include <new>

namespace {
    using namespace xtcp;
    using namespace xtcp::cc;

    constexpr Int64 kBwUnit = INT64_C(1) << 24;
    constexpr UInt32 kScaleShift = 10;
    constexpr UInt64 kScale = UINT64_C(1) << kScaleShift;

    constexpr UInt32 kG2GrowthNum = 122;
    constexpr UInt32 kG2GrowthDen = 1000;
    constexpr UInt32 kG3FastThNum = 11;
    constexpr UInt32 kG3FastThDen = 10;
    constexpr UInt32 kG3SlowThNum = 21;
    constexpr UInt32 kG3SlowThDen = 20;
    constexpr UInt32 kPdNoiseGateNum = 95;
    constexpr UInt32 kPdNoiseGateDen = 100;
    constexpr UInt32 kJitterSeedShift = 2;
    constexpr UInt32 kJitterEwmaNum = 7;
    constexpr UInt32 kJitterEwmaDen = 8;
    constexpr UInt32 kQdelayEwmaNum = 7;
    constexpr UInt32 kQdelayEwmaDen = 8;
    constexpr UInt32 kMinSamples = 5;
    constexpr UInt32 kStalenessRnds = 128;
    constexpr UInt32 kRttMinFloorUs = 1;
    constexpr UInt32 kRttSampleMaxUs = 500000;
    constexpr UInt32 kPEstInit = 1000;
    constexpr UInt32 kPEstFloor = 10;
    constexpr UInt32 kPEstDecayShift = 4;
    constexpr UInt32 kPEstGrowthShift = 3;
    constexpr UInt32 kPEstMax = 1000000;
    constexpr UInt32 kLockThreshUs = 5000;
    constexpr UInt32 kFastOnlyThreshUs = 7500;
    constexpr UInt32 kBitfield3bitMax = 7;
    constexpr UInt32 kBwRtCycleLen = 10;
    constexpr UInt32 kCycleLen = 8;
    constexpr UInt32 kHighGain = 256 * 2885 / 1000 + 1;   /* BBR_UNIT=256 */
    constexpr UInt32 kCwndGain = 256 * 2;
    constexpr UInt32 kFullBwCnt = 3;
    constexpr UInt32 kCwndMinTarget = 4;
    constexpr UInt32 kCwndAbsoluteMin = 1;
    constexpr UInt32 kMinRttUninit = 0xFFFFFFFF;
    constexpr UInt32 kModeStartup = 0;
    constexpr UInt32 kModeProbeBw = 1;
    constexpr UInt32 kModeDrain = 2;

    enum Mode : Byte {
        kStartup = 0,
        kProbeBw = 1,
        kDrain = 2,
    };

    struct BwSample {
        UInt64 val = 0;
        UInt32 rtt_cnt = 0;
    };

    /**
     * @brief KCC private state (per connection, ca_priv).
     */
    struct KccState {
        UInt64  x_est = 0;
        UInt32  p_est = kPEstInit;
        UInt32  qdelay_avg = 0;
        UInt32  jitter_ewma = 0;
        UInt32  sample_cnt = 0;
        UInt32  min_rtt_us = kMinRttUninit;
        UInt32  min_rtt_stamp = 0;
        UInt32  mr_update_rtt_cnt = 0;
        UInt32  rtt_cnt = 0;
        UInt32  confirm_cnt = 0;
        UInt32  confirm_slow_cnt = 0;
        UInt32  locked = 0;
        BwSample bw_samples[kBwRtCycleLen];
        UInt32  bw_sample_count = 0;
        UInt32  bw_sample_cur = 0;
        UInt64  max_bw = 0;
        UInt32  mode = kModeStartup;
        UInt32  pacing_gain = kHighGain;
        UInt32  cwnd_gain = kHighGain;
        UInt32  cycle_idx = 0;
        UInt32  full_bw_reached = 0;
        UInt64  full_bw = 0;
        UInt32  full_bw_cnt = 0;
        UInt32  has_seen_rtt = 0;
        UInt64  prev_ack_us = 0;
        UInt64  last_ack_us = 0;
        UInt64  total_delivered = 0;
        UInt64  prev_delivered = 0;
        UInt64  next_rtt_delivered = 0;
        UInt64  next_rtt_stamp_us = 0;
        UInt64  round_sample_delivered = 0;
        UInt64  round_sample_interval_us = 0;
        UInt64  congestion_window_bytes = 10 * 1460;

        UInt64 BwMax() const noexcept {
            if (0 == bw_sample_count) {
                return 0;
            }
            UInt64 result = 0;
            for (UInt32 i = 0; i < bw_sample_count; ++i) {
                if (rtt_cnt - bw_samples[i].rtt_cnt >= kBwRtCycleLen) {
                    continue;
                }
                if (bw_samples[i].val > result) {
                    result = bw_samples[i].val;
                }
            }
            if (0 == result) {
                for (UInt32 i = 0; i < bw_sample_count; ++i) {
                    if (bw_samples[i].val > result) {
                        result = bw_samples[i].val;
                    }
                }
            }
            return result;
        }
        void BwUpdate(UInt64 bw, UInt32 cnt_rtt) noexcept {
            if (0 == bw) {
                return;
            }
            // Rate samples can arrive several times within one delivery
            // round. Keep the best sample for that round instead of letting
            // each ACK overwrite one of the ten RTT-window entries.
            if (0 < bw_sample_count && bw_samples[bw_sample_cur].rtt_cnt == cnt_rtt) {
                if (bw > bw_samples[bw_sample_cur].val) {
                    bw_samples[bw_sample_cur].val = bw;
                }
                return;
            }
            if (0 == bw_sample_count) {
                bw_sample_count = 1;
                bw_sample_cur = 0;
                bw_samples[0].val = bw;
                bw_samples[0].rtt_cnt = cnt_rtt;
                return;
            }
            const UInt32 next = (bw_sample_cur + 1) % kBwRtCycleLen;
            bw_samples[next].val = bw;
            bw_samples[next].rtt_cnt = cnt_rtt;
            bw_sample_cur = next;
            if (bw_sample_count < kBwRtCycleLen) {
                ++bw_sample_count;
            }
        }
        UInt32 CycleGain() const noexcept {
            switch (cycle_idx % kCycleLen) {
            case 0: return 256 * 5 / 4;
            case 1: return 256 * 3 / 4;
            default: return 256;
            }
        }
    };

    KccState* Priv(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return NULLPTR;
        }
        if (NULLPTR == sk->ca_priv) {
            sk->ca_priv = new (std::nothrow) KccState();
        }
        return static_cast<KccState*>(sk->ca_priv);
    }

    void GeodesicUpdate(KccState* k, UInt32 rtt_us) noexcept {
        const UInt32 rtt = (rtt_us > kRttMinFloorUs) ? rtt_us : kRttMinFloorUs;
        const UInt64 z = static_cast<UInt64>(rtt) << kScaleShift;

        if (0 == k->sample_cnt) {
            k->x_est = z;
            k->p_est = kPEstInit;
            k->qdelay_avg = 0;
            k->jitter_ewma = rtt >> kJitterSeedShift;
            if (k->jitter_ewma < 1) {
                k->jitter_ewma = 1;
            }
            k->sample_cnt = 1;
            return;
        }
        if (1 == k->sample_cnt && k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us) {
            const UInt64 ceiling = static_cast<UInt64>(k->min_rtt_us) << kScaleShift;
            if (k->x_est > ceiling) {
                k->x_est = ceiling;
            }
        }

        const Int64 innovation = static_cast<Int64>(z) - static_cast<Int64>(k->x_est);
        const UInt64 abs_innov = (innovation >= 0) ? static_cast<UInt64>(innovation)
                                                   : static_cast<UInt64>(-(innovation + 1)) + 1;

        // G1: instant downward absorption (censored min).
        if (innovation <= 0) {
            k->x_est = (k->x_est < z) ? k->x_est : z;
        } else {
            // G2: bounded geometric growth capped at the observation.
            const UInt64 growth = k->x_est * kG2GrowthNum / kG2GrowthDen;
            UInt64 new_x = k->x_est + growth;
            if (new_x < k->x_est) {
                new_x = 0xFFFFFFFFFFFFFFFFull;
            }
            k->x_est = (new_x < z) ? new_x : z;
        }

        // Staleness pull-back.
        if (k->min_rtt_us != kMinRttUninit &&
            k->rtt_cnt - k->mr_update_rtt_cnt >= kStalenessRnds) {
            const UInt64 mr_scaled = static_cast<UInt64>(k->min_rtt_us) << kScaleShift;
            if (k->x_est <= mr_scaled * kG3FastThNum / kG3FastThDen) {
                k->x_est = mr_scaled * kPdNoiseGateNum / kPdNoiseGateDen;
                k->mr_update_rtt_cnt = k->rtt_cnt;
            }
        }

        // Jitter EWMA (7/8), capped.
        {
            const UInt32 raw_jitter = static_cast<UInt32>(
                (abs_innov >> kScaleShift) > 0xFFFFFFFFull ? 0xFFFFFFFFu
                                                           : static_cast<UInt32>(abs_innov >> kScaleShift));
            k->jitter_ewma = (k->sample_cnt > 1)
                                 ? (k->jitter_ewma * kJitterEwmaNum + raw_jitter) / kJitterEwmaDen
                                 : raw_jitter;
            const UInt32 jitter_cap = (k->min_rtt_us != kMinRttUninit)
                                          ? ((k->min_rtt_us > kRttSampleMaxUs) ? k->min_rtt_us : kRttSampleMaxUs)
                                          : kRttSampleMaxUs;
            if (k->jitter_ewma > jitter_cap) {
                k->jitter_ewma = jitter_cap;
            }
        }

        // Queuing-delay EWMA (7/8): max(0, z - x_est) >> 10.
        {
            const UInt32 qdelay_instant = (z > k->x_est)
                                              ? static_cast<UInt32>((z - k->x_est) >> kScaleShift)
                                              : 0;
            if (1 == k->sample_cnt) {
                k->qdelay_avg = qdelay_instant;
            } else {
                k->qdelay_avg = static_cast<UInt32>(
                    (static_cast<UInt64>(k->qdelay_avg) * kQdelayEwmaNum + qdelay_instant) / kQdelayEwmaDen);
            }
        }

        if (k->sample_cnt < 0xFFFFFFFFu) {
            ++k->sample_cnt;
        }

        // Convergence proxy p_est.
        if (k->sample_cnt >= kMinSamples) {
            const UInt64 x_est_us = k->x_est >> kScaleShift;
            if (x_est_us <= static_cast<UInt64>(k->min_rtt_us) * kG3SlowThNum / kG3SlowThDen &&
                0 == k->confirm_cnt && 0 == k->confirm_slow_cnt) {
                const UInt32 delta = (k->p_est > kPEstFloor) ? (k->p_est - kPEstFloor) >> kPEstDecayShift : 0;
                if (k->p_est > kPEstFloor + delta) {
                    k->p_est -= (delta > 1) ? delta : 1;
                }
            } else if (x_est_us > static_cast<UInt64>(k->min_rtt_us) * kG3FastThNum / kG3FastThDen) {
                const UInt32 delta = (k->p_est < kPEstInit) ? (kPEstInit - k->p_est) >> kPEstGrowthShift : 0;
                if (k->p_est + delta < kPEstMax) {
                    k->p_est += (delta > 1) ? delta : 1;
                }
            }
        }
    }

    void UpdateMinRtt(KccState* k, UInt32 rtt_us, UInt64 now_us) noexcept {
        if (0 == rtt_us) {
            return;
        }
        const UInt32 mr_snapshot = k->min_rtt_us;
        GeodesicUpdate(k, rtt_us);

        if (rtt_us < kLockThreshUs) {
            k->locked = 1;
        }
        // G3 dual-threshold consecutive-event detection.
        if (0 == k->locked && k->min_rtt_us >= kFastOnlyThreshUs) {
            if (k->x_est >= static_cast<UInt64>(k->min_rtt_us) * kScale * kG3FastThNum / kG3FastThDen) {
                if (k->confirm_cnt < kBitfield3bitMax) {
                    ++k->confirm_cnt;
                }
            } else {
                k->confirm_cnt = 0;
            }
            if (k->x_est >= static_cast<UInt64>(k->min_rtt_us) * kScale * kG3SlowThNum / kG3SlowThDen) {
                if (k->confirm_slow_cnt < kBitfield3bitMax) {
                    ++k->confirm_slow_cnt;
                }
            } else {
                k->confirm_slow_cnt = 0;
            }
        }
        if (rtt_us < mr_snapshot || mr_snapshot == kMinRttUninit) {
            k->min_rtt_us = rtt_us;
            k->min_rtt_stamp = static_cast<UInt32>(now_us);
            k->mr_update_rtt_cnt = k->rtt_cnt;
        }
    }

    void KccInit(XtcpConnCc* sk) noexcept {
        KccState* k = Priv(sk);
        if (NULLPTR == k) {
            return;
        }
        k->mode = kModeStartup;
        k->pacing_gain = kHighGain;
        k->cwnd_gain = kHighGain;
        k->p_est = kPEstInit;
        // Mirror kcc_core_init, but size the initial window by the peer's
        // actual MSS: 10 segments of a 536-byte-MSS peer are 5360 bytes,
        // not 14600 (a hardcoded 1460 overstates the window ~2.7x there).
        k->congestion_window_bytes = 10 * ((0 < sk->mss) ? static_cast<UInt32>(sk->mss) : 1460u);
        sk->snd_cwnd = 10;                       /* mirror cwnd_segs = 10 */
    }

    void KccRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != sk) {
            delete static_cast<KccState*>(sk->ca_priv);
            sk->ca_priv = NULLPTR;
        }
    }

    void KccMain(XtcpConnCc* sk, const RateSample* rs) noexcept {
        KccState* k = Priv(sk);
        if (NULLPTR == k || NULLPTR == rs) {
            return;
        }
        const UInt64 delivered = static_cast<UInt64>(rs->delivered);
        const UInt32 rtt_us = rs->rtt_us;
        // Reference kcc_core_on_ack: acked = delivered_bytes > 0 ? delivered_bytes : 0.
        // The FSM supplies rs->delivered as the bytes delivered since the last
        // emitted rate sample (a cumulative-batch delta; rs->acked is this ACK's
        // own advance), so acked here is byte accounting, not a segment count
        // (a segment/byte mix stalled the round).
        const UInt64 acked = delivered;
        const UInt64 now_us = static_cast<UInt64>(rs->interval_us) + k->last_ack_us;

        k->prev_delivered = k->total_delivered;
        k->total_delivered += acked;
        k->prev_ack_us = k->last_ack_us;
        k->last_ack_us = now_us;

        // Model update.
        const UInt64 interval_us = (now_us > k->prev_ack_us) ? (now_us - k->prev_ack_us) : 0;
        const UInt32 round_rtt_us = (0 < rtt_us) ? rtt_us : 1;
        const bool round_completed = 0 == k->next_rtt_stamp_us || now_us >= k->next_rtt_stamp_us;
        bool completed_sample_round = false;
        if (round_completed) {
            if (0 < k->round_sample_delivered && 0 < k->round_sample_interval_us) {
                completed_sample_round = true;
            }
            k->round_sample_delivered = 0;
            k->round_sample_interval_us = 0;
            const UInt64 round_us = (0 < round_rtt_us) ? round_rtt_us : 1;
            k->next_rtt_stamp_us = now_us + round_us;
            ++k->rtt_cnt;
        }
        UInt64 bw = 0;
        if (0 < delivered && 0 < interval_us) {
            bw = (delivered << 24) / interval_us;
        }
        if (0 < delivered && 0 < interval_us) {
            k->round_sample_delivered += delivered;
            k->round_sample_interval_us += interval_us;
        }
        k->BwUpdate(bw, k->rtt_cnt);
        k->max_bw = k->BwMax();
        if (0 < rtt_us) {
            UpdateMinRtt(k, rtt_us, now_us);
        }

        // Mode and gains.
        switch (k->mode) {
        case kModeStartup:
            k->pacing_gain = kHighGain;
            k->cwnd_gain = kHighGain;
            break;
        case kModeDrain:
            k->pacing_gain = 256 * 1000 / 2885;
            k->cwnd_gain = kHighGain;
            break;
        case kModeProbeBw:
            // Reference kcc_update_model: kcc_advance_cycle_phase is never called,
            // so cycle_idx stays 0 and the gain is the constant probe phase (5/4).
            k->pacing_gain = k->CycleGain();
            k->cwnd_gain = kCwndGain;
            break;
        }

        // Full-bw detection and FSM transitions.
        if (completed_sample_round && 0 == k->full_bw_reached) {
            const UInt64 bw_now = k->BwMax();
            // "3.2% step" (kFullBwThresh = 320 = 3.2%): a plateau round
            // grows by less than 3.2% vs the running max. Count CONSECUTIVE
            // plateau rounds (growth resets the counter); 3 in a row => the
            // pipe is full and STARTUP exits (BBR-style full-bw detection).
            // The pre-fix check `bw_now >= full_bw * 320 / 100` required
            // 320% growth per round - it never fired, so STARTUP's 2.885x
            // gain ran forever (standing queue, ~65% overshoot, continuous
            // loss; the DRAIN/PROBE_BW FSM was unreachable).
            // (full_bw + 3.2% cannot overflow: full_bw <= 2^56, the sum
            // stays below 2^64.)
            if (bw_now >= k->full_bw + (k->full_bw / 1000) * 32) {
                k->full_bw_cnt = 0;  // still growing >= 3.2%/round: keep probing
            } else {
                ++k->full_bw_cnt;    // plateau round
            }
            if (bw_now > k->full_bw) {
                k->full_bw = bw_now;
            }
            if (k->full_bw_cnt >= kFullBwCnt) {
                k->full_bw_reached = 1;
            }
        }
        if (kModeStartup == k->mode && k->full_bw_reached) {
            k->mode = kModeDrain;
        }
        if (kModeDrain == k->mode && k->rtt_cnt >= 3) {
            k->mode = kModeProbeBw;
            k->cycle_idx = 0;
        }

        // Control outputs.
        const UInt64 pacing_bw = (0 != k->max_bw) ? k->max_bw
            : ((0 != bw) ? bw : kBwUnit);
        UInt64 rate = (pacing_bw * k->pacing_gain) >> 8;
        rate = (rate * 990000ull) >> 24;
        if (0 == k->has_seen_rtt && k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us && 0 < sk->mss) {
            k->has_seen_rtt = 1;
            const UInt64 rtt = (k->min_rtt_us > 0) ? k->min_rtt_us : 1;
            const UInt64 cwnd_segs = k->congestion_window_bytes / sk->mss;
            const UInt64 bdp_bw = (cwnd_segs * kBwUnit) / rtt;
            UInt64 boot_rate = bdp_bw * sk->mss;
            boot_rate = (boot_rate * kHighGain) >> 8;
            boot_rate = (boot_rate * 990000ull) >> 24;
            if (boot_rate > rate) {
                rate = boot_rate;
            }
        }
        if (k->full_bw_reached) {
            sk->pacing_rate = rate;
        } else if (rate > sk->pacing_rate) {
            sk->pacing_rate = rate;
        }

        // cwnd (bytes), loss deduction, BDP target, floor.
        UInt64 cwnd = k->congestion_window_bytes;
        if (0 < acked) {
            if (0 < rs->lost) {
                cwnd = (cwnd > static_cast<UInt64>(rs->lost)) ? cwnd - rs->lost
                                                              : kCwndAbsoluteMin * sk->mss;
            }
            if (k->min_rtt_us != kMinRttUninit && 0 < k->min_rtt_us) {
                // Reference kcc_set_cwnd gets the raw max_bw (only kcc_set_pacing_rate
                // floors to BW_UNIT), so the BDP uses max_bw unfloored.
                UInt64 bdp = (k->max_bw * k->min_rtt_us) >> 24;
                bdp = (bdp * k->cwnd_gain) >> 8;
                if (bdp < kCwndMinTarget * sk->mss) {
                    bdp = kCwndMinTarget * sk->mss;
                }
                if (cwnd < bdp) {
                    cwnd = bdp;
                }
            }
        }
        if (cwnd < kCwndMinTarget * sk->mss) {
            cwnd = kCwndMinTarget * sk->mss;
        }
        k->congestion_window_bytes = cwnd;
        if (0 < sk->mss) {
            // Clamp: a poisoned min_rtt sample (first ACK after a long
            // stall) can inflate the BDP far beyond UInt32 segments; the
            // pacing gate bounds actual sending, but the cast must not
            // wrap into garbage (m3: cwnd/mss > 2^32 overflowed).
            const UInt64 segs = cwnd / sk->mss;
            sk->snd_cwnd = (segs > 0x7FFFFFFFull)
                ? 0x7FFFFFFFu
                : static_cast<UInt32>(segs);
        }
    }

    UInt32 KccSsthresh(XtcpConnCc* sk) noexcept {
        sk->snd_cwnd = kCwndMinTarget;
        return kCwndMinTarget;
    }

    const XtcpCongestionOps& KccOps() noexcept {
        static const XtcpCongestionOps ops = {
            "kcc",
            KccInit,
            KccRelease,
            KccSsthresh,
            NULLPTR,          /* cong_avoid */
            NULLPTR,          /* set_state */
            NULLPTR,          /* cwnd_event */
            NULLPTR,          /* pkts_acked */
            NULLPTR,          /* undo_cwnd */
            KccMain,          /* cong_control */
            NULLPTR,
            0,
        };
        return ops;
    }
}

namespace xtcp {
    namespace cc {
        /**
         * @brief Registers the KCC port (KCC is the stack's default CC; select
         *        others via SetDefaultCongestionControl; built-in Reno remains
         *        the fallback when no plugin is configured).
         */
        void RegisterKcc() noexcept {
            RegisterCongestionControl(KccOps());
        }
    }
}

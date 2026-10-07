/**
 * @file test_cc_kcc.cpp
 * @brief KCC fidelity differential vs the reference core
 *        (plugins/ref/kcc_core.c): geodesic estimator outputs (x_est/p_est/
 *        qdelay) and cwnd/pacing rate over a deterministic RTT sequence.
 */

#include <xtcp/cc/cc.h>

#include <cstdio>

extern "C" {
#include "ref/kcc_core.c"
}

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestKccDifferential() {
    xtcp::cc::RegisterKcc();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
    CHECK(NULLPTR != ops);

    // Deterministic RTT sequence: starts at 30ms, dips to 20ms (new min),
    // then a slow upward drift with noise.
    UInt32 seed = 0xABCD1234;
    auto next = [&seed]() -> UInt32 {
        seed = seed * 1664525u + 1013904223u;
        return seed;
    };

    kcc_core ref;
    kcc_core_init(&ref);
    ref.mss = 1460;
    ref.last_ack_us = 1000000;  // align the first-step interval semantics

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;

    const UInt32 kSteps = 3000;
    UInt64 now_us = 1000000;
    for (UInt32 i = 0; i < kSteps; ++i) {
        UInt32 rtt_us;
        if (i < 200) {
            rtt_us = 30000 - i * 5;              // 30ms -> 29ms
        } else if (i < 400) {
            rtt_us = 20000 + (next() % 500);     // new min ~20ms
        } else {
            rtt_us = 20000 + (i % 1000) * 3 + (next() % 2000);  // drift + noise
        }
        const UInt32 acked = 1 + (next() % 4);
        const UInt32 delivered = acked * 1460;
        const UInt32 flight = 20 * 1460;
        const UInt32 lost = (0 == (i % 700)) ? delivered : 0;
        const UInt32 interval_us = 10000 + (next() % 5000);
        now_us += interval_us;

        // Reference core.
        kcc_core_on_ack(&ref, static_cast<s64>(now_us), delivered, rtt_us, flight, lost);

        // Port.
        xtcp::cc::RateSample rs;
        rs.delivered = delivered;
        rs.interval_us = interval_us;
        rs.rtt_us = rtt_us;
        rs.acked = acked;
        rs.lost = lost;
        sk.inflight = flight;
        ops->cong_control(&sk, &rs);

        // Compare geodesic estimator outputs (exact).
        const s64 ref_cwnd = kcc_core_cwnd_segs(&ref);
        if (ref_cwnd != static_cast<s64>(sk.snd_cwnd)) {
            std::fprintf(stderr, "CWND MISMATCH step %u: ref=%lld port=%u\n",
                         i, (long long)ref_cwnd, sk.snd_cwnd);
            ++g_failures;
            break;
        }
        const s64 ref_rate = kcc_core_pacing_rate(&ref);
        if (0 != ref_rate) {
            const UInt64 diff = (ref_rate > static_cast<s64>(sk.pacing_rate))
                                    ? (ref_rate - static_cast<s64>(sk.pacing_rate))
                                    : (static_cast<s64>(sk.pacing_rate) - ref_rate);
            if (diff > (static_cast<UInt64>(ref_rate) / 100)) {  // 1% tolerance
                std::fprintf(stderr, "RATE MISMATCH step %u: ref=%lld port=%llu\n",
                             i, (long long)ref_rate, (unsigned long long)sk.pacing_rate);
                ++g_failures;
                break;
            }
        }
    }
    ops->release(&sk);
}

static void TestKccRoundBoundaryTracksFlight() {
    xtcp::cc::RegisterKcc();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
    CHECK(NULLPTR != ops);

    kcc_core ref;
    kcc_core_init(&ref);
    ref.mss = 1460;
    ref.last_ack_us = 1000000;

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;
    constexpr UInt32 kDelivered = 1460;
    constexpr UInt32 kFirstDelivered = 10 * kDelivered;
    constexpr UInt32 kFlight = 20 * 1460;
    constexpr UInt32 kInterval = 100;
    UInt64 now_us = 1000000;

    // Ten ACK samples occur within the 1ms RTT. Keep the best bandwidth
    // sample in the round, but advance full-bandwidth detection per round.
    for (UInt32 i = 0; i < 10; ++i) {
        const UInt32 delivered = (0 == i) ? kFirstDelivered : kDelivered;
        now_us += kInterval;
        kcc_core_on_ack(&ref, static_cast<s64>(now_us), delivered, 1000,
                        kFlight, 0);
        sk.inflight = kFlight;
        xtcp::cc::RateSample rs;
        rs.delivered = delivered;
        rs.interval_us = kInterval;
        rs.rtt_us = 1000;
        rs.acked = kDelivered;
        ops->cong_control(&sk, &rs);
        CHECK(1 == ref.rtt_cnt);
        CHECK((static_cast<s64>(kFirstDelivered) << 24) / kInterval == ref.max_bw);
        CHECK(0 == ref.full_bw_cnt);
        CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&ref)) == sk.snd_cwnd);
    }

    now_us += kInterval;
    kcc_core_on_ack(&ref, static_cast<s64>(now_us), kDelivered, 1000,
                    kFlight, 0);
    xtcp::cc::RateSample rs;
    rs.delivered = kDelivered;
    rs.interval_us = kInterval;
    rs.rtt_us = 1000;
    rs.acked = kDelivered;
    ops->cong_control(&sk, &rs);
    CHECK(2 == ref.rtt_cnt);
    CHECK((static_cast<s64>(kFirstDelivered) << 24) / kInterval == ref.max_bw);
    CHECK(0 == ref.full_bw_cnt);
    CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&ref)) == sk.snd_cwnd);
    ops->release(&sk);
}

static void TestKccRoundBoundaryTracksCurrentRtt() {
    xtcp::cc::RegisterKcc();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
    CHECK(NULLPTR != ops);

    kcc_core ref;
    kcc_core_init(&ref);
    ref.mss = 1460;
    ref.last_ack_us = 1000000;

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;
    constexpr UInt32 kFlight = 20 * 1460;
    constexpr UInt32 kFastDelivered = 10 * 1460;
    UInt64 now_us = 1000000;
    const auto sample = [&](UInt32 delivered, UInt32 interval_us, UInt32 rtt_us) {
        now_us += interval_us;
        kcc_core_on_ack(&ref, static_cast<s64>(now_us), delivered, rtt_us,
                        kFlight, 0);
        sk.inflight = kFlight;
        xtcp::cc::RateSample rs;
        rs.delivered = delivered;
        rs.interval_us = interval_us;
        rs.rtt_us = rtt_us;
        rs.acked = delivered;
        ops->cong_control(&sk, &rs);
        CHECK(static_cast<UInt32>(kcc_core_cwnd_segs(&ref)) == sk.snd_cwnd);
    };

    // Establish a 1ms min RTT and a high rate sample, then model a queued
    // 4ms RTT with ACK rate samples every 400us. The ten-round bandwidth
    // window must age in current RTTs, not ten times faster at min RTT.
    sample(kFastDelivered, 100, 1000);
    CHECK(1 == ref.rtt_cnt);
    const s64 max_bw = (static_cast<s64>(kFastDelivered) << 24) / 100;
    CHECK(max_bw == ref.max_bw);
    for (UInt32 i = 0; i < 20; ++i) {
        sample(1460, 400, 4000);
        CHECK(max_bw == ref.max_bw);
    }
    CHECK(3 == ref.rtt_cnt);
    ops->release(&sk);
}

static void TestKccRegistry() {
    xtcp::cc::RegisterKcc();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
    CHECK(NULLPTR != ops);
    CHECK(0 == std::strcmp("kcc", ops->name));

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;
    CHECK(NULLPTR != sk.ca_priv);

    // Initial state: STARTUP, cwnd = 10.
    CHECK(10 == sk.snd_cwnd);
    ops->release(&sk);
    CHECK(NULLPTR == sk.ca_priv);
}

static void TestKccFullBwTransition() {
    // PIN: full-bw detection must fire on 3 consecutive PLATEAU rounds
    // (growth < 3.2%/round) and drive STARTUP -> DRAIN -> PROBE_BW. The
    // pre-fix check `bw_now >= full_bw * 320/100` required 320% growth and
    // never fired: STARTUP's 2.885x gain ran forever (pacing_rate stays the
    // STARTUP value below).
    xtcp::cc::RegisterKcc();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("kcc");
    CHECK(NULLPTR != ops);

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;

    // Constant-rate drive: delivered 29200 B per 20000 us = 1.46 B/us.
    // bw = (29200 << 24) / 20000 = 24494735.
    // STARTUP rate = ((bw * 739) >> 8) * 990000 >> 24 = 4172463.
    // PROBE_BW rate = ((bw * 320) >> 8) * 990000 >> 24 = 1806749.
    constexpr UInt64 kStartupRate = 4172463;
    constexpr UInt64 kProbeRate = 1806749;
    const UInt32 kDelivered = 29200;
    const UInt32 kInterval = 20000;
    UInt64 rates[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (UInt32 i = 0; i < 8; ++i) {
        xtcp::cc::RateSample rs;
        rs.delivered = kDelivered;
        rs.interval_us = kInterval;
        rs.rtt_us = 20000;
        rs.acked = kDelivered;
        rs.lost = 0;
        ops->cong_control(&sk, &rs);
        rates[i] = sk.pacing_rate;
    }
    // One sample seeds the model; a completed round establishes full_bw,
    // then three plateau rounds accrue before STARTUP exits.
    for (UInt32 i = 0; i < 5; ++i) {
        CHECK(kStartupRate == rates[i]);
    }
    // Samples 6-8: PROBE_BW (gain 5/4). Pre-fix this stayed at the STARTUP
    // monotone max forever - the assertion pins the DRAIN/PROBE_BW FSM.
    for (UInt32 i = 5; i < 8; ++i) {
        std::fprintf(stderr, "[kcc-fbw] sample %u rate=%llu (expect %llu probe)\n",
                     i + 1, (unsigned long long)rates[i], (unsigned long long)kProbeRate);
        CHECK(kProbeRate == rates[i]);
    }
    ops->release(&sk);
}

int main() {
    TestKccRegistry();
    TestKccDifferential();
    TestKccRoundBoundaryTracksFlight();
    TestKccRoundBoundaryTracksCurrentRtt();
    TestKccFullBwTransition();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_cc_kcc: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_cc_kcc: all passed\n");
    return 0;
}

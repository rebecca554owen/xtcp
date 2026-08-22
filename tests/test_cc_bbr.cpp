/**
 * @file test_cc_bbr.cpp
 * @brief CC framework tests: registry, BBRv1 fidelity differential vs the
 *        reference core (plugins/ref/bbr_core.c), CUBIC sample behavior.
 */

#include <xtcp/cc/cc.h>

#include <cstdio>
#include <cstdlib>

extern "C" {
#include "ref/bbr_core.c"
}

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestRegistry() {
    xtcp::cc::RegisterBbrv1();
    xtcp::cc::RegisterCubic();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("bbr"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("cubic"));
    CHECK(NULLPTR == xtcp::cc::FindCongestionControl("nope"));
}

/**
 * @brief Runs the same deterministic ACK sequence through the C reference
 *        core and the C++ port, comparing cwnd / pacing rate / mode.
 */
static void TestBbrFidelityDifferential() {
    xtcp::cc::RegisterBbrv1();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("bbr");
    CHECK(NULLPTR != ops);

    // Deterministic pseudo-random sequence (fixed seed).
    UInt32 seed = 0x12345678;
    auto next = [&seed]() -> UInt32 {
        seed = seed * 1664525u + 1013904223u;
        return seed;
    };

    // Reference core.
    bbr_core ref;
    bbr_core_init(&ref);
    ref.mss = 1460;
    ref.snd_cwnd = 10;
    ref.rtt_us = 0;

    // Port.
    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;
    sk.snd_cwnd = 10;

    const UInt32 kSteps = 2000;
    UInt64 now_ms = 100000;
    for (UInt32 i = 0; i < kSteps; ++i) {
        const UInt32 rtt_us = 20000 + (next() % 5000);       // 20-25ms
        const UInt32 acked = 1 + (next() % 8);               // 1-8 packets
        const UInt32 interval_us = rtt_us / 2;               // ~2 ACKs per RTT
        const UInt32 delivered = acked * 1460;
        const UInt32 inflight = sk.snd_cwnd * 1460;
        const UInt32 app_limited = 0;
        const UInt32 lost = (0 == (i % 500)) ? delivered : 0;  // occasional loss

        // Reference core step.
        bbr_core_on_ack(&ref, delivered, interval_us, rtt_us, acked, lost,
                        now_ms, inflight, app_limited);

        // Port step.
        xtcp::cc::RateSample rs;
        rs.delivered = delivered;
        rs.interval_us = interval_us;
        rs.rtt_us = rtt_us;
        rs.acked = acked;
        rs.lost = lost;
        rs.is_app_limited = app_limited;
        sk.inflight = inflight;
        ops->cong_control(&sk, &rs);

        // Compare outputs (1% tolerance on rates; cwnd equal).
        const UInt32 ref_cwnd = bbr_core_cwnd(&ref);
        if (ref_cwnd != sk.snd_cwnd) {
            std::fprintf(stderr, "CWND MISMATCH step %u: ref=%u port=%u\n", i, ref_cwnd, sk.snd_cwnd);
            ++g_failures;
            break;
        }
        const UInt64 ref_rate = bbr_core_pacing_rate(&ref);
        if (0 != ref_rate) {
            const UInt64 diff = (ref_rate > sk.pacing_rate) ? (ref_rate - sk.pacing_rate)
                                                            : (sk.pacing_rate - ref_rate);
            if (diff > (ref_rate / 100)) {  // 1% tolerance
                std::fprintf(stderr, "RATE MISMATCH step %u: ref=%llu port=%llu\n",
                             i, (unsigned long long)ref_rate, (unsigned long long)sk.pacing_rate);
                ++g_failures;
                break;
            }
        }

        now_ms += interval_us / 1000;
    }
    ops->release(&sk);
}
static void TestCubicSample() {
    xtcp::cc::RegisterCubic();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("cubic");
    CHECK(NULLPTR != ops);

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;
    sk.snd_cwnd = 10;
    sk.snd_ssthresh = 0x7FFFFFFF;

    // Slow start growth.
    const UInt32 before = sk.snd_cwnd;
    ops->cong_avoid(&sk, 0, 2920);
    CHECK(sk.snd_cwnd > before);

    // Loss event halves the window (beta = 0.7). The FSM contract (CutCwnd):
    // dispatch ssthresh (updates the CUBIC epoch state and returns the new
    // threshold), then cwnd_event (NOTIFICATION only - reducing inside the
    // event handler would double the cut and capture wmax from the already
    // reduced window), then clamp snd_cwnd to the threshold.
    const UInt32 ssth = ops->ssthresh(&sk);
    ops->cwnd_event(&sk, xtcp::cc::kCaEventLoss);
    if (sk.snd_cwnd > ssth) {
        sk.snd_cwnd = ssth;
    }
    CHECK(sk.snd_cwnd <= 10);
    CHECK(sk.snd_cwnd >= 7);
    ops->release(&sk);
}

static void TestBbrFullBwTransition() {
    // PIN: full-bw detection must exit STARTUP after 3 consecutive PLATEAU
    // rounds (growth < 25%/round resets the counter - BBR paper Fig. 3).
    // The pre-fix code counted GROWTH rounds: under a constant-rate drive
    // the counter stayed 0 and STARTUP's 2.885x gain ran forever.
    xtcp::cc::RegisterBbrv1();
    const xtcp::cc::XtcpCongestionOps* ops = xtcp::cc::FindCongestionControl("bbr");
    CHECK(NULLPTR != ops);

    xtcp::cc::XtcpConnCc sk;
    ops->init(&sk);
    sk.mss = 1460;

    // Constant-rate drive: delivered 29200 B per 20000 us -> bw =
    // 29200 * 1e6 / 20000 = 1460000 B/s.
    // STARTUP rate = bw * 2885001 / 1e6 = 4212101.
    // DRAIN rate (gain 1000/2885) = bw * 346620 / 1e6 = 506065.
    // PROBE_BW rate (gain 5/4) = bw * 1250000 / 1e6 = 1825000.
    constexpr UInt64 kStartupRate = 4212101;
    constexpr UInt64 kDrainRate = 506065;
    constexpr UInt64 kProbeRate = 1825000;
    const UInt32 kDelivered = 29200;
    const UInt32 kInterval = 20000;
    // BDP = bw * min_rtt = 1460000 * 20000 / 1e6 = 29200 bytes. Start with a
    // FULL pipe so the STARTUP->DRAIN transition holds (inflight > BDP).
    sk.inflight = 5 * 29200;
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
    // Samples 1-3: STARTUP.
    for (UInt32 i = 0; i < 3; ++i) {
        CHECK(kStartupRate == rates[i]);
    }
    // Sample 4: full_bw reached (3 plateau rounds) -> DRAIN (gain 1/2.885,
    // BBR paper Fig. 3). The full pipe (inflight 5x BDP) makes the drain
    // HOLD - the queue built during STARTUP is drained before probing.
    std::fprintf(stderr, "[bbr-fbw] sample 4 rate=%llu (expect %llu drain)\n",
                 (unsigned long long)rates[3], (unsigned long long)kDrainRate);
    CHECK(kDrainRate == rates[3]);
    CHECK(kDrainRate == rates[4]);  // still draining at 5x BDP
    CHECK(kDrainRate == rates[5]);
    // The pipe drains: PROBE_BW resumes (gain 5/4).
    sk.inflight = 0;
    xtcp::cc::RateSample rs;
    rs.delivered = kDelivered;
    rs.interval_us = kInterval;
    rs.rtt_us = 20000;
    rs.acked = kDelivered;
    rs.lost = 0;
    ops->cong_control(&sk, &rs);
    std::fprintf(stderr, "[bbr-fbw] post-drain rate=%llu (expect %llu probe)\n",
                 (unsigned long long)sk.pacing_rate, (unsigned long long)kProbeRate);
    CHECK(kProbeRate == sk.pacing_rate);
    ops->release(&sk);
}

int main() {
    TestRegistry();
    TestBbrFidelityDifferential();
    TestCubicSample();
    TestBbrFullBwTransition();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_cc_bbr: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_cc_bbr: all passed\n");
    return 0;
}

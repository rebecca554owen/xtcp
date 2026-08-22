/*
 * kcc_core.c
 *
 * KCC v2.0 (Geodesic) pure computation core extracted from the UCP
 * userspace port, which mirrors
 * the kernel tcp_kcc.c algorithm. Reference for fidelity differential
 * testing. Constants are verbatim from ucp_constants.h / tcp_kcc.c.
 */

#if defined(__GNUC__) || defined(__clang__)
#define XTCP_KCC_UNUSED __attribute__((unused))
#else
#define XTCP_KCC_UNUSED
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4505)
#endif

#include <stdint.h>
#include <string.h>

#define BW_SCALE 24
#define BW_UNIT (INT64_C(1) << BW_SCALE)
#define BBR_SCALE 8
#define BBR_UNIT (1 << BBR_SCALE)
#define KCC_SCALE_SHIFT 10
#define KCC_SCALE (INT64_C(1) << KCC_SCALE_SHIFT)

#define KCC_G2_GROWTH_NUM 122
#define KCC_G2_GROWTH_DEN 1000
#define KCC_G3_FAST_TH_NUM 11
#define KCC_G3_FAST_TH_DEN 10
#define KCC_G3_SLOW_TH_NUM 21
#define KCC_G3_SLOW_TH_DEN 20
#define KCC_PD_NOISE_GATE_NUM 95
#define KCC_PD_NOISE_GATE_DEN 100
#define KCC_JITTER_SEED_SHIFT 2
#define KCC_EWMA_JITTER_NUM 7
#define KCC_EWMA_JITTER_DEN 8
#define KCC_EWMA_QDELAY_NUM 7
#define KCC_EWMA_QDELAY_DEN 8
#define KCC_MIN_SAMPLES 5
#define KCC_STALENESS_RNDS 128
#define KCC_RTT_MIN_FLOOR_US 1
#define KCC_RTT_SAMPLE_MAX_US 500000
#define KCC_P_EST_INIT 1000
#define KCC_P_EST_FLOOR 10
#define KCC_P_EST_DECAY_SHIFT 4
#define KCC_P_EST_GROWTH_SHIFT 3
#define KCC_P_EST_MAX 1000000
#define KCC_LOCK_THRESH_US 5000
#define KCC_FAST_ONLY_THRESH_US 7500
#define KCC_BITFIELD_3BIT_MAX 7
#define KCC_BW_RT_CYCLE_LEN 10
#define KCC_PROBE_BW_CYCLE_LEN 8
#define KCC_HIGH_GAIN (BBR_UNIT * 2885 / 1000 + 1)
#define KCC_DRAIN_GAIN (BBR_UNIT * 1000 / 2885)
#define KCC_CWND_GAIN (BBR_UNIT * 2)
#define KCC_FULL_BW_THRESH 320
#define KCC_FULL_BW_CNT 3
#define KCC_CWND_MIN_TARGET 4
#define KCC_CWND_ABSOLUTE_MIN 1
#define MICROS_PER_SECOND 1000000LL
#define MIN_RTT_UNINIT 0xFFFFFFFFu

#define KCC_MODE_STARTUP 0
#define KCC_MODE_PROBE_BW 1
#define KCC_MODE_DRAIN 2

#define GAIN_PROBE_PHASE_NUM 5
#define GAIN_PROBE_PHASE_DEN 4
#define GAIN_DRAIN_PHASE_NUM 3
#define GAIN_DRAIN_PHASE_DEN 4
#define GAIN_CRUISE_PHASE_NUM 1
#define GAIN_CRUISE_PHASE_DEN 1

typedef int64_t s64;
typedef uint64_t u64;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint8_t u8;

struct kcc_bw_sample {
	s64 val;
	u32 rtt_cnt;
};

struct kcc_core {
	/* Geodesic estimator state */
	u64  x_est;            /* scaled by KCC_SCALE */
	u32  p_est;
	u32  qdelay_avg;
	u32  jitter_ewma;
	u32  sample_cnt;
	u32  min_rtt_us;
	u32  min_rtt_stamp;
	u32  mr_update_rtt_cnt;
	u32  rtt_cnt;
	u32  confirm_cnt;
	u32  confirm_slow_cnt;
	u32  locked;

	/* Bandwidth window */
	struct kcc_bw_sample bw_samples[KCC_BW_RT_CYCLE_LEN];
	u32  bw_sample_count;
	u32  bw_sample_cur;
	s64  max_bw;

	/* FSM */
	u32  mode;
	u32  pacing_gain;
	u32  cwnd_gain;
	u32  cycle_idx;
	u32  full_bw_reached;
	u32  full_bw;
	u32  full_bw_cnt;
	u32  has_seen_rtt;
	u32  prev_ack_us;
	u32  last_ack_us;
	s64  total_delivered;
	s64  prev_delivered;
	s64  next_rtt_delivered;

	/* Inputs */
	u32  mss;
	s64  congestion_window_bytes;
	u32  flight_bytes;

	/* Outputs */
	s64  pacing_rate_bytes_per_second;
	s64  cwnd_segs;
};

static u64 kcc_min_u64(u64 a, u64 b) { return a < b ? a : b; }
static u32 kcc_max_u32(u32 a, u32 b) { return a > b ? a : b; }

static void kcc_bw_update(struct kcc_core *k, s64 bw, u32 rtt_cnt) {
	if (bw <= 0) return;
	if (k->bw_sample_count == 0) {
		k->bw_sample_count = 1;
		k->bw_sample_cur = 0;
		k->bw_samples[0].val = bw;
		k->bw_samples[0].rtt_cnt = rtt_cnt;
		return;
	}
	int next = (int)((k->bw_sample_cur + 1) % KCC_BW_RT_CYCLE_LEN);
	k->bw_samples[next].val = bw;
	k->bw_samples[next].rtt_cnt = rtt_cnt;
	k->bw_sample_cur = (u32)next;
	if (k->bw_sample_count < KCC_BW_RT_CYCLE_LEN) k->bw_sample_count++;
}

static s64 kcc_bw_max(const struct kcc_core *k) {
	if (0 == k->bw_sample_count) return 0;
	s64 result = 0;
	u32 cur_rtt = k->rtt_cnt;
	for (u32 i = 0; i < k->bw_sample_count; i++) {
		if (cur_rtt - k->bw_samples[i].rtt_cnt >= KCC_BW_RT_CYCLE_LEN) continue;
		if (k->bw_samples[i].val > result) result = k->bw_samples[i].val;
	}
	if (0 == result && k->bw_sample_count > 0) {
		for (u32 i = 0; i < k->bw_sample_count; i++) {
			if (k->bw_samples[i].val > result) result = k->bw_samples[i].val;
		}
	}
	return result;
}

static void kcc_geodesic_update(struct kcc_core *k, s64 rtt_us) {
	u32 rtt = (u32)(rtt_us > KCC_RTT_MIN_FLOOR_US ? rtt_us : KCC_RTT_MIN_FLOOR_US);
	u64 z = (u64)rtt << KCC_SCALE_SHIFT;

	if (0 == k->sample_cnt) {
		k->x_est = z;
		k->p_est = KCC_P_EST_INIT;
		k->qdelay_avg = 0;
		k->jitter_ewma = rtt >> KCC_JITTER_SEED_SHIFT;
		if (k->jitter_ewma < 1) k->jitter_ewma = 1;
		k->sample_cnt = 1;
		return;
	}

	if (1 == k->sample_cnt && k->min_rtt_us != MIN_RTT_UNINIT && k->min_rtt_us > 0) {
		u64 ceiling = (u64)k->min_rtt_us << KCC_SCALE_SHIFT;
		if (k->x_est > ceiling) k->x_est = ceiling;
	}

	s64 innovation = (s64)z - (s64)k->x_est;
	u64 abs_innov = innovation >= 0 ? (u64)innovation : (u64)(-(innovation + 1)) + 1;

	if (innovation <= 0) {
		k->x_est = kcc_min_u64(k->x_est, z);
	} else {
		u64 growth = k->x_est * KCC_G2_GROWTH_NUM / KCC_G2_GROWTH_DEN;
		u64 new_x = k->x_est + growth;
		if (new_x < k->x_est) new_x = 0xFFFFFFFFFFFFFFFFull;
		k->x_est = kcc_min_u64(new_x, z);
	}

	if (k->min_rtt_us != MIN_RTT_UNINIT &&
		k->rtt_cnt - k->mr_update_rtt_cnt >= KCC_STALENESS_RNDS) {
		u64 mr_scaled = (u64)k->min_rtt_us << KCC_SCALE_SHIFT;
		if (k->x_est <= mr_scaled * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
			k->x_est = mr_scaled * KCC_PD_NOISE_GATE_NUM / KCC_PD_NOISE_GATE_DEN;
			k->mr_update_rtt_cnt = k->rtt_cnt;
		}
	}

	{
		u32 raw_jitter = (u32)((abs_innov >> KCC_SCALE_SHIFT) > 0xFFFFFFFFull
								   ? 0xFFFFFFFFu
								   : (u32)(abs_innov >> KCC_SCALE_SHIFT));
		k->jitter_ewma = (k->sample_cnt > 1)
							 ? ((k->jitter_ewma * KCC_EWMA_JITTER_NUM + raw_jitter) / KCC_EWMA_JITTER_DEN)
							 : raw_jitter;
		u32 jitter_cap = (k->min_rtt_us != MIN_RTT_UNINIT)
							 ? kcc_max_u32(k->min_rtt_us, KCC_RTT_SAMPLE_MAX_US)
							 : (u32)KCC_RTT_SAMPLE_MAX_US;
		if (k->jitter_ewma > jitter_cap) k->jitter_ewma = jitter_cap;
	}

	{
		u32 qdelay_instant = (z > k->x_est) ? (u32)((z - k->x_est) >> KCC_SCALE_SHIFT) : 0;
		if (1 == k->sample_cnt) {
			k->qdelay_avg = qdelay_instant;
		} else {
			k->qdelay_avg = (u32)(((u64)k->qdelay_avg * KCC_EWMA_QDELAY_NUM + qdelay_instant) /
								  KCC_EWMA_QDELAY_DEN);
		}
	}

	if (k->sample_cnt < 0xFFFFFFFFu) k->sample_cnt++;

	if (k->sample_cnt >= KCC_MIN_SAMPLES) {
		u32 p_floor = KCC_P_EST_FLOOR;
		u64 x_est_us = k->x_est >> KCC_SCALE_SHIFT;
		if (x_est_us <= (u64)k->min_rtt_us * KCC_G3_SLOW_TH_NUM / KCC_G3_SLOW_TH_DEN &&
			!k->confirm_cnt && !k->confirm_slow_cnt) {
			u32 delta = k->p_est > p_floor ? (k->p_est - p_floor) >> KCC_P_EST_DECAY_SHIFT : 0;
			if (k->p_est > p_floor + delta) k->p_est -= (delta > 1 ? delta : 1);
		} else if (x_est_us > (u64)k->min_rtt_us * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
			u32 delta = k->p_est < KCC_P_EST_INIT ? (KCC_P_EST_INIT - k->p_est) >> KCC_P_EST_GROWTH_SHIFT : 0;
			if (k->p_est + delta < KCC_P_EST_MAX) k->p_est += (delta > 1 ? delta : 1);
		}
	}
}

static void kcc_update_min_rtt(struct kcc_core *k, s64 rtt_us, s64 now_us) {
	if (rtt_us <= 0) return;
	u32 rtt = (u32)rtt_us;
	u32 mr_snapshot = k->min_rtt_us;

	kcc_geodesic_update(k, rtt_us);

	if (rtt < KCC_LOCK_THRESH_US) k->locked = 1;

	if (!k->locked && k->min_rtt_us >= KCC_FAST_ONLY_THRESH_US) {
		if (k->x_est >= (u64)k->min_rtt_us * KCC_SCALE * KCC_G3_FAST_TH_NUM / KCC_G3_FAST_TH_DEN) {
			if (k->confirm_cnt < KCC_BITFIELD_3BIT_MAX) k->confirm_cnt++;
		} else {
			k->confirm_cnt = 0;
		}
		if (k->x_est >= (u64)k->min_rtt_us * KCC_SCALE * KCC_G3_SLOW_TH_NUM / KCC_G3_SLOW_TH_DEN) {
			if (k->confirm_slow_cnt < KCC_BITFIELD_3BIT_MAX) k->confirm_slow_cnt++;
		} else {
			k->confirm_slow_cnt = 0;
		}
	}

	if (rtt < mr_snapshot || mr_snapshot == MIN_RTT_UNINIT) {
		k->min_rtt_us = rtt;
		k->min_rtt_stamp = (u32)now_us;
		k->mr_update_rtt_cnt = k->rtt_cnt;
	}
}

static u32 kcc_get_cycle_pacing_gain(const struct kcc_core *k) {
	u32 idx = k->cycle_idx % KCC_PROBE_BW_CYCLE_LEN;
	switch (idx) {
	case 0: return (u32)(BBR_UNIT * GAIN_PROBE_PHASE_NUM / GAIN_PROBE_PHASE_DEN);
	case 1: return (u32)(BBR_UNIT * GAIN_DRAIN_PHASE_NUM / GAIN_DRAIN_PHASE_DEN);
	default: return BBR_UNIT;
	}
}

static XTCP_KCC_UNUSED void kcc_advance_cycle_phase(struct kcc_core *k) {
	k->cycle_idx = (k->cycle_idx + 1) % KCC_PROBE_BW_CYCLE_LEN;
	k->pacing_gain = kcc_get_cycle_pacing_gain(k);
}

static void kcc_check_full_bw_reached(struct kcc_core *k) {
	if (k->full_bw_reached) return;
	s64 bw = kcc_bw_max(k);
	/* "3.2% step" (KCC_FULL_BW_THRESH = 320 = 3.2%): a plateau round grows
	 * by less than 3.2% vs the running max. Count CONSECUTIVE plateau
	 * rounds (growth resets the counter); 3 in a row => the pipe is full
	 * and STARTUP can exit (BBR-style full-bw detection). The pre-fix
	 * check `bw >= full_bw * 320 / 100` required 320% growth per round -
	 * it never fired, so STARTUP's 2.885x gain ran forever.
	 * (bw >= full_bw + 3.2% is impossible to overflow: full_bw is u32.) */
	if (bw >= (s64)(k->full_bw + (k->full_bw / 1000) * 32)) {
		k->full_bw_cnt = 0;  /* still growing >= 3.2%/round: keep probing */
	} else {
		k->full_bw_cnt++;    /* plateau round */
	}
	if (bw > (s64)k->full_bw) k->full_bw = (u32)bw;
	if (k->full_bw_cnt >= KCC_FULL_BW_CNT) k->full_bw_reached = 1;
}

static void kcc_update_model(struct kcc_core *k, s64 now_us, s64 delivered, s64 rtt_us, s64 acked, s64 flight_bytes) {
	(void)acked;
	(void)flight_bytes;

	s64 interval_us = now_us - (s64)k->prev_ack_us;
	if (interval_us < 0) interval_us = 0;

	/* Round boundary */
	u32 prev_rtt_cnt = k->rtt_cnt;
	if (!(k->prev_delivered < k->next_rtt_delivered)) {
		k->next_rtt_delivered = k->total_delivered;
		k->rtt_cnt++;
	}

	s64 bw = 0;
	if (delivered > 0 && interval_us > 0) {
		bw = (delivered << BW_SCALE) / interval_us;
	}
	(void)prev_rtt_cnt;
	kcc_bw_update(k, bw, k->rtt_cnt);
	k->max_bw = kcc_bw_max(k);

	if (rtt_us > 0) {
		kcc_update_min_rtt(k, rtt_us, now_us);
	}

	/* Mode/gain assignment */
	switch (k->mode) {
	case KCC_MODE_STARTUP:
		k->pacing_gain = KCC_HIGH_GAIN;
		k->cwnd_gain = KCC_HIGH_GAIN;
		break;
	case KCC_MODE_DRAIN:
		k->pacing_gain = KCC_DRAIN_GAIN;
		k->cwnd_gain = KCC_HIGH_GAIN;
		break;
	case KCC_MODE_PROBE_BW:
		k->pacing_gain = kcc_get_cycle_pacing_gain(k);
		k->cwnd_gain = KCC_CWND_GAIN;
		break;
	}

	kcc_check_full_bw_reached(k);
	if (k->mode == KCC_MODE_STARTUP && k->full_bw_reached) {
		k->mode = KCC_MODE_DRAIN;
	}
	if (k->mode == KCC_MODE_DRAIN && k->rtt_cnt >= 3) {
		k->mode = KCC_MODE_PROBE_BW;
		k->cycle_idx = 0;
	}
}

static void kcc_set_pacing_rate(struct kcc_core *k, s64 bw, s32 gain) {
	if (bw <= 0) bw = BW_UNIT;
	s64 rate = (bw * gain) >> BBR_SCALE;
	rate = (rate * 990000LL) >> BW_SCALE;
	if (!k->has_seen_rtt && k->min_rtt_us > 0 && k->min_rtt_us != MIN_RTT_UNINIT) {
		k->has_seen_rtt = 1;
		s64 rtt = k->min_rtt_us > 0 ? k->min_rtt_us : 1;
		s64 cwnd_segs = k->congestion_window_bytes / k->mss;
		s64 bdp_bw = (cwnd_segs * BW_UNIT) / rtt;
		s64 boot_rate = (bdp_bw * k->mss) >> 0;
		boot_rate = (boot_rate * KCC_HIGH_GAIN) >> BBR_SCALE;
		boot_rate = (boot_rate * 990000LL) >> BW_SCALE;
		if (boot_rate > rate) rate = boot_rate;
	}
	if (k->full_bw_reached) {
		k->pacing_rate_bytes_per_second = rate;
	} else if (rate > k->pacing_rate_bytes_per_second) {
		k->pacing_rate_bytes_per_second = rate;
	}
}

static void kcc_set_cwnd(struct kcc_core *k, s64 bw, s32 gain, s64 acked, s64 flight_bytes, s64 losses) {
	(void)flight_bytes;
	s64 cwnd = k->congestion_window_bytes;

	if (acked <= 0) {
		goto done_cwnd;
	}
	if (losses > 0) {
		cwnd = (cwnd > losses) ? cwnd - losses : (s64)KCC_CWND_ABSOLUTE_MIN * k->mss;
	}
	{
		s64 bdp = (bw * (s64)k->min_rtt_us) >> BW_SCALE;
		bdp = (bdp * gain) >> BBR_SCALE;
		if (bdp < (s64)KCC_CWND_MIN_TARGET * k->mss) bdp = (s64)KCC_CWND_MIN_TARGET * k->mss;
		if (cwnd < bdp) cwnd = bdp;
	}

done_cwnd:
	if (cwnd < (s64)KCC_CWND_MIN_TARGET * k->mss) cwnd = (s64)KCC_CWND_MIN_TARGET * k->mss;
	k->congestion_window_bytes = cwnd;
	k->cwnd_segs = cwnd / k->mss;
}

/* ---- Public API (fidelity differential driver) ---- */

void kcc_core_init(struct kcc_core *k) {
	memset(k, 0, sizeof(*k));
	k->min_rtt_us = MIN_RTT_UNINIT;
	k->min_rtt_stamp = 0;
	k->mr_update_rtt_cnt = 0;
	k->mode = KCC_MODE_STARTUP;
	k->pacing_gain = KCC_HIGH_GAIN;
	k->cwnd_gain = KCC_HIGH_GAIN;
	k->p_est = KCC_P_EST_INIT;
	k->congestion_window_bytes = 10 * 1460;
	k->cwnd_segs = 10;
}

void kcc_core_on_ack(struct kcc_core *k, s64 now_us, s64 delivered_bytes, s64 rtt_us, s64 flight_bytes, s64 losses) {
	k->flight_bytes = (u32)flight_bytes;
	s64 acked = delivered_bytes > 0 ? delivered_bytes : 0;
	k->prev_delivered = k->total_delivered;
	k->total_delivered += acked;
	k->prev_ack_us = k->last_ack_us;
	k->last_ack_us = (u32)now_us;

	kcc_update_model(k, now_us, delivered_bytes, rtt_us, acked, flight_bytes);

	s64 pacing_bw = k->max_bw;
	kcc_set_pacing_rate(k, pacing_bw, (s32)k->pacing_gain);
	kcc_set_cwnd(k, pacing_bw, (s32)k->cwnd_gain, acked, flight_bytes, losses);
}

u64  kcc_core_x_est(const struct kcc_core *k) { return k->x_est; }
u32  kcc_core_p_est(const struct kcc_core *k) { return k->p_est; }
u32  kcc_core_qdelay(const struct kcc_core *k) { return k->qdelay_avg; }
u32  kcc_core_min_rtt(const struct kcc_core *k) { return k->min_rtt_us; }
s64  kcc_core_cwnd_segs(const struct kcc_core *k) { return k->cwnd_segs; }
s64  kcc_core_pacing_rate(const struct kcc_core *k) { return k->pacing_rate_bytes_per_second; }
u32  kcc_core_mode(const struct kcc_core *k) { return k->mode; }

/*
 * bbr_core.c
 *
 * BBRv1 pure computation core extracted from Linux tcp_bbr.c (reference
 * for fidelity differential testing). Constants and decision logic are
 * verbatim; kernel dependencies (struct sock, tcp_* helpers) removed.
 *
 * Behavioral authority: Linux kernel tcp_bbr.c (kernel module).
 */

#ifdef _MSC_VER
#pragma warning(disable: 4100 4505)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define XTCP_BBR_UNUSED __attribute__((unused))
#else
#define XTCP_BBR_UNUSED
#endif

#include <stdint.h>
#include <string.h>

#define BBR_UNIT 1000000u
#define BBR_SCALE 8

enum bbr_mode {
	BBR_STARTUP,
	BBR_DRAIN,
	BBR_PROBE_BW,
	BBR_PROBE_RTT,
};

/* Window length of bw filter (in rounds): */
#define BBR_BW_RTTS 10  /* CYCLE_LEN(8) + 2 */
#define BBR_MIN_RTT_WIN_SEC 10
#define BBR_PROBE_RTT_MODE_MS 200
#define BBR_CYCLE_LEN 8
#define BBR_CWND_MIN_TARGET 4
#define BBR_HIGH_GAIN (BBR_UNIT * 2885 / 1000 + 1)
#define BBR_DRAIN_GAIN (BBR_UNIT * 1000 / 2885)
#define BBR_CWND_GAIN (BBR_UNIT * 2)
#define BBR_FULL_BW_THRESH (BBR_UNIT * 5 / 4)

static const int bbr_pacing_gain[BBR_CYCLE_LEN] = {
	BBR_UNIT * 5 / 4, BBR_UNIT * 3 / 4,
	BBR_UNIT, BBR_UNIT, BBR_UNIT, BBR_UNIT, BBR_UNIT, BBR_UNIT,
};

/* Simple minmax window (10 rounds) for bw samples. */
struct minmax {
	uint32_t vals[BBR_BW_RTTS];
	uint32_t count;
	uint32_t next;
};

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;

struct bbr_core {
	u32 min_rtt_us;
	u32 min_rtt_stamp;
	u32 probe_rtt_done_stamp;
	u32 probe_rtt_enter;       /* PROBE_RTT entry time (ms) */
	u32 saved_pacing_gain;     /* cycle gain to resume after PROBE_RTT */
	u8  saved_cycle_idx;
	struct minmax bw;
	u32 rtt_cnt;
	u32 next_rtt_delivered;
	u64 cycle_mstamp;
	u8 mode;
	u8 round_start;
	u8 idle_restart;
	u8 probe_rtt_round_done;
	u32 pacing_gain;
	u32 cwnd_gain;
	u8 full_bw_reached;
	u8 full_bw_cnt;
	u8 cycle_idx;
	u8 has_seen_rtt;
	u32 prior_cwnd;
	u32 full_bw;
	u64 ack_epoch_mstamp;
	u32 ack_epoch_acked;
	u16 extra_acked;
	u8 extra_acked_win_rtts;
	u8 extra_acked_win_idx;
	/* Inputs from the connection: */
	u64 delivered;        /* total bytes delivered */
	u64 delivered_mstamp; /* last delivery timestamp (ms) */
	u32 snd_cwnd;
	u32 rtt_us;           /* latest sample */
	u32 mss;
	u32 inflight;
	u32 app_limited;
	/* Outputs: */
	u64 pacing_rate;      /* bytes/sec */
	u32 cwnd;             /* packets */
};

static void minmax_init(struct minmax *m) {
	memset(m->vals, 0, sizeof(m->vals));
	m->count = 0;
	m->next = 0;
}

static u32 minmax_get(const struct minmax *m) {
	if (0 == m->count) return 0;
	u32 best = m->vals[0];
	for (u32 i = 1; i < m->count; ++i) {
		if (m->vals[i] > best) best = m->vals[i];
	}
	return best;
}

static void minmax_add(struct minmax *m, u32 val) {
	m->vals[m->next] = val;
	m->next = (m->next + 1) % BBR_BW_RTTS;
	if (m->count < BBR_BW_RTTS) ++m->count;
}

static u32 bbr_max_bw(const struct bbr_core *b) {
	return minmax_get(&b->bw);
}

static u32 bbr_bw(const struct bbr_core *b) {
	return minmax_get(&b->bw);
}

static void bbr_init_pacing_rate_from_rtt(struct bbr_core *b) {
	u32 bw = bbr_max_bw(b);
	if (0 != bw) return;
	/* Start with a rate based on initial cwnd and min RTT (bytes/sec): */
	u64 rate = (u64)b->snd_cwnd * b->mss;
	if (0 != b->min_rtt_us) rate = rate * 1000000ull / b->min_rtt_us;
	else rate = rate * 1000;  /* assume 1ms */
	b->pacing_rate = rate;
}

static void bbr_set_pacing_rate(struct bbr_core *b, u32 bw, int gain) {
	/* bw is bytes/sec (delivered*UNIT/interval cancels to /s); the gain is
	 * UNIT-scaled, so bytes/sec = bw * gain / UNIT. (A previous
	 * "bw/UNIT * gain/UNIT" divided twice and shrank the pacing by 1e6,
	 * stalling large transfers.) */
	u64 rate = (u64)bw * (u32)gain / BBR_UNIT;
	if (0 == rate) rate = 1;
	b->pacing_rate = rate;
}

static u32 bbr_bdp(struct bbr_core *b, u32 bw, int gain) {
	if (0 == b->min_rtt_us) return b->snd_cwnd;
	u64 bdp = (u64)bw * b->min_rtt_us;         /* bytes/sec * us */
	bdp = bdp / BBR_UNIT;                      /* bytes (us->s) */
	bdp = bdp * (u32)gain / BBR_UNIT;          /* gain-scaled bytes */
	if (0 != b->mss) bdp = bdp / b->mss + 1;   /* packets */
	return (u32)bdp;
}

static u32 bbr_inflight(struct bbr_core *b, u32 bw, int gain) {
	u32 cwnd = bbr_bdp(b, bw, gain);
	return cwnd;
}

static XTCP_BBR_UNUSED void bbr_save_cwnd(struct bbr_core *b) {
	b->prior_cwnd = b->snd_cwnd;
}

static XTCP_BBR_UNUSED u32 bbr_quantization_budget(struct bbr_core *b, u32 cwnd) {
	(void)b;
	return cwnd;
}

static void bbr_set_cwnd(struct bbr_core *b, const u32 rs_acked, const u32 rs_delivered, const u32 rs_rtt_us) {
	(void)rs_acked;
	(void)rs_delivered;
	(void)rs_rtt_us;
	u32 bw = bbr_max_bw(b);
	u32 target_cwnd = bbr_inflight(b, bw, (int)b->cwnd_gain);
	u32 cwnd = target_cwnd;
	if (BBR_PROBE_RTT == b->mode) {
		/* PROBE_RTT: the 4-packet window forces the queue to drain so the
		 * RTT sample measures the true empty-path RTT (paper Fig. 5;
		 * mirrored in cc_bbrv1.cpp). */
		cwnd = BBR_CWND_MIN_TARGET;
	}
	if (b->full_bw_reached && 0 == rs_acked) {
		u32 cap = b->snd_cwnd;
		if (b->snd_cwnd >= target_cwnd) cap = b->prior_cwnd;
		if (b->app_limited) cap = b->snd_cwnd;
		if (cwnd > cap) cwnd = cap;
	}
	b->snd_cwnd = cwnd;
	b->cwnd = cwnd;
}

static void bbr_update_bw(struct bbr_core *b, const u32 rs_delivered, const u32 rs_interval_us) {
	if (0 == rs_interval_us) return;
	u32 bw = (u32)(((u64)rs_delivered * BBR_UNIT) / rs_interval_us);
	if (b->full_bw_reached && bw < b->full_bw) {
		/* no-op: keep the window */
	}
	minmax_add(&b->bw, bw);
}

static void bbr_update_min_rtt(struct bbr_core *b, u32 sample_rtt_us, u64 now_ms) {
	if (0 == sample_rtt_us) return;
	if (0 == b->min_rtt_us || sample_rtt_us < b->min_rtt_us) {
		b->min_rtt_us = sample_rtt_us;
		b->min_rtt_stamp = (u32)now_ms;
	}
}

static int bbr_is_next_cycle_phase(struct bbr_core *b, const u32 rs_acked, const u32 rs_delivered, u64 now_ms) {
	u32 bw = bbr_max_bw(b);
	/* Real pipe occupancy in BYTES (audit M3): the pre-fix snd_cwnd*mss
	 * (always 2x BDP) made the probe condition true immediately and the
	 * drain false, collapsing the cycle to ~2 samples. */
	u64 inflight = (u64)b->inflight;
	(void)rs_acked;
	(void)rs_delivered;
	(void)now_ms;
	/* If below bandwidth target, probe for more bw: */
	if (b->pacing_gain > BBR_UNIT) {
		return inflight >= (u64)bbr_inflight(b, bw, (int)b->pacing_gain);
	}
	/* If above bandwidth target, drain: */
	if (b->pacing_gain < BBR_UNIT) {
		return inflight <= (u64)bbr_inflight(b, bw, (int)b->pacing_gain);
	}
	return 0;
}

static void bbr_advance_cycle_phase(struct bbr_core *b) {
	b->cycle_idx = (b->cycle_idx + 1) % BBR_CYCLE_LEN;
	b->pacing_gain = (u32)bbr_pacing_gain[b->cycle_idx];
}

static void bbr_update_cycle_phase(struct bbr_core *b, const u32 rs_acked, const u32 rs_delivered, u64 now_ms) {
	if (b->mode != BBR_PROBE_BW) return;
	if (bbr_is_next_cycle_phase(b, rs_acked, rs_delivered, now_ms)) {
		bbr_advance_cycle_phase(b);
	}
}

static void bbr_check_full_bw_reached(struct bbr_core *b, u32 bw) {
	if (b->full_bw_reached) return;
	/* BBR paper Fig. 3: exit STARTUP after 3 rounds WITHOUT >1.25x gain -
	 * growth RESETS the plateau counter. (Pre-fix: growth incremented,
	 * so the 2.885x STARTUP ramp exited mid-ramp and plateaus never
	 * exited - both wrong. Mirrored in cc_bbrv1.cpp.) */
	if (bw >= ((u64)b->full_bw * BBR_FULL_BW_THRESH / BBR_UNIT)) {
		b->full_bw_cnt = 0;  /* still growing >= 25%/round: keep probing */
	} else {
		++b->full_bw_cnt;    /* plateau round */
	}
	if (3 <= b->full_bw_cnt) {
		b->full_bw_reached = 1;
	}
	if (bw > b->full_bw) b->full_bw = bw;
}

static void bbr_reset_probe_bw_mode(struct bbr_core *b) {
	b->mode = BBR_PROBE_BW;
	b->cycle_idx = 0;
	b->pacing_gain = (u32)bbr_pacing_gain[0];
	b->cwnd_gain = BBR_CWND_GAIN;
}

static XTCP_BBR_UNUSED void bbr_reset_startup_mode(struct bbr_core *b) {
	b->mode = BBR_STARTUP;
	b->pacing_gain = BBR_HIGH_GAIN;
	b->cwnd_gain = BBR_HIGH_GAIN;
}

static XTCP_BBR_UNUSED void bbr_set_state(struct bbr_core *b, u8 new_state) {
	(void)b;
	(void)new_state;
}

static void bbr_init(struct bbr_core *b) {
	b->rtt_us = 0;
	b->min_rtt_us = 0;
	minmax_init(&b->bw);
	b->rtt_cnt = 0;
	b->round_start = 0;
	b->idle_restart = 0;
	b->full_bw = 0;
	b->full_bw_cnt = 0;
	b->full_bw_reached = 0;
	b->cycle_idx = 0;
	b->has_seen_rtt = 0;
	b->prior_cwnd = 0;
	b->mode = BBR_STARTUP;
	b->pacing_gain = BBR_HIGH_GAIN;
	b->cwnd_gain = BBR_HIGH_GAIN;
	bbr_init_pacing_rate_from_rtt(b);
}

static void bbr_main(struct bbr_core *b, const u32 rs_delivered, const u32 rs_interval_us, const u32 rs_rtt_us, const u32 rs_acked, const u32 rs_lost, u64 now_ms) {
	(void)rs_lost;
	/* Model update: */
	bbr_update_bw(b, rs_delivered, rs_interval_us);
	bbr_update_min_rtt(b, rs_rtt_us, now_ms);
	bbr_check_full_bw_reached(b, bbr_max_bw(b));
	if (0 != rs_rtt_us) b->has_seen_rtt = 1;

	/* State machine: */
	switch (b->mode) {
	case BBR_STARTUP:
		if (b->full_bw_reached) {
			/* BBR paper Fig. 3: STARTUP -> DRAIN (gain 1/2.885) drains the
			 * queue built during STARTUP before probing resumes (audit M2;
			 * mirrored in cc_bbrv1.cpp). */
			b->mode = BBR_DRAIN;
			b->pacing_gain = (u32)(BBR_UNIT * 1000ull / 2885);
			b->cwnd_gain = BBR_HIGH_GAIN;
		}
		break;
	case BBR_DRAIN: {
		/* Exit when the STARTUP queue has drained: inflight <= BDP (bytes),
		 * using the REAL pipe occupancy (audit M3). */
		u32 bw = bbr_max_bw(b);
		u64 bdp = (0 != b->min_rtt_us) ? (u64)bw * b->min_rtt_us / BBR_UNIT : 0;
		if (0 == bdp || (u64)b->inflight <= bdp) {
			bbr_reset_probe_bw_mode(b);
		}
		break;
	}
	case BBR_PROBE_BW:
		/* PROBE_RTT (audit M2): refresh the min-RTT filter every 10 s with
		 * a 4-packet window; without it min_rtt only ratchets down. */
		if (0 != b->min_rtt_stamp && now_ms >= (u64)b->min_rtt_stamp + BBR_MIN_RTT_WIN_SEC * 1000ull) {
			b->saved_cycle_idx = b->cycle_idx;
			b->saved_pacing_gain = b->pacing_gain;
			b->probe_rtt_enter = (u32)now_ms;
			b->mode = BBR_PROBE_RTT;
		}
		bbr_update_cycle_phase(b, rs_acked, rs_delivered, now_ms);
		break;
	case BBR_PROBE_RTT:
		/* 200 ms of 4-packet probing refreshes min_rtt; pacing gain 1.0 so
		 * the probe does not inflate the queue. Then resume. */
		b->pacing_gain = BBR_UNIT;
		if (now_ms >= (u64)b->probe_rtt_enter + BBR_PROBE_RTT_MODE_MS) {
			b->cycle_idx = b->saved_cycle_idx;
			b->pacing_gain = b->saved_pacing_gain;
			b->mode = BBR_PROBE_BW;
		}
		break;
	}

	/* Control outputs: */
	bbr_set_pacing_rate(b, bbr_bw(b), (int)b->pacing_gain);
	bbr_set_cwnd(b, rs_acked, rs_delivered, rs_rtt_us);
}

/* ---- Public API (fidelity differential driver) ---- */

void bbr_core_init(struct bbr_core *b) {
	memset(b, 0, sizeof(*b));
	bbr_init(b);
}

void bbr_core_on_ack(struct bbr_core *b,
					 uint32_t rs_delivered, uint32_t rs_interval_us,
					 uint32_t rs_rtt_us, uint32_t rs_acked, uint32_t rs_lost,
					 uint64_t now_ms, uint32_t inflight, uint32_t app_limited) {
	b->delivered += rs_delivered;
	b->delivered_mstamp = now_ms;
	b->inflight = inflight;
	b->app_limited = app_limited;
	bbr_main(b, rs_delivered, rs_interval_us, rs_rtt_us, rs_acked, rs_lost, now_ms);
}

uint32_t bbr_core_cwnd(const struct bbr_core *b) { return b->cwnd; }
uint64_t bbr_core_pacing_rate(const struct bbr_core *b) { return b->pacing_rate; }
uint8_t  bbr_core_mode(const struct bbr_core *b) { return b->mode; }
uint32_t bbr_core_min_rtt(const struct bbr_core *b) { return b->min_rtt_us; }
uint32_t bbr_core_max_bw(const struct bbr_core *b) { return bbr_max_bw(b); }

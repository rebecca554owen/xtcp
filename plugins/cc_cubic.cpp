/**
 * @file cc_cubic.cpp
 * @brief CUBIC port (RFC 8312) as a tutorial sample: validates the CC
 *        porting guide and serves as a fairness baseline.
 */

#include <xtcp/cc/cc.h>

#include <cmath>
#include <new>

namespace {
    using namespace xtcp;
    using namespace xtcp::cc;

    constexpr Double kCubicC = 0.4;
    constexpr Double kCubicBeta = 0.7;
    constexpr UInt32 kCubicCwndMin = 2;

    struct CubicState {
        UInt32  wmax = 0;          /* W_max: window before the last reduction */
        Double  k = 0;             /* K: rounds to reach W_max from epoch start */
        UInt64  epoch_base = 0;    /* delivered bytes at epoch start (last reduction) */
        UInt64  recovery_base = 0; /* delivered bytes at fast-recovery entry */
        UInt32  loss_cwnd = 0;     /* cwnd at the loss that entered recovery */
        Double  cnt = 0;           /* fractional cwnd-growth accumulator (ca->cnt) */
        UInt32  last_acked = 0;
        Byte    in_recovery = 0;
        Byte    initialized = 0;
    };

    CubicState* Priv(XtcpConnCc* sk) noexcept {
        if (NULLPTR == sk) {
            return NULLPTR;
        }
        if (NULLPTR == sk->ca_priv) {
            sk->ca_priv = new (std::nothrow) CubicState();
        }
        return static_cast<CubicState*>(sk->ca_priv);
    }

    void CubicInit(XtcpConnCc* sk) noexcept {
        CubicState* c = Priv(sk);
        if (NULLPTR != c) {
            c->epoch_base = sk->delivered;  /* RFC 8312: t counts from here */
            c->initialized = 1;
        }
    }

    void CubicRelease(XtcpConnCc* sk) noexcept {
        if (NULLPTR != sk) {
            delete static_cast<CubicState*>(sk->ca_priv);
            sk->ca_priv = NULLPTR;
        }
    }

    UInt32 CubicSsthresh(XtcpConnCc* sk) noexcept {
        CubicState* c = Priv(sk);
        if (NULLPTR != c) {
            // RFC 8312: W_max is the window before this reduction, and a new
            // epoch starts here - t counts from this delivered base, never
            // from the connection's cumulative delivered count (which would
            // grow t without bound across epochs and explode the cubic target).
            c->wmax = sk->snd_cwnd;
            c->k = std::cbrt(static_cast<Double>(c->wmax) * (1.0 - kCubicBeta) / kCubicC);
            c->epoch_base = sk->delivered;
            c->cnt = 0;
            // Fast recovery: remember the window in flight at the loss so the
            // growth guard below can detect when recovery has fully drained it.
            c->loss_cwnd = sk->snd_cwnd;
            c->recovery_base = sk->delivered;
            c->in_recovery = 1;
        }
        UInt32 ssthresh = static_cast<UInt32>(static_cast<Double>(sk->snd_cwnd) * kCubicBeta);
        if (ssthresh < kCubicCwndMin) {
            ssthresh = kCubicCwndMin;
        }
        return ssthresh;
    }

    void CubicCongAvoid(XtcpConnCc* sk, UInt32 ack, UInt32 acked) noexcept {
        (void)ack;
        CubicState* c = Priv(sk);
        if (NULLPTR == c) {
            return;
        }
        if (0 == sk->mss) {
            return;
        }
        // Slow start (RFC 5681): one segment per segment ACKed. Always allowed,
        // including the slow start that follows an RTO (cwnd was cut to 1; the
        // in_recovery guard below only gates the congestion-avoidance growth).
        if (sk->snd_cwnd < sk->snd_ssthresh) {
            sk->snd_cwnd += acked / sk->mss;
            if (0 == acked / sk->mss && 0 < acked) {
                ++sk->snd_cwnd;
            }
            // RFC 5681: slow start ends at ssthresh - clamp so a burst ACK
            // cannot overshoot into the CA region (mirror of the Reno path).
            if (sk->snd_cwnd > sk->snd_ssthresh) {
                sk->snd_cwnd = sk->snd_ssthresh;
            }
            return;
        }
        // Fast-recovery guard (RFC 8312, RFC 5681): the ACK clock keeps firing
        // (partial) ACKs during recovery; do not grow the window while in it.
        // Exit once the whole window that was in flight at the loss has been
        // acknowledged again.
        if (0 != c->in_recovery) {
            const UInt64 recov_bytes = static_cast<UInt64>(c->loss_cwnd) * sk->mss;
            if (sk->delivered - c->recovery_base >= recov_bytes) {
                c->in_recovery = 0;
            } else {
                return;
            }
        }
        // Congestion avoidance: cubic W(t) = C*(t-K)^3 + W_max, t in rounds
        // (RFC 8312 eq. 1/2). One round is one W_max worth of acknowledged
        // bytes, measured from the epoch base recorded at the last reduction.
        if (1 > sk->snd_cwnd) {
            sk->snd_cwnd = 1;
        }
        const UInt64 round_bytes = (0 < c->wmax)
            ? static_cast<UInt64>(c->wmax) * sk->mss
            : static_cast<UInt64>(sk->snd_cwnd) * sk->mss;
        const Double t = (0 < round_bytes)
            ? static_cast<Double>(sk->delivered - c->epoch_base) / static_cast<Double>(round_bytes)
            : 0.0;
        const Double wmax_d = static_cast<Double>(c->wmax > sk->snd_cwnd ? c->wmax : sk->snd_cwnd);
        const Double dt = t - c->k;
        Double target = kCubicC * dt * dt * dt + wmax_d;
        if (target < static_cast<Double>(sk->snd_cwnd) + 1.0) {
            target = static_cast<Double>(sk->snd_cwnd) + 1.0;
        }
        // Per-ACK increment in segments, spread over the cwnd ACKs that make
        // up one round. Accumulated in floating point (ca->cnt semantics) so
        // fractional increments below one segment are never truncated to zero.
        const Double increment = (target - static_cast<Double>(sk->snd_cwnd)) /
                                 static_cast<Double>(sk->snd_cwnd);
        c->cnt += increment * (static_cast<Double>(acked) / static_cast<Double>(sk->mss));
        while (c->cnt >= 1.0) {
            c->cnt -= 1.0;
            if (sk->snd_cwnd < 0x7FFFFFFF) {
                ++sk->snd_cwnd;
            }
        }
        if (sk->snd_cwnd < kCubicCwndMin) {
            sk->snd_cwnd = kCubicCwndMin;
        }
    }

    UInt32 CubicUndoCwnd(XtcpConnCc* sk) noexcept {
        return sk->snd_cwnd;
    }

    void CubicCwndEvent(XtcpConnCc* sk, CaEvent ev) noexcept {
        (void)sk;  // notification only: the reduction runs in the ssthresh hook
        if (kCaEventLoss == ev || kCaEventEcnCe == ev) {
            // RFC 3168 s6.1.2 / RFC 8312: a CE-marked round (or a loss)
            // reduces cwnd with beta = 0.7. The reduction itself runs in the
            // ssthresh hook (CutCwnd / ECN withdraw path dispatch it before
            // the event); this handler is a NOTIFICATION only. Reducing here
            // again would double the cut (0.7^2 = 0.49W) and capture wmax
            // from the already-reduced window, violating RFC 8312's
            // "W_max = window just before the reduction".
        }
    }

    const XtcpCongestionOps& CubicOps() noexcept {
        static const XtcpCongestionOps ops = {
            "cubic",
            CubicInit,
            CubicRelease,
            CubicSsthresh,
            CubicCongAvoid,   /* cong_avoid */
            NULLPTR,
            CubicCwndEvent,
            NULLPTR,
            CubicUndoCwnd,
            NULLPTR,          /* cong_control (classic path) */
            NULLPTR,
            0,
        };
        return ops;
    }
}

namespace xtcp {
    namespace cc {
        /**
         * @brief Registers the CUBIC tutorial sample.
         */
        void RegisterCubic() noexcept {
            RegisterCongestionControl(CubicOps());
        }
    }
}

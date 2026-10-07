#pragma once

/**
 * @file cc.h
 * @brief Congestion control hooks, kernel tcp_congestion_ops style.
 *
 * The XtcpCongestionOps fields mirror Linux net/ipv4/tcp_cong.c semantics
 * so kernel CC modules port into xtcp with logic and constants unchanged.
 */

#include <xtcp/stdafx.h>
#include <xtcp/core/tcp.h>

namespace xtcp {
    namespace cc {
        /**
         * @brief Per-connection fields the CC hooks operate on (kernel
         *        tcp_sock field equivalents). Defined in core/tcp.h so the
         *        connection owns the state; the alias keeps the cc API name.
         */
        using XtcpConnCc = core::XtcpConnCc;

        /**
         * @brief ACK sample (kernel struct ack_sample equivalent).
         */
        struct AckSample {
            UInt32  rtt_us     = 0;   /**< RTT sample */
            UInt32  acked      = 0;   /**< Bytes acknowledged */
            UInt32  delivered  = 0;   /**< Total delivered count */
            UInt32  inflight   = 0;
        };

        /**
         * @brief Rate sample (kernel struct rate_sample equivalent).
         */
        struct RateSample {
            UInt32  delivered      = 0;  /**< Delivered since last sample */
            UInt32  interval_us    = 0;  /**< Elapsed since last sample */
            UInt32  rtt_us         = 0;  /**< RTT sample (0 = none) */
            UInt32  lost           = 0;  /**< Lost bytes since last sample */
            UInt32  acked          = 0;
            UInt32  is_app_limited = 0;
        };

        /** Read-only KCC model state; bandwidth is Q24 bytes/us. */
        struct KccTelemetrySnapshot {
            UInt64 max_bw_q24 = 0;
            UInt64 full_bw_q24 = 0;
            UInt64 total_delivered = 0;
            UInt64 round_sample_delivered = 0;
            UInt64 round_sample_interval_us = 0;
            UInt64 last_sample_delivered = 0;
            UInt64 last_sample_interval_us = 0;
            UInt32 rtt_round = 0;
            UInt32 min_rtt_us = 0;
            UInt32 full_bw_count = 0;
            UInt32 full_bw_reached = 0;
            UInt32 mode = 0;  // 0=STARTUP, 1=PROBE_BW, 2=DRAIN
            UInt32 sample_count = 0;
            UInt32 has_seen_rtt = 0;
        };

        /**
         * @brief CA events (kernel enum tcp_ca_event equivalent).
         */
        enum CaEvent : Byte {
            kCaEventLoss       = 0,
            kCaEventEcnCe      = 1,
            kCaEventAck        = 2,
            kCaEventDelayedAck = 3,
            kCaEventNewData    = 4,
        };

        /**
         * @brief CC hook table (kernel tcp_congestion_ops equivalent).
         */
        struct XtcpCongestionOps {
            const char* name = NULLPTR;
            void (*init)(XtcpConnCc* sk) = NULLPTR;
            void (*release)(XtcpConnCc* sk) = NULLPTR;
            UInt32 (*ssthresh)(XtcpConnCc* sk) = NULLPTR;
            void (*cong_avoid)(XtcpConnCc* sk, UInt32 ack, UInt32 acked) = NULLPTR;
            void (*set_state)(XtcpConnCc* sk, Byte new_state) = NULLPTR;
            void (*cwnd_event)(XtcpConnCc* sk, CaEvent ev) = NULLPTR;
            void (*pkts_acked)(XtcpConnCc* sk, const AckSample* sample) = NULLPTR;
            UInt32 (*undo_cwnd)(XtcpConnCc* sk) = NULLPTR;
            void (*cong_control)(XtcpConnCc* sk, const RateSample* rs) = NULLPTR;
            UInt32 (*reinit_ssthresh)(XtcpConnCc* sk) = NULLPTR;
            Byte    flags = 0;
            bool (*kcc_telemetry)(const XtcpConnCc* sk, KccTelemetrySnapshot& out) = NULLPTR;
        };

        /**
         * @brief Registers a CC algorithm (immediate availability).
         */
        bool RegisterCongestionControl(const XtcpCongestionOps& ops) noexcept;
        /**
         * @brief Unregisters a CC algorithm by name.
         */
        bool UnregisterCongestionControl(const char* name) noexcept;
        /**
         * @brief Looks up a CC algorithm by name.
         * @return Hook table, or NULLPTR.
         */
        const XtcpCongestionOps* FindCongestionControl(const char* name) noexcept;
        /**
         * @brief Copies a registered (active) algorithm into out atomically.
         * @param name Algorithm name.
         * @param out  Receives a private copy of the hook table.
         * @return True when found and active.
         * @note The returned copy is safe to keep beyond registration changes:
         *       Unregister/Register mutate the registry entry, never the copy.
         */
        bool GetCongestionControl(const char* name, XtcpCongestionOps& out) noexcept;
        /**
         * @brief Applies an ACK/rate sample to a connection's CC.
         * @param sk    Connection CC state.
         * @param ops   Algorithm hooks (may be NULLPTR for no-op).
         * @param rs    Rate sample.
         */
        void ApplyRateSample(XtcpConnCc* sk, const XtcpCongestionOps* ops, const RateSample* rs,
                     UInt32 ack) noexcept;

        /**
         * @brief Registers the BBRv1 port (reference algorithm).
         */
        void RegisterBbrv1() noexcept;
        /**
         * @brief Registers the CUBIC sample (tutorial port).
         */
        void RegisterCubic() noexcept;
        /**
         * @brief Registers the KCC port (built-in algorithm; KCC is the
         *        default CC for new connections, Reno when no ops plug in).
         */
        void RegisterKcc() noexcept;
        /**
         * @brief Registers the built-in algorithms (KCC, BBRv1, CUBIC) once.
         * @note Called automatically by XtcpStack construction.
         */
        void RegisterBuiltinCc() noexcept;
    }
}

#pragma once

/**
 * @file qdisc.h
 * @brief Pluggable qdisc framework (kernel Qdisc_ops style): registration,
 *        instantiation, enqueue/dequeue hooks. Default algorithm: FQ
 *        (sch_fq semantics); FIFO provided as a tutorial sample.
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>
#include <xtcp/core/timer.h>

#include <chrono>
#include <mutex>

namespace xtcp {
    namespace qdisc {
        using xtcp::core::TimePoint;

        /**
         * @brief Monotonic microseconds (same clock family as core::TimePoint).
         */
        inline TimePoint NowUs() noexcept {
            return static_cast<TimePoint>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }

        /**
         * @brief Algorithm parameters (kernel fq-style knobs).
         */
        struct QdiscParams {
            UInt32 buckets         = 1024;   /**< Flow hash buckets */
            UInt32 max_flow_queue  = 100;    /**< Max segments per flow */
            UInt32 max_global_queue = 10000; /**< Max segments overall */
            bool   pacing_enabled  = true;
            UInt32 target_us       = 5000;   /**< CoDel/Cobalt target delay (us) */
            UInt32 interval_us     = 100000; /**< CoDel/Cobalt interval (us) */
        };

        class XtcpQdisc;

        /**
         * @brief Qdisc algorithm hooks (kernel Qdisc_ops semantics).
         */
        struct XtcpQdiscOps {
            const char* name = NULLPTR;
            int (*init)(XtcpQdisc* q, const QdiscParams* params) = NULLPTR;
            void (*destroy)(XtcpQdisc* q) = NULLPTR;
            int (*enqueue)(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet) = NULLPTR;
            buf::BufRef (*dequeue)(XtcpQdisc* q, TimePoint now, TimePoint* next_pacing) = NULLPTR;
            bool (*has_backlog)(const XtcpQdisc* q) = NULLPTR;
            int (*change)(XtcpQdisc* q, const QdiscParams* params) = NULLPTR;
            void (*reset)(XtcpQdisc* q) = NULLPTR;
            int (*set_pacing_rate)(XtcpQdisc* q, UInt64 flow_id, UInt64 rate_bps) = NULLPTR;  /**< optional: per-flow pacing rate */
UInt64 (*get_pacing_rate)(const XtcpQdisc* q, UInt64 flow_id) = NULLPTR;  /**< optional: current per-flow rate (0 = unset/unknown) */
            int (*remove_flow)(XtcpQdisc* q, UInt64 flow_id) = NULLPTR;  /**< optional: drop one flow (conn close reclaim); returns the number of queued segments dropped (the host decrements its tx counter for them) */
            int (*enqueue_drain)(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet,
                                 TimePoint now, buf::BufRef* out,
                                 TimePoint* next_pacing) = NULLPTR;  /**< optional (perf): enqueue and, when the qdisc had NO backlog before this packet AND the flow is immediately drainable (no pacing gate), return the packet in *out for direct emission - one lock, no drain-loop round-trip. Returns 0 when accepted (out empty = queued behind backlog/pacing; out non-empty = emitted now), -1 when dropped (invalid or queue limit) - the host then runs the normal drain path for accepted-but-queued packets. */
        };

        /**
         * @brief Qdisc instance (opaque private data in private_data).
         */
        class XtcpQdisc {
        public:
            const XtcpQdiscOps* ops = NULLPTR;
            QdiscParams         params;
            void*               private_data = NULLPTR;
            /**
             * @brief Serializes every ops entry point: the stack may enqueue
             *        from a worker thread while the pacing clock drains from
             *        another (Emit vs PollAckTimers).
             */
            mutable std::mutex  syncobj_;
        };

        /**
         * @brief Registers an algorithm; immediate availability.
         * @return True when registered (duplicate names rejected).
         */
        bool RegisterQdisc(const XtcpQdiscOps& ops) noexcept;
        /**
         * @brief Unregisters an algorithm (existing instances keep running).
         */
        bool UnregisterQdisc(const char* name) noexcept;
        /**
         * @brief Looks up an algorithm by name.
         */
        const XtcpQdiscOps* FindQdisc(const char* name) noexcept;
        /**
         * @brief Creates an instance.
         * @return Instance, or NULLPTR on failure.
         */
        XtcpQdisc* CreateQdisc(const char* name, const QdiscParams& params) noexcept;
        /**
         * @brief Destroys an instance.
         */
        void DestroyQdisc(XtcpQdisc* q) noexcept;

        /**
         * @brief Registers the default FQ algorithm (sch_fq semantics).
         */
        void RegisterFqDefault() noexcept;
        /**
         * @brief Registers the fq_codel algorithm (sch_fq_codel semantics:
         *        per-flow FIFO queues + per-queue CoDel AQM + DRR).
         */
        void RegisterFqCoDel() noexcept;
        /**
         * @brief Registers the cake algorithm (sch_cake semantics, core
         *        subset: per-flow DRR + Cobalt AQM; no dual-rate shaping).
         */
        void RegisterCake() noexcept;
        /**
         * @brief Registers the FIFO tutorial sample.
         */
        void RegisterFifoSample() noexcept;
    }
}

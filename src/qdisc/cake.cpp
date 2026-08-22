/**
 * @file cake.cpp
 * @brief cake qdisc (Linux sch_cake semantics, core subset): per-flow
 *        FIFO queues hashed by flow id, single-tier deficit round robin
 *        (per-flow bandwidth fairness) and a per-flow Cobalt AQM (Blue
 *        probabilistic marking plus the CoDel control-law dropping state
 *        machine). Not implemented: dual-rate shaping, ATM/PTM overhead
 *        compensation, NAT wash, ECN CE-marking - documented as out of
 *        scope.
 */

#include <xtcp/qdisc/qdisc.h>

#include <deque>
#include <list>
#include <unordered_map>

namespace xtcp {
    namespace qdisc {
        namespace {
            constexpr UInt32 kQuantum      = 1514;    /**< DRR quantum (kernel CAKE_QUANTUM) */
            constexpr UInt32 kBlueIncrement = 2;      /**< Blue probability ramp step (/1000) per over-target dequeue */
            constexpr UInt32 kBlueDecrement = 32;     /**< Blue probability decay step (/1000) per under-target dequeue */

            struct Flow {
                bool                in_active = false;  // O(1) active-set membership (mirror of fq.cpp)
                UInt64              flow_id = 0;
                UInt64              deficit = 0;
                UInt32              segs    = 0;
                std::deque<buf::BufRef> queue;
                std::deque<TimePoint>    enq_time;
                // Cobalt AQM state (per flow).
                bool                dropping = false;
                UInt32              count = 0;
                TimePoint           first_above = 0;
                TimePoint           drop_next = 0;
                UInt32              blue_in = 0;  /**< Blue drop probability * 1000 (0..1000) */
            };

            struct CakePrivate {
                QdiscParams params;
                std::list<Flow> flows;
                std::unordered_map<UInt64, std::list<Flow>::iterator> by_id;
                std::list<Flow*> active;
                size_t total_segs = 0;
                std::atomic<bool> has_work{false};

                UInt32 SegsOf(const buf::BufRef& pkt) const noexcept {
                    return (0 < pkt.Meta().segs) ? pkt.Meta().segs : 1;
                }
                Flow* Find(UInt64 flow_id) noexcept {
                    auto it = by_id.find(flow_id);
                    if (it == by_id.end()) {
                        return NULLPTR;
                    }
                    return &*it->second;
                }
                Flow* AcquireFlow(UInt64 flow_id) noexcept {
                    Flow* flow = Find(flow_id);
                    if (NULLPTR != flow) {
                        return flow;
                    }
                    // OOM-safe: emplace/push_back can throw bad_alloc (this
                    // function is noexcept - an uncaught throw would
                    // std::terminate the process). Strong guarantee per
                    // container; roll back the inserted parts, report NULLPTR
                    // (the caller drops; TCP RTO recovers the bytes).
                    try {
                        flows.emplace_back();
                    } catch (...) {
                        return NULLPTR;
                    }
                    Flow& f = flows.back();
                    f.flow_id = flow_id;
                    f.deficit = kQuantum;
                    try {
                        by_id.emplace(flow_id, std::prev(flows.end()));
                    } catch (...) {
                        flows.pop_back();
                        return NULLPTR;
                    }
                    try {
                        f.in_active = true;  // new flow starts active
                        active.push_back(&f);
                    } catch (...) {
                        by_id.erase(flow_id);
                        flows.pop_back();
                        return NULLPTR;
                    }
                    return &f;
                }
                void AttachToActive(Flow* flow) noexcept {
                    // O(1) membership: active is only appended/removed under
                    // the qdisc lock, so the flag mirrors membership exactly.
                    if (!flow->in_active) {
                        flow->in_active = true;
                        active.push_back(flow);
                    }
                }
                // Kernel sch_cake: when a flow drains to empty, the Cobalt
                // state is reset (cobalt_vars_init: dropping = false,
                // first_above = 0). Without this a fresh burst would find a
                // stale first_above/dropping and drop its very first packet.
                static void ResetCobalt(Flow& f) noexcept {
                    f.dropping = false;
                    f.count = 0;
                    f.first_above = 0;
                    f.drop_next = 0;
                }
            };

            /** Kernel codel_control_law, shifted-drop-rate form. */
            static TimePoint ControlLaw(TimePoint t, UInt32 count, UInt32 interval_us) noexcept {
                UInt32 shift = 0;
                UInt32 c = count;
                while (c > 1) {
                    c >>= 1;
                    ++shift;
                }
                return t + static_cast<TimePoint>(interval_us >> shift);
            }

            int CakeInit(XtcpQdisc* q, const QdiscParams* params) noexcept {
                CakePrivate* p = new (std::nothrow) CakePrivate();
                if (NULLPTR == p) {
                    return -1;
                }
                p->params = *params;
                if (0 == p->params.buckets) {
                    p->params.buckets = 1024;
                }
                q->private_data = p;
                return 0;
            }

            void CakeDestroy(XtcpQdisc* q) noexcept {
                delete static_cast<CakePrivate*>(q->private_data);
                q->private_data = NULLPTR;
            }

            int CakeEnqueue(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                CakePrivate* p = static_cast<CakePrivate*>(q->private_data);
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;
                }
                const UInt32 segs = p->SegsOf(packet);
                Flow* flow = p->Find(flow_id);
                if (NULLPTR != flow && flow->segs + segs > p->params.max_flow_queue) {
                    return -1;  // per-flow limit: tail-drop
                }
                if (p->total_segs + segs > p->params.max_global_queue) {
                    return -1;  // global limit: tail-drop
                }
                if (NULLPTR == flow) {
                    if (segs > p->params.max_flow_queue) {
                        return -1;
                    }
                    flow = p->AcquireFlow(flow_id);
                    if (NULLPTR == flow) {
                        return -1;
                    }
                }
                p->has_work.store(true, std::memory_order_release);
                const TimePoint now = NowUs();
                flow->queue.push_back(std::move(packet));
                flow->enq_time.push_back(now);
                flow->segs += segs;
                p->total_segs += segs;
                p->AttachToActive(flow);
                return 0;
            }

            buf::BufRef CakeDequeue(XtcpQdisc* q, TimePoint now, TimePoint* next_pacing) noexcept {
                CakePrivate* p = static_cast<CakePrivate*>(q->private_data);
                if (NULLPTR == p || !p->has_work.load(std::memory_order_acquire)) {
                    if (NULLPTR != next_pacing) {
                        *next_pacing = 0;
                    }
                    return buf::BufRef();
                }
                std::lock_guard<std::mutex> scope(q->syncobj_);
                if (NULLPTR != next_pacing) {
                    *next_pacing = 0;
                }
                if (p->active.empty()) {
                    return buf::BufRef();
                }
                const UInt32 rotation_limit = static_cast<UInt32>(p->active.size());
                for (UInt32 i = 0; i < rotation_limit; ++i) {
                    if (p->active.empty()) {
                        break;
                    }
                    Flow* flow = p->active.front();
                    p->active.pop_front();
                    flow->in_active = false;  // left the active set; re-attached explicitly below
                    if (flow->queue.empty()) {
                        continue;
                    }
                    const TimePoint enq = flow->enq_time.front();
                    const UInt32 sojourn = static_cast<UInt32>(
                        (now > enq) ? (now - enq) : 0);
                    // Read the AQM params from the private copy: CakeChange
                    // updates p->params, so q->params would be stale here.
                    const UInt32 target_us = (0 < p->params.target_us) ? p->params.target_us : 1;
                    const UInt32 interval_us = (0 < p->params.interval_us) ? p->params.interval_us : 1;

                    // Cobalt AQM: Blue probabilistic drops plus the CoDel
                    // control-law dropping state machine.
                    if (sojourn > target_us) {
                        if (0 == flow->first_above) {
                            flow->first_above = now;
                        }
                        // Blue: the probability ramps while over target
                        // (kernel cake_blue_add on over-target sojourn).
                        if (flow->blue_in < 1000) {
                            flow->blue_in += kBlueIncrement;
                            if (flow->blue_in > 1000) {
                                flow->blue_in = 1000;
                            }
                        }
                    } else {
                        // Under target: decay Blue probability, leave CoDel
                        // dropping state.
                        if (flow->blue_in > 0) {
                            flow->blue_in = (flow->blue_in < kBlueDecrement)
                                ? 0 : flow->blue_in - kBlueDecrement;
                        }
                        if (flow->dropping) {
                            flow->dropping = false;
                        }
                        flow->first_above = 0;
                        flow->count = 0;
                    }

                    // Blue: probabilistic drop independent of the CoDel state
                    // machine (kernel cobalt_should_drop: a random draw below
                    // p_drop drops the head). The draw hashes now^flow_id so
                    // the distribution stays uniform across flows without an
                    // RNG in the qdisc hot path.
                    if (0 < flow->blue_in) {
                        const UInt32 r = static_cast<UInt32>(
                            ((now >> 8) ^ static_cast<TimePoint>(flow->flow_id)) % 1000u);
                        if (r < flow->blue_in) {
                            buf::BufRef head = std::move(flow->queue.front());
                            flow->queue.pop_front();
                            flow->enq_time.pop_front();
                            const UInt32 segs = p->SegsOf(head);
                            flow->segs -= segs;
                            p->total_segs -= segs;
                            if (0 == p->total_segs) {
                                p->has_work.store(false, std::memory_order_release);
                            }
                            if (!flow->queue.empty()) {
                                p->AttachToActive(flow);
                            } else {
                                p->ResetCobalt(*flow);  // drained: reset AQM state
                            }
                            continue;  // dropped: keep draining in THIS call
                        }
                    }

                    if (!flow->dropping && 0 != flow->first_above &&
                        sojourn > target_us && now - flow->first_above >= interval_us) {
                        // Cobalt: interval expired while still above target -
                        // enter dropping and drop this head NOW (kernel
                        // cobalt_should_drop), then re-arm the control law.
                        flow->dropping = true;
                        flow->count = 1;
                        flow->drop_next = ControlLaw(now, 1, interval_us);
                        buf::BufRef head = std::move(flow->queue.front());
                        flow->queue.pop_front();
                        flow->enq_time.pop_front();
                        const UInt32 segs = p->SegsOf(head);
                        flow->segs -= segs;
                        p->total_segs -= segs;
                        if (0 == p->total_segs) {
                            p->has_work.store(false, std::memory_order_release);
                        }
                        if (!flow->queue.empty()) {
                            p->AttachToActive(flow);
                        } else {
                            p->ResetCobalt(*flow);  // drained: reset AQM state
                        }
                        continue;  // dropped: keep draining in THIS call (kernel codel_dequeue loops)
                    }

                    if (flow->dropping && now >= flow->drop_next) {
                        // CoDel control-law drop of the head.
                        buf::BufRef head = std::move(flow->queue.front());
                        flow->queue.pop_front();
                        flow->enq_time.pop_front();
                        const UInt32 segs = p->SegsOf(head);
                        flow->segs -= segs;
                        p->total_segs -= segs;
                        if (0 == p->total_segs) {
                            p->has_work.store(false, std::memory_order_release);
                        }
                        flow->count += 1;
                        flow->drop_next = ControlLaw(now, flow->count, interval_us);
                        if (!flow->queue.empty()) {
                            p->AttachToActive(flow);
                        } else {
                            p->ResetCobalt(*flow);  // drained: reset AQM state
                        }
                        continue;  // dropped: keep draining in THIS call (kernel codel_dequeue loops)
                    }

                    buf::BufRef& head = flow->queue.front();
                    const UInt32 len = head.Len();
                    const UInt32 segs = p->SegsOf(head);
                    if (flow->deficit < len) {
                        flow->deficit += kQuantum;
                    }
                    flow->deficit -= len;
                    buf::BufRef out = std::move(head);
                    flow->queue.pop_front();
                    flow->enq_time.pop_front();
                    flow->segs -= segs;
                    p->total_segs -= segs;
                    if (0 == p->total_segs) {
                        p->has_work.store(false, std::memory_order_release);
                    }
                    if (!flow->queue.empty()) {
                        p->AttachToActive(flow);
                    } else {
                        p->ResetCobalt(*flow);  // drained: reset AQM state
                    }
                    return out;
                }
                return buf::BufRef();
            }

            bool CakeHasBacklog(const XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                const CakePrivate* p = static_cast<const CakePrivate*>(q->private_data);
                return NULLPTR != p && 0 < p->total_segs;
            }

            int CakeChange(XtcpQdisc* q, const QdiscParams* params) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                CakePrivate* p = static_cast<CakePrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return -1;
                }
                p->params = *params;
                return 0;
            }

            void CakeReset(XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                CakePrivate* p = static_cast<CakePrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return;
                }
                p->flows.clear();
                p->by_id.clear();
                for (Flow* af : p->active) { af->in_active = false; }
                p->active.clear();
                p->total_segs = 0;
                p->has_work.store(false, std::memory_order_release);
            }

            int CakeRemoveFlow(XtcpQdisc* q, UInt64 flow_id) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                CakePrivate* p = static_cast<CakePrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return 0;
                }
                auto it = p->by_id.find(flow_id);
                if (it == p->by_id.end()) {
                    return 0;
                }
                Flow& flow = *it->second;
                const int dropped = static_cast<int>(flow.segs);
                p->total_segs -= flow.segs;
                flow.in_active = false;
                p->active.remove(&flow);
                p->flows.erase(it->second);
                p->by_id.erase(it);
                if (0 == p->total_segs) {
                    p->has_work.store(false, std::memory_order_release);
                }
                return dropped;
            }

            const XtcpQdiscOps& CakeOps() noexcept {
                static const XtcpQdiscOps ops = {
                    "cake",
                    CakeInit,
                    CakeDestroy,
                    CakeEnqueue,
                    CakeDequeue,
                    CakeHasBacklog,
                    CakeChange,
                    CakeReset,
                    NULLPTR,   // set_pacing_rate
                    NULLPTR,   // get_pacing_rate
                    CakeRemoveFlow,
                    NULLPTR,   // enqueue_drain
                };
                return ops;
            }
        }

        /**
         * @brief Registers the cake algorithm (sch_cake semantics, core
         *        subset: per-flow DRR + Cobalt AQM; no dual-rate shaping).
         */
        void RegisterCake() noexcept {
            RegisterQdisc(CakeOps());
        }
    }
}

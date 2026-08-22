/**
 * @file fq_codel.cpp
 * @brief fq_codel qdisc (Linux sch_fq_codel semantics): per-flow FIFO
 *        queues hashed by flow id, deficit round robin scheduling and a
 *        per-queue CoDel active queue management (target 5ms, interval
 *        100ms, kernel codel control-law drop timing).
 */

#include <xtcp/qdisc/qdisc.h>

#include <deque>
#include <list>
#include <unordered_map>

namespace xtcp {
    namespace qdisc {
        namespace {
            constexpr UInt32 kQuantum      = 1514;    /**< DRR quantum (bytes, kernel FQ_CODEL_QUANTUM) */

            struct CoDelState {
                bool       dropping      = false;
                UInt32     count         = 0;
                TimePoint  first_above   = 0;  /**< First dequeue where sojourn > target */
                TimePoint  drop_next     = 0;  /**< Next scheduled drop instant */
            };

            struct FlowEntry {
                bool                in_active = false;  // O(1) active-set membership (mirror of fq.cpp)
                UInt64              flow_id = 0;
                UInt64              deficit = 0;
                UInt32              segs    = 0;
                std::deque<buf::BufRef> queue;
                std::deque<TimePoint>    enq_time;  /**< enqueue instant per packet */
                CoDelState          codel;
            };

            struct FqCoDelPrivate {
                QdiscParams params;
                std::list<FlowEntry> flows;
                std::unordered_map<UInt64, std::list<FlowEntry>::iterator> by_id;
                std::list<FlowEntry*> active;
                size_t total_segs = 0;
                std::atomic<bool> has_work{false};

                UInt32 SegsOf(const buf::BufRef& pkt) const noexcept {
                    return (0 < pkt.Meta().segs) ? pkt.Meta().segs : 1;
                }
                FlowEntry* Find(UInt64 flow_id) noexcept {
                    auto it = by_id.find(flow_id);
                    if (it == by_id.end()) {
                        return NULLPTR;
                    }
                    return &*it->second;
                }
                FlowEntry* AcquireFlow(UInt64 flow_id) noexcept {
                    FlowEntry* flow = Find(flow_id);
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
                    FlowEntry& f = flows.back();
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
                void AttachToActive(FlowEntry* flow) noexcept {
                    // O(1) membership: active is only appended/removed under
                    // the qdisc lock, so the flag mirrors membership exactly.
                    if (!flow->in_active) {
                        flow->in_active = true;
                        active.push_back(flow);
                    }
                }
                // Kernel sch_codel: when a flow drains to empty, the CoDel
                // state is reset (codel_vars_init: first_above_time = 0,
                // dropping = false). Without this, a fresh burst would find
                // a stale first_above/dropping from the previous overload and
                // drop its very first packet (the interval already elapsed).
                static void ResetCodel(CoDelState& cd) noexcept {
                    cd.dropping = false;
                    cd.count = 0;
                    cd.first_above = 0;
                    cd.drop_next = 0;
                }
            };

            /** Kernel codel_shift + codel_control_law:
             *  delay(t) = t + interval >> shift(count), where shift is the
             *  position of the highest set bit (interval, interval/2,
             *  interval/4, ... - exponentially growing drop rate). Count is
             *  unbounded (the kernel does not clamp it either): under
             *  sustained overload the drop spacing shrinks toward zero. */
            static TimePoint CoDelControlLaw(TimePoint t, UInt32 count, UInt32 interval_us) noexcept {
                UInt32 shift = 0;
                while (count > 1) {
                    count >>= 1;
                    ++shift;
                }
                const UInt32 step = (shift < 31) ? (interval_us >> shift) : 0;
                return t + static_cast<TimePoint>(step);
            }

            int FqCoDelInit(XtcpQdisc* q, const QdiscParams* params) noexcept {
                FqCoDelPrivate* p = new (std::nothrow) FqCoDelPrivate();
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

            void FqCoDelDestroy(XtcpQdisc* q) noexcept {
                delete static_cast<FqCoDelPrivate*>(q->private_data);
                q->private_data = NULLPTR;
            }

            int FqCoDelEnqueue(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;
                }
                const UInt32 segs = p->SegsOf(packet);
                FlowEntry* flow = p->Find(flow_id);
                if (NULLPTR != flow && flow->segs + segs > p->params.max_flow_queue) {
                    return -1;  // per-flow limit exceeded: tail-drop
                }
                if (p->total_segs + segs > p->params.max_global_queue) {
                    return -1;  // global limit exceeded: tail-drop
                }
                if (NULLPTR == flow) {
                    if (segs > p->params.max_flow_queue) {
                        return -1;  // new flow exceeds per-flow limit
                    }
                    flow = p->AcquireFlow(flow_id);
                    if (NULLPTR == flow) {
                        return -1;
                    }
                }
                p->has_work.store(true, std::memory_order_release);
                const TimePoint now = NowUs();
                flow->queue.push_back(std::move(packet));
                flow->enq_time.push_back(now);  // CoDel sojourn anchor (kernel codel_get_enqueue_time)
                flow->segs += segs;
                p->total_segs += segs;
                p->AttachToActive(flow);
                return 0;
            }

            int FqCoDelEnqueueDrain(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet,
                                    TimePoint now, buf::BufRef* out, TimePoint* next_pacing) noexcept {
                // Perf fast path (mirror of fq.cpp FqEnqueueDrain): when the
                // qdisc had NO backlog before this packet, the packet IS the
                // next one out under DRR, so one lock enqueues AND emits it
                // directly, skipping the DrainTxQdisc round-trip. Correctness:
                // a just-enqueued packet has sojourn ~0 << CoDel target, so the
                // AQM verdict is identically "emit" (the first-post-filter
                // dequeue would also emit it); DRR order is preserved.
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
                if (NULLPTR != next_pacing) {
                    *next_pacing = 0;
                }
                if (NULLPTR != out) {
                    *out = buf::BufRef();
                }
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;  // invalid: drop (mirror FqCoDelEnqueue)
                }
                const UInt32 segs = p->SegsOf(packet);
                const bool was_empty = (0 == p->total_segs);
                FlowEntry* flow = p->Find(flow_id);
                if (NULLPTR != flow && flow->segs + segs > p->params.max_flow_queue) {
                    return -1;  // per-flow limit: tail-drop
                }
                if (p->total_segs + segs > p->params.max_global_queue) {
                    return -1;  // global limit: tail-drop
                }
                if (NULLPTR == flow) {
                    if (segs > p->params.max_flow_queue) {
                        return -1;  // new flow exceeds per-flow limit
                    }
                    flow = p->AcquireFlow(flow_id);
                    if (NULLPTR == flow) {
                        return -1;
                    }
                }
                p->has_work.store(true, std::memory_order_release);
                flow->queue.push_back(std::move(packet));
                flow->enq_time.push_back(now);  // CoDel sojourn anchor
                flow->segs += segs;
                p->total_segs += segs;
                p->AttachToActive(flow);
                if (!was_empty || NULLPTR == out) {
                    return 0;  // backlog exists (or no out slot): normal drain
                }
                // Queue was empty: this packet is the head of the only flow.
                const UInt32 len = flow->queue.front().Len();
                if (flow->deficit < len) {
                    // Debit short: give the flow quantum (mirror of
                    // FqCoDelDequeue's top-up) so credit never stalls the path.
                    flow->deficit += kQuantum;
                }
                flow->deficit -= len;
                buf::BufRef fast = std::move(flow->queue.front());
                flow->queue.pop_front();
                flow->enq_time.pop_front();
                flow->segs -= segs;
                p->total_segs -= segs;
                if (0 == p->total_segs) {
                    p->has_work.store(false, std::memory_order_release);
                }
                // Drained: mirror FqCoDelDequeue's empty-flow handling (reset
                // the AQM state, leave the active set - a drained flow must
                // not rotate ahead of newly enqueued ones).
                p->ResetCodel(flow->codel);
                flow->in_active = false;
                p->active.remove(flow);
                *out = std::move(fast);
                return 0;
            }

            buf::BufRef FqCoDelDequeue(XtcpQdisc* q, TimePoint now, TimePoint* next_pacing) noexcept {
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
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
                    FlowEntry* flow = p->active.front();
                    p->active.pop_front();
                    flow->in_active = false;  // left the active set; re-attached explicitly below
                    if (flow->queue.empty()) {
                        continue;
                    }
                    const TimePoint enq = flow->enq_time.front();
                    const UInt32 sojourn = static_cast<UInt32>(
                        (now > enq) ? (now - enq) : 0);
                    // Read the AQM params from the private copy: FqCoDelChange
                    // updates p->params, so q->params would be stale here.
                    const UInt32 target_us = (0 < p->params.target_us) ? p->params.target_us : 1;
                    const UInt32 interval_us = (0 < p->params.interval_us) ? p->params.interval_us : 1;
                    CoDelState& cd = flow->codel;
                    if (sojourn <= target_us) {
                        // Back within target: leave dropping state, clear the
                        // first-above marker so a later spike restarts the
                        // interval window.
                        if (cd.dropping) {
                            cd.dropping = false;
                        }
                        cd.first_above = 0;
                        cd.count = 0;
                    } else if (sojourn > target_us) {
                        // Above target. Kernel sch_codel: the FIRST time the
                        // sojourn exceeds target, record first_above; the drop
                        // happens only when the condition has persisted for
                        // one interval (the queue is not draining).
                        if (0 == cd.first_above) {
                            cd.first_above = now;
                        }
                    }
                    if (!cd.dropping && 0 != cd.first_above &&
                        sojourn > target_us && now - cd.first_above >= interval_us) {
                        // Interval expired while still above target: enter
                        // dropping and drop this head NOW (kernel
                        // codel_should_drop returns true on this very
                        // dequeue), then re-arm the control law.
                        cd.dropping = true;
                        cd.count = 1;
                        cd.drop_next = CoDelControlLaw(now, 1, interval_us);
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
                            p->ResetCodel(flow->codel);  // drained: reset AQM state
                        }
                        // Dropped, not emitted: keep draining in THIS call so
                        // sustained overload drops at line rate (kernel
                        // codel_dequeue loops while dropping && now >= drop_next).
                        continue;
                    }
                    if (cd.dropping) {
                        // Kernel sch_codel dropping mode: while sojourn stays
                        // above target, drop the head on each control-law
                        // instant; if it drops back below target we exit
                        // dropping and drain normally.
                        if (now >= cd.drop_next) {
                            buf::BufRef head = std::move(flow->queue.front());
                            flow->queue.pop_front();
                            flow->enq_time.pop_front();
                            const UInt32 segs = p->SegsOf(head);
                            flow->segs -= segs;
                            p->total_segs -= segs;
                            if (0 == p->total_segs) {
                                p->has_work.store(false, std::memory_order_release);
                            }
                            // The next drop comes exponentially sooner (kernel
                            // codel_should_drop re-arms drop_next per drop).
                            cd.count += 1;
                            cd.drop_next = CoDelControlLaw(now, cd.count, interval_us);
                            if (!flow->queue.empty()) {
                                p->AttachToActive(flow);
                            } else {
                                p->ResetCodel(flow->codel);  // drained: reset AQM state
                            }
                            // Dropped, not emitted: keep draining in THIS call
                            // (kernel codel_dequeue drops the head then pulls
                            // the next packet in the same invocation).
                            continue;
                        }
                        // Dropping but not yet at the next instant: emit the
                        // head normally (kernel also dequeues here).
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
                            p->ResetCodel(flow->codel);  // drained: reset AQM state
                        }
                        return out;
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
                        p->ResetCodel(flow->codel);  // drained: reset AQM state
                    }
                    return out;
                }
                return buf::BufRef();
            }

            bool FqCoDelHasBacklog(const XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                const FqCoDelPrivate* p = static_cast<const FqCoDelPrivate*>(q->private_data);
                return NULLPTR != p && 0 < p->total_segs;
            }

            int FqCoDelChange(XtcpQdisc* q, const QdiscParams* params) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return -1;
                }
                p->params = *params;
                return 0;
            }

            void FqCoDelReset(XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return;
                }
                p->flows.clear();
                p->by_id.clear();
                for (FlowEntry* af : p->active) {
                    af->in_active = false;
                }
                p->active.clear();
                p->total_segs = 0;
                p->has_work.store(false, std::memory_order_release);
            }

            int FqCoDelRemoveFlow(XtcpQdisc* q, UInt64 flow_id) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqCoDelPrivate* p = static_cast<FqCoDelPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return 0;
                }
                auto it = p->by_id.find(flow_id);
                if (it == p->by_id.end()) {
                    return 0;  // idempotent
                }
                FlowEntry& flow = *it->second;
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

            const XtcpQdiscOps& FqCoDelOps() noexcept {
                static const XtcpQdiscOps ops = {
                    "fq_codel",
                    FqCoDelInit,
                    FqCoDelDestroy,
                    FqCoDelEnqueue,
                    FqCoDelDequeue,
                    FqCoDelHasBacklog,
                    FqCoDelChange,
                    FqCoDelReset,
                    NULLPTR,   // set_pacing_rate: not implemented (kernel fq_codel has no pacing)
                    NULLPTR,   // get_pacing_rate
                    FqCoDelRemoveFlow,
                    FqCoDelEnqueueDrain,
                };
                return ops;
            }
        }

        /**
         * @brief Registers the fq_codel algorithm (sch_fq_codel semantics).
         */
        void RegisterFqCoDel() noexcept {
            RegisterQdisc(FqCoDelOps());
        }
    }
}

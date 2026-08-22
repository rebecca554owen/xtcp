/**
 * @file fq.cpp
 * @brief Default FQ algorithm (Linux sch_fq semantics): per-flow queues,
 *        deficit round robin, internal pacing, GSO segment counting.
 */

#include <xtcp/qdisc/qdisc.h>

#include <deque>
#include <list>
#include <unordered_map>

namespace xtcp {
    namespace qdisc {
        namespace {
            constexpr UInt32 kQuantum = 1500;  /**< DRR quantum (bytes) */

            struct FqFlow {
                UInt64              flow_id  = 0;
                UInt64              deficit  = 0;
                UInt64              pacing_rate = 0;  /**< bits per second */
                TimePoint           next_time = 0;
                UInt32              segs     = 0;     /**< Queued segment count */
                bool                in_active = false;  /**< O(1) AttachToActive membership test */
                std::deque<buf::BufRef> queue;
            };

            struct FqPrivate {
                QdiscParams params;
                std::list<FqFlow> flows;
                std::unordered_map<UInt64, std::list<FqFlow>::iterator> by_id;
                std::list<FqFlow*> active;  /**< DRR rotation */
                std::unordered_map<UInt64, UInt64> pending_rates;  /**< Rates set before their flow existed (applied on flow creation, cleared on remove) */
                size_t total_segs = 0;
                // Hot-path fast flag (perf): the stack drains the qdisc after
                // every enqueue, so an idle qdisc sees one "empty" dequeue per
                // drained packet - each taking syncobj_ for nothing. When no
                // flow has queued segments, dequeue returns empty WITHOUT the
                // lock. Invariant: false implies every flow queue is empty
                // (active empty); set on enqueue, cleared when the last
                // segment is dequeued. A stale true (set after a racing
                // clear) is harmless: the dequeue then locks and finds
                // nothing. A stale false is impossible (release-store after
                // the push, acquire-load before the check).
                std::atomic<bool> has_work{false};

                UInt32 SegsOf(const buf::BufRef& pkt) const noexcept {
                    return (0 < pkt.Meta().segs) ? pkt.Meta().segs : 1;
                }
                FqFlow* Find(UInt64 flow_id) noexcept {
                    auto it = by_id.find(flow_id);
                    if (it == by_id.end()) {
                        return NULLPTR;
                    }
                    return &*it->second;
                }
                FqFlow* AcquireFlow(UInt64 flow_id) noexcept {
                    FqFlow* flow = Find(flow_id);
                    if (NULLPTR != flow) {
                        return flow;
                    }
                    // OOM-safe: emplace/push_back can throw bad_alloc (this
                    // function is noexcept - an uncaught throw would
                    // std::terminate the process). Each container offers the
                    // strong guarantee, so a failed step leaves it unchanged;
                    // roll back the already-inserted parts and report NULLPTR
                    // (the caller drops; TCP RTO recovers the bytes).
                    try {
                        flows.emplace_back();
                    } catch (...) {
                        return NULLPTR;
                    }
                    FqFlow& f = flows.back();
                    f.flow_id = flow_id;
                    f.deficit = kQuantum;
                    try {
                        by_id.emplace(flow_id, std::prev(flows.end()));
                    } catch (...) {
                        flows.pop_back();
                        return NULLPTR;
                    }
                    try {
                        active.push_back(&f);
                        f.in_active = true;
                    } catch (...) {
                        by_id.erase(flow_id);
                        flows.pop_back();
                        return NULLPTR;
                    }
                    // Apply a rate that was set before this flow existed
                    // (FqSetPacingRate's pending path).
                    auto pit = pending_rates.find(flow_id);
                    if (pit != pending_rates.end()) {
                        f.pacing_rate = pit->second;
                        pending_rates.erase(pit);
                    }
                    return &f;
                }
                void DetachFromActive(FqFlow* flow) noexcept {
                    active.remove(flow);
                    flow->in_active = false;
                }
                void AttachToActive(FqFlow* flow) noexcept {
                    // O(1) membership: active is only appended/removed under
                    // the qdisc lock, so the flag mirrors membership exactly.
                    if (!flow->in_active) {
                        flow->in_active = true;
                        active.push_back(flow);
                    }
                }
            };

            int FqInit(XtcpQdisc* q, const QdiscParams* params) noexcept {
                FqPrivate* p = new (std::nothrow) FqPrivate();
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

            void FqDestroy(XtcpQdisc* q) noexcept {
                delete static_cast<FqPrivate*>(q->private_data);
                q->private_data = NULLPTR;
            }

            int FqEnqueue(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                // Zero-length packets must be rejected here: a len-0 non-empty
                // BufRef dequeues later as a valid packet whose Data()[0] read
                // (stack DrainTxQdisc) would be an out-of-bounds access.
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;
                }
                const UInt32 segs = p->SegsOf(packet);
                FqFlow* flow = p->Find(flow_id);
                if (NULLPTR != flow && flow->segs + segs > p->params.max_flow_queue) {
                    return -1;  // per-flow limit exceeded: drop
                }
                if (p->total_segs + segs > p->params.max_global_queue) {
                    return -1;  // global limit exceeded: drop
                }
                if (NULLPTR == flow) {
                    if (segs > p->params.max_flow_queue) {
                        return -1;  // new flow exceeds per-flow limit: drop
                    }
                    flow = p->AcquireFlow(flow_id);
                    if (NULLPTR == flow) {
                        return -1;
                    }
                }
                // Publish BEFORE the push (release): a dequeue fast-path that
                // reads false has provably not observed this enqueue, so the
                // queue was empty at its instant - "nothing to dequeue" is
                // accurate. (A store after the push would let a concurrent
                // dequeuer read false while the packet is already queued.)
                p->has_work.store(true, std::memory_order_release);
                flow->queue.push_back(std::move(packet));
                flow->segs += segs;
                p->total_segs += segs;
                p->AttachToActive(flow);
                return 0;
            }

            buf::BufRef FqDequeue(XtcpQdisc* q, TimePoint now, TimePoint* next_pacing) noexcept {
                // Fast path: no queued segments at all - skip the lock. The
                // store in FqEnqueue is release, this load is acquire: a
                // false here means no enqueue has been published yet, so
                // "nothing to dequeue" is accurate (a racing enqueue either
                // precedes us - store visible - or follows, and its own
                // SendOne drains it immediately; a missed cross-thread drain
                // is caught by DrainTxQdisc's has_backlog safety net).
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p || !p->has_work.load(std::memory_order_acquire)) {
                    if (NULLPTR != next_pacing) {
                        *next_pacing = 0;
                    }
                    return buf::BufRef();
                }
                std::lock_guard<std::mutex> scope(q->syncobj_);
                if (p->active.empty()) {
                    if (NULLPTR != next_pacing) {
                        *next_pacing = 0;
                    }
                    return buf::BufRef();
                }
                if (NULLPTR != next_pacing) {
                    *next_pacing = 0;
                }
                const UInt32 rotation_limit = static_cast<UInt32>(p->active.size());
                for (UInt32 i = 0; i < rotation_limit; ++i) {
                    if (p->active.empty()) {
                        break;
                    }
                    FqFlow* flow = p->active.front();
                    p->active.pop_front();
                    flow->in_active = false;  // mirror: the flow is no longer in the rotation list
                    if (flow->queue.empty()) {
                        // Drained: NOT re-registered (the flow object and its
                        // pacing state stay in by_id; AttachToActive re-adds it
                        // on the next enqueue). Re-rotating an empty flow would
                        // let it jump ahead of newly enqueued flows.
                        continue;
                    }
                    // Internal pacing: flow not eligible yet.
                    if (p->params.pacing_enabled && 0 < flow->pacing_rate &&
                        now < flow->next_time) {
                        if (NULLPTR != next_pacing && (0 == *next_pacing || flow->next_time < *next_pacing)) {
                            *next_pacing = flow->next_time;
                        }
                        p->active.push_back(flow);
                        flow->in_active = true;  // mirror membership
                        continue;
                    }
                    buf::BufRef& head = flow->queue.front();
                    const UInt32 len = head.Len();
                    const UInt32 segs = p->SegsOf(head);
                    if (flow->deficit < len) {
                        if (!p->params.pacing_enabled || 0 < flow->pacing_rate) {
                            // Pacing disabled (pure DRR mode) or this flow is
                            // paced: not enough credit this round - skip and
                            // rotate. Give the caller a clock even though
                            // nothing was dequeued: without it the stack never
                            // re-polls and the packet sits in the qdisc forever.
                            // Prefer this flow's pacing deadline if it has one,
                            // else "now" (deficit accrues every round). This is
                            // the kernel DRR semantic (deficit < len -> rotate,
                            // one quantum per round), pinned by
                            // TestFqDeficitRotation.
                            flow->deficit += kQuantum;
                            if (NULLPTR != next_pacing) {
                                const TimePoint t = (flow->next_time > now) ? flow->next_time : now;
                                if (0 == *next_pacing || t < *next_pacing) {
                                    *next_pacing = t;
                                }
                            }
                            p->active.push_back(flow);
                            flow->in_active = true;  // mirror membership
                            continue;
                        }
                        // Pacing enabled but this flow has no rate: there is no
                        // pacing gate to release the segment at a later
                        // deadline, so the deficit must not hold it behind an
                        // extra poll round - that caps throughput at one MSS
                        // per drain (quantum < 2*MSS) and forces a busy
                        // re-poll (next = now) every PollAckTimers. Top the
                        // credit up past this segment and send now.
                        while (flow->deficit < len) {
                            flow->deficit += kQuantum;
                        }
                    }
                    flow->deficit -= len;
                    buf::BufRef out = std::move(head);
                    flow->queue.pop_front();
                    flow->segs -= segs;
                    p->total_segs -= segs;
                    if (0 == p->total_segs) {
                        p->has_work.store(false, std::memory_order_release);
                    }
                    if (p->params.pacing_enabled && 0 < flow->pacing_rate) {
                        // next_time = now + bytes*8/rate_bps seconds.
                        flow->next_time = now + static_cast<TimePoint>(
                            (static_cast<UInt64>(len) * 8000000ull) / flow->pacing_rate);
                        if (NULLPTR != next_pacing) {
                            // Merge with any earlier (smaller) deadline seen
                            // this round instead of overwriting it.
                            *next_pacing = (0 == *next_pacing || flow->next_time < *next_pacing) ?
                                flow->next_time : *next_pacing;
                        }
                    }
                    if (!flow->queue.empty()) {
                        p->active.push_back(flow);
                        flow->in_active = true;  // mirror membership
                    }
                    return out;
                }
                return buf::BufRef();
            }

            int FqEnqueueDrain(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet,
                               TimePoint now, buf::BufRef* out, TimePoint* next_pacing) noexcept {
                // Perf fast path (see ops doc): the stack drains after every
                // enqueue. For the common case - qdisc empty, flow un-paced -
                // one lock does enqueue + immediate dequeue and the packet is
                // emitted directly, skipping the DrainTxQdisc loop (a second
                // mutex + GetTickUs + TxBatch round-trip per segment).
                // Correctness: the queue was EMPTY before this packet, so the
                // packet IS the next one out under DRR - returning it now
                // preserves ordering and fairness. A pacing deadline on this
                // flow defers emission (same gate as FqDequeue).
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR != next_pacing) {
                    *next_pacing = 0;
                }
                if (NULLPTR != out) {
                    *out = buf::BufRef();
                }
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;  // invalid: drop (mirror FqEnqueue)
                }
                const UInt32 segs = p->SegsOf(packet);
                const bool was_empty = (0 == p->total_segs);
                FqFlow* flow = p->Find(flow_id);
                if (NULLPTR != flow && flow->segs + segs > p->params.max_flow_queue) {
                    return -1;  // per-flow limit: drop (tail-drop)
                }
                if (p->total_segs + segs > p->params.max_global_queue) {
                    return -1;  // global limit: drop
                }
                if (NULLPTR == flow) {
                    if (segs > p->params.max_flow_queue) {
                        return -1;  // new flow exceeds limit: drop
                    }
                    flow = p->AcquireFlow(flow_id);
                    if (NULLPTR == flow) {
                        return -1;
                    }
                }
                p->has_work.store(true, std::memory_order_release);
                flow->queue.push_back(std::move(packet));
                flow->segs += segs;
                p->total_segs += segs;
                p->AttachToActive(flow);
                if (!was_empty || NULLPTR == out) {
                    return 0;  // backlog exists (or no out slot): normal drain
                }
                // Queue was empty: this packet is the head of the only flow.
                if (p->params.pacing_enabled && 0 < flow->pacing_rate &&
                    now < flow->next_time) {
                    // Pacing gate: defer like FqDequeue would.
                    if (NULLPTR != next_pacing) {
                        *next_pacing = flow->next_time;
                    }
                    return 0;
                }
                const UInt32 len = flow->queue.front().Len();
                if (flow->deficit < len) {
                    // Deficit below the packet: give the flow its quantum
                    // (mirror of FqDequeue's un-paced top-up) so the fast
                    // path does not stall on credit.
                    while (flow->deficit < len) {
                        flow->deficit += kQuantum;
                    }
                }
                flow->deficit -= len;
                buf::BufRef fast = std::move(flow->queue.front());
                flow->queue.pop_front();
                flow->segs -= segs;
                p->total_segs -= segs;
                if (0 == p->total_segs) {
                    p->has_work.store(false, std::memory_order_release);
                }
                if (p->params.pacing_enabled && 0 < flow->pacing_rate) {
                    flow->next_time = now + static_cast<TimePoint>(
                        (static_cast<UInt64>(len) * 8000000ull) / flow->pacing_rate);
                }
                // Mirror FqDequeue's post-drain detach: a flow whose queue is
                // empty must NOT stay registered in active (it would rotate
                // ahead of newly enqueued flows and drain its next packet
                // out of turn).
                p->DetachFromActive(flow);
                *out = std::move(fast);
                return 0;
            }

            bool FqHasBacklog(const XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                const FqPrivate* p = static_cast<const FqPrivate*>(q->private_data);
                return NULLPTR != p && 0 < p->total_segs;
            }

            int FqChange(XtcpQdisc* q, const QdiscParams* params) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return -1;
                }
                p->params = *params;
                return 0;
            }

            void FqReset(XtcpQdisc* q) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return;
                }
                p->flows.clear();
                p->by_id.clear();
                p->active.clear();
                p->pending_rates.clear();
                p->total_segs = 0;
                p->has_work.store(false, std::memory_order_release);
            }

            int FqRemoveFlow(XtcpQdisc* q, UInt64 flow_id) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return 0;
                }
                p->pending_rates.erase(flow_id);  // a closed flow's rate must not leak into a conn_id-reusing successor
                auto it = p->by_id.find(flow_id);
                if (it == p->by_id.end()) {
                    return 0;  // unknown flow: idempotent
                }
                FqFlow& flow = *it->second;
                // Any still-queued segments belong to a closed connection that
                // can never be retransmitted: drop them (their pool blocks are
                // released when the deque destructs) and keep the counters in
                // sync so FqHasBacklog does not linger on a stale total. The
                // dropped count is returned so the host can subtract the
                // segments from its tx counter (they never reached the wire).
                const int dropped = static_cast<int>(flow.segs);
                p->total_segs -= flow.segs;
                p->active.remove(&flow);
                p->flows.erase(it->second);
                p->by_id.erase(it);
                if (0 == p->total_segs) {
                    p->has_work.store(false, std::memory_order_release);
                }
                return dropped;
            }

            int FqSetPacingRate(XtcpQdisc* q, UInt64 flow_id, UInt64 rate_bps) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return -1;
                }
                FqFlow* flow = p->Find(flow_id);
                if (NULLPTR == flow) {
                    // Unknown flow: remember the rate and apply it when the
                    // flow is created. The host's rate bridge caches the
                    // propagated rate (it must not take the qdisc mutex per
                    // segment), and it calls set_pacing_rate BEFORE the first
                    // enqueue - without this, a connection whose CC rate
                    // stabilizes early would never be paced at all.
                    p->pending_rates[flow_id] = rate_bps;
                    return 0;
                }
                flow->pacing_rate = rate_bps;
                // ANY rate change invalidates the pending pacing deadline: a
                // next_time computed at the OLD (slower) rate would keep
                // gating the next packet for up to len*8/old_rate - a 1460B
                // packet at 1 KB/s stalls 11.7 s after the rate is raised
                // (audit m2). Clearing it lets the next dequeue compute the
                // deadline with the new rate.
                flow->next_time = 0;
                return 0;
            }

            UInt64 FqGetPacingRate(const XtcpQdisc* q, UInt64 flow_id) noexcept {
                std::lock_guard<std::mutex> scope(q->syncobj_);  // syncobj_ is mutable
                FqPrivate* p = static_cast<FqPrivate*>(q->private_data);
                if (NULLPTR == p) {
                    return 0;
                }
                FqFlow* flow = p->Find(flow_id);
                if (NULLPTR == flow) {
                    return 0;  // unknown flow: 0 = unset
                }
                return flow->pacing_rate;
            }

            const XtcpQdiscOps& FqOps() noexcept {
                static const XtcpQdiscOps ops = {
                    "fq",
                    FqInit,
                    FqDestroy,
                    FqEnqueue,
                    FqDequeue,
                    FqHasBacklog,
                    FqChange,
                    FqReset,
                    FqSetPacingRate,
                    FqGetPacingRate,
                    FqRemoveFlow,
                    FqEnqueueDrain,
                };
                return ops;
            }
        }

        /**
         * @brief Registers the default FQ algorithm.
         */
        void RegisterFqDefault() noexcept {
            RegisterQdisc(FqOps());
        }
    }
}


/**
 * @file fifo.cpp
 * @brief FIFO qdisc tutorial sample: validates the pluggable interface.
 */

#include <xtcp/qdisc/qdisc.h>

#include <deque>

namespace xtcp {
    namespace qdisc {
        namespace {
            struct FifoPrivate {
                std::deque<buf::BufRef> queue;
            };

            int FifoInit(XtcpQdisc* q, const QdiscParams* params) noexcept {
                (void)params;
                q->private_data = new (std::nothrow) FifoPrivate();
                return (NULLPTR != q->private_data) ? 0 : -1;
            }

            void FifoDestroy(XtcpQdisc* q) noexcept {
                delete static_cast<FifoPrivate*>(q->private_data);
                q->private_data = NULLPTR;
            }

            int FifoEnqueue(XtcpQdisc* q, UInt64 flow_id, buf::BufRef&& packet) noexcept {
            std::lock_guard<std::mutex> scope(q->syncobj_);
                (void)flow_id;
                FifoPrivate* p = static_cast<FifoPrivate*>(q->private_data);
                if (NULLPTR == p || packet.IsEmpty() || 0 == packet.Len()) {
                    return -1;
                }
                if (p->queue.size() >= q->params.max_global_queue) {
                    return -1;
                }
                p->queue.push_back(std::move(packet));
                return 0;
            }

            buf::BufRef FifoDequeue(XtcpQdisc* q, TimePoint now, TimePoint* next_pacing) noexcept {
            std::lock_guard<std::mutex> scope(q->syncobj_);
                (void)now;
                if (NULLPTR != next_pacing) {
                    *next_pacing = 0;
                }
                FifoPrivate* p = static_cast<FifoPrivate*>(q->private_data);
                if (NULLPTR == p || p->queue.empty()) {
                    return buf::BufRef();
                }
                buf::BufRef out = std::move(p->queue.front());
                p->queue.pop_front();
                return out;
            }

            bool FifoHasBacklog(const XtcpQdisc* q) noexcept {
            std::lock_guard<std::mutex> scope(q->syncobj_);
                const FifoPrivate* p = static_cast<const FifoPrivate*>(q->private_data);
                return NULLPTR != p && !p->queue.empty();
            }

            int FifoChange(XtcpQdisc* q, const QdiscParams* params) noexcept {
            std::lock_guard<std::mutex> scope(q->syncobj_);
                q->params = *params;
                return 0;
            }

            void FifoReset(XtcpQdisc* q) noexcept {
            std::lock_guard<std::mutex> scope(q->syncobj_);
                FifoPrivate* p = static_cast<FifoPrivate*>(q->private_data);
                if (NULLPTR != p) {
                    p->queue.clear();
                }
            }

            const XtcpQdiscOps& FifoOps() noexcept {
                static const XtcpQdiscOps ops = {
                    "fifo",
                    FifoInit,
                    FifoDestroy,
                    FifoEnqueue,
                    FifoDequeue,
                    FifoHasBacklog,
                    FifoChange,
                    FifoReset,
                    NULLPTR,  // no pacing
                };
                return ops;
            }
        }

        /**
         * @brief Registers the FIFO tutorial algorithm.
         */
        void RegisterFifoSample() noexcept {
            RegisterQdisc(FifoOps());
        }
    }
}


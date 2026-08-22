/**
 * @file scheduler.cpp
 * @brief Scheduler, MPSC queue, migration checkpoint/restore.
 */

#include <xtcp/core/scheduler.h>

#include <new>

namespace xtcp {
    namespace core {
        /* ---------------- MpscQueue ---------------- */

        MpscQueue::MpscQueue(UInt32 capacity) noexcept : capacity_(capacity) {
            Node* sentinel = new (std::nothrow) Node();
            if (NULLPTR == sentinel) {
                capacity_ = 0;
            }
            head_.store(sentinel, std::memory_order_relaxed);
            tail_.store(sentinel, std::memory_order_relaxed);
        }

        MpscQueue::~MpscQueue() noexcept {
            Node* node = head_.load(std::memory_order_relaxed);
            while (NULLPTR != node) {
                Node* next = node->next.load(std::memory_order_relaxed);
                delete node;
                node = next;
            }
        }

        bool MpscQueue::Push(buf::BufRef&& packet) noexcept {
            if (0 == capacity_) {
                return false;
            }
            UInt32 slot = count_.fetch_add(1, std::memory_order_relaxed);
            if (slot >= capacity_) {
                count_.fetch_sub(1, std::memory_order_relaxed);
                return false;
            }
            Node* node = new (std::nothrow) Node();
            if (NULLPTR == node) {
                count_.fetch_sub(1, std::memory_order_relaxed);
                return false;
            }
            node->packet = std::move(packet);
            Node* prev = tail_.exchange(node, std::memory_order_acq_rel);
            prev->next.store(node, std::memory_order_release);
            return true;
        }

        buf::BufRef MpscQueue::Pop() noexcept {
            Node* head = head_.load(std::memory_order_relaxed);
            if (NULLPTR == head) {
                return buf::BufRef();
            }
            Node* next = head->next.load(std::memory_order_acquire);
            if (NULLPTR == next) {
                return buf::BufRef();
            }
            head_.store(next, std::memory_order_relaxed);
            buf::BufRef packet = std::move(next->packet);
            delete head;
            count_.fetch_sub(1, std::memory_order_relaxed);
            return packet;
        }

        UInt32 MpscQueue::Size() const noexcept {
            return count_.load(std::memory_order_relaxed);
        }

        /* ---------------- Scheduler ---------------- */

        Scheduler::Scheduler(UInt32 shard_count, UInt32 flow_capacity, UInt32 pool_blocks) noexcept {
            if (0 == shard_count) {
                shard_count = 1;
            }
            shards_.reserve(shard_count);
            inboxes_.reserve(shard_count);
            for (UInt32 i = 0; i < shard_count; ++i) {
                Shard* shard = new (std::nothrow) Shard(flow_capacity, pool_blocks);
                MpscQueue* inbox = new (std::nothrow) MpscQueue(4096);
                if (NULLPTR == shard || NULLPTR == inbox) {
                    delete shard;
                    delete inbox;
                    continue;
                }
                shards_.push_back(shard);
                inboxes_.push_back(inbox);
            }
            shard_count_ = static_cast<UInt32>(shards_.size());
            route_counts_.resize(shard_count_, 0);
        }

        Scheduler::~Scheduler() noexcept {
            for (MpscQueue* q : inboxes_) {
                delete q;
            }
            for (Shard* s : shards_) {
                delete s;
            }
        }

        UInt32 Scheduler::PlaceNewFlow() noexcept {
            std::lock_guard<std::mutex> scope(route_lock_);
            UInt32 best = 0;
            size_t best_load = ~static_cast<size_t>(0);
            for (UInt32 i = 0; i < shards_.size(); ++i) {
                const size_t load = static_cast<size_t>(route_counts_[i]) + inboxes_[i]->Size();
                if (load < best_load) {
                    best_load = load;
                    best = i;
                }
            }
            return best;
        }

        UInt32 Scheduler::Route(const FlowKey& key) noexcept {
            std::lock_guard<std::mutex> scope(route_lock_);
            auto it = routes_.find(key);
            if (it == routes_.end()) {
                return 0xFFFFFFFF;
            }
            return it->second;
        }

        void Scheduler::RegisterFlow(const FlowKey& key, UInt32 shard) noexcept {
            std::lock_guard<std::mutex> scope(route_lock_);
            auto it = routes_.find(key);
            if (routes_.end() == it) {
                routes_.emplace(key, shard);
                if (shard < route_counts_.size()) {
                    ++route_counts_[shard];
                }
                return;
            }
            if (it->second < route_counts_.size()) {
                --route_counts_[it->second];
            }
            it->second = shard;
            if (shard < route_counts_.size()) {
                ++route_counts_[shard];
            }
        }

        void Scheduler::UnregisterFlow(const FlowKey& key) noexcept {
            std::lock_guard<std::mutex> scope(route_lock_);
            auto it = routes_.find(key);
            if (routes_.end() == it) {
                return;
            }
            if (it->second < route_counts_.size()) {
                --route_counts_[it->second];
            }
            routes_.erase(it);
        }

        bool Scheduler::Deliver(const FlowKey& key, buf::BufRef&& packet) noexcept {
            const UInt32 shard = Route(key);
            if (0xFFFFFFFF == shard || shard >= inboxes_.size()) {
                return false;
            }
            return inboxes_[shard]->Push(std::move(packet));
        }

        buf::BufRef Scheduler::Poll(UInt32 shard) noexcept {
            if (shard >= inboxes_.size()) {
                return buf::BufRef();
            }
            return inboxes_[shard]->Pop();
        }

        TcpConn::ConnCheckpoint Scheduler::Checkpoint(const TcpConn& conn) noexcept {
            return conn.MakeCheckpoint();
        }

        void Scheduler::Restore(TcpConn& conn, const TcpConn::ConnCheckpoint& ckpt) noexcept {
            conn.ApplyCheckpoint(ckpt);
        }
    }
}

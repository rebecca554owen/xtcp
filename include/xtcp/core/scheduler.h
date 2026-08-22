#pragma once

/**
 * @file scheduler.h
 * @brief Scheduler: dynamic placement of new flows onto the least-loaded
 *        shard, flow routing, cross-shard packet queues, hot migration.
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>
#include <xtcp/core/shard.h>
#include <xtcp/core/tcp.h>

#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace xtcp {
    namespace core {
        typedef UInt64 ConnId;  /**< Connection identifier (0 = invalid) */

        namespace scheduler_hash {
            inline UInt64 HashFlowKey(const FlowKey& key) noexcept {
                UInt64 h = static_cast<UInt64>(key.addr_family);
                h = h * 31 + key.saddr[0];
                h = h * 31 + key.saddr[1];
                h = h * 31 + key.saddr[2];
                h = h * 31 + key.saddr[3];
                h = h * 31 + key.daddr[0];
                h = h * 31 + key.daddr[1];
                h = h * 31 + key.daddr[2];
                h = h * 31 + key.daddr[3];
                h = h * 31 + key.sport;
                h = h * 31 + key.dport;
                return h;
            }
        }

        /**
         * @brief Hash functor for FlowKey (unordered_map support).
         */
        struct FlowKeyHash {
            size_t operator()(const FlowKey& key) const noexcept {
                return static_cast<size_t>(scheduler_hash::HashFlowKey(key));
            }
        };

        /**
         * @brief Cross-shard packet queue: multi-producer, single-consumer.
         * @note Producers may be any shard thread; the consumer is the owner
         *       shard. Order is the enqueue order per producer; global order
         *       across producers follows arrival at the head pointer.
         */
        class MpscQueue {
        public:
            MpscQueue(UInt32 capacity) noexcept;
            virtual ~MpscQueue() noexcept;

            /**
             * @brief Enqueues a packet (any thread).
             * @return True on success; false when full.
             */
            bool Push(buf::BufRef&& packet) noexcept;
            /**
             * @brief Dequeues a packet (owner thread only).
             * @return Packet, or empty when the queue is empty.
             */
            buf::BufRef Pop() noexcept;
            /**
             * @brief Approximate occupancy.
             */
            UInt32 Size() const noexcept;
            /**
             * @brief True when empty.
             */
            bool IsEmpty() const noexcept { return 0 == Size(); }

        private:
            struct Node {
                buf::BufRef packet;
                std::atomic<Node*> next = NULLPTR;
            };

            std::atomic<Node*> head_;
            std::atomic<Node*> tail_;
            std::atomic<UInt32> count_ = 0;
            UInt32 capacity_ = 0;
        };

        /**
         * @brief Scheduler: shard array, placement, routing, migration.
         */
        class Scheduler {
        public:
            Scheduler(UInt32 shard_count, UInt32 flow_capacity, UInt32 pool_blocks) noexcept;
            virtual ~Scheduler() noexcept;

            /**
             * @brief Picks the least-loaded shard for a new flow.
             * @return Shard index.
             */
            UInt32 PlaceNewFlow() noexcept;
            /**
             * @brief Routes a flow key to its owning shard.
             * @return Shard index, or 0xFFFFFFFF when unknown.
             */
            UInt32 Route(const FlowKey& key) noexcept;
            /**
             * @brief Registers a flow mapping (control plane, locked).
             */
            void RegisterFlow(const FlowKey& key, UInt32 shard) noexcept;
            /**
             * @brief Unregisters a flow mapping.
             */
            void UnregisterFlow(const FlowKey& key) noexcept;
            /**
             * @brief Delivers a packet to the shard owning the key.
             * @return True when delivered; false when the flow is unknown or
             *         the target queue is full.
             */
            bool Deliver(const FlowKey& key, buf::BufRef&& packet) noexcept;
            /**
             * @brief Polls one packet from a shard's inbox.
             */
            buf::BufRef Poll(UInt32 shard) noexcept;

            /** @brief Number of live shards (equals shards_.size(); may be less
             *         than the requested count when construction ran out of
             *         memory). 0 means no shards were built. */
            UInt32 ShardCount() const noexcept { return shard_count_; }
            /** @brief Shard reference. Out-of-range indexes fall back to the
             *         first live shard; a sentinel shard is returned when no
             *         shards were built, so GetShard never indexes out of
             *         bounds even after a partial construction failure. */
            Shard& GetShard(UInt32 index) noexcept {
                if (index >= static_cast<UInt32>(shards_.size())) {
                    index = 0;
                }
                if (shards_.empty()) {
                    static Shard kEmptyShard(0, 0);
                    return kEmptyShard;
                }
                return *shards_[index];
            }
            /**
             * @brief Checkpoints a connection for migration.
             */
            static TcpConn::ConnCheckpoint Checkpoint(const TcpConn& conn) noexcept;
            /**
             * @brief Restores a checkpoint into a connection.
             */
            static void Restore(TcpConn& conn, const TcpConn::ConnCheckpoint& ckpt) noexcept;

        private:
            UInt32  shard_count_ = 0;             /**< Actual live shard count */
            std::vector<Shard*> shards_;
            std::vector<MpscQueue*> inboxes_;
            std::vector<UInt32> route_counts_;     /**< Per-shard route count (placement load metric) */
            std::mutex route_lock_;
            std::unordered_map<FlowKey, UInt32, FlowKeyHash> routes_;
        };
    }
}

namespace std {
    template <>
    struct hash<xtcp::core::FlowKey> {
        size_t operator()(const xtcp::core::FlowKey& key) const noexcept {
            return static_cast<size_t>(xtcp::core::scheduler_hash::HashFlowKey(key));
        }
    };
}

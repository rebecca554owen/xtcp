#pragma once

/**
 * @file shard.h
 * @brief Per-core shard: flow table, memory pool, timer wheel.
 *
 * A shard owns all data-plane state for its partition. It is strictly
 * single-threaded: no locks are needed inside the data path.
 */

#include <xtcp/stdafx.h>
#include <xtcp/core/mempool.h>
#include <xtcp/core/timer.h>

namespace xtcp {
    namespace core {
        typedef UInt64 ConnId;  /**< Connection identifier (0 = invalid) */

        /**
         * @brief Flow key: 5-tuple with address family.
         * @note IPv4 keys keep words [1..3] zero; comparison is fixed-width.
         */
        struct FlowKey {
            Byte    addr_family = 0;  /**< 4 or 6 */
            UInt32  saddr[4]    = { 0, 0, 0, 0 };
            UInt32  daddr[4]    = { 0, 0, 0, 0 };
            UInt16  sport       = 0;
            UInt16  dport       = 0;

            bool operator==(const FlowKey& rhs) const noexcept {
                return addr_family == rhs.addr_family &&
                       sport == rhs.sport && dport == rhs.dport &&
                       saddr[0] == rhs.saddr[0] && saddr[1] == rhs.saddr[1] &&
                       saddr[2] == rhs.saddr[2] && saddr[3] == rhs.saddr[3] &&
                       daddr[0] == rhs.daddr[0] && daddr[1] == rhs.daddr[1] &&
                       daddr[2] == rhs.daddr[2] && daddr[3] == rhs.daddr[3];
            }
        };

        /**
         * @brief Per-core shard.
         */
        class Shard {
        public:
            Shard(UInt32 flow_capacity, UInt32 pool_blocks) noexcept;
            virtual ~Shard() noexcept;

            /**
             * @brief Inserts a flow mapping.
             * @param key Flow key.
             * @param conn_id Connection id.
             * @return True on success; false when the key already exists or
             *         the table cannot grow.
             */
            bool AddFlow(const FlowKey& key, ConnId conn_id) noexcept;
            /**
             * @brief Resolves a flow key.
             * @param key Flow key.
             * @return ConnId, or 0 when not found.
             */
            ConnId Lookup(const FlowKey& key) const noexcept;
            /**
             * @brief Removes a flow mapping (tombstone + lazy compaction).
             * @return True when removed; false when absent.
             */
            bool RemoveFlow(const FlowKey& key) noexcept;
            /**
             * @brief Number of live flow mappings.
             */
            size_t FlowCount() const noexcept { return flow_count_; }
            /**
             * @brief Per-shard memory pool.
             */
            Mempool& Pool() noexcept { return pool_; }
            /**
             * @brief Per-shard timer wheel.
             */
            TimerWheel& Timers() noexcept { return timers_; }
            /**
             * @brief Advances the shard clock, firing due timers.
             * @param now Monotonic microseconds.
             */
            size_t AdvanceTime(TimePoint now) noexcept { return timers_.AdvanceTo(now); }

        private:
            struct Slot {
                FlowKey key;
                ConnId  conn_id   = 0;
                bool    tombstone = false;
            };

            static constexpr UInt32 kMinCapacity = 16;
            static constexpr Double kMaxLoadFactor = 0.70;
            static constexpr UInt32 kTombstoneThreshold = 4;  /**< cap / threshold */

            UInt32 Hash(const FlowKey& key) const noexcept;
            void Grow() noexcept;
            void Compact() noexcept;

            Slot*       table_      = NULLPTR;
            UInt32      capacity_   = 0;   /**< Power of two */
            UInt32      mask_       = 0;
            size_t      flow_count_ = 0;
            UInt32      tomb_count_ = 0;
            Mempool     pool_;
            TimerWheel  timers_;
        };
    }
}

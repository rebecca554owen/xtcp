/**
 * @file shard.cpp
 * @brief Shard implementation: open-addressing flow table with tombstones,
 *        per-shard pool and timer wheel.
 */

#include <xtcp/core/shard.h>

#include <new>

namespace xtcp {
    namespace core {
        namespace {
            inline UInt32 Mix(UInt64 h) noexcept {
                h ^= h >> 33;
                h *= 0xFF51AFD7ED558CCDull;
                h ^= h >> 33;
                h *= 0xC4CEB9FE1A85EC53ull;
                h ^= h >> 33;
                return static_cast<UInt32>(h);
            }

            constexpr UInt32 kMaxCapacity = 1u << 30;  /**< Largest power-of-two table: doubling beyond this would overflow UInt32 to 0. */
        }

        Shard::Shard(UInt32 flow_capacity, UInt32 pool_blocks) noexcept
            : pool_(64, pool_blocks) {
            if (flow_capacity > kMaxCapacity) {
                flow_capacity = kMaxCapacity;
            }
            UInt32 cap = kMinCapacity;
            while (cap < flow_capacity) {
                if (cap >= kMaxCapacity) {
                    cap = kMaxCapacity;
                    break;
                }
                cap <<= 1;
            }
            capacity_ = cap;
            mask_ = capacity_ - 1;
            table_ = new (std::nothrow) Slot[capacity_]();
            if (NULLPTR == table_) {
                capacity_ = 0;
                mask_ = 0;
            }
        }

        Shard::~Shard() noexcept {
            delete[] table_;
            table_ = NULLPTR;
        }

        UInt32 Shard::Hash(const FlowKey& key) const noexcept {
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
            return Mix(h);
        }

        void Shard::Grow() noexcept {
            const UInt32 new_cap = capacity_ << 1;
            Slot* new_table = new (std::nothrow) Slot[new_cap]();
            if (NULLPTR == new_table) {
                return;
            }
            const UInt32 new_mask = new_cap - 1;
            for (UInt32 i = 0; i < capacity_; ++i) {
                const Slot& slot = table_[i];
                if (0 != slot.conn_id) {
                    UInt32 idx = Hash(slot.key) & new_mask;
                    while (0 != new_table[idx].conn_id) {
                        idx = (idx + 1) & new_mask;
                    }
                    new_table[idx] = slot;
                }
            }
            delete[] table_;
            table_ = new_table;
            capacity_ = new_cap;
            mask_ = new_mask;
            tomb_count_ = 0;
        }

        void Shard::Compact() noexcept {
            Slot* new_table = new (std::nothrow) Slot[capacity_]();
            if (NULLPTR == new_table) {
                return;
            }
            for (UInt32 i = 0; i < capacity_; ++i) {
                const Slot& slot = table_[i];
                if (0 != slot.conn_id) {
                    UInt32 idx = Hash(slot.key) & mask_;
                    while (0 != new_table[idx].conn_id) {
                        idx = (idx + 1) & mask_;
                    }
                    new_table[idx] = slot;
                }
            }
            delete[] table_;
            table_ = new_table;
            tomb_count_ = 0;
        }

        bool Shard::AddFlow(const FlowKey& key, ConnId conn_id) noexcept {
            if (NULLPTR == table_) {
                return false;
            }
            // Exact integer form of (flow+1) > 0.70*capacity: avoids a FP
            // conversion per flow add and any IEEE rounding at the boundary.
            if (static_cast<UInt64>(flow_count_ + 1) * 100 > 70ull * capacity_) {
                Grow();
            }
            if (NULLPTR == table_) {
                return false;
            }
            UInt32 idx = Hash(key) & mask_;
            UInt32 first_tombstone = capacity_;
            UInt32 probes = 0;
            while (probes < capacity_) {
                Slot& slot = table_[idx];
                if (0 == slot.conn_id && !slot.tombstone) {
                    break;  // empty slot: insert here
                }
                if (0 == slot.conn_id && slot.tombstone && capacity_ == first_tombstone) {
                    first_tombstone = idx;
                }
                if (0 != slot.conn_id && slot.key == key) {
                    return false;  // duplicate key
                }
                idx = (idx + 1) & mask_;
                ++probes;
            }
            if (probes >= capacity_) {
                return false;  // table full of tombstones
            }
            UInt32 target = idx;
            if (capacity_ != first_tombstone) {
                target = first_tombstone;  // reuse a tombstone
            }
            Slot& slot = table_[target];
            slot.key = key;
            slot.conn_id = conn_id;
            slot.tombstone = false;
            if (target == idx) {
                // used a fresh empty slot
            } else if (target == first_tombstone) {
                --tomb_count_;
            }
            ++flow_count_;
            return true;
        }

        ConnId Shard::Lookup(const FlowKey& key) const noexcept {
            if (NULLPTR == table_) {
                return 0;
            }
            UInt32 idx = Hash(key) & mask_;
            UInt32 probes = 0;
            while (probes < capacity_) {
                const Slot& slot = table_[idx];
                if (0 == slot.conn_id && !slot.tombstone) {
                    break;  // empty: chain ends
                }
                if (0 != slot.conn_id && slot.key == key) {
                    return slot.conn_id;
                }
                idx = (idx + 1) & mask_;
                ++probes;
            }
            return 0;
        }

        bool Shard::RemoveFlow(const FlowKey& key) noexcept {
            if (NULLPTR == table_) {
                return false;
            }
            UInt32 idx = Hash(key) & mask_;
            UInt32 probes = 0;
            while (probes < capacity_) {
                Slot& slot = table_[idx];
                if (0 == slot.conn_id && !slot.tombstone) {
                    return false;  // chain ends without a match
                }
                if (0 != slot.conn_id && slot.key == key) {
                    slot.conn_id = 0;
                    slot.tombstone = true;
                    ++tomb_count_;
                    --flow_count_;
                    if (tomb_count_ > (capacity_ / kTombstoneThreshold)) {
                        Compact();
                    }
                    return true;
                }
                idx = (idx + 1) & mask_;
                ++probes;
            }
            return false;
        }
    }
}

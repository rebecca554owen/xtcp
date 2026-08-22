#pragma once

/**
 * @file bufref.h
 * @brief Zero-copy reference-counted packet buffer with tiered pools.
 *
 * A BufRef is movable but not copyable: transfer moves the reference
 * without copying payload bytes. Ref/Unref are atomic so references can
 * cross shard boundaries; payload is never moved.
 */

#include <xtcp/stdafx.h>

#include <atomic>
#include <mutex>

namespace xtcp {
    namespace buf {
        /**
         * @brief Bytes per block header (pool* + refcount). The payload
         *        returned by BufPool::Acquire() starts kHeaderBytes past the
         *        block start, so usable payload per block is
         *        BlockSize() - kHeaderBytes.
         */
        constexpr UInt32 kHeaderBytes = 16;
        /**
         * @brief Largest usable payload a single pool block can hold (the
         *        biggest size class minus the block header). Super-segments
         *        larger than this cannot be zero-copy and fall back to
         *        segmentation.
         */
        constexpr UInt32 kMaxPoolPayload = 32768 - kHeaderBytes;
        /**
         * @brief GSO segment metadata attached to a super-segment.
         */
        struct SegMeta {
            UInt32 gso_size = 0;  /**< Bytes per GSO segment */
            UInt16 mss      = 0;  /**< TCP MSS */
            UInt16 segs     = 0;  /**< Segment count */
        };

        /**
         * @brief A single tier of the buffer pool (fixed block size).
         * @note Acquire/Release are thread-safe: the per-thread cache layer
         *       is lock-free; the shared free list is mutex-serialized (not
         *       an atomic lock-free structure). Blocks cross shards via
         *       refcount handoff and return to the pool on the consumer side.
         */
        class BufPool {
        public:
            BufPool(UInt32 block_size, UInt32 block_count) noexcept;
            virtual ~BufPool() noexcept;
            /**
             * @brief Allocates a block with refcount header.
             * @return Payload pointer or NULLPTR when exhausted.
             */
            Byte* Acquire() noexcept;
            /**
             * @brief Returns a block to the pool (refcount must be zero).
             * @param payload Payload pointer from Acquire().
             */
            void Release(Byte* payload) noexcept;
            /**
             * @brief Bytes of usable payload per block.
             */
            UInt32 BlockSize() const noexcept { return block_size_; }
            /**
             * @brief Total blocks in this tier.
             */
            UInt32 Capacity() const noexcept { return block_count_; }
            /**
             * @brief Free blocks remaining.
             */
            UInt32 FreeCount() const noexcept { return free_count_.load(std::memory_order_relaxed); }
            /**
             * @brief True after ShutdownPools: no further Acquire/Release
             *        writes into this pool are allowed.
             */
            bool IsDestroyed() const noexcept { return destroyed_.load(std::memory_order_acquire); }
            /**
             * @brief Marks the pool destroyed (only ShutdownPools).
             */
            void MarkDestroyed() noexcept { destroyed_.store(true, std::memory_order_release); }
            /**
             * @brief Re-arms a destroyed pool for reuse (only InitPools after
             *        ShutdownPools; the arena is still allocated).
             */
            void ResetDestroyed() noexcept { destroyed_.store(false, std::memory_order_release); }
            /**
             * @brief Returns a batch of blocks to the global free list.
             * @param payloads Block payloads to return.
             * @param count Number of blocks.
             */
            void FlushToGlobal(Byte* const* payloads, UInt32 count) noexcept;

        private:
            Byte*                   arena_       = NULLPTR;
            std::atomic<void*>      free_list_   = NULLPTR;
            std::atomic<UInt32>     free_count_  = 0;
            UInt32                  block_size_  = 0;
            UInt32                  block_count_ = 0;
            UInt32                  index_       = 0;   /**< Pool tier index */
            std::atomic<bool>       destroyed_   = false;  /**< Set by ShutdownPools: stop all Acquire/Release writes */
            mutable std::mutex      sync_;       /**< Serializes global list access */
            friend struct BufPoolLocal;  // per-thread cache access
        };

        /**
         * @brief Reference-counted packet buffer (zero-copy, movable).
         */
        class BufRef {
        public:
            BufRef() noexcept = default;
            // No virtual dtor: BufRef is never derived from (no polymorphic
            // use; BufPool is a separate class) - dropping the vtable saves a
            // vptr per object and an indirect call per destruction on the
            // per-packet hot path. Deliberately not 'final' - the absence of
            // virtuals makes the dtor non-polymorphic by construction.
            ~BufRef() noexcept;
            BufRef(const BufRef&) = delete;
            BufRef& operator=(const BufRef&) = delete;
            BufRef(BufRef&& other) noexcept;
            BufRef& operator=(BufRef&& other) noexcept;

            /**
             * @brief Acquires a buffer from the tiered pools.
             * @param min_size Minimum payload bytes required.
             * @return BufRef owning a buffer, or empty when pools exhausted.
             */
            static BufRef Acquire(UInt32 min_size) noexcept;
            /**
             * @brief Creates a shared handle (increments the refcount).
             * @note Payload bytes are shared, never copied.
             */
            BufRef Clone() noexcept {
                BufRef copy;
                copy.pool_ = pool_;
                copy.refs_ = refs_;
                copy.data_ = data_;
                copy.capacity_ = capacity_;
                copy.len_ = len_;
                copy.meta_ = meta_;
                if (NULLPTR != refs_) {
                    // relaxed: incrementing a refcount needs no release/acquire
                    // ordering — only the decrement that reaches zero (Unref's
                    // acq_rel fetch_sub) must synchronize with the pool return.
                    // Matches Ref()'s relaxed increment (bufref.cpp). Calling
                    // constraint: Clone()/Ref()/Unref() on a shared handle must
                    // never race with the last Unref(), or the block may already
                    // be back in the pool (use-after-free).
                    refs_->fetch_add(1, std::memory_order_relaxed);
                }
                return copy;
            }
            /**
             * @brief Increments the reference count.
             */
            void Ref() noexcept;
            /**
             * @brief Decrements; returns the block to its pool at zero.
             */
            void Unref() noexcept;
            /**
             * @brief Payload pointer.
             */
            Byte* Data() noexcept { return data_; }
            /**
             * @brief Payload pointer (const view).
             */
            const Byte* Data() const noexcept { return data_; }
            /**
             * @brief Payload capacity in bytes.
             */
            UInt32 Capacity() const noexcept { return capacity_; }
            /**
             * @brief Logical payload length.
             */
            UInt32 Len() const noexcept { return len_; }
            /**
             * @brief Sets the logical payload length.
             */
            void SetLen(UInt32 len) noexcept { len_ = (len <= capacity_) ? len : capacity_; }
            /**
             * @brief Current reference count.
             */
            UInt32 UseCount() const noexcept;
            /**
             * @brief GSO metadata (valid when segs > 0).
             */
            SegMeta& Meta() noexcept { return meta_; }
            /**
             * @brief GSO metadata (const view).
             */
            const SegMeta& Meta() const noexcept { return meta_; }
            /**
             * @brief True when this ref owns no buffer.
             */
            bool IsEmpty() const noexcept { return NULLPTR == data_; }

        private:
            static BufRef AcquireFrom(BufPool& pool, Byte* payload) noexcept;
            void Release() noexcept;

            BufPool*    pool_     = NULLPTR;
            std::atomic<UInt32>* refs_ = NULLPTR;
            Byte*       data_     = NULLPTR;
            UInt32      capacity_ = 0;
            UInt32      len_      = 0;
            SegMeta     meta_;
        };

        /**
         * @brief Default packet buffer tiers: 2KB / 4KB / 32KB.
         */
        void InitPools() noexcept;
        /**
         * @brief Marks all tiered pools destroyed and returns this thread's
         *        cached blocks. The arenas are NOT freed here (freeing them
         *        concurrently with a peer thread's Acquire/Release is a
         *        use-after-free window); the PoolRegistry's static destructor
         *        frees every pool at process exit. After this call Acquire
         *        returns empty and Release drops blocks.
         */
        void ShutdownPools() noexcept;
    }
}

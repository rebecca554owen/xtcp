#pragma once

/**
 * @file mempool.h
 * @brief Per-core fixed-block memory pool (single-threaded, no locks).
 */

#include <xtcp/stdafx.h>

#include <vector>

namespace xtcp {
    namespace core {
        /**
         * @brief Fixed-size block pool with free-list.
         * @note Single-shard only: not thread-safe by design.
         */
        class Mempool {
        public:
            /**
             * @brief Constructs a pool.
             * @param block_size Bytes per block (>= 16).
             * @param block_count Number of preallocated blocks.
             */
            Mempool(UInt32 block_size, UInt32 block_count) noexcept;
            ~Mempool() noexcept;
            Mempool(const Mempool&) = delete;
            Mempool& operator=(const Mempool&) = delete;
            Mempool(Mempool&&) = delete;
            Mempool& operator=(Mempool&&) = delete;
            /**
             * @brief Allocates one block.
             * @return Block pointer or NULLPTR when exhausted.
             */
            void* Alloc() noexcept;
            /**
             * @brief Returns a block to the pool.
             * @param ptr Block previously returned by Alloc().
             * @note Defensive: foreign/unowned pointers (outside the arena or
             *       misaligned) and double-free past capacity are rejected
             *       without touching the free-list (O(1) range+alignment check).
             */
            void Free(void* ptr) noexcept;
            /**
             * @brief Total block capacity (fixed).
             */
            UInt32 Capacity() const noexcept { return block_count_; }
            /**
             * @brief Blocks currently on the free list.
             */
            UInt32 FreeCount() const noexcept { return free_count_; }
            /**
             * @brief Bytes per block.
             */
            UInt32 BlockSize() const noexcept { return block_size_; }

        private:
            Byte*       arena_       = NULLPTR;
            void*       free_list_   = NULLPTR;
            UInt32      block_size_  = 0;
            UInt32      block_count_ = 0;
            UInt32      free_count_  = 0;
            std::vector<Byte> in_use_;  /**< 1 = block allocated (not on free list) */
        };
    }
}

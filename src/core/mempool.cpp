/**
 * @file mempool.cpp
 * @brief Fixed-block pool implementation.
 */

#include <xtcp/core/mempool.h>

#include <cassert>

namespace xtcp {
    namespace core {
        Mempool::Mempool(UInt32 block_size, UInt32 block_count) noexcept
            : block_size_(block_size), block_count_(block_count) {
            if (16 > block_size) {
                block_size_ = 16;
            }
            // Alignment contract: the free list stores void* inside every
            // block and callers may use blocks for SIMD (16-byte) data. Round
            // the stride up to a multiple of 16 so every block starts
            // 16-aligned (arena_ from xtcp::Malloc is 16-aligned) and the
            // pointer store is always aligned (D8: verify before mutate).
            block_size_ = (block_size_ + 15u) & ~15u;
            arena_ = static_cast<Byte*>(xtcp::Malloc(static_cast<UInt64>(block_size_) * block_count_));
            if (NULLPTR == arena_) {
                block_count_ = 0;
                in_use_.clear();
                return;
            }
            in_use_.assign(block_count_, 0);
            for (UInt32 i = 0; i < block_count_; ++i) {
                Byte* block = arena_ + static_cast<UInt64>(block_size_) * i;
                *reinterpret_cast<void**>(block) = free_list_;
                free_list_ = block;
                ++free_count_;
            }
        }

        Mempool::~Mempool() noexcept {
            xtcp::Mfree(arena_);
            arena_ = NULLPTR;
            free_list_ = NULLPTR;
        }

        void* Mempool::Alloc() noexcept {
            if (NULLPTR == free_list_) {
                return NULLPTR;
            }
            void* block = free_list_;
            free_list_ = *reinterpret_cast<void**>(block);
            --free_count_;
            const UInt64 off = reinterpret_cast<UInt64>(block) - reinterpret_cast<UInt64>(arena_);
            in_use_[static_cast<UInt32>(off / block_size_)] = 1;
            return block;
        }

        void Mempool::Free(void* ptr) noexcept {
            if (NULLPTR == ptr) {
                return;
            }
            const UInt64 addr = reinterpret_cast<UInt64>(ptr);
            const UInt64 base = reinterpret_cast<UInt64>(arena_);
            const UInt64 bytes = static_cast<UInt64>(block_size_) * block_count_;
            bool owned = false;
            if (addr >= base) {
                const UInt64 off = addr - base;
                owned = (off < bytes) && (0 == off % block_size_);
            }
            if (!owned) {
                assert(false);
                return;
            }
            const UInt32 index = static_cast<UInt32>((addr - base) / block_size_);
            if (0 == in_use_[index]) {
                // Block not currently allocated: double free or foreign block.
                assert(false);
                return;
            }
            // Verify-then-mutate (D8): the corruption guard must run BEFORE
            // marking the block free - otherwise a tripped guard leaves the
            // block marked free but never on the free list (permanently
            // lost).
            if (free_count_ >= block_count_) {
                assert(false);
                return;
            }
            in_use_[index] = 0;
            *reinterpret_cast<void**>(ptr) = free_list_;
            free_list_ = ptr;
            ++free_count_;
        }
    }
}

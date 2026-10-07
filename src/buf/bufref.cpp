/**
 * @file bufref.cpp
 * @brief Zero-copy buffer pool implementation.
 */

#include <xtcp/buf/bufref.h>

namespace xtcp {
    namespace buf {
        namespace {
            constexpr UInt32 kPoolCount = 3;
            BufPool* g_pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
            constexpr UInt32 kPoolSizes[kPoolCount] = { 2048, 4096, 32768 };
            // The small tiers carry ordinary TCP packets and their retransmit
            // references. A 4-flow, 1 MiB-per-flow test can retain >2,500 MSS
            // buffers at once, so the previous 1,536 small blocks exhausted
            // both tiers and converted ACK ingress into packet loss. Keep the
            // large-GRO tier bounded independently; the small tiers provide
            // enough packet capacity for the configured send-buffer envelope.
            constexpr UInt32 kPoolBlocks[kPoolCount] = { 8192, 4096, 128 };

            // Pool lifetime: pools are created by InitPools and are NEVER
            // freed by ShutdownPools. A concurrent Acquire/Release running on
            // another thread has no lock-free way to prove the pool is still
            // alive (the IsDestroyed check at Acquire entry is a TOCTOU vs
            // the shutdown delete), so freeing the arena at shutdown is a
            // use-after-free risk for exactly that window. Instead the
            // registry below owns every pool and frees them in its static
            // destructor (process exit) - LSan stays clean, and no thread can
            // ever touch a freed arena. ShutdownPools only marks the pools
            // destroyed (Acquire returns empty, Release drops blocks) and
            // resets the TLS caches; InitPools re-arms a destroyed pool on
            // re-init.
            struct PoolRegistry {
                BufPool* pools[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
                ~PoolRegistry() noexcept {
                    for (UInt32 i = 0; i < kPoolCount; ++i) {
                        delete pools[i];
                    }
                }
            };
            PoolRegistry g_registry;

            // Per-thread cache cap per tier. BufPoolLocal::blocks is sized to
            // the largest cap (kLocalCapMax) so a single constant array works.
            // tier-2 (32KB) has only 128 blocks: a per-thread hoard of 16
            // lets >=8 threads starve the global free list, so its cap is
            // scaled down to 4 while tier-0 keeps 16.
            constexpr UInt32 kLocalCapMax = 16;
            // Per-thread cache cap per tier. tier-2 (32KB) hoarding is the
            // starvation root cause: only 128 blocks exist, and with any
            // nonzero cap >=32 threads can hoard the WHOLE pool in their
            // private caches while other threads see an empty global free
            // list (Acquire returns empty = silent packet loss). Cap 0
            // disables hoarding for tier-2 entirely: every release returns
            // the block to the global list immediately, so any thread can
            // reuse it. The cost is one extra atomic per large-buffer
            // release/acquire (rare - 32KB blocks) versus a structural
            // cross-thread starvation.
            constexpr UInt32 kLocalCaps[kPoolCount] = { 16, 8, 0 };

            /**
             * @brief Per-thread block cache: most Acquire/Release never touch
             *        the shared free list, eliminating cross-core contention.
             */
            struct BufPoolLocal {
                BufPool* pool[kPoolCount] = { NULLPTR, NULLPTR, NULLPTR };
                Byte*    blocks[kPoolCount][kLocalCapMax];
                UInt32   count[kPoolCount] = { 0, 0, 0 };

                Byte* Take(UInt32 idx) noexcept {
                    if (0 < count[idx]) {
                        return blocks[idx][--count[idx]];
                    }
                    return NULLPTR;
                }
                void Put(BufPool* p, UInt32 idx, Byte* payload) noexcept {
                    // After ShutdownPools marks a pool destroyed, no thread
                    // may write blocks back into it (the arena may be freed).
                    // Drop the block instead; the leak is bounded by shutdown.
                    if (p->IsDestroyed()) {
                        return;
                    }
                    if (0 == kLocalCaps[idx]) {
                        // No-hoarding tier (tier-2): return straight to the
                        // global free list so released blocks are visible to
                        // every thread (starvation root fix).
                        p->FlushToGlobal(&payload, 1);
                        return;
                    }
                    if (kLocalCaps[idx] <= count[idx]) {
                        p->FlushToGlobal(blocks[idx], count[idx]);
                        count[idx] = 0;
                    }
                    blocks[idx][count[idx]++] = payload;
                }
                ~BufPoolLocal() noexcept {
                    for (UInt32 i = 0; i < kPoolCount; ++i) {
                        if (NULLPTR != pool[i] && 0 < count[i]) {
                            // Skip destroyed pools: their arena may already be
                            // freed, so flushing would be a use-after-free.
                            if (pool[i]->IsDestroyed()) {
                                count[i] = 0;
                                pool[i] = NULLPTR;
                                continue;
                            }
                            pool[i]->FlushToGlobal(blocks[i], count[i]);
                            count[i] = 0;
                        }
                    }
                }
            };
            thread_local BufPoolLocal t_local;
        }

        BufPool::BufPool(UInt32 block_size, UInt32 block_count) noexcept
            : block_size_(block_size), block_count_(block_count) {
            if (kHeaderBytes > block_size_) {
                block_size_ = kHeaderBytes;
            }
            // Assign the tier index by block size (matches kPoolSizes order).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (block_size == kPoolSizes[i]) {
                    index_ = i;
                    break;
                }
            }
            arena_ = static_cast<Byte*>(xtcp::Malloc(static_cast<UInt64>(block_size_) * block_count_));
            if (NULLPTR == arena_) {
                block_count_ = 0;
                return;
            }
            void* head = NULLPTR;
            for (UInt32 i = 0; i < block_count_; ++i) {
                Byte* block = arena_ + static_cast<UInt64>(block_size_) * i;
                *reinterpret_cast<void**>(block) = head;
                head = block;
            }
            free_list_.store(head, std::memory_order_relaxed);
            free_count_.store(block_count_, std::memory_order_relaxed);
        }

        BufPool::~BufPool() noexcept {
            xtcp::Mfree(arena_);
            arena_ = NULLPTR;
        }

        Byte* BufPool::Acquire() noexcept {
            // No acquisitions after ShutdownPools: the pool may be freed.
            if (IsDestroyed()) {
                return NULLPTR;
            }
            // Fast path: per-thread cache (lock-free). The slot is tier-
            // indexed, so only use it when THIS pool owns the cached blocks
            // - a second pool sharing the tier (user-created pools with a
            // matching block size) must never receive another pool's blocks.
            if (t_local.pool[index_] == this) {
                if (Byte* payload = t_local.Take(index_)) {
                    Byte* block = payload - kHeaderBytes;
                    *reinterpret_cast<BufPool**>(block) = this;
                    *reinterpret_cast<std::atomic<UInt32>*>(block + sizeof(void*)) = 1;
                    return payload;
                }
            }
            // Slow path: shared free list (mutex-serialized, ABA-safe).
            std::lock_guard<std::mutex> scope(sync_);
            void* block = free_list_.load(std::memory_order_relaxed);
            if (NULLPTR == block) {
                return NULLPTR;
            }
            free_list_.store(*reinterpret_cast<void**>(block), std::memory_order_relaxed);
            free_count_.fetch_sub(1, std::memory_order_relaxed);
            Byte* payload = static_cast<Byte*>(block) + kHeaderBytes;
            *reinterpret_cast<BufPool**>(block) = this;
            *reinterpret_cast<std::atomic<UInt32>*>(static_cast<Byte*>(block) + sizeof(void*)) = 1;
            return payload;
        }

        void BufPool::Release(Byte* payload) noexcept {
            // Fast path: cache locally (lock-free), flush in batches. Only
            // when THIS pool already owns the tier slot - a slot owned by a
            // different pool holds that pool's blocks, and caching ours
            // there would let a later flush push foreign blocks into our
            // global free list (cross-pool corruption).
            if (t_local.pool[index_] == this) {
                t_local.Put(this, index_, payload);
                return;
            }
            if (NULLPTR == t_local.pool[index_]) {
                t_local.pool[index_] = this;
                t_local.Put(this, index_, payload);
                return;
            }
            // Slot owned by another pool sharing this tier: bypass the
            // cache entirely and return straight to the global free list.
            FlushToGlobal(&payload, 1);
        }

        void BufPool::FlushToGlobal(Byte* const* payloads, UInt32 count) noexcept {
            std::lock_guard<std::mutex> scope(sync_);
            for (UInt32 i = 0; i < count; ++i) {
                Byte* block = payloads[i] - kHeaderBytes;
                *reinterpret_cast<void**>(block) = free_list_.load(std::memory_order_relaxed);
                free_list_.store(block, std::memory_order_relaxed);
            }
            free_count_.fetch_add(count, std::memory_order_relaxed);
        }

        BufRef::BufRef(BufRef&& other) noexcept {
            pool_ = other.pool_;
            refs_ = other.refs_;
            data_ = other.data_;
            capacity_ = other.capacity_;
            len_ = other.len_;
            meta_ = other.meta_;
            other.pool_ = NULLPTR;
            other.refs_ = NULLPTR;
            other.data_ = NULLPTR;
            other.capacity_ = 0;
            other.len_ = 0;
            other.meta_ = SegMeta();
        }

        BufRef& BufRef::operator=(BufRef&& other) noexcept {
            if (this != &other) {
                Unref();  // release this handle's reference first
                pool_ = other.pool_;
                refs_ = other.refs_;
                data_ = other.data_;
                capacity_ = other.capacity_;
                len_ = other.len_;
                meta_ = other.meta_;
                other.pool_ = NULLPTR;
                other.refs_ = NULLPTR;
                other.data_ = NULLPTR;
                other.capacity_ = 0;
                other.len_ = 0;
                other.meta_ = SegMeta();
            }
            return *this;
        }

        BufRef::~BufRef() noexcept {
            Unref();  // shared handles must not release the block until zero
        }

        BufRef BufRef::Acquire(UInt32 min_size) noexcept {
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                BufPool* pool = g_pools[i];
                if (NULLPTR == pool) {
                    continue;
                }
                if ((pool->BlockSize() - kHeaderBytes) >= min_size) {
                    Byte* payload = pool->Acquire();
                    if (NULLPTR != payload) {
                        return AcquireFrom(*pool, payload);
                    }
                }
            }
            return BufRef();
        }

        BufRef BufRef::AcquireFrom(BufPool& pool, Byte* payload) noexcept {
            BufRef ref;
            ref.pool_ = &pool;
            ref.data_ = payload;
            ref.capacity_ = pool.BlockSize() - kHeaderBytes;
            ref.len_ = 0;
            ref.refs_ = reinterpret_cast<std::atomic<UInt32>*>(payload - kHeaderBytes + sizeof(void*));
            return ref;
        }

        void BufRef::Ref() noexcept {
            if (NULLPTR != refs_) {
                refs_->fetch_add(1, std::memory_order_relaxed);
            }
        }

        void BufRef::Unref() noexcept {
            if (NULLPTR != refs_) {
                if (1 == refs_->fetch_sub(1, std::memory_order_acq_rel)) {
                    Release();
                }
            }
        }

        void BufRef::Release() noexcept {
            if (NULLPTR != data_) {
                pool_->Release(data_);
            }
            pool_ = NULLPTR;
            refs_ = NULLPTR;
            data_ = NULLPTR;
            capacity_ = 0;
            len_ = 0;
            meta_ = SegMeta();  // match the move semantics: no stale GSO metadata on an empty handle
        }

        UInt32 BufRef::UseCount() const noexcept {
            if (NULLPTR == refs_) {
                return 0;
            }
            return refs_->load(std::memory_order_relaxed);
        }

        void InitPools() noexcept {
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR == g_pools[i]) {
                    BufPool* p = new (std::nothrow) BufPool(kPoolSizes[i], kPoolBlocks[i]);
                    g_pools[i] = p;
                    g_registry.pools[i] = p;
                } else if (g_pools[i]->IsDestroyed()) {
                    // Re-init after ShutdownPools: re-arm the same pool
                    // (its arena is still allocated - the registry frees it
                    // at process exit).
                    g_pools[i]->ResetDestroyed();
                }
            }
        }

        void ShutdownPools() noexcept {
            // Step 1: mark every pool destroyed BEFORE any frees. From this
            // point any Acquire returns empty and any Release/thread-cache
            // flush drops blocks instead of writing to a pool that may be
            // freed (Bug 2: other threads' caches and outstanding BufRefs
            // must never touch a freed arena).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR != g_pools[i]) {
                    g_pools[i]->MarkDestroyed();
                }
            }
            // Step 2: return this thread's cached blocks to their pools'
            // global free lists (safe: the pools are still allocated here).
            for (UInt32 i = 0; i < kPoolCount; ++i) {
                if (NULLPTR != t_local.pool[i] && 0 < t_local.count[i]) {
                    t_local.pool[i]->FlushToGlobal(t_local.blocks[i], t_local.count[i]);
                    t_local.count[i] = 0;
                    t_local.pool[i] = NULLPTR;
                }
            }
            // Step 3: the pools are NOT freed here (see the PoolRegistry
            // note above): freeing the arena while another thread may be
            // mid-Acquire/Release is a use-after-free (the IsDestroyed check
            // at Acquire entry is a TOCTOU vs this delete). The registry's
            // static destructor frees every pool at process exit, keeping
            // LSan clean without any concurrency window.
        }
    }
}

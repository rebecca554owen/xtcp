/**
 * @file zc_probe.cpp
 * @brief Zero-copy probe counters.
 */

#include <xtcp/zc/zc_probe.h>

#if defined(memcpy)
#undef memcpy
#endif

namespace xtcp {
    namespace zc {
        std::atomic<UInt64> g_memcpy_count = 0;
        std::atomic<UInt64> g_memcpy_bytes = 0;

        void Reset() noexcept {
            g_memcpy_count.store(0, std::memory_order_relaxed);
            g_memcpy_bytes.store(0, std::memory_order_relaxed);
        }

        UInt64 Count() noexcept { return g_memcpy_count.load(std::memory_order_relaxed); }
        UInt64 Bytes() noexcept { return g_memcpy_bytes.load(std::memory_order_relaxed); }

        void* CountedMemcpy(void* dst, const void* src, UInt64 n) noexcept {
            if (0 != n) {
                g_memcpy_count.fetch_add(1, std::memory_order_relaxed);
                g_memcpy_bytes.fetch_add(n, std::memory_order_relaxed);
            }
            return std::memcpy(dst, src, static_cast<size_t>(n));
        }
    }
}

void* xtcp_zc_memcpy(void* dst, const void* src, UInt64 n) noexcept {
    return xtcp::zc::CountedMemcpy(dst, src, n);
}

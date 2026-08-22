#pragma once

/**
 * @file zc_probe.h
 * @brief Zero-copy probe: counted memcpy interposition for ZC gate asserts.
 *
 * When XTCP_ZC_PROBE is defined, unqualified memcpy in instrumented
 * translation units routes through xtcp_zc_memcpy which counts calls and
 * bytes. The gate asserts zero copies on hot data-plane paths.
 *
 * Interposition limitation: a function-like macro cannot distinguish
 * qualified from unqualified spellings, so ONLY bare memcpy is rewritten.
 * `std::memcpy` becomes `std::xtcp_zc_memcpy` (a nonexistent symbol) and
 * fails to compile. Instrumented TUs MUST use bare unqualified memcpy and
 * never the `std::` prefix; xtcp_zc_memcpy is declared at global scope so
 * bare calls resolve.
 */

#include <xtcp/stdafx.h>

#include <atomic>
#include <cstring>

namespace xtcp {
    namespace zc {
        /**
         * @brief Counters maintained by the probe.
         */
        extern std::atomic<UInt64> g_memcpy_count;
        extern std::atomic<UInt64> g_memcpy_bytes;

        /**
         * @brief Resets both counters to zero.
         */
        void Reset() noexcept;
        /**
         * @brief Returns the total number of counted memcpy calls.
         */
        UInt64 Count() noexcept;
        /**
         * @brief Returns the total number of counted copied bytes.
         */
        UInt64 Bytes() noexcept;
        /**
         * @brief Counted memcpy (probe entry).
         */
        void* CountedMemcpy(void* dst, const void* src, UInt64 n) noexcept;
    }
}

#if defined(XTCP_ZC_PROBE)
void* xtcp_zc_memcpy(void* dst, const void* src, UInt64 n) noexcept;
#define memcpy xtcp_zc_memcpy
#endif

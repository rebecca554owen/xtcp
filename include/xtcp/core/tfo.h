#pragma once

/**
 * @file tfo.h
 * @brief TCP Fast Open (RFC 7413) cookie management: server-side cookie
 *        generation/verification keyed by the peer address and a per-process
 *        secret.
 */

#include <xtcp/stdafx.h>

namespace xtcp {
    namespace core {
        constexpr UInt32 kTfoCookieLen = 8;  /**< Server-generated cookie size (bytes) */
        constexpr UInt32 kTfoMinCookieLen = 4;   /**< RFC 7413: minimum peer cookie size (bytes) */
        constexpr UInt32 kTfoMaxCookieLen = 16;  /**< RFC 7413: maximum peer cookie size (bytes) */
        constexpr UInt32 kTfoMaxEarlyData = 16384;  /**< RFC 7413 4.3.3: server-side SYN-carried early-data cap (bytes) */

        /**
         * @brief TFO cookie generator/verifier.
         */
        class TfoCookie {
        public:
            TfoCookie() noexcept;

            /**
             * @brief Generates a cookie for a peer address.
             * @param addr Peer address (family-normalized 32-bit words).
             * @param out  8-byte cookie buffer.
             */
            void Generate(const UInt32 addr[4], Byte out[kTfoCookieLen]) const noexcept;
            /**
             * @brief Verifies a cookie.
             * @param addr Peer address.
             * @param cookie 8-byte cookie.
             * @return True when valid.
             */
            bool Check(const UInt32 addr[4], const Byte cookie[kTfoCookieLen]) const noexcept;

        private:
            UInt64 Hash(const UInt32 addr[4], UInt64 time_disc) const noexcept;

            UInt64 secret_;
        };
    }
}

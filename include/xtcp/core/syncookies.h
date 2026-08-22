#pragma once

/**
 * @file syncookies.h
 * @brief SYN cookies (RFC 4987): stateless SYN flood defense. The listener
 *        encodes the MSS into the ISN when the SYN queue overflows; the
 *        returning ACK carries the cookie, verified without any state.
 */

#include <xtcp/stdafx.h>

namespace xtcp {
    namespace core {
        /**
         * @brief SYN cookie encoder/verifier (stateless).
         * @note Cookie layout [31..27] 5 hash bits, [26..3] 24 bits of
         *       (hash XOR rolling time), [2..0] MSS index. The time never
         *       displaces the verified hash bits; effective per-attempt
         *       forgery probability is 2^-5 (hash bits) x the 60 s
         *       freshness window 60/2^24 (~2^-18) = ~2^-23, NOT the 29-bit
         *       "hash width" (the other 24 hash bits are hidden under the
         *       time XOR, not verified). The secret is 128 bits from the OS
         *       CSPRNG, so extracting it from captured cookies is infeasible.
         */
        class Syncookies {
        public:
            Syncookies() noexcept;

            /**
             * @brief Computes a cookie for a SYN.
             * @param saddr Source address.
             * @param daddr Destination address.
             * @param sport Source port.
             * @param dport Destination port.
             * @param seq   Peer SYN sequence number.
             * @param time_sec Monotonic seconds (rolling).
             * @param mss_index MSS table index (0-7).
             * @return Cookie value (the ISN to use for SYN+ACK).
             */
            UInt32 Compute(UInt32 saddr, UInt32 daddr, UInt16 sport, UInt16 dport,
                           UInt32 seq, UInt32 time_sec, Byte mss_index) noexcept;
            /**
             * @brief Computes a cookie for a SYN (full 128-bit addresses).
             * @param saddr[4] Source address (all 4 IPv6 words folded into the
             *        hash; IPv4 stores its address in word 0, rest zero).
             * @param daddr[4] Destination address.
             * @note Hashing only addr[0] let IPv6 peers sharing the same /32
             *       prefix collide on identical (ports, seq) cookies; the
             *       full 4-word fold (mirror of scheduler_hash::HashFlowKey)
             *       removes that forgery surface.
             */
            UInt32 Compute(const UInt32 saddr[4], const UInt32 daddr[4], UInt16 sport, UInt16 dport,
                           UInt32 seq, UInt32 time_sec, Byte mss_index) noexcept;
            /**
             * @brief Verifies an ACK's cookie.
             * @param cookie  ISN from the SYN+ACK (cookie).
             * @param ack_seq The ACK sequence (must be cookie + 1).
             * @param saddr/daddr/sport/dport/seq Same as Compute.
             * @param time_sec Current monotonic seconds.
             * @param window_sec Acceptable age window.
             * @param mss_index Receives the decoded MSS index (out).
             * @return True when the cookie is valid and fresh.
             */
            bool Verify(UInt32 cookie, UInt32 ack_seq, UInt32 saddr, UInt32 daddr,
                        UInt16 sport, UInt16 dport, UInt32 seq, UInt32 time_sec,
                        UInt32 window_sec, Byte& mss_index) noexcept;
            /**
             * @brief Verifies an ACK's cookie (full 128-bit addresses).
             * @param saddr[4] Source address (all 4 IPv6 words).
             * @param daddr[4] Destination address.
             */
            bool Verify(UInt32 cookie, UInt32 ack_seq, const UInt32 saddr[4], const UInt32 daddr[4],
                        UInt16 sport, UInt16 dport, UInt32 seq, UInt32 time_sec,
                        UInt32 window_sec, Byte& mss_index) noexcept;

        private:
            /** @brief Folds a 128-bit address into one word via the h*31
             *         polynomial (mirror of scheduler_hash::HashFlowKey). */
            static UInt32 FoldAddr(const UInt32 addr[4]) noexcept;
            UInt32 Hash(UInt32 saddr, UInt32 daddr, UInt16 sport, UInt16 dport,
                        UInt32 seq) const noexcept;

            UInt64 secret_[2];  /**< 128-bit CSPRNG secret (see syncookies.cpp) */
        };
    }
}

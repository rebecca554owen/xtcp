#pragma once

/**
 * @file ip.h
 * @brief IPv4/IPv6 header parsing, checksums (RFC 1071/1624), fragmentation
 *        reassembly (RFC 791 / RFC 8200).
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>

#include <array>
#include <map>
#include <unordered_map>

namespace xtcp {
    namespace core {
        /**
         * @brief Parsed IPv4 header.
         */
        struct Ip4Hdr {
            UInt32  src         = 0;    /**< Source address (network order) */
            UInt32  dst         = 0;    /**< Destination address (network order) */
            Byte    proto       = 0;    /**< Next protocol (6 TCP, 17 UDP) */
            UInt16  payload_off = 0;    /**< Offset of the payload in the packet */
            UInt16  hdr_len     = 0;    /**< IP header length */
            UInt16  total_len   = 0;    /**< IP total length */
            UInt16  id          = 0;    /**< Identification (fragmentation) */
            UInt16  frag_off    = 0;    /**< Fragment offset (8-byte units) */
            Byte    flags       = 0;    /**< MF/DF flags */
        };

        /**
         * @brief Parsed IPv6 header (with basic extension header skipping).
         */
        struct Ip6Hdr {
            UInt32  src[4]      = { 0, 0, 0, 0 };  /**< Source address (network order) */
            UInt32  dst[4]      = { 0, 0, 0, 0 };  /**< Destination address (network order) */
            Byte    proto       = 0;               /**< Final next-header protocol */
            UInt16  payload_off = 0;               /**< Offset of the payload */
            UInt16  hdr_len     = 0;               /**< IPv6 header + extension headers */
            UInt16  payload_len = 0;               /**< IPv6 payload length */
            UInt32  frag_id     = 0;               /**< Fragment identification (0 when not a fragment) */
            UInt16  frag_off    = 0;               /**< Fragment offset (8-byte units) */
            Byte    frag_more   = 0;               /**< More-fragments flag */
        };

        /**
         * @brief Computes the Internet checksum (RFC 1071).
         * @param data Buffer to checksum.
         * @param len  Length in bytes.
         * @return One's-complement checksum (host order).
         * @note Bit-identical to ChecksumScalar on every input. On CPUs with
         *       SSSE3 a vectorized accumulation runs (pshufb + 32-bit lane
         *       folds); otherwise the scalar path. Addition is commutative,
         *       so any accumulation order yields the same folded result.
         */
        UInt16 Checksum(const void* data, UInt32 len) noexcept;
        /**
         * @brief Scalar RFC 1071 checksum (reference implementation; used by
         *        the differential tests and as the no-SIMD fallback).
         */
        UInt16 ChecksumScalar(const void* data, UInt32 len) noexcept;
        /**
         * @brief True when the CPU has SSSE3 (pshufb), i.e. the vectorized
         *        checksum path is safe. Cached per process (benign race).
         */
        bool CpuHasSsse3() noexcept;
        /**
         * @brief Incremental checksum update (RFC 1624).
         * @param old_sum  Previous checksum.
         * @param old_word Old 16-bit word at the changed location.
         * @param new_word New 16-bit word.
         * @return Updated checksum.
         */
        UInt16 ChecksumDelta(UInt16 old_sum, UInt16 old_word, UInt16 new_word) noexcept;

        /**
         * @brief Parses an IPv4 header.
         * @param data Packet bytes.
         * @param len  Packet length.
         * @param out  Filled on success.
         * @return True when the header is valid and fits the packet.
         */
        bool ParseIp4(const Byte* data, UInt32 len, Ip4Hdr& out) noexcept;
        /**
         * @brief Parses an IPv6 header (skipping basic extension headers).
         * @param data Packet bytes.
         * @param len  Packet length.
         * @param out  Filled on success.
         * @return True when the header is valid and fits the packet.
         */
        bool ParseIp6(const Byte* data, UInt32 len, Ip6Hdr& out) noexcept;

        /**
         * @brief Parsed ICMPv4 "fragmentation needed" error (RFC 1191).
         */
        struct IcmpFragNeeded {
            bool     valid = false;
            UInt16   mtu   = 0;       /**< Next-hop MTU announced by the router */
            Byte     family = 4;
            UInt32   src_addr[4] = { 0, 0, 0, 0 };  /**< Original packet's source (our endpoint) */
            UInt16   src_port = 0;
            UInt32   dst_addr[4] = { 0, 0, 0, 0 };  /**< Original packet's destination (peer) */
            UInt16   dst_port = 0;
        };

        /**
         * @brief Parses an ICMPv4 destination-unreachable/fragmentation-needed
         *        message and extracts the embedded original TCP endpoints.
         * @param data ICMP packet bytes (starting at the IPv4 header).
         * @param len  Packet length.
         * @param out  Filled on success (valid=true for type 3 code 4).
         * @return True when the ICMP message parsed.
         */
        bool ParseIcmpFragNeeded(const Byte* data, UInt32 len, IcmpFragNeeded& out) noexcept;

        /**
         * @brief Reassembly key (IPv4 id or IPv6 frag id + addresses).
         */
        struct FragKey {
            Byte    version  = 0;   /**< 4 or 6 */
            Byte    proto    = 0;   /**< Upper-layer protocol (RFC 791 reassembly key) */
            UInt32  src[4]   = { 0, 0, 0, 0 };
            UInt32  dst[4]   = { 0, 0, 0, 0 };
            UInt32  id       = 0;
            bool operator==(const FragKey& rhs) const noexcept {
                return version == rhs.version && proto == rhs.proto && id == rhs.id &&
                       src[0] == rhs.src[0] && src[1] == rhs.src[1] &&
                       src[2] == rhs.src[2] && src[3] == rhs.src[3] &&
                       dst[0] == rhs.dst[0] && dst[1] == rhs.dst[1] &&
                       dst[2] == rhs.dst[2] && dst[3] == rhs.dst[3];
            }
        };

        /**
         * @brief Hash functor for FragKey (unordered_map support).
         *        Polynomial mix over every key field (version, proto, id,
         *        src[4], dst[4]) — mirrors FlowKeyHash (scheduler.h).
         */
        struct FragKeyHash {
            size_t operator()(const FragKey& key) const noexcept {
                UInt64 h = static_cast<UInt64>(key.version);
                h = h * 31 + key.proto;
                h = h * 31 + key.id;
                h = h * 31 + key.src[0];
                h = h * 31 + key.src[1];
                h = h * 31 + key.src[2];
                h = h * 31 + key.src[3];
                h = h * 31 + key.dst[0];
                h = h * 31 + key.dst[1];
                h = h * 31 + key.dst[2];
                h = h * 31 + key.dst[3];
                return static_cast<size_t>(h);
            }
        };

        /**
         * @brief One incoming fragment.
         */
        struct Fragment {
            UInt16          offset = 0;     /**< Offset in 8-byte units */
            bool            more   = false; /**< More-fragments flag */
            const Byte*     data   = NULLPTR;
            UInt32          len    = 0;
        };

        /**
         * @brief Fragment reassembly table with timeout expiry.
         * @note Reassembly concatenates fragments (unavoidable copy on the
         *       receive path; documented zero-copy exemption).
         */
        class IpFragTable {
        public:
            IpFragTable(UInt64 timeout_us, UInt32 max_sets) noexcept;
            virtual ~IpFragTable() noexcept;

            /**
             * @brief Adds one fragment.
             * @param now  Monotonic time (microseconds).
             * @param key  Reassembly key.
             * @param frag Fragment data (referenced only during the call).
             * @param out  On complete reassembly, the full payload; buffer
             *             must be released by the caller.
             * @return 1 complete (out valid), 0 pending, -1 error/discarded.
             */
            Int32 Add(UInt64 now, const FragKey& key, const Fragment& frag, buf::BufRef& out) noexcept;
            /**
             * @brief Expires sets idle longer than the timeout.
             * @param now Monotonic time.
             * @return Number of sets expired.
             */
            UInt32 Expire(UInt64 now) noexcept;
            /**
             * @brief Number of live reassembly sets (relaxed atomic: the
             *        caller uses it as a cheap "is the table empty" hint to
             *        skip the Expire lock on idle sweeps).
             */
            UInt32 SetCount() const noexcept { return set_count_.load(std::memory_order_relaxed); }
            /**
             * @brief Total datagrams successfully reassembled (monotonic,
             *        relaxed atomic: evidence that fragmentation occurred,
             *        for tests and diagnostics).
             */
            UInt64 ReassembledCount() const noexcept {
                return reassembled_total_.load(std::memory_order_relaxed);
            }

        private:
            struct FragSet;
            FragSet* FindSet(const FragKey& key) noexcept;
            FragSet* CreateSet(UInt64 now, const FragKey& key) noexcept;
            void DestroySet(FragSet* set) noexcept;

            UInt64  timeout_us_ = 0;
            UInt32  max_sets_   = 0;
            std::atomic<UInt32> set_count_ = 0;  /**< live reassembly sets */
            std::atomic<UInt64> reassembled_total_ = 0;  /**< completed datagrams */
            std::unordered_map<FragKey, FragSet*, FragKeyHash> sets_;  /**< key -> live reassembly set */
            std::map<std::array<UInt32, 5>, UInt32> src_counts_;  /**< per-(version,source) live-set count (anti-bomb cap, O(1) check) */
        };
    }
}

/**
 * @file ip.cpp
 * @brief IPv4/IPv6 parsing, checksums, fragmentation reassembly.
 */

#include <xtcp/core/ip.h>

#include <new>

#if defined(XTCP_X86)
    #if defined(_MSC_VER)
        #include <intrin.h>
        #include <immintrin.h>
    #elif defined(__GNUC__) || defined(__clang__)
        #include <immintrin.h>
        #include <cpuid.h>
    #endif
#endif
#if defined(XTCP_ARM) && defined(__ARM_NEON)
    #include <arm_neon.h>
#endif

namespace xtcp {
    namespace core {
        namespace {
            constexpr Byte kIpv4 = 4;
            constexpr Byte kIpv6 = 6;
            // Reassembly must fit one pool block to be deliverable: the
            // largest tier is 32768 bytes minus the 16-byte BufRef header
            // (bufref.cpp kPoolSizes / buf::kHeaderBytes). Cap reassembly to
            // that usable capacity; oversized datagrams are rejected.
            constexpr UInt32 kMaxPayload = 32768 - buf::kHeaderBytes;
            // Per-source in-flight reassembly group cap: bounds the memory a
            // single (possibly spoofed) source address can pin, independent of
            // the global max_sets_ total (fragment-bomb defense, RFC 791/8200).
            constexpr UInt32 kMaxSetsPerSource = 8;

            inline UInt16 Load16(const Byte* p) noexcept {
                return static_cast<UInt16>((static_cast<UInt16>(p[0]) << 8) | p[1]);
            }

            inline UInt32 Load32(const Byte* p) noexcept {
                return (static_cast<UInt32>(p[0]) << 24) |
                       (static_cast<UInt32>(p[1]) << 16) |
                       (static_cast<UInt32>(p[2]) << 8)  |
                       static_cast<UInt32>(p[3]);
            }
        }

        UInt16 ChecksumScalar(const void* data, UInt32 len) noexcept {
            const Byte* p = static_cast<const Byte*>(data);
            UInt64 sum = 0;
            UInt32 n = len;
            // 32-bit word accumulation halves the traversal (RFC 1071
            // permits any word width; the fold handles carries).
            while (4 <= n) {
                sum += Load32(p);
                p += 4;
                n -= 4;
            }
            while (1 < n) {
                sum += Load16(p);
                p += 2;
                n -= 2;
            }
            if (0 < n) {
                sum += static_cast<UInt16>(static_cast<UInt16>(p[0]) << 8);
            }
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return static_cast<UInt16>(~sum & 0xFFFF);
        }

#if defined(XTCP_X86) && (defined(__SSSE3__) || defined(__SSSE3) || defined(_MSC_VER))
        UInt16 ChecksumSimd(const void* data, UInt32 len) noexcept {
            // SSSE3 vectorized RFC 1071: pshufb reverses each 16-byte chunk
            // into 8 big-endian 16-bit words, zero-extended into 32-bit
            // accumulators (8 lanes). Addition is commutative/associative,
            // so the final fold matches the scalar path bit-for-bit.
            // Overflow: a 32-bit lane holds 65536 additions of a <=65535
            // word; the periodic drain (every 16 KiB) keeps lanes far below
            // 2^32 even for multi-MiB buffers, and the UInt64 sink cannot
            // overflow for any len <= 2^32.
            const Byte* p = static_cast<const Byte*>(data);
            __m128i acc_lo = _mm_setzero_si128();
            __m128i acc_hi = _mm_setzero_si128();
            static const __m128i kRev16 = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            UInt64 sum = 0;
            UInt32 n = len;
            while (32 <= n) {
                __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
                __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16));
                x = _mm_shuffle_epi8(x, kRev16);
                y = _mm_shuffle_epi8(y, kRev16);
                acc_lo = _mm_add_epi32(acc_lo, _mm_unpacklo_epi16(x, _mm_setzero_si128()));
                acc_lo = _mm_add_epi32(acc_lo, _mm_unpackhi_epi16(x, _mm_setzero_si128()));
                acc_hi = _mm_add_epi32(acc_hi, _mm_unpacklo_epi16(y, _mm_setzero_si128()));
                acc_hi = _mm_add_epi32(acc_hi, _mm_unpackhi_epi16(y, _mm_setzero_si128()));
                p += 32;
                n -= 32;
                if (0 == (n & 0x3FFF)) {
                    // Periodic drain: fold the accumulators into the 64-bit
                    // sink so no 32-bit lane can ever wrap (see above).
                    alignas(16) UInt32 lo[4];
                    alignas(16) UInt32 hi[4];
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(lo), acc_lo);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(hi), acc_hi);
                    for (UInt32 i = 0; i < 4; ++i) {
                        sum += static_cast<UInt64>(lo[i]) + hi[i];
                    }
                    acc_lo = _mm_setzero_si128();
                    acc_hi = _mm_setzero_si128();
                }
            }
            alignas(16) UInt32 lo[4];
            alignas(16) UInt32 hi[4];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(lo), acc_lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(hi), acc_hi);
            for (UInt32 i = 0; i < 4; ++i) {
                sum += static_cast<UInt64>(lo[i]) + hi[i];
            }
            // Tail: mirror the scalar 32/16/8-bit accumulation.
            while (4 <= n) {
                sum += Load32(p);
                p += 4;
                n -= 4;
            }
            while (1 < n) {
                sum += Load16(p);
                p += 2;
                n -= 2;
            }
            if (0 < n) {
                sum += static_cast<UInt16>(static_cast<UInt16>(p[0]) << 8);
            }
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return static_cast<UInt16>(~sum & 0xFFFF);
        }
#elif defined(XTCP_ARM) && defined(__ARM_NEON)
        UInt16 ChecksumNeon(const void* data, UInt32 len) noexcept {
            // NEON vectorized RFC 1071: vrev16q reverses bytes within each
            // 16-byte chunk for big-endian accumulation, zero-extended into
            // 32-bit accumulators (8 lanes). Same arithmetic as scalar path.
            const Byte* p = static_cast<const Byte*>(data);
            uint32x4_t acc_lo = vdupq_n_u32(0);
            uint32x4_t acc_hi = vdupq_n_u32(0);
            UInt64 sum = 0;
            UInt32 n = len;
            while (32 <= n) {
                uint8x16_t x = vld1q_u8(p);
                uint8x16_t y = vld1q_u8(p + 16);
                x = vrev16q_u8(x);
                y = vrev16q_u8(y);
                acc_lo = vaddq_u32(acc_lo, vmovl_u16(vget_low_u16(vreinterpretq_u16_u8(x))));
                acc_lo = vaddq_u32(acc_lo, vmovl_u16(vget_high_u16(vreinterpretq_u16_u8(x))));
                acc_hi = vaddq_u32(acc_hi, vmovl_u16(vget_low_u16(vreinterpretq_u16_u8(y))));
                acc_hi = vaddq_u32(acc_hi, vmovl_u16(vget_high_u16(vreinterpretq_u16_u8(y))));
                p += 32;
                n -= 32;
                if (0 == (n & 0x3FFF)) {
                    alignas(16) UInt32 lo[4];
                    alignas(16) UInt32 hi[4];
                    vst1q_u32(lo, acc_lo);
                    vst1q_u32(hi, acc_hi);
                    for (UInt32 i = 0; i < 4; ++i) {
                        sum += static_cast<UInt64>(lo[i]) + hi[i];
                    }
                    acc_lo = vdupq_n_u32(0);
                    acc_hi = vdupq_n_u32(0);
                }
            }
            alignas(16) UInt32 lo[4];
            alignas(16) UInt32 hi[4];
            vst1q_u32(lo, acc_lo);
            vst1q_u32(hi, acc_hi);
            for (UInt32 i = 0; i < 4; ++i) {
                sum += static_cast<UInt64>(lo[i]) + hi[i];
            }
            while (4 <= n) {
                sum += Load32(p);
                p += 4;
                n -= 4;
            }
            while (1 < n) {
                sum += Load16(p);
                p += 2;
                n -= 2;
            }
            if (0 < n) {
                sum += static_cast<UInt16>(static_cast<UInt16>(p[0]) << 8);
            }
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return static_cast<UInt16>(~sum & 0xFFFF);
        }
#endif

        bool CpuHasSsse3() noexcept {
#if !defined(XTCP_X86)
            // Non-x86 (ARM/RISC-V/...): no cpuid, no SSSE3 - the caller's
            // #if-gated dispatch already excludes the SIMD path; this
            // returns false as a belt-and-suspenders so a hypothetical
            // unguarded caller still takes the scalar path.
            return false;
#else
            // Cached per process: the CPU feature set cannot change, so the
            // first call racing is benign (both racers observe the same set).
            static const bool has_ssse3 = []() noexcept {
#if defined(_MSC_VER)
                int cpu_info[4];
                __cpuid(cpu_info, 1);
                return 0 != (cpu_info[2] & (1 << 9));  // ECX bit 9 = SSSE3
#elif defined(__GNUC__) || defined(__clang__)
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return 0 != (ecx & (1 << 9));  // ECX bit 9 = SSSE3
#else
                (void)0;
                return false;
#endif
            }();
            return has_ssse3;
#endif
        }

        UInt16 Checksum(const void* data, UInt32 len) noexcept {
#if defined(XTCP_X86) && (defined(__SSSE3__) || defined(__SSSE3) || defined(_MSC_VER))
            if (CpuHasSsse3()) {
                return ChecksumSimd(data, len);
            }
#endif
            return ChecksumScalar(data, len);
        }

        UInt16 ChecksumDelta(UInt16 old_sum, UInt16 old_word, UInt16 new_word) noexcept {
            // RFC 1624: HC' = ~(~HC + ~m + m')
            UInt32 sum = (~old_sum & 0xFFFF);
            sum += (~old_word & 0xFFFF);
            sum += new_word;
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return static_cast<UInt16>(~sum & 0xFFFF);
        }

        bool ParseIp4(const Byte* data, UInt32 len, Ip4Hdr& out) noexcept {
            if (NULLPTR == data || 20 > len) {
                return false;
            }
            const Byte version_ihl = data[0];
            const Byte version = static_cast<Byte>(version_ihl >> 4);
            const UInt32 ihl = static_cast<UInt32>(version_ihl & 0x0F) * 4;
            if (kIpv4 != version || 20 > ihl || ihl > len) {
                return false;
            }
            const UInt16 total_len = Load16(data + 2);
            if (ihl > total_len || total_len > len) {
                return false;
            }
            out.src         = Load32(data + 12);
            out.dst         = Load32(data + 16);
            out.proto       = data[9];
            out.hdr_len     = static_cast<UInt16>(ihl);
            out.total_len   = total_len;
            out.payload_off = static_cast<UInt16>(ihl);
            out.id          = Load16(data + 4);
            const UInt16 frag_field = Load16(data + 6);
            out.frag_off    = static_cast<UInt16>(frag_field & 0x1FFF);
            out.flags       = static_cast<Byte>((frag_field >> 13) & 0x07);
            return true;
        }

        bool ParseIp6(const Byte* data, UInt32 len, Ip6Hdr& out) noexcept {
            if (NULLPTR == data || 40 > len) {
                return false;
            }
            const Byte version = static_cast<Byte>(data[0] >> 4);
            if (kIpv6 != version) {
                return false;
            }
            const UInt16 payload_len = Load16(data + 4);
            if (static_cast<UInt32>(40) + payload_len > len) {
                return false;
            }
            out.src[0] = Load32(data + 8);
            out.src[1] = Load32(data + 12);
            out.src[2] = Load32(data + 16);
            out.src[3] = Load32(data + 20);
            out.dst[0] = Load32(data + 24);
            out.dst[1] = Load32(data + 28);
            out.dst[2] = Load32(data + 32);
            out.dst[3] = Load32(data + 36);
            out.payload_len = payload_len;

            // Walk basic extension headers up to the transport protocol.
            Byte next_header = data[6];
            UInt32 off = 40;
            const UInt32 end = 40 + payload_len;
            out.hdr_len = 0;
            while (off < end) {
                switch (next_header) {
                case 0:    // Hop-by-Hop
                case 43:   // Routing
                case 60: { // Destination Options
                    if ((off + 1) >= end) {
                        return false;  // Hdr Ext Len byte lies past the end
                    }
                    const UInt32 hdr_ext_len = (static_cast<UInt32>(data[off + 1]) + 1) * 8;
                    if ((off + hdr_ext_len) > end) {
                        return false;
                    }
                    next_header = data[off];
                    off += hdr_ext_len;
                    break;
                }
                case 44: { // Fragment header
                    if ((off + 8) > end) {
                        return false;
                    }
                    out.frag_id   = Load32(data + off + 4);
                    const UInt16 frag_field = Load16(data + off + 2);
                    out.frag_off  = static_cast<UInt16>(frag_field >> 3);
                    out.frag_more = static_cast<Byte>(frag_field & 0x1);
                    next_header   = data[off];
                    off += 8;
                    if (0 < out.frag_off) {
                        // RFC 8200: a non-first fragment header is followed
                        // only by payload, never by extension headers.
                        if (0xFFFF < off) {
                            return false;
                        }
                        out.proto = next_header;
                        out.payload_off = static_cast<UInt16>(off);
                        out.hdr_len = static_cast<UInt16>(off);
                        return true;
                    }
                    break;
                }
                default:
                    if (0xFFFF < off) {
                        return false;  // UInt16 payload_off/hdr_len truncate
                    }
                    out.proto = next_header;
                    out.payload_off = static_cast<UInt16>(off);
                    out.hdr_len = static_cast<UInt16>(off);
                    return true;
                }
            }
            if (0xFFFF < off) {
                return false;  // UInt16 payload_off/hdr_len truncate
            }
            out.proto = next_header;
            out.payload_off = static_cast<UInt16>(off);
            out.hdr_len = static_cast<UInt16>(off);
            return true;
        }

        bool ParseIcmpFragNeeded(const Byte* data, UInt32 len, IcmpFragNeeded& out) noexcept {
            out.valid = false;
            if (NULLPTR == data || len < 28) {
                return false;
            }
            Ip4Hdr ip4;
            if (!ParseIp4(data, len, ip4) || 1 != ip4.proto) {  // ICMP
                return false;
            }
            const Byte* icmp = data + ip4.payload_off;
            const UInt32 icmp_len = len - ip4.payload_off;
            if (icmp_len < 8 || 3 != icmp[0] || 4 != icmp[1]) {
                return false;  // not "destination unreachable / fragmentation needed"
            }
            out.valid = true;
            out.mtu = Load16(icmp + 6);
            // The embedded original IP header follows the ICMP header. Real
            // routers copy it verbatim (RFC 792/1812), so its total_len still
            // says the ORIGINAL datagram length (e.g. 1500) while the ICMP
            // message carries only a truncated prefix (IP header + first 8
            // bytes of the TCP header). ParseIp4's total_len > actual-bytes
            // rejection must not apply here: it would leave the endpoints at
            // zero, the flow lookup would never match, and PMTUD would
            // silently die. Parse leniently - only the IHL must fit, and the
            // TCP ports need ihl + 4 <= orig_len.
            const Byte* orig = icmp + 8;
            const UInt32 orig_len = icmp_len - 8;
            if (orig_len < 20) {
                return true;  // mtu only, no endpoints
            }
            const Byte version_ihl = orig[0];
            if (kIpv4 != (version_ihl >> 4)) {
                return true;
            }
            const UInt32 ihl = static_cast<UInt32>(version_ihl & 0x0F) * 4;
            if (20 > ihl || ihl > orig_len) {
                return true;
            }
            if (6 != orig[9]) {
                return true;  // not TCP
            }
            if (ihl + 4 > orig_len) {
                return true;  // TCP ports truncated
            }
            out.src_addr[0] = Load32(orig + 12);
            out.src_port = Load16(orig + ihl + 0);
            out.dst_addr[0] = Load32(orig + 16);
            out.dst_port = Load16(orig + ihl + 2);
            return true;
        }

        /* ---------------- Fragment reassembly ---------------- */

        struct IpFragTable::FragSet {
            FragKey     key;
            UInt64      last_time;
            Byte*       data       = NULLPTR;  /**< Reassembly buffer */
            UInt32      data_len   = 0;        /**< Bytes covered so far (max seen end) */
            UInt32      total_len  = 0;        /**< Expected total (0 = unknown) */
            UInt16*     have       = NULLPTR;  /**< Bitmap of received 8-byte units */
            UInt32      have_units = 0;        /**< Bitmap size in units */
            UInt32      received   = 0;        /**< Received units count */
        };

        IpFragTable::IpFragTable(UInt64 timeout_us, UInt32 max_sets) noexcept
            : timeout_us_(timeout_us), max_sets_(max_sets) {}

        IpFragTable::~IpFragTable() noexcept {
            for (auto& entry : sets_) {
                DestroySet(entry.second);
            }
            sets_.clear();
        }

        IpFragTable::FragSet* IpFragTable::FindSet(const FragKey& key) noexcept {
            auto it = sets_.find(key);
            if (sets_.end() == it) {
                return NULLPTR;
            }
            return it->second;
        }

        IpFragTable::FragSet* IpFragTable::CreateSet(UInt64 now, const FragKey& key) noexcept {
            if (max_sets_ <= set_count_.load(std::memory_order_relaxed)) {
                return NULLPTR;
            }
            // Reject a new group once this source address already holds the
            // per-source cap (attackers vary id/dst/proto; version+src is the
            // minimal identity that keeps one sender bounded). Maintained as
            // an O(1) count map instead of a linear scan per CreateSet.
            const std::array<UInt32, 5> src_key = { key.version, key.src[0], key.src[1], key.src[2], key.src[3] };
            UInt32& cnt = src_counts_[src_key];
            if (kMaxSetsPerSource <= cnt) {
                return NULLPTR;
            }
            ++cnt;
            FragSet* set = new (std::nothrow) FragSet();
            if (NULLPTR == set) {
                return NULLPTR;
            }
            set->key = key;
            set->last_time = now;
            sets_.emplace(key, set);
            set_count_.fetch_add(1, std::memory_order_relaxed);
            return set;
        }

        void IpFragTable::DestroySet(FragSet* set) noexcept {
            if (NULLPTR == set) {
                return;
            }
            // Mirror of the CreateSet increment: drop the per-source count
            // (all destroy paths funnel through here - Add completion, Expire).
            const std::array<UInt32, 5> src_key = { set->key.version, set->key.src[0], set->key.src[1],
                                                    set->key.src[2], set->key.src[3] };
            auto it = src_counts_.find(src_key);
            if (src_counts_.end() != it) {
                if (0 == --it->second) {
                    src_counts_.erase(it);
                }
            }
            xtcp::Mfree(set->data);
            set->data = NULLPTR;
            xtcp::Mfree(set->have);
            set->have = NULLPTR;
            delete set;
        }

        Int32 IpFragTable::Add(UInt64 now, const FragKey& key, const Fragment& frag, buf::BufRef& out) noexcept {
            if (NULLPTR == frag.data || 0 == frag.len) {
                return -1;
            }
            const UInt32 offset = static_cast<UInt32>(frag.offset) * 8;
            // Subtraction form: `offset + frag.len` wraps for len near
            // UINT32_MAX and can slip past the cap below, letting an
            // oversized fragment pass and overrun the buffer. Guard offset
            // first (no borrow), then bound len against the remaining room.
            if (kMaxPayload <= offset) {
                return -1;
            }
            if (frag.len > (kMaxPayload - offset)) {
                return -1;
            }
            // RFC 791: all fragments except the last must be a multiple of
            // 8 octets. The reassembly bitmap is 8-byte-granular, so a
            // malformed non-final fragment whose length is not a multiple of
            // 8 marks the unit covering its tail without writing it fully -
            // a later fragment starting at the next unit boundary would
            // complete the set with the gap bytes never written (uninitialized
            // heap copied into the reassembled datagram).
            if (frag.more && 0 != (frag.len % 8)) {
                return -1;
            }
            const UInt32 end = offset + frag.len;

            FragSet* set = FindSet(key);
            if (NULLPTR == set) {
                set = CreateSet(now, key);
                if (NULLPTR == set) {
                    return -1;
                }
            }

            if (NULLPTR == set->have) {
                const UInt32 units = (end + 7) / 8;
                if (0 == units) {
                    return -1;
                }
                // Commit both buffers only after both allocations succeed;
                // a partial success (have set, data NULL) leaves a stale
                // entry whose next fragment memcpy's into NULL.
                UInt16* have = static_cast<UInt16*>(xtcp::Malloc((units + 15) / 16 * sizeof(UInt16)));
                Byte* data = static_cast<Byte*>(xtcp::Malloc(kMaxPayload));
                if (NULLPTR == have || NULLPTR == data) {
                    xtcp::Mfree(have);
                    xtcp::Mfree(data);
                    return -1;
                }
                std::memset(have, 0, (units + 15) / 16 * sizeof(UInt16));
                set->have = have;
                set->data = data;
                set->have_units = units;
            }

            // Reject overlaps by checking all covered 8-byte units; grow the
            // bitmap when a later fragment extends beyond the initial size.
            const UInt32 first_unit = offset / 8;
            const UInt32 last_unit = (end + 7) / 8;
            if (set->have_units < last_unit) {
                UInt32 new_units = set->have_units;
                while (new_units < last_unit) {
                    new_units = (0 == new_units) ? 16 : new_units * 2;
                }
                UInt16* grown = static_cast<UInt16*>(xtcp::Malloc((new_units + 15) / 16 * sizeof(UInt16)));
                if (NULLPTR == grown) {
                    return -1;
                }
                std::memset(grown, 0, (new_units + 15) / 16 * sizeof(UInt16));
                if (NULLPTR != set->have && 0 < set->have_units) {
                    std::memcpy(grown, set->have, (set->have_units + 15) / 16 * sizeof(UInt16));
                }
                xtcp::Mfree(set->have);
                set->have = grown;
                set->have_units = new_units;
            }
            for (UInt32 u = first_unit; u < last_unit; ++u) {
                if (0 != (set->have[u / 16] & static_cast<UInt16>(1 << (u % 16)))) {
                    return -1;  // duplicate/overlap
                }
            }
            for (UInt32 u = first_unit; u < last_unit; ++u) {
                set->have[u / 16] |= static_cast<UInt16>(1 << (u % 16));
            }
            std::memcpy(set->data + offset, frag.data, frag.len);
            set->received += (last_unit - first_unit);

            // Refresh the expiry clock only on an accepted first fragment
            // (offset 0). Refreshing on every fragment lets an attacker keep
            // a set alive past the timeout forever; the offset-0 fragment is
            // accepted at most once per set (later duplicates are rejected
            // above), so this bounds the set's lifetime.
            if (0 == frag.offset) {
                set->last_time = now;
            }

            if (!frag.more) {
                set->total_len = end;
            }
            if (end > set->data_len) {
                set->data_len = end;
            }

            // Complete when the final fragment arrived and every unit in
            // [0, total_len) is present. Coverage, not count: `received`
            // counts marked 8-byte units, which fragments can inflate beyond
            // total_len, so a count check passes while holes remain and
            // uninitialized memory gets delivered.
            if (0 != set->total_len) {
                const UInt32 units = (set->total_len + 7) / 8;
                if (set->received >= units) {
                    bool complete = true;
                    for (UInt32 u = 0; u < units; ++u) {
                        if (0 == (set->have[u / 16] & static_cast<UInt16>(1 << (u % 16)))) {
                            complete = false;
                            break;
                        }
                    }
                    if (complete) {
                        // Detach from the table before destroying (avoid dangling reads).
                        if (0 != sets_.erase(set->key)) {
                            set_count_.fetch_sub(1, std::memory_order_relaxed);
                        }

                        buf::BufRef packet = buf::BufRef::Acquire(set->total_len);
                        if (packet.IsEmpty()) {
                            DestroySet(set);
                            return -1;
                        }
                        std::memcpy(packet.Data(), set->data, set->total_len);
                        packet.SetLen(set->total_len);
                        out = std::move(packet);
                        DestroySet(set);
                        reassembled_total_.fetch_add(1, std::memory_order_relaxed);
                        return 1;
                    }
                }
            }
            return 0;
        }

        UInt32 IpFragTable::Expire(UInt64 now) noexcept {
            UInt32 expired = 0;
            for (auto it = sets_.begin(); it != sets_.end();) {
                FragSet* set = it->second;
                if ((now - set->last_time) > timeout_us_) {
                    DestroySet(set);
                    it = sets_.erase(it);
                    set_count_.fetch_sub(1, std::memory_order_relaxed);
                    ++expired;
                    continue;
                }
                ++it;
            }
            return expired;
        }
    }
}


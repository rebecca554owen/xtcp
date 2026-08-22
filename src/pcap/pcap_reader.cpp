/**
 * @file pcap_reader.cpp
 * @brief pcap container parser.
 */

#include <xtcp/pcap/pcap_reader.h>

#include <cstring>

namespace xtcp {
    namespace pcap {
        namespace {
            constexpr UInt32 kGlobalHdrLen = 24;
            constexpr UInt32 kRecordHdrLen = 16;
            constexpr UInt32 kMaxRecordCount = 1000000;

            inline UInt32 Load32(const Byte* p) noexcept {
                return (static_cast<UInt32>(p[0]) << 24) |
                       (static_cast<UInt32>(p[1]) << 16) |
                       (static_cast<UInt32>(p[2]) << 8)  |
                       static_cast<UInt32>(p[3]);
            }

            inline UInt32 BSwap32(UInt32 v) noexcept {
                return ((v & 0x000000FFu) << 24) |
                       ((v & 0x0000FF00u) << 8)  |
                       ((v & 0x00FF0000u) >> 8)  |
                       ((v & 0xFF000000u) >> 24);
            }
        }

        bool ParsePcap(const Byte* buf, UInt32 len, std::vector<Record>& out) {
            if (NULLPTR == buf || len < kGlobalHdrLen) {
                return false;
            }
            const UInt32 magic = Load32(buf);
            bool swap = false;
            if (0xA1B2C3D4 == magic || 0xA1B23C4D == magic) {
                swap = false;  // big-endian file
            } else if (0xD4C3B2A1 == magic || 0x4D3C2BA1 == magic) {
                swap = true;   // little-endian file
            } else {
                return false;
            }
            // 0xA1B23C4D / 0x4D3C2BA1 magic => nanosecond timestamps
            // (classic pcap v2.4 nanosecond variant); the rest are microseconds.
            const bool nanos = (0xA1B23C4D == magic) || (0x4D3C2BA1 == magic);
            const auto Field = [swap](const Byte* p) noexcept -> UInt32 {
                const UInt32 v = Load32(p);
                return swap ? BSwap32(v) : v;
            };
            // RFC-style format gate: the version fields (major at offset 4,
            // minor at offset 6, each a 16-bit field in the FILE's byte
            // order) must describe a classic pcap file (major 2). Any buffer
            // with a valid magic parses otherwise, regardless of
            // version/garbage fields (B1). In a big-endian file the major
            // occupies the HIGH half of the u32 at +4; in a little-endian
            // file (after BSwap) it is the LOW half - shift accordingly.
            const UInt16 version_major =
                static_cast<UInt16>((Field(buf + 4) >> (swap ? 0 : 16)) & 0xFFFF);
            if (2 != version_major) {
                return false;
            }
            const UInt16 network = static_cast<UInt16>(Field(buf + 20) & 0xFFFF);

            UInt32 off = kGlobalHdrLen;
            UInt32 rec_count = 0;
            while ((len - off) >= kRecordHdrLen) {
                if (kMaxRecordCount <= rec_count) {
                    return false;  // record-count cap (OOM guard)
                }
                const UInt32 ts_sec = Field(buf + off + 0);
                const UInt32 ts_frac = Field(buf + off + 4);
                const UInt32 incl_len = Field(buf + off + 8);
                const UInt32 orig_len = Field(buf + off + 12);
                if (incl_len > (len - off - kRecordHdrLen)) {
                    return false;  // truncated record
                }
                if (orig_len < incl_len) {
                    return false;  // malformed: captured more than the original
                }
                Record rec;
                rec.ts_sec = ts_sec;
                rec.ts_frac = ts_frac;
                rec.nanos = nanos;
                rec.network = network;
                rec.orig_len = orig_len;
                rec.data.assign(buf + off + kRecordHdrLen, buf + off + kRecordHdrLen + incl_len);
                out.push_back(std::move(rec));
                ++rec_count;
                off += kRecordHdrLen + incl_len;
            }
            if (0 != (len - off)) {
                return false;  // trailing partial record header
            }
            return true;
        }
    }
}

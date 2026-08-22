/**
 * @file gso.cpp
 * @brief Software GSO segmentation (zero-copy payload reference).
 */

#include <xtcp/core/gso.h>
#include <xtcp/core/ip.h>
#include <xtcp/core/tcp.h>

namespace xtcp {
    namespace core {
        namespace {
            constexpr Byte kProtoTcp = 6;

            inline void Store16(Byte* p, UInt16 v) noexcept {
                p[0] = static_cast<Byte>(v >> 8);
                p[1] = static_cast<Byte>(v & 0xFF);
            }
            inline void Store32(Byte* p, UInt32 v) noexcept {
                p[0] = static_cast<Byte>(v >> 24);
                p[1] = static_cast<Byte>(v >> 16);
                p[2] = static_cast<Byte>(v >> 8);
                p[3] = static_cast<Byte>(v & 0xFF);
            }

            inline UInt16 ChecksumCombine(UInt16 a, UInt16 b) noexcept {
                UInt32 sum = (static_cast<UInt32>(~a) & 0xFFFF) + (static_cast<UInt32>(~b) & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                return static_cast<UInt16>(~sum & 0xFFFF);
            }
        }

        bool GsoSegment(const buf::BufRef& packet, UInt16 mss, std::vector<GsoSeg>& out) noexcept {
            if (packet.IsEmpty() || 40 > packet.Len() || 0 == mss) {
                return false;
            }
            const Byte* p = packet.Data();
            const UInt32 total_len = packet.Len();
            const Byte version = static_cast<Byte>(p[0] >> 4);

            UInt32 ip_hdr_len = 0;
            UInt32 ip_total = 0;  // IP-declared total packet length
            Byte next_header = 6;  // TCP (we only segment TCP)
            if (4 == version) {
                Ip4Hdr ip;
                if (!ParseIp4(p, total_len, ip)) {
                    return false;
                }
                if (0 < ip.frag_off || 0 != (ip.flags & 0x01)) {
                    return false;  // fragmented input: not a complete packet
                }
                ip_hdr_len = ip.payload_off;
                ip_total = ip.total_len;
            } else if (6 == version) {
                Ip6Hdr ip;
                if (!ParseIp6(p, total_len, ip)) {
                    return false;
                }
                if (0 != ip.frag_off || 0 != ip.frag_more) {
                    return false;  // fragmented input: not a complete packet
                }
                ip_hdr_len = ip.payload_off;
                ip_total = 40 + ip.payload_len;  // base header + declared payload
            } else {
                return false;
            }

            TcpHdr tcp;
            if (!ParseTcp(p + ip_hdr_len, total_len - ip_hdr_len, tcp)) {
                return false;
            }
            const UInt32 tcp_hdr_len = tcp.payload_off;
            // Payload is bounded by the IP header's declared length, not the
            // (possibly larger) backing buffer: a BufRef longer than the IP
            // packet must not expose trailing garbage as payload.
            UInt32 payload_len = total_len - ip_hdr_len - tcp_hdr_len;
            if (ip_total > ip_hdr_len + tcp_hdr_len) {
                const UInt32 ip_payload = ip_total - ip_hdr_len - tcp_hdr_len;
                if (ip_payload < payload_len) {
                    payload_len = ip_payload;
                }
            } else {
                payload_len = 0;  // IP declares fewer bytes than the TCP header needs
            }
            if (0 == payload_len) {
                return false;
            }
            const Byte* payload = p + ip_hdr_len + tcp_hdr_len;
            const UInt32 max_mss = 65495 - (ip_hdr_len + tcp_hdr_len);
            if (mss > max_mss) {
                mss = static_cast<UInt16>(max_mss);
            }
            const UInt32 seg_count = (payload_len + mss - 1) / mss;
            if (65535 / seg_count < 1) {
                return false;
            }

            out.clear();
            out.reserve(seg_count);

            const bool is_v6 = (6 == version);

            for (UInt32 i = 0; i < seg_count; ++i) {
                const UInt32 off = i * mss;
                const UInt32 seg_len = (off + mss < payload_len) ? mss : (payload_len - off);
                const UInt32 seg_tcp_len = tcp_hdr_len + seg_len;

                // Per-segment header buffer (pool-allocated, zero-copy payload).
                buf::BufRef hdr_ref = buf::BufRef::Acquire(ip_hdr_len + tcp_hdr_len);
                if (hdr_ref.IsEmpty()) {
                    out.clear();  // keep the output atomic: false => no partial segments
                    return false;
                }
                Byte* hdr = hdr_ref.Data();
                std::memcpy(hdr, p, ip_hdr_len);                       // copy IP header
                if (is_v6) {
                    // RFC 8200: Payload Length = everything after the 40-byte
                    // base header (extension headers + TCP header + payload).
                    const UInt32 v6_plen = seg_tcp_len + ip_hdr_len - 40;
                    hdr[4] = static_cast<Byte>((v6_plen >> 8) & 0xFF);
                    hdr[5] = static_cast<Byte>(v6_plen & 0xFF);
                } else {
                    Store16(hdr + 2, static_cast<UInt16>(ip_hdr_len + seg_tcp_len));  // total length
                    hdr[6] = 0x40;                                          // DF
                    hdr[7] = 0x00;
                    Store16(hdr + 10, 0);                                   // clear old checksum
                    const UInt16 ip_sum = Checksum(hdr, ip_hdr_len);       // recompute IP checksum
                    Store16(hdr + 10, ip_sum);
                }

                std::memcpy(hdr + ip_hdr_len, p + ip_hdr_len, tcp_hdr_len);  // copy TCP header
                // RFC 1122: PSH/FIN/URG only on the final segment; ECE (ECN)
                // stays on every segment.
                const UInt16 seg_flags = (i + 1 < seg_count)
                    ? static_cast<UInt16>(tcp.flags & static_cast<UInt16>(~(kFlagPsh | kFlagFin | kFlagUrg)))
                    : tcp.flags;
                hdr[ip_hdr_len + 13] = static_cast<Byte>(seg_flags);  // TCP flags byte
                const UInt32 seg_seq = tcp.seq + off;
                Store32(hdr + ip_hdr_len + 4, seg_seq);                     // sequence
                Store16(hdr + ip_hdr_len + 16, 0);                          // checksum placeholder
                Store16(hdr + ip_hdr_len + 18, (0 != (seg_flags & kFlagUrg))
                    ? static_cast<UInt16>(static_cast<UInt32>(tcp.urgent) - off)
                    : 0);                          // urgent (adjusted for the segment offset)

                // TCP checksum: pseudo header + TCP header + payload. Full
                // recompute per segment (the header's seq/urgent fields and
                // the payload window change with the offset; a delta update
                // would need the same inputs read twice).
                Byte pseudo[40];
                UInt32 pseudo_len = 0;
                if (is_v6) {
                    // RFC 8200: src(16) + dst(16) + length(4) + zero(3) + next(1).
                    for (UInt32 b = 0; b < 32; ++b) {
                        pseudo[b] = p[8 + b];
                    }
                    pseudo[32] = static_cast<Byte>((seg_tcp_len >> 24) & 0xFF);
                    pseudo[33] = static_cast<Byte>((seg_tcp_len >> 16) & 0xFF);
                    pseudo[34] = static_cast<Byte>((seg_tcp_len >> 8) & 0xFF);
                    pseudo[35] = static_cast<Byte>(seg_tcp_len & 0xFF);
                    pseudo[36] = 0;
                    pseudo[37] = 0;
                    pseudo[38] = 0;
                    pseudo[39] = next_header;
                    pseudo_len = 40;
                } else {
                    std::memcpy(pseudo, p + 12, 8);                         // src + dst
                    pseudo[8] = 0;
                    pseudo[9] = kProtoTcp;
                    Store16(pseudo + 10, static_cast<UInt16>(seg_tcp_len));
                    pseudo_len = 12;
                }
                const UInt16 pseudo_sum = Checksum(pseudo, pseudo_len);
                const UInt16 hdr_sum = Checksum(hdr + ip_hdr_len, tcp_hdr_len);
                const UInt16 payload_sum = Checksum(payload + off, seg_len);
                const UInt16 tcp_sum = ChecksumCombine(ChecksumCombine(pseudo_sum, hdr_sum), payload_sum);
                Store16(hdr + ip_hdr_len + 16, tcp_sum);

                GsoSeg seg;
                seg.hdr_ref = std::move(hdr_ref);
                seg.seq = seg_seq;
                seg.ack = tcp.ack;
                seg.flags = seg_flags;
                seg.payload_len = seg_len;
                seg.iovs.reserve(2);
                GsoIov hdr_iov;
                hdr_iov.data = seg.hdr_ref.Data();  // owned by the segment
                hdr_iov.len = ip_hdr_len + tcp_hdr_len;
                seg.iovs.push_back(hdr_iov);
                if (0 < seg_len) {
                    GsoIov payload_iov;
                    payload_iov.data = payload + off;  // zero-copy reference
                    payload_iov.len = seg_len;
                    seg.iovs.push_back(payload_iov);
                }
                out.push_back(std::move(seg));
            }
            return true;
        }
    }
}

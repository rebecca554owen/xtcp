#pragma once

/**
 * @file raw_pkt.h
 * @brief Hand-built IPv4+TCP packet helpers with VALID checksums (RFC 791/
 *        RFC 793), so tests behave identically under the default build and
 *        the checksum-validate build (XTCP_CHECKSUM_VALIDATE: a zero-checksum
 *        segment is dropped there, silently changing the scenario).
 */

#include <xtcp/stdafx.h>

#include <cstring>
#include <vector>

namespace xtcp {
    namespace harness {
        /** RFC 1071 Internet checksum over a byte range. */
        inline UInt16 RawChecksum(const Byte* data, UInt32 len) noexcept {
            UInt64 sum = 0;
            UInt32 i = 0;
            for (; i + 1 < len; i += 2) {
                sum += static_cast<UInt32>((static_cast<UInt32>(data[i]) << 8) | data[i + 1]);
            }
            if (i < len) {
                sum += static_cast<UInt32>(static_cast<UInt32>(data[i]) << 8);
            }
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return static_cast<UInt16>(~sum & 0xFFFF);
        }

        /** Fills the IPv4 header checksum field of a 20-byte IPv4 header.
         *  Zeroes the field first so the helper is idempotent (safe to call
         *  again after a field was mutated and the checksum re-computed). */
        inline void FillIp4Checksum(Byte* ip) noexcept {
            ip[10] = 0;
            ip[11] = 0;
            const UInt16 csum = RawChecksum(ip, 20);
            ip[10] = static_cast<Byte>(csum >> 8);
            ip[11] = static_cast<Byte>(csum & 0xFF);
        }

        /**
         * @brief Fills the TCP checksum field of a TCP header at `tcp` whose
         *        packet has the given IPv4 src/dst at `ip+12`. Sums in place
         *        (the checksum field is temporarily zeroed), so segments with
         *        options or payload beyond a fixed stack buffer are handled
         *        correctly. `tcp_len` covers header + payload.
         */
        inline void FillTcp4Checksum(Byte* ip, Byte* tcp, UInt32 tcp_len) noexcept {
            Byte pseudo[12];
            std::memcpy(pseudo, ip + 12, 8);  // src + dst
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = static_cast<Byte>((tcp_len >> 8) & 0xFF);
            pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
            tcp[16] = 0;
            tcp[17] = 0;  // zero the checksum field before summing
            UInt64 sum = 0;
            for (UInt32 i = 0; i < 12; i += 2) {
                sum += static_cast<UInt32>((static_cast<UInt32>(pseudo[i]) << 8) | pseudo[i + 1]);
            }
            for (UInt32 i = 0; i < tcp_len; i += 2) {
                sum += static_cast<UInt32>((static_cast<UInt32>(tcp[i]) << 8) |
                                           ((i + 1 < tcp_len) ? tcp[i + 1] : 0));
            }
            while (0 != (sum >> 16)) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            const UInt16 csum = static_cast<UInt16>(~sum & 0xFFFF);
            tcp[16] = static_cast<Byte>(csum >> 8);
            tcp[17] = static_cast<Byte>(csum & 0xFF);
        }

        /**
         * @brief Neutralizes window scaling on a hand-built SYN+ACK: zeroes
         *        the WSOPT value (kind 3) and restores the window field to
         *        the unscaled 65535, recomputing the checksum. Tests that
         *        inject raw window fields (shrink/trickle scenarios) use this
         *        to keep the connection UNSCALED - the stack now offers
         *        RFC 7323 WSOPT=7 by default, and a scaled peer would
         *        interpret every injected raw field with a shift.
         * @return True when the SYN+ACK was found and patched.
         */
        inline bool PatchSynAckUnscaled(Byte* pkt, UInt32 len) noexcept {
            if (NULLPTR == pkt || 40 > len || 4 != (pkt[0] >> 4)) {
                return false;
            }
            const UInt32 tcp_off = static_cast<UInt32>(pkt[0] & 0x0F) * 4;
            if (len < tcp_off + 20) {
                return false;
            }
            const UInt32 tcp_hdr_len = static_cast<UInt32>(pkt[tcp_off + 12] >> 4) * 4;
            if (len < tcp_off + tcp_hdr_len) {
                return false;
            }
            if (0 == (pkt[tcp_off + 13] & 0x12)) {
                return false;  // not a SYN+ACK
            }
            bool found = false;
            for (UInt32 off = tcp_off + 20; off + 1 < tcp_off + tcp_hdr_len;) {
                const Byte kind = pkt[off];
                if (0 == kind) {
                    break;
                }
                if (1 == kind) {
                    ++off;
                    continue;
                }
                const Byte olen = pkt[off + 1];
                if (olen < 2 || tcp_off + tcp_hdr_len < off + olen) {
                    return false;
                }
                if (3 == kind && 3 == olen) {
                    pkt[off + 2] = 0;  // WSOPT value 0: no scaling
                    found = true;
                    break;
                }
                off += olen;
            }
            if (!found) {
                return false;
            }
            pkt[tcp_off + 14] = 0xFF;  // unscaled window field 65535
            pkt[tcp_off + 15] = 0xFF;
            FillTcp4Checksum(pkt, pkt + tcp_off, tcp_hdr_len);
            return true;
        }

        /**
         * @brief Builds a full IPv4+TCP segment (40 bytes + payload) with
         *        valid IP and TCP checksums.
         */
        inline std::vector<Byte> BuildIp4Tcp(UInt32 src_ip, UInt32 dst_ip, UInt16 sport, UInt16 dport,
                                             UInt32 seq, UInt32 ack, Byte flags,
                                             const Byte* payload = NULLPTR, UInt32 plen = 0) noexcept {
            std::vector<Byte> out(40 + plen, 0);
            Byte* ip = out.data();
            ip[0] = 0x45;
            const UInt32 total = 40 + plen;
            ip[2] = static_cast<Byte>(total >> 8);
            ip[3] = static_cast<Byte>(total & 0xFF);
            ip[8] = 64;
            ip[9] = 6;
            ip[12] = static_cast<Byte>(src_ip >> 24); ip[13] = static_cast<Byte>(src_ip >> 16);
            ip[14] = static_cast<Byte>(src_ip >> 8);  ip[15] = static_cast<Byte>(src_ip & 0xFF);
            ip[16] = static_cast<Byte>(dst_ip >> 24); ip[17] = static_cast<Byte>(dst_ip >> 16);
            ip[18] = static_cast<Byte>(dst_ip >> 8);  ip[19] = static_cast<Byte>(dst_ip & 0xFF);
            Byte* t = ip + 20;
            t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
            t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
            t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
            t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
            t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
            t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
            t[12] = 0x50;
            t[13] = flags;
            t[14] = 0xFF; t[15] = 0xFF;
            if (0 < plen && NULLPTR != payload) {
                std::memcpy(t + 20, payload, plen);
            }
            FillIp4Checksum(ip);
            FillTcp4Checksum(ip, t, 20 + plen);
            return out;
        }
    }
}

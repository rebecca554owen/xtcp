#pragma once

/**
 * @file gso.h
 * @brief Software GSO segmentation at the tx boundary (zero-copy: payload
 *        bytes are referenced via IOVs, never copied). TSO passthrough is
 *        decided by NDI capability bits.
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>

#include <vector>

namespace xtcp {
    namespace core {
        /**
         * @brief One I/O vector: a contiguous byte range.
         */
        struct GsoIov {
            const Byte* data = NULLPTR;
            UInt32      len  = 0;
        };

        /**
         * @brief One output segment: header IOV(s) plus one payload IOV.
         * @note LIFETIME CONTRACT: the payload IOV data pointers reference
         *       the caller's packet buffer (zero-copy) - the GsoSeg vector
         *       does NOT pin the source buffer's refcount. The consumer
         *       (EmitLocked) copies every IOV into a fresh buffer
         *       synchronously, before the source BufRef is released; any
         *       consumer that defers the copy must hold a Clone() of the
         *       source for the lifetime of the iovs.
         */
        struct GsoSeg {
            buf::BufRef         hdr_ref;   /**< Owns the header buffer */
            std::vector<GsoIov> iovs;
            UInt32 seq = 0;   /**< TCP sequence of the first byte */
            UInt32 ack = 0;
            UInt16 flags = 0;
            UInt32 payload_len = 0;
        };

        /**
         * @brief Segments a complete IPv4+TCP super-segment into MSS-sized
         *        segments. Header bytes are rebuilt per segment; payload
         *        bytes are referenced (zero-copy).
         * @param packet Super-segment (IP payload form, full IP packet).
         * @param mss    MSS in bytes.
         * @param out    Receives the segments.
         * @return True on success.
         */
        bool GsoSegment(const buf::BufRef& packet, UInt16 mss, std::vector<GsoSeg>& out) noexcept;
    }
}

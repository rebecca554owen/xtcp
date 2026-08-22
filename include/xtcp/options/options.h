#pragma once

/**
 * @file options.h
 * @brief Kernel-compat option layer (setsockopt style): per-connection
 *        options named and semantically aligned with the Linux kernel
 *        (TCP_NODELAY, TCP_FASTOPEN, TCP_KEEPIDLE, ...).
 */

#include <xtcp/stdafx.h>
#include <xtcp/core/tcp.h>

namespace xtcp {
    namespace options {
        /**
         * @brief Per-connection option ids (Linux setsockopt TCP_* values).
         */
        enum SocketOption : Int32 {
            kTcpNodelay         = 1,    /**< TCP_NODELAY: disable Nagle */
            kTcpCork            = 3,    /**< TCP_CORK (accepted, no-op v1) */
            kTcpKeepidle        = 4,
            kTcpKeepintvl       = 5,
            kTcpKeepcnt         = 6,
            kTcpSynCnt          = 7,
            kTcpQuickack        = 12,
            kTcpMaxseg          = 2,
            kTcpFastopen        = 23,   /**< Server-side TFO */
            kTcpFastopenConnect = 30,   /**< Client-side TFO */
            kTcpUserTimeout     = 18,
            kTcpDeferAccept     = 9,
            kTcpEcn             = 64,   /**< TCP_ECN (RFC 3168) negotiation */
            kTcpNoSackPermitted = 65,   /**< Suppress SACK-permitted on SYN (RFC 5827 ER tests / kernel tcp_sack=0 parity) */
        };

        /**
         * @brief Sets a per-connection option.
         * @param conn Connection.
         * @param opt  Option id.
         * @param value Option value.
         * @param len  Value length.
         * @return True when the option was applied.
         */
        bool SetOption(core::TcpConn& conn, SocketOption opt, const void* value, UInt32 len) noexcept;
        /**
         * @brief Gets a per-connection option.
         * @param out  Receives the value.
         * @param len  In/out: buffer size / value size.
         * @return True when the option is readable.
         */
        bool GetOption(const core::TcpConn& conn, SocketOption opt, void* out, UInt32& len) noexcept;
    }
}

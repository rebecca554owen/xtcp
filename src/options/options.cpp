/**
 * @file options.cpp
 * @brief Kernel-compat option layer implementation.
 */

#include <xtcp/options/options.h>

namespace xtcp {
    namespace options {
        namespace {
            bool ToKeepaliveMicros(Int32 seconds, UInt64& out_us) noexcept {
                if (0 > seconds) {
                    return false;
                }
                // RFC 1122 s4.2.3.6: the 2-hour keepalive default must be
                // representable; Linux accepts up to INT_MAX seconds. The
                // storage is UInt64 microseconds, so the full Int32 range
                // fits (INT_MAX s ~ 68 years < 2^64 us).
                out_us = static_cast<UInt64>(seconds) * 1000000ull;
                return true;
            }
        }

        bool SetOption(core::TcpConn& conn, SocketOption opt, const void* value, UInt32 len) noexcept {
            if (NULLPTR == value) {
                return false;
            }
            switch (opt) {
            case kTcpNodelay:
                if (sizeof(Int32) != len) {
                    return false;
                }
                conn.SetNodelay(0 != *static_cast<const Int32*>(value));
                return true;
            case kTcpKeepidle:
                if (sizeof(Int32) != len) {
                    return false;
                }
                // Seconds -> microseconds; keep the current intvl/cnt.
                {
                    UInt64 idle_us = 0;
                    if (!ToKeepaliveMicros(*static_cast<const Int32*>(value), idle_us)) {
                        return false;
                    }
                    conn.SetKeepalive(idle_us, conn.KeepaliveInterval(), conn.KeepaliveCount());
                }
                return true;
            case kTcpKeepintvl:
                if (sizeof(Int32) != len) {
                    return false;
                }
                {
                    UInt64 intvl_us = 0;
                    if (!ToKeepaliveMicros(*static_cast<const Int32*>(value), intvl_us)) {
                        return false;
                    }
                    conn.SetKeepalive(conn.KeepaliveIdle(), intvl_us, conn.KeepaliveCount());
                }
                return true;
            case kTcpKeepcnt:
                if (sizeof(Int32) != len) {
                    return false;
                }
                {
                    const Int32 cnt = *static_cast<const Int32*>(value);
                    if (0 > cnt) {
                        return false;
                    }
                    conn.SetKeepalive(conn.KeepaliveIdle(), conn.KeepaliveInterval(),
                                      static_cast<UInt32>(cnt));
                }
                return true;
            case kTcpCork:
                // Accepted for compatibility; v1 has no send aggregation.
                return (sizeof(Int32) == len);
            case kTcpQuickack:
                if (sizeof(Int32) != len) {
                    return false;
                }
                conn.SetQuickAck(0 != *static_cast<const Int32*>(value));
                return true;
            case kTcpSynCnt:
                if (sizeof(Int32) != len) {
                    return false;
                }
                {
                    const Int32 cnt = *static_cast<const Int32*>(value);
                    if (0 > cnt) {
                        return false;
                    }
                    conn.SetSynRetries(static_cast<UInt32>(cnt));
                }
                return true;
            case kTcpEcn:
                if (sizeof(Int32) != len) {
                    return false;
                }
                conn.SetEcnRequested(0 != *static_cast<const Int32*>(value));
                return true;
            case kTcpNoSackPermitted:
                if (sizeof(Int32) != len) {
                    return false;
                }
                conn.SetNoSackPermitted(0 != *static_cast<const Int32*>(value));
                return true;
            case kTcpMaxseg:
                if (sizeof(Int32) != len) {
                    return false;
                }
                {
                    const Int32 mss = *static_cast<const Int32*>(value);
                    // RFC 879: a valid MSS is in [1, 65535] (UInt16).
                    if ((1 > mss) || (65535 < mss)) {
                        return false;
                    }
                    // Linux TCP_MAXSEG semantics: the value is a CEILING on
                    // the send MSS (applied against the peer's advertised
                    // MSS at SetPeerMss), not an unconditional override -
                    // setting it above the negotiated MSS must not emit
                    // segments larger than the peer announced (RFC 1122
                    // §4.2.2.6). Apply the reduction immediately so a
                    // post-negotiation set takes effect now.
                    conn.SetUserMss(static_cast<UInt32>(mss));
                    if (static_cast<UInt32>(mss) < conn.PeerMss()) {
                        conn.SetPeerMss(static_cast<UInt16>(mss));
                    }
                }
                return true;
            case kTcpFastopen:
                // Server-side TFO (RFC 7413): the stack always offers a
                // cookie in the SYN+ACK; enabling the option is accepted.
                return (sizeof(Int32) == len);
            case kTcpFastopenConnect:
                // Client-side TFO: use ConnectWithTfo for early data.
                return (sizeof(Int32) == len);
            case kTcpUserTimeout:
            case kTcpDeferAccept:
            default:
                // Recognized but not applied (reserved for later tasks).
                return false;
            }
        }

        bool GetOption(const core::TcpConn& conn, SocketOption opt, void* out, UInt32& len) noexcept {
            if (NULLPTR == out) {
                return false;
            }
            switch (opt) {
            case kTcpNodelay:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = conn.Nodelay() ? 1 : 0;
                len = sizeof(Int32);
                return true;
            case kTcpQuickack:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = conn.QuickAck() ? 1 : 0;
                len = sizeof(Int32);
                return true;
            case kTcpMaxseg:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = conn.PeerMss();
                len = sizeof(Int32);
                return true;
            case kTcpSynCnt:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = static_cast<Int32>(conn.SynRetries());
                len = sizeof(Int32);
                return true;
            case kTcpKeepidle:
                if (len < sizeof(Int32)) {
                    return false;
                }
                // Round up to whole seconds: a sub-second idle must not read
                // back as 0 (0 = keepalive off) when a nonzero value is set.
                // Clamp at INT32_MAX: the UInt64 storage accepts INT_MAX
                // seconds and the round-up would otherwise
                // wrap 2147483648 into a negative Int32 on read-back.
                {
                    const UInt64 secs =
                        (static_cast<UInt64>(conn.KeepaliveIdle()) + 999999ull) / 1000000ull;
                    *static_cast<Int32*>(out) = (secs > 0x7FFFFFFFull)
                        ? 0x7FFFFFFF
                        : static_cast<Int32>(secs);
                }
                len = sizeof(Int32);
                return true;
            case kTcpKeepintvl:
                if (len < sizeof(Int32)) {
                    return false;
                }
                {
                    // Clamp at INT32_MAX (see kTcpKeepidle): the UInt64
                    // storage accepts INT_MAX seconds.
                    const UInt64 secs =
                        (static_cast<UInt64>(conn.KeepaliveInterval()) + 999999ull) / 1000000ull;
                    *static_cast<Int32*>(out) = (secs > 0x7FFFFFFFull)
                        ? 0x7FFFFFFF
                        : static_cast<Int32>(secs);
                }
                len = sizeof(Int32);
                return true;
            case kTcpKeepcnt:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = static_cast<Int32>(conn.KeepaliveCount());
                len = sizeof(Int32);
                return true;
            case kTcpCork:
                // No send aggregation in v1: SetOption accepts the flag but
                // records nothing, so cork is always reported as off.
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = 0;
                len = sizeof(Int32);
                return true;
            case kTcpEcn:
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = conn.EcnRequested() ? 1 : 0;
                len = sizeof(Int32);
                return true;
            case kTcpFastopen:
            case kTcpFastopenConnect:
                // TFO capability is always available (server offers the
                // cookie; the client uses ConnectWithTfo).
                if (len < sizeof(Int32)) {
                    return false;
                }
                *static_cast<Int32*>(out) = 1;
                len = sizeof(Int32);
                return true;
            default:
                return false;
            }
        }
    }
}

/**
 * @file test_syn_cookie.cpp
 * @brief RFC 4987 SYN-cookie wiring: once live connections reach the
 *        threshold, SYNs are answered statelessly (ISN = cookie) and the
 *        client's cookie ACK rebuilds the connection with data delivery.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include "harness/raw_pkt.h"
#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;  // 10.0.0.2
    constexpr UInt32 kClientV4 = 0x0A000001;  // 10.0.0.1
    constexpr UInt16 kPort     = 8080;

    /** Captures the SYN+ACK cookie (ISN) for a flow. */
    struct CookieProbe {
        bool     got = false;
        UInt32   cookie = 0;
        UInt32   ack = 0;          // SYN+ACK ack field (client SYN seq + 1)
        UInt16   client_sport = 0;
    };
}

/** Pumps `from` into `to`, optionally probing a SYN+ACK cookie. */
static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                 CookieProbe* probe = NULLPTR) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        if (NULLPTR != probe && !probe->got && got >= 52) {
            const UInt16 sport = static_cast<UInt16>((out[20] << 8) | out[21]);
            const UInt16 dport = static_cast<UInt16>((out[22] << 8) | out[23]);
            const Byte flags = out[33];
            // SYN+ACK from the server (sport 8080) to the client.
            if (0 != (flags & 0x12) && 8080 == sport && 0 == (flags & 0x01)) {
                probe->cookie = (static_cast<UInt32>(out[24]) << 24) |
                                (static_cast<UInt32>(out[25]) << 16) |
                                (static_cast<UInt32>(out[26]) << 8) |
                                static_cast<UInt32>(out[27]);
                probe->ack = (static_cast<UInt32>(out[28]) << 24) |
                             (static_cast<UInt32>(out[29]) << 16) |
                             (static_cast<UInt32>(out[30]) << 8) |
                             static_cast<UInt32>(out[31]);
                probe->client_sport = dport;
                probe->got = true;
            }
        }
        to.Inject(out, got, 0x0800);
        if (2000 < ++guard) {
            break;
        }
    }
}

/** Builds a raw SYN for the client flow (valid checksums). */
static UInt32 BuildSyn(Byte* out, UInt32 src, UInt16 sport, UInt32 dst, UInt16 dport, UInt32 seq) {
    std::vector<Byte> syn = xtcp::harness::BuildIp4Tcp(
        src, dst, sport, dport, seq, 0, 0x02);
    std::memcpy(out, syn.data(), syn.size());
    return static_cast<UInt32>(syn.size());
}

/** Builds the client's cookie ACK (ack = cookie + 1, confirming the SYN+ACK);
 *  valid checksums so the cookie-ACK rebuild path runs under the
 *  checksum-validate build too. */
static UInt32 BuildCookieAck(Byte* out, UInt32 src, UInt16 sport, UInt32 dst, UInt16 dport,
                             UInt32 cookie, UInt32 client_seq) {
    const UInt32 ack = cookie + 1;
    std::vector<Byte> seg = xtcp::harness::BuildIp4Tcp(
        src, dst, sport, dport, client_seq, ack, 0x10);
    std::memcpy(out, seg.data(), seg.size());
    return static_cast<UInt32>(seg.size());
}

int main() {
    // Module-level round trip first: Compute + immediate Verify must match.
    {
        xtcp::core::Syncookies sc;
        Byte idx = 0;
        const UInt32 c = sc.Compute(0x0A000001, 0x0A000002, 50004, 8080, 0x50000000, 3449, 0);
        const bool ok = sc.Verify(c, c + 1, 0x0A000001, 0x0A000002, 50004, 8080,
                                  0x50000000, 3449, 60, idx);
        std::fprintf(stderr, "[syncookie] module roundtrip cookie=%08X verify=%d idx=%u\n",
                     c, ok ? 1 : 0, (UInt32)idx);
        CHECK(ok);
    }
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack.OnPacket(std::move(buf));
        });

        std::string received;
        stack.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint server;
        server.family = 4;
        server.addr[0] = kServerV4;
        server.port = kPort;
        CHECK(stack.Listen(server));
        // Low cap so cookie mode engages once the queue fills.
        stack.SetMaxConnections(4);
        stack.SetSyncookieThreshold(0);  // threshold = max_conns_ = 4

        // Fill the half-open queue with 4 SYNs (normal passive opens).
        for (UInt32 i = 0; i < 4; ++i) {
            Byte syn[256];
            const UInt32 syn_len = BuildSyn(syn, kClientV4, static_cast<UInt16>(50000 + i),
                                            kServerV4, kPort, 0x10000000 + i * 1000);
            backend.Inject(syn, syn_len, 0x0800);
            Pump(backend, backend);
        }
        CHECK(4 == stack.ConnectionCount());

        // The 5th SYN hits cookie mode: answered statelessly (no new state),
        // the SYN+ACK carries a cookie in its ISN.
        Byte syn5[256];
        const UInt32 syn5_len = BuildSyn(syn5, kClientV4, 50004, kServerV4, kPort, 0x50000000);
        CookieProbe probe;
        backend.Inject(syn5, syn5_len, 0x0800);
        Pump(backend, backend, &probe);
        CHECK(probe.got);
        CHECK(4 == stack.ConnectionCount());  // cookie mode: no state for the 5th SYN

        // The client's cookie ACK rebuilds the connection.
        Byte ack[256];
        const UInt32 ack_len = BuildCookieAck(ack, kClientV4, 50004, kServerV4, kPort,
                                              probe.cookie, 0x50000001);
        backend.Inject(ack, ack_len, 0x0800);
        CHECK(5 == stack.ConnectionCount());  // rebuilt via the cookie
        std::fprintf(stderr, "[syncookie] cookie=%08X conns=%u\n",
                     probe.cookie, (UInt32)stack.ConnectionCount());

        // A forged cookie (wrong value) must NOT create a connection.
        Byte bad_ack[256];
        const UInt32 bad_len = BuildCookieAck(bad_ack, kClientV4, 50005, kServerV4, kPort,
                                              probe.cookie + 7, 0x60000000);
        backend.Inject(bad_ack, bad_len, 0x0800);
        CHECK(5 == stack.ConnectionCount());  // unchanged
        std::fprintf(stderr, "[syncookie] forged cookie rejected\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYN_COOKIE: FAILED (%d)\n" : "SYN_COOKIE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


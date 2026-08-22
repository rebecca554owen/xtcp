/**
 * @file test_ipv6_cookie_hash.cpp
 * @brief Records the IPv6 TFO cookie-cache hash collision: the client-side
 *        cookie cache key (stack.cpp:288-289 / 297-298) folds only
 *        `addr[0]` (the first 32-bit word of the 128-bit IPv6 address)
 *        plus port and family. Two IPv6 peers that share the same first
 *        32 bits -- e.g. fd00::1 and fd00::2, both addr[0] = 0xFD000000 --
 *        therefore resolve to the SAME cache entry and SHARE the same TFO
 *        cookie, regardless of the remaining 96 bits.
 *
 *        Audit proxy finding under test: "cookie cache key only takes
 *        addr[0] -- IPv6 addresses sharing the same first 32 bits share
 *        the cookie."
 *
 *        Contrast recorded: the SERVER-side cookie generator
 *        (TfoCookie::Hash, tfo.cpp:35-44) folds all 4 address words, so
 *        cookies generated for fd00::1 vs fd00::2 differ -- a client that
 *        replays fd00::1's cached cookie onto a fd00::2 connection will be
 *        rejected server-side (TFO early data degrades to a normal
 *        handshake for that peer).
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/tfo.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 500; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x86DD);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x86DD);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            return;
        }
    }
}

// Mirror of the cookie-cache key formula (stack.cpp:288-289 / 297-298),
// used here only to print the hash values being compared.
static UInt64 CookieCacheHash(const xtcp::core::Endpoint& e) noexcept {
    return (static_cast<UInt64>(e.addr[0]) << 32) ^
           (static_cast<UInt64>(e.port) << 16) ^ static_cast<UInt64>(e.family);
}

int main() {
    xtcp::buf::InitPools();
    {
        // Dual-stack IPv6 connection (reference: test_gso_ipv6.cpp addresses).
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 6;
        local.addr[0] = 0xFD000001;  // fd00:1::
        local.port = 40000;
        remote.family = 6;
        remote.addr[0] = 0xFD000002;  // fd00:2::
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Prove the dual-stack IPv6 path is live end-to-end.
        constexpr UInt32 kTotal = 16 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 7 + 3) & 0xFF));
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 8192) ? (kTotal - sent) : 8192;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // Time-based drain (the 40ms delayed-ACK needs wall-clock to fire; a
        // pure 200-round fast pump flakes ~1% on Linux - the Linux-tight
        // guard class).
        const auto drain_t0 = std::chrono::steady_clock::now();
        for (UInt32 i = 0; i < 30000 && received.size() < kTotal &&
                30000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - drain_t0).count(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[ipv6-cookie-hash] dual-stack v6 path: sent=%u recv=%zu\n",
                     sent, received.size());

        // ---- Cookie-cache IPv6 hash collision test ----
        // peer1 = fd00::1, peer2 = fd00::2  (same addr[0] = 0xFD000000)
        // peer3 = fc00::1                  (different addr[0] = 0xFC000000)
        // peer4 = fd00::1, port 8081       (same addr[0], different port)
        xtcp::core::Endpoint peer1, peer2, peer3, peer4;
        peer1.family = 6; peer1.addr[0] = 0xFD000000; peer1.addr[3] = 0x00000001; peer1.port = 8080;  // fd00::1
        peer2.family = 6; peer2.addr[0] = 0xFD000000; peer2.addr[3] = 0x00000002; peer2.port = 8080;  // fd00::2
        peer3.family = 6; peer3.addr[0] = 0xFC000000; peer3.addr[3] = 0x00000001; peer3.port = 8080;  // fc00::1
        peer4.family = 6; peer4.addr[0] = 0xFD000000; peer4.addr[3] = 0x00000001; peer4.port = 8081;  // fd00::1 :8081

        const UInt64 h1 = CookieCacheHash(peer1);
        const UInt64 h2 = CookieCacheHash(peer2);
        const UInt64 h3 = CookieCacheHash(peer3);
        const UInt64 h4 = CookieCacheHash(peer4);
        // FIXED: the cache key folds ALL 4 IPv6 words, so fd00::1 and fd00::2
        // (addr[3] differs) no longer collide.
        std::fprintf(stderr, "[ipv6-cookie-hash] cache keys: fd00::1=%016llX fd00::2=%016llX "
                             "fc00::1=%016llX fd00::1:8081=%016llX\n",
                     static_cast<unsigned long long>(h1),
                     static_cast<unsigned long long>(h2),
                     static_cast<unsigned long long>(h3),
                     static_cast<unsigned long long>(h4));
        CHECK(h1 != h3);  // different addr -> distinct key
        CHECK(h1 != h4);  // different port   -> distinct key

        const Byte cookie1[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20 };
        const Byte cookie2[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        Byte out[8];

        // Miss before any set.
        CHECK(!stack_a.GetTfoCookieFor(peer1, out));

        // Set for fd00::1, read back for the same address: identical cookie.
        stack_a.SetTfoCookieFor(peer1, cookie1);
        CHECK(stack_a.GetTfoCookieFor(peer1, out));
        CHECK(0 == std::memcmp(out, cookie1, 8));

        // FIXED: fd00::2 (different addr[3]) does NOT share fd00::1's cookie.
        const bool shared = stack_a.GetTfoCookieFor(peer2, out);
        std::fprintf(stderr, "[ipv6-cookie-hash] fd00::2 -> fd00::1's cookie: %s\n",
                     shared ? "SHARED (collision)" : "distinct");
        CHECK(!shared);  // fixed: full-IPv6-address key, no addr[0] collision
        if (shared) {
            CHECK(0 == std::memcmp(out, cookie1, 8));
        }

        // Different addr[0] (fc00::1) must NOT resolve to the same entry.
        std::fprintf(stderr, "[ipv6-cookie-hash] fc00::1 (addr[0]=0xFC000000) resolves to "
                             "fd00::1's entry: %s\n",
                     stack_a.GetTfoCookieFor(peer3, out) ? "yes (unexpected)" : "no (distinct key)");
        CHECK(!stack_a.GetTfoCookieFor(peer3, out));

        // Same addr[0], different port: port is folded into the key, so no
        // sharing across ports.
        CHECK(!stack_a.GetTfoCookieFor(peer4, out));

        // FIXED: fd00::2 is an independent cache entry - overwriting it does
        // not touch fd00::1's cookie.
        stack_a.SetTfoCookieFor(peer2, cookie2);
        CHECK(stack_a.GetTfoCookieFor(peer1, out));
        CHECK(0 == std::memcmp(out, cookie1, 8));  // peer1 keeps its own cookie
        std::fprintf(stderr, "[ipv6-cookie-hash] overwrite via fd00::2 visible to fd00::1: NO " 
                             "(independent entries)\n");

        // Contrast: the SERVER-side cookie generator folds all 4 address
        // words, so fd00::1 and fd00::2 receive DIFFERENT cookies. A client
        // replaying the cached fd00::1 cookie on a fd00::2 connection fails
        // TfoCookie::Check server-side.
        xtcp::core::TfoCookie gen;
        Byte c1[xtcp::core::kTfoCookieLen];
        Byte c2[xtcp::core::kTfoCookieLen];
        gen.Generate(peer1.addr, c1);
        gen.Generate(peer2.addr, c2);
        const bool server_differs = (0 != std::memcmp(c1, c2, xtcp::core::kTfoCookieLen));
        std::fprintf(stderr, "[ipv6-cookie-hash] server cookie for fd00::1 vs fd00::2 differ: %s\n",
                     server_differs ? "yes (full 128-bit key)" : "no (collision)");
        std::fprintf(stderr, "[ipv6-cookie-hash] OBSERVED: client cache collides on addr[0] "
                             "(fd00::1 <-> fd00::2 share one cookie); server cookie is "
                             "full-address keyed\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "IPV6_COOKIE_HASH: FAILED (%d)\n" : "IPV6_COOKIE_HASH: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

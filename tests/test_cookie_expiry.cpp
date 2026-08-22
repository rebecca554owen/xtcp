/**
 * @file test_cookie_expiry.cpp
 * @brief SYN-cookie expiry: Verify's freshness window (stack.cpp passes a
 *        60 s window) must reject stale cookies and accept fresh ones.
 */

#include <xtcp/core/syncookies.h>

#include <cstdio>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestExpiryWindow() {
    xtcp::core::Syncookies sc;
    const UInt32 saddr = 0xC0A80101, daddr = 0x0A000002;
    const UInt16 sport = 40000, dport = 443;
    const UInt32 seq = 0x11223344;
    const UInt32 t1 = 1000000;  // issue time (monotonic seconds)
    const UInt32 window = 60;   // stack.cpp cookie freshness window
    const Byte mss_idx = 3;

    const UInt32 cookie = sc.Compute(saddr, daddr, sport, dport, seq, t1, mss_idx);
    CHECK(0 != cookie);

    // 30 s later: well inside the 60 s window -> accepted.
    {
        Byte mss = 0xFF;
        CHECK(sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq,
                        t1 + 30, window, mss));
        CHECK(mss_idx == mss);
    }
    // 59 s later: still inside -> accepted.
    {
        Byte mss = 0xFF;
        CHECK(sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq,
                        t1 + 59, window, mss));
    }
    // Exactly at the boundary (age == window): NOT stale, because the
    // implementation rejects only when age > window_sec.
    {
        Byte mss = 0xFF;
        CHECK(sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq,
                        t1 + 60, window, mss));
    }
    // 61 s later: just past the window -> rejected.
    {
        Byte mss = 0xFF;
        CHECK(!sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq,
                         t1 + 61, window, mss));
    }
    // 120 s later: far past the window -> stale, must be rejected.
    {
        Byte mss = 0xFF;
        CHECK(!sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq,
                         t1 + 120, window, mss));
    }
}

static void TestStaleAckSeq() {
    // A stale cookie must be rejected regardless of the ACK carrying it.
    xtcp::core::Syncookies sc;
    const UInt32 cookie = sc.Compute(1, 2, 3, 4, 100, 500, 2);
    Byte mss = 0;
    CHECK(!sc.Verify(cookie, cookie + 1, 1, 2, 3, 4, 100, 500 + 120, 60, mss));
}

int main() {
    TestExpiryWindow();
    TestStaleAckSeq();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_cookie_expiry: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_cookie_expiry: all passed\n");
    return 0;
}

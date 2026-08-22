/**
 * @file test_syncookies.cpp
 * @brief SYN cookies (RFC 4987) tests: round-trip, stale window, tamper
 *        rejection.
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

static void TestRoundTrip() {
    xtcp::core::Syncookies sc;
    const UInt32 saddr = 0xC0A80101, daddr = 0x0A000002;
    const UInt16 sport = 40000, dport = 443;
    const UInt32 seq = 0x11223344;
    const UInt32 time = 1000000;  // monotonic seconds (rolling)

    const UInt32 cookie = sc.Compute(saddr, daddr, sport, dport, seq, time, 4);
    CHECK(0 != cookie);

    Byte mss = 0xFF;
    CHECK(sc.Verify(cookie, cookie + 1, saddr, daddr, sport, dport, seq, time, 240, mss));
    CHECK(4 == mss);
}

static void TestWrongAckSeq() {
    xtcp::core::Syncookies sc;
    const UInt32 cookie = sc.Compute(1, 2, 3, 4, 100, 500, 1);
    Byte mss = 0;
    // ACK seq must equal cookie + 1.
    CHECK(!sc.Verify(cookie, cookie + 2, 1, 2, 3, 4, 100, 500, 240, mss));
}

static void TestStaleCookie() {
    xtcp::core::Syncookies sc;
    const UInt32 cookie = sc.Compute(1, 2, 3, 4, 100, 500, 2);
    Byte mss = 0;
    // 300s later with a 240s window: stale.
    CHECK(!sc.Verify(cookie, cookie + 1, 1, 2, 3, 4, 100, 500 + 300, 240, mss));
    // Within the window: valid.
    CHECK(sc.Verify(cookie, cookie + 1, 1, 2, 3, 4, 100, 500 + 100, 240, mss));
}

static void TestTampered() {
    xtcp::core::Syncookies sc;
    const UInt32 cookie = sc.Compute(1, 2, 3, 4, 100, 500, 3);
    Byte mss = 0;
    // Different peer sequence -> hash mismatch.
    CHECK(!sc.Verify(cookie, cookie + 1, 1, 2, 3, 4, 999, 500, 240, mss));
    // Different addresses -> mismatch.
    CHECK(!sc.Verify(cookie, cookie + 1, 9, 9, 3, 4, 100, 500, 240, mss));
}

static void TestMssVariants() {
    xtcp::core::Syncookies sc;
    for (Byte mss = 0; mss < 8; ++mss) {
        const UInt32 cookie = sc.Compute(7, 8, 9, 10, 200, 777, mss);
        Byte out = 0xFF;
        CHECK(sc.Verify(cookie, cookie + 1, 7, 8, 9, 10, 200, 777, 240, out));
        CHECK(mss == out);
    }
}

static void TestTimeWrap() {
    // The 24-bit time field wraps every ~194 days of uptime. The cookie
    // computed just BEFORE the wrap must verify just AFTER it (the age is
    // modular UInt32 subtraction, so the freshness window survives the
    // wrap). t1 = 2^24 - 30, verified at t1 + 40 (wrapped to ~10).
    xtcp::core::Syncookies sc;
    const UInt32 t1 = (1u << 24) - 30;
    const UInt32 cookie = sc.Compute(5, 6, 7, 8, 300, t1, 2);
    Byte mss = 0;
    CHECK(sc.Verify(cookie, cookie + 1, 5, 6, 7, 8, 300, t1 + 40, 240, mss));  // age 40 < 240
    CHECK(2 == mss);
    // Far past the window (age > 240) after the wrap must be rejected.
    CHECK(!sc.Verify(cookie, cookie + 1, 5, 6, 7, 8, 300, t1 + 300, 240, mss));
}

int main() {
    TestRoundTrip();
    TestWrongAckSeq();
    TestStaleCookie();
    TestTampered();
    TestMssVariants();
    TestTimeWrap();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_syncookies: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_syncookies: all passed\n");
    return 0;
}

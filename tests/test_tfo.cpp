/**
 * @file test_tfo.cpp
 * @brief TCP Fast Open (RFC 7413) tests: cookie round-trip, address
 *        binding, tamper rejection.
 */

#include <xtcp/core/tfo.h>

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestCookieRoundTrip() {
    xtcp::core::TfoCookie tfo;
    const UInt32 addr[4] = { 0xC0A80101, 0, 0, 0 };
    Byte cookie[xtcp::core::kTfoCookieLen];

    tfo.Generate(addr, cookie);
    CHECK(tfo.Check(addr, cookie));
}

static void TestAddressBinding() {
    xtcp::core::TfoCookie tfo;
    const UInt32 addr[4] = { 0xC0A80101, 0, 0, 0 };
    const UInt32 other[4] = { 0x0A000002, 0, 0, 0 };
    Byte cookie[xtcp::core::kTfoCookieLen];

    tfo.Generate(addr, cookie);
    CHECK(!tfo.Check(other, cookie));  // cookie bound to the address
}

static void TestTampered() {
    xtcp::core::TfoCookie tfo;
    const UInt32 addr[4] = { 1, 2, 3, 4 };
    Byte cookie[xtcp::core::kTfoCookieLen];

    tfo.Generate(addr, cookie);
    cookie[3] ^= 0xFF;  // flip a byte
    CHECK(!tfo.Check(addr, cookie));
}

static void TestIpv6Cookie() {
    xtcp::core::TfoCookie tfo;
    const UInt32 addr[4] = { 0x20010DB8, 0, 0, 1 };
    Byte cookie[xtcp::core::kTfoCookieLen];

    tfo.Generate(addr, cookie);
    CHECK(tfo.Check(addr, cookie));
    cookie[0] ^= 0x01;
    CHECK(!tfo.Check(addr, cookie));
}

int main() {
    TestCookieRoundTrip();
    TestAddressBinding();
    TestTampered();
    TestIpv6Cookie();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_tfo: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_tfo: all passed\n");
    return 0;
}

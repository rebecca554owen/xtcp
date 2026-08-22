/**
 * @file test_zc_probe.cpp
 * @brief Zero-copy probe tests: counting and reset.
 */

#include <xtcp/zc/zc_probe.h>

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

static void TestCount() {
    xtcp::zc::Reset();
    CHECK(0 == xtcp::zc::Count());
    CHECK(0 == xtcp::zc::Bytes());

    Byte src[64];
    Byte dst[64];
    std::memset(src, 0xAB, sizeof(src));

    xtcp::zc::CountedMemcpy(dst, src, 64);
    xtcp::zc::CountedMemcpy(dst, src, 32);
    CHECK(2 == xtcp::zc::Count());
    CHECK(96 == xtcp::zc::Bytes());
    CHECK(0 == std::memcmp(dst, src, 32));

    xtcp::zc::Reset();
    CHECK(0 == xtcp::zc::Count());
    CHECK(0 == xtcp::zc::Bytes());
}

int main() {
    TestCount();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_zc_probe: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_zc_probe: all passed\n");
    return 0;
}

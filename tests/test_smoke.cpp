/**
 * @file test_smoke.cpp
 * @brief Smoke test: library links and version is non-empty.
 */

#include <xtcp/xtcp.h>

#include <cstdio>
#include <cstring>

int main() {
    const char* version = xtcp::Version();
    if (NULLPTR == version) {
        std::fprintf(stderr, "FAIL: Version() returned null\n");
        return 1;
    }
    if (0 == std::strlen(version)) {
        std::fprintf(stderr, "FAIL: Version() returned empty string\n");
        return 1;
    }
    std::printf("PASS: xtcp version = %s\n", version);
    return 0;
}

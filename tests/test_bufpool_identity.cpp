/**
 * @file test_bufpool_identity.cpp
 * @brief Per-thread cache pool-identity: two BufPool instances sharing a
 *        tier index must never exchange blocks. The per-thread cache is
 *        indexed by tier index only; Acquire/Release must check that the
 *        cached blocks actually belong to the pool being used.
 */

#include <xtcp/buf/bufref.h>

#include <cstdio>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

int main() {
    // Two user pools with the same block size share the tier index (0).
    // Static storage: the per-thread cache flushes at thread exit, which
    // runs after main's locals are destroyed but before static objects -
    // heap/stack pools would be a use-after-return in the TLS destructor.
    static xtcp::buf::BufPool a(2048, 4);
    static xtcp::buf::BufPool b(2048, 4);
    CHECK(4 == a.Capacity());
    CHECK(4 == b.Capacity());

    // Fill thread A's per-thread cache slot with A's blocks.
    Byte* a0 = a.Acquire();
    Byte* a1 = a.Acquire();
    Byte* a2 = a.Acquire();
    Byte* a3 = a.Acquire();
    CHECK(NULLPTR != a0 && NULLPTR != a1 && NULLPTR != a2 && NULLPTR != a3);
    CHECK(0 == a.FreeCount());
    a.Release(a0);
    a.Release(a1);
    a.Release(a2);
    a.Release(a3);
    // All 4 cached in the thread-local slot (owner = pool a).
    CHECK(0 == a.FreeCount());

    // B must NEVER return A's blocks: B's own free list has exactly 4
    // blocks, so the 5th Acquire must fail. With the identity bug the
    // shared cache hands out A's blocks and B returns 8 distinct blocks.
    Byte* b0 = b.Acquire();
    Byte* b1 = b.Acquire();
    Byte* b2 = b.Acquire();
    Byte* b3 = b.Acquire();
    CHECK(NULLPTR != b0 && NULLPTR != b1 && NULLPTR != b2 && NULLPTR != b3);
    CHECK(NULLPTR == b.Acquire());  // B exhausted: never A's cached blocks

    b.Release(b0);
    b.Release(b1);
    b.Release(b2);
    b.Release(b3);

    // A's cached blocks must still be intact for A.
    Byte* a0b = a.Acquire();
    CHECK(NULLPTR != a0b);
    a.Release(a0b);

    if (0 < g_failures) {
        std::fprintf(stderr, "test_bufpool_identity: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_bufpool_identity: all passed\n");
    return 0;
}

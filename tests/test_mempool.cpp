/**
 * @file test_mempool.cpp
 * @brief Mempool tests: leak-free churn, disjoint blocks, reuse.
 */

#include <xtcp/core/mempool.h>

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void TestChurnNoLeak() {
    xtcp::core::Mempool pool(64, 1024);
    CHECK(1024 == pool.Capacity());
    CHECK(1024 == pool.FreeCount());

    std::vector<void*> blocks;
    for (UInt32 i = 0; i < 1024; ++i) {
        void* p = pool.Alloc();
        CHECK(NULLPTR != p);
        blocks.push_back(p);
    }
    CHECK(0 == pool.FreeCount());
    CHECK(NULLPTR == pool.Alloc());  // exhausted

    for (void* p : blocks) {
        pool.Free(p);
    }
    CHECK(1024 == pool.FreeCount());
}

static void TestReuse() {
    xtcp::core::Mempool pool(32, 4);
    void* a = pool.Alloc();
    void* b = pool.Alloc();
    void* c = pool.Alloc();
    void* d = pool.Alloc();
    CHECK(NULLPTR != a && NULLPTR != b && NULLPTR != c && NULLPTR != d);

    pool.Free(b);
    void* b2 = pool.Alloc();
    CHECK(b == b2);  // free-list reuse (LIFO)
    pool.Free(a);
    pool.Free(c);
    pool.Free(d);
    pool.Free(b2);
    CHECK(4 == pool.FreeCount());
}

static void TestDisjoint() {
    xtcp::core::Mempool pool(16, 8);
    std::vector<void*> blocks;
    for (int i = 0; i < 8; ++i) {
        blocks.push_back(pool.Alloc());
    }
    for (size_t i = 0; i < blocks.size(); ++i) {
        for (size_t j = i + 1; j < blocks.size(); ++j) {
            CHECK(blocks[i] != blocks[j]);
        }
    }
    for (void* p : blocks) {
        pool.Free(p);
    }
}

int main() {
    TestChurnNoLeak();
    TestReuse();
    TestDisjoint();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_mempool: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_mempool: all passed\n");
    return 0;
}

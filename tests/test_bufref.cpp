/**
 * @file test_bufref.cpp
 * @brief BufRef tests: refcount lifecycle, zero-copy move, pool return.
 */

#include <xtcp/buf/bufref.h>

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

static void TestAcquireAndRefcount() {
    xtcp::buf::InitPools();
    xtcp::buf::BufRef ref = xtcp::buf::BufRef::Acquire(2048);
    CHECK(!ref.IsEmpty());
    CHECK(1 == ref.UseCount());
    CHECK(2048 <= ref.Capacity());

    ref.Ref();
    CHECK(2 == ref.UseCount());
    ref.Unref();
    CHECK(1 == ref.UseCount());

    Byte* data = ref.Data();
    std::memcpy(data, "payload", 7);
    ref.SetLen(7);
    CHECK(7 == ref.Len());
    ref.Unref();  // refcount zero -> returned to pool
    CHECK(0 == ref.UseCount());
}

static void TestMoveNoCopy() {
    xtcp::buf::InitPools();
    xtcp::buf::BufRef ref = xtcp::buf::BufRef::Acquire(2048);
    CHECK(!ref.IsEmpty());
    Byte* original = ref.Data();
    std::memcpy(original, "keep-me", 7);
    ref.SetLen(7);

    xtcp::buf::BufRef moved = std::move(ref);  // transfer, no payload copy
    CHECK(1 == moved.UseCount());
    CHECK(original == moved.Data());           // same memory, zero copy
    CHECK(ref.IsEmpty());                      // source is now empty
    CHECK(0 == std::memcmp("keep-me", moved.Data(), 7));
    moved.Unref();
}

static void TestPoolReturnReuse() {
    xtcp::buf::InitPools();
    xtcp::buf::BufRef a = xtcp::buf::BufRef::Acquire(2048);
    CHECK(!a.IsEmpty());
    Byte* data_a = a.Data();
    a.Unref();

    xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(2048);
    CHECK(!b.IsEmpty());
    // Pool is LIFO: acquiring the same tier may return the same block.
    CHECK(data_a == b.Data());
    b.Unref();
}

static void TestSegMeta() {
    xtcp::buf::InitPools();
    xtcp::buf::BufRef ref = xtcp::buf::BufRef::Acquire(16384);
    CHECK(!ref.IsEmpty());
    ref.Meta().gso_size = 8192;
    ref.Meta().mss = 1460;
    ref.Meta().segs = 6;
    CHECK(8192 == ref.Meta().gso_size);
    CHECK(1460 == ref.Meta().mss);
    CHECK(6 == ref.Meta().segs);
    ref.Unref();
}

int main() {
    TestAcquireAndRefcount();
    TestMoveNoCopy();
    TestPoolReturnReuse();
    TestSegMeta();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_bufref: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_bufref: all passed\n");
    return 0;
}

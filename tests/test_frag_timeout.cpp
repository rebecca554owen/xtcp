/**
 * @file test_frag_timeout.cpp
 * @brief IP fragment reassembly table: timeout expiry (small timeout_us),
 *        max_sets eviction (small cap), and out-of-order fragments arriving
 *        mid-reassembly. Complements test_ip.cpp (reassembly success +
 *        duplicate rejection).
 */

#include <xtcp/core/ip.h>

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

static xtcp::core::FragKey MakeKey(Byte version, UInt32 src, UInt32 dst, UInt32 id) {
    xtcp::core::FragKey key;
    key.version = version;
    key.src[0] = src;
    key.dst[0] = dst;
    key.id = id;
    return key;
}

static void TestTimeoutSmallWindow() {
    xtcp::buf::InitPools();
    // Tiny timeout: any set idle longer than 1000us must be swept.
    xtcp::core::IpFragTable table(1000, 8);

    xtcp::core::FragKey key = MakeKey(4, 0xC0A80101, 0x0A000002, 0x1111);
    Byte payload[16];
    std::memset(payload, 0x33, sizeof(payload));
    xtcp::buf::BufRef out;
    xtcp::core::Fragment f;
    f.offset = 0; f.more = true; f.data = payload; f.len = 8;

    CHECK(0 == table.Add(1000, key, f, out));
    CHECK(1 == table.SetCount());

    // Fresh: now-last == timeout, not > timeout -> survives.
    CHECK(0 == table.Expire(2000));
    CHECK(1 == table.SetCount());

    // Past the timeout: the set must be expired and freed.
    CHECK(1 == table.Expire(2001));
    CHECK(0 == table.SetCount());

    // After expiry a new group may be created freely.
    CHECK(0 == table.Add(3000, key, f, out));
    CHECK(1 == table.SetCount());
    CHECK(1 == table.Expire(3000 + 1000 + 1));
    CHECK(0 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

static void TestMaxSetsEviction() {
    xtcp::buf::InitPools();
    // Only two concurrent reassembly groups allowed.
    xtcp::core::IpFragTable table(1'000'000, 2);

    Byte payload[16];
    std::memset(payload, 0x44, sizeof(payload));
    xtcp::buf::BufRef out;
    xtcp::core::Fragment f;
    f.offset = 0; f.more = true; f.data = payload; f.len = 8;

    xtcp::core::FragKey k1 = MakeKey(4, 0x01000001, 0x02000001, 0x21);
    xtcp::core::FragKey k2 = MakeKey(4, 0x03000001, 0x04000001, 0x22);
    CHECK(0 == table.Add(1000, k1, f, out));
    CHECK(0 == table.Add(2000, k2, f, out));
    CHECK(2 == table.SetCount());

    // Third distinct group exceeds max_sets_ -> rejected (fragment-bomb cap).
    xtcp::core::FragKey k3 = MakeKey(4, 0x05000001, 0x06000001, 0x23);
    CHECK(-1 == table.Add(3000, k3, f, out));
    CHECK(2 == table.SetCount());

    // Existing groups remain usable; completing k1 frees a slot.
    xtcp::core::Fragment tail;
    tail.offset = 1; tail.more = false; tail.data = payload + 8; tail.len = 8;
    CHECK(1 == table.Add(4000, k1, tail, out));
    CHECK(16 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 16));
    out.Unref();
    CHECK(1 == table.SetCount());

    // Slot reclaimed -> the previously rejected group is now accepted.
    CHECK(0 == table.Add(5000, k3, f, out));
    CHECK(2 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

static void TestOutOfOrderMidReassembly() {
    xtcp::buf::InitPools();
    xtcp::core::IpFragTable table(1'000'000, 8);

    xtcp::core::FragKey key = MakeKey(6, 0x20010DB8, 0x20010DB9, 0x99);
    Byte payload[64];
    for (UInt32 i = 0; i < sizeof(payload); ++i) {
        payload[i] = static_cast<Byte>(0xA0 + i);
    }
    xtcp::buf::BufRef out;

    // Tail arrives first; reassembly is pending, no output yet.
    xtcp::core::Fragment f2;
    f2.offset = 6; f2.more = false; f2.data = payload + 48; f2.len = 16;  // [48,64)
    CHECK(0 == table.Add(1000, key, f2, out));
    CHECK(1 == table.SetCount());  // pending set retained

    // Middle arrives second.
    xtcp::core::Fragment f1;
    f1.offset = 3; f1.more = true; f1.data = payload + 24; f1.len = 24;  // [24,48)
    CHECK(0 == table.Add(2000, key, f1, out));

    // Head completes the datagram; all units present -> reassembled.
    xtcp::core::Fragment f0;
    f0.offset = 0; f0.more = true; f0.data = payload; f0.len = 24;       // [0,24)
    CHECK(1 == table.Add(3000, key, f0, out));
    CHECK(!out.IsEmpty());
    CHECK(64 == out.Len());
    CHECK(0 == std::memcmp(payload, out.Data(), 64));
    out.Unref();
    CHECK(0 == table.SetCount());
    xtcp::buf::ShutdownPools();
}

int main() {
    TestTimeoutSmallWindow();
    TestMaxSetsEviction();
    TestOutOfOrderMidReassembly();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_frag_timeout: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_frag_timeout: all passed\n");
    return 0;
}

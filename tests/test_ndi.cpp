/**
 * @file test_ndi.cpp
 * @brief NDI tests: manual backend rx/tx round-trip, ordering, caps.
 */

#include <xtcp/ndi/manual.h>

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

static void TestInjectRx() {
    xtcp::ndi::ManualBackend backend;
    static const Byte payload[] = { 0x45, 0x00, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04 };
    bool received = false;

    backend.SetRxHandler([&](xtcp::ndi::Packet&& packet) {
        received = true;
        CHECK(8 == packet.len);
        CHECK(0x0800 == packet.eth_type);
        CHECK(NULLPTR != packet.data);
        CHECK(0 == std::memcmp(payload, packet.data, sizeof(payload)));
    });

    backend.Inject(payload, sizeof(payload), 0x0800);
    CHECK(received);
}

static void TestTxPoll() {
    xtcp::ndi::ManualBackend backend;
    static const Byte frame1[] = { 0xAA, 0xBB, 0xCC };
    static const Byte frame2[] = { 0x11, 0x22, 0x33, 0x44 };

    xtcp::ndi::Packet p1;
    p1.data = const_cast<Byte*>(frame1);
    p1.len = sizeof(frame1);
    p1.eth_type = 0x0800;
    backend.Tx(std::move(p1));

    xtcp::ndi::Packet p2;
    p2.data = const_cast<Byte*>(frame2);
    p2.len = sizeof(frame2);
    p2.eth_type = 0x86DD;
    backend.Tx(std::move(p2));

    CHECK(2 == backend.TxPending());

    Byte out[65536];
    UInt32 got = backend.PollTx(out);
    CHECK(3 == got);
    CHECK(0 == std::memcmp(frame1, out, 3));

    got = backend.PollTx(out);
    CHECK(4 == got);
    CHECK(0 == std::memcmp(frame2, out, 4));

    got = backend.PollTx(out);
    CHECK(0 == got);
    CHECK(0 == backend.TxPending());
}

static void TestCaps() {
    xtcp::ndi::ManualBackend backend;
    CHECK(xtcp::ndi::kCapNone == backend.Caps());
}

static void TestTxPollBatch() {
    xtcp::ndi::ManualBackend backend;
    // 5 frames of distinct sizes.
    for (UInt32 i = 1; i <= 5; ++i) {
        Byte frame[64];
        for (UInt32 j = 0; j < i; ++j) {
            frame[j] = static_cast<Byte>(i * 10 + j);
        }
        xtcp::ndi::Packet p;
        p.data = frame;
        p.len = i;
        p.eth_type = 0x0800;
        backend.Tx(std::move(p));
    }
    CHECK(5 == backend.TxPending());

    // Batch of 3: pops 3 packets in one lock.
    Byte out[65536];
    UInt32 lens[8];
    UInt32 n = backend.PollTxBatch(out, sizeof(out), lens, 3);
    CHECK(3 == n);
    UInt32 off = 0;
    for (UInt32 i = 1; i <= 3; ++i) {
        CHECK(i == lens[i - 1]);
        for (UInt32 j = 0; j < i; ++j) {
            CHECK(static_cast<Byte>(i * 10 + j) == out[off + j]);
        }
        off += i;
    }
    CHECK(2 == backend.TxPending());

    // Remaining 2 with a cap of 8.
    n = backend.PollTxBatch(out, sizeof(out), lens, 8);
    CHECK(2 == n);
    CHECK(4 == lens[0] && 5 == lens[1]);
    CHECK(0 == backend.TxPending());

    // Empty: 0.
    CHECK(0 == backend.PollTxBatch(out, sizeof(out), lens, 8));
}

int main() {
    TestInjectRx();
    TestTxPoll();
    TestCaps();
    TestTxPollBatch();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_ndi: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_ndi: all passed\n");
    return 0;
}

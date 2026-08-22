/**
 * @file test_txqueue_overflow.cpp
 * @brief ManualBackend drop-oldest bound (kTxQueueMax path): with a small
 *        cap configured, Tx/TxBatch must keep the queue length bounded and
 *        release the OLDEST packet, preserving only the newest packets.
 */

#include <xtcp/ndi/manual.h>

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

static xtcp::ndi::Packet MakePacket(Byte* storage, Byte value) noexcept {
    storage[0] = value;  // distinct buffer per packet; Tx copies synchronously
    xtcp::ndi::Packet p;
    p.data     = storage;
    p.len      = 1;
    p.eth_type = 0x0800;
    return p;
}

static void TestTxDropOldest() {
    xtcp::ndi::ManualBackend backend;
    backend.SetTxQueueCap(4);

    Byte bufs[5];
    for (UInt32 i = 0; i < 5; ++i) {
        backend.Tx(MakePacket(&bufs[i], static_cast<Byte>(i)));
        CHECK(backend.TxPending() <= 4);  // length bounded at all times
    }
    CHECK(4 == backend.TxPending());  // oldest (0) was released

    // Remaining queue holds the newest 4 packets, oldest first.
    Byte out[65536];
    for (UInt32 i = 1; i <= 4; ++i) {
        const UInt32 n = backend.PollTx(out);
        CHECK(1 == n);
        CHECK(i == out[0]);
    }
    CHECK(0 == backend.TxPending());
}

static void TestTxBatchDropOldest() {
    xtcp::ndi::ManualBackend backend;
    backend.SetTxQueueCap(4);

    Byte bufs[5];
    xtcp::ndi::Packet batch[5];
    for (UInt32 i = 0; i < 5; ++i) {
        batch[i] = MakePacket(&bufs[i], static_cast<Byte>(i));
    }
    // Drop-oldest never rejects: all 5 are accepted into the bounded queue,
    // and the bound is what evicts the oldest.
    CHECK(5 == backend.TxBatch(batch, 5));
    CHECK(4 == backend.TxPending());  // one evicted, queue capped at 4

    Byte out[65536];
    for (UInt32 i = 1; i <= 4; ++i) {
        const UInt32 n = backend.PollTx(out);
        CHECK(1 == n);
        CHECK(i == out[0]);  // oldest (0) dropped, newest 4 survive
    }
    CHECK(0 == backend.TxPending());
}

static void TestZeroCapDropsAll() {
    xtcp::ndi::ManualBackend backend;
    backend.SetTxQueueCap(0);
    Byte bufs[3];
    for (UInt32 i = 0; i < 3; ++i) {
        backend.Tx(MakePacket(&bufs[i], static_cast<Byte>(i)));
    }
    CHECK(0 == backend.TxPending());  // zero cap: nothing survives
    CHECK(0 == backend.TxBatch(NULLPTR, 0));
}

static void TestDefaultCapUnbounded() {
    xtcp::ndi::ManualBackend backend;
    // Default cap is far above any test volume: nothing is dropped.
    Byte bufs[5];
    for (UInt32 i = 0; i < 5; ++i) {
        backend.Tx(MakePacket(&bufs[i], static_cast<Byte>(i)));
    }
    CHECK(5 == backend.TxPending());
    Byte out[65536];
    for (UInt32 i = 0; i < 5; ++i) {
        const UInt32 n = backend.PollTx(out);
        CHECK(1 == n);
        CHECK(i == out[0]);
    }
}

int main() {
    TestTxDropOldest();
    TestTxBatchDropOldest();
    TestZeroCapDropsAll();
    TestDefaultCapUnbounded();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_txqueue_overflow: %d failure(s)\n", g_failures);
        return 1;
    }
    std::fprintf(stderr, "TXQUEUE_OVERFLOW: ALL PASSED\n");
    return 0;
}

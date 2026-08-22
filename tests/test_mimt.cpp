/**
 * @file test_mimt.cpp
 * @brief MIMT async flow tests: async dispatch guarantee (no synchronous
 *        reentry), read/write/close completions, 1:1 pairing rule.
 */

#include <xtcp/mimt/mimt.h>

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

static void TestAsyncReadDispatch() {
    xtcp::mimt::MimtFlow flow;
    bool completed = false;
    bool completed_in_rx = false;

    // Initiate an async read.
    Byte buf[64];
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncRead(buf, sizeof(buf),
                                                    [&](xtcp::mimt::Result, UInt32 n) {
                                                        completed = true;
                                                        completed_in_rx = false;
                                                        CHECK(5 == n);
                                                    }));

    // Second concurrent read must be rejected (1:1 pairing).
    Byte buf2[64];
    CHECK(xtcp::mimt::Result::kInFlight == flow.AsyncRead(buf2, sizeof(buf2), NULLPTR));

    // Feed data on the "rx path".
    const Byte data[] = { 'h', 'e', 'l', 'l', 'o' };
    flow.OnData(data, 5);

    // Completion must NOT fire yet (async dispatch guarantee).
    CHECK(!completed);

    // Dispatch fires the completion asynchronously.
    CHECK(0 < flow.Dispatch());
    CHECK(completed);
    CHECK(0 == std::memcmp(buf, data, 5));
}

static void TestAsyncReadWaitsForData() {
    xtcp::mimt::MimtFlow flow;
    bool completed = false;
    Byte buf[8];
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncRead(buf, sizeof(buf),
                                                    [&](xtcp::mimt::Result, UInt32 n) {
                                                        completed = true;
                                                        CHECK(3 == n);
                                                    }));
    // No data yet: dispatch does nothing.
    CHECK(0 == flow.Dispatch());
    CHECK(!completed);

    const Byte data[] = { 1, 2, 3 };
    flow.OnData(data, 3);
    flow.Dispatch();
    CHECK(completed);
    CHECK(0 == std::memcmp(buf, data, 3));
}

static void TestAsyncWrite() {
    xtcp::mimt::MimtFlow flow;
    bool sink_called = false;
    bool completed = false;
    std::vector<Byte> emitted;

    flow.SetWriteSink([&](const Byte* d, UInt32 n) {
        sink_called = true;
        emitted.assign(d, d + n);
        return true;
    });

    const Byte payload[] = { 'x', 't', 'c', 'p' };
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncWrite(payload, 4,
                                                     [&](xtcp::mimt::Result, UInt32 n) {
                                                         completed = true;
                                                         CHECK(4 == n);
                                                     }));
    // Write completion also dispatches asynchronously.
    CHECK(!completed);
    flow.Dispatch();
    CHECK(sink_called);
    CHECK(completed);
    CHECK(0 == std::memcmp(emitted.data(), payload, 4));
}

static void TestAsyncClose() {
    xtcp::mimt::MimtFlow flow;
    bool closed = false;
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncClose([&](xtcp::mimt::Result) { closed = true; }));
    CHECK(!closed);
    flow.Dispatch();
    CHECK(closed);
    CHECK(flow.IsClosed());

    // Operations on a closed flow are rejected.
    Byte buf[4];
    CHECK(xtcp::mimt::Result::kClosed == flow.AsyncRead(buf, 4, NULLPTR));
}

static void TestChunkedRead() {
    xtcp::mimt::MimtFlow flow;
    // Feed two chunks, then read once: the read FILLS TO THE REQUESTED
    // LENGTH from consecutive queued chunks (stream semantics - TCP is a
    // byte stream; wire segmentation must not leak into app reads). A
    // single-chunk fill here deadlocked real callers under ARM/QEMU
    // scheduling: a partial completion consumed the parked read while the
    // caller waited for its full length before re-parking.
    flow.OnData(reinterpret_cast<const Byte*>("abc"), 3);
    flow.OnData(reinterpret_cast<const Byte*>("de"), 2);
    Byte buf[8];
    UInt32 got = 0;
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncRead(buf, 8,
                                                    [&](xtcp::mimt::Result, UInt32 n) { got = n; }));
    flow.Dispatch();
    CHECK(5 == got);
    CHECK(0 == std::memcmp(buf, "abcde", 5));

    // Queue drained exactly: a second read parks and waits for new data.
    UInt32 got2 = 0;
    CHECK(xtcp::mimt::Result::kOk == flow.AsyncRead(buf, 8,
                                                    [&](xtcp::mimt::Result, UInt32 n) { got2 = n; }));
    flow.Dispatch();
    CHECK(0 == got2);  // still parked: nothing queued

    // Data arrives later: the PARKED read completes with a short read
    // (only 2 of the requested 8 bytes were available - short reads happen
    // exclusively when the queue runs out mid-request).
    flow.OnData(reinterpret_cast<const Byte*>("xy"), 2);
    Byte buf3[8] = {0};
    std::memcpy(buf, buf3, 0);  // no-op; keep buf naming clear
    flow.Dispatch();
    CHECK(2 == got2);
    CHECK(0 == std::memcmp(buf, "xy", 2));
}

int main() {
    TestAsyncReadDispatch();
    TestAsyncReadWaitsForData();
    TestAsyncWrite();
    TestAsyncClose();
    TestChunkedRead();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_mimt: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_mimt: all passed\n");
    return 0;
}

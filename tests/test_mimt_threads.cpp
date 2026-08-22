/**
 * @file test_mimt_threads.cpp
 * @brief MIMT thread-safety (BUG-2): a user thread issuing AsyncRead /
 *        AsyncWrite concurrently with an event-loop thread calling Dispatch()
 *        must not race - every accepted async operation completes exactly
 *        once (1:1 pairing), write ordering is preserved, and no state is
 *        corrupted. The flow mutex serializes all entry points; completion
 *        callbacks fire outside the lock so they may re-enter Async*.
 *
 *        Runs best under ASan (build-asan-win) which catches the memory
 *        races a plain build tolerates by luck.
 */

#include <xtcp/mimt/mimt.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kWrites = 2000;   // user-thread async writes
    constexpr UInt32 kChunk = 4096;    // rx chunk injected by the "wire"
    constexpr UInt32 kRounds = 20000;  // event-loop dispatch rounds
}

int main() {

    xtcp::mimt::MimtFlow flow;
    std::atomic<UInt32> write_ok = 0;   // completions with kOk
    std::atomic<UInt32> read_ok = 0;    // read completions with kOk
    std::atomic<UInt32> write_refused = 0;  // kInFlight / kClosed
    std::atomic<bool> done = false;

    // The "wire": the event-loop thread delivers data via OnData and drains
    // writes via the sink (which simply accepts everything).
    flow.SetWriteSink([](const Byte*, UInt32) { return true; });

    // 1:1 accounting: only ACCEPTED ops (Async* returned kOk) must complete
    // exactly once; kInFlight refusals (queue cap / read pending) are legal.
    std::atomic<UInt32> accepted_w = 0;
    std::atomic<UInt32> accepted_r = 0;

    // User thread: async writes with completion counting (1:1 check).
    // The AsyncRead buffers must OUTLIVE the completions (the docs require
    // it: "buf must survive until the completion fires" - completions run on
    // the event-loop thread, possibly long after the issuing thread moved
    // on), so they are heap-allocated up front, never stack locals.
    std::vector<std::vector<Byte>> read_bufs(kWrites, std::vector<Byte>(kChunk, 0));
    std::thread user([&]() {
        Byte buf[64];
        std::memset(buf, 0x7B, sizeof(buf));
        for (UInt32 i = 0; i < kWrites; ++i) {
            const xtcp::mimt::Result r = flow.AsyncWrite(
                buf, sizeof(buf), [&](xtcp::mimt::Result r2, UInt32 n) {
                    if (xtcp::mimt::Result::kOk == r2 && 64 == n) {
                        ++write_ok;
                    } else {
                        ++write_refused;
                    }
                });
            if (xtcp::mimt::Result::kOk == r) {
                ++accepted_w;
            } else {
                ++write_refused;
            }
            // AsyncRead ping-pong: a read must complete with the exact chunk.
            const xtcp::mimt::Result rr = flow.AsyncRead(
                read_bufs[i].data(), static_cast<UInt32>(read_bufs[i].size()),
                [&](xtcp::mimt::Result r2, UInt32 n) {
                    if (xtcp::mimt::Result::kOk == r2 && kChunk == n) {
                        ++read_ok;
                    }
                });
            if (xtcp::mimt::Result::kOk == rr) {
                ++accepted_r;
            }
        }
        done = true;
    });

    // Event-loop thread: inject data, dispatch completions.
    std::thread loop([&]() {
        Byte data[kChunk];
        std::memset(data, 0x3C, sizeof(data));
        for (UInt32 i = 0; i < kRounds && (write_ok.load() < accepted_w.load() || read_ok.load() < accepted_r.load()); ++i) {
            flow.OnData(data, sizeof(data));
            flow.Dispatch();
        }
    });

    user.join();
    loop.join();

    // After the user thread ends, no new reads can be accepted: keep
    // injecting data + dispatching until every accepted read completed.
    Byte tail[kChunk];
    std::memset(tail, 0x3C, sizeof(tail));
    for (UInt32 i = 0; i < 10000 && (write_ok.load() < accepted_w.load() || read_ok.load() < accepted_r.load()); ++i) {
        if (read_ok.load() < accepted_r.load()) {
            flow.OnData(tail, sizeof(tail));
        }
        flow.Dispatch();
    }

    std::fprintf(stderr,
                 "[mimt-threads] writes %u/%u reads %u/%u refused(kInFlight/cap)=%u\n",
                 write_ok.load(), accepted_w.load(), read_ok.load(), accepted_r.load(),
                 write_refused.load());
    CHECK(0 < accepted_w.load());       // the scenario actually exercised writes
    CHECK(0 < accepted_r.load());       // ... and reads
    CHECK(write_ok.load() == accepted_w.load());  // every accepted write completed exactly once
    CHECK(read_ok.load() == accepted_r.load());   // every accepted read completed exactly once

    flow.Close();
    std::fprintf(stderr, g_failures ? "MIMT_THREADS: FAILED (%d)\n" : "MIMT_THREADS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

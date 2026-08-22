/**
 * @file test_conn_stress.cpp
 * @brief Concurrent connection churn: many threads open/send/close flows on
 *        one XtcpStack over a ManualBackend. Verifies no data race, no crash,
 *        no state corruption (run under ASan for full effect).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#include <crtdbg.h>
#endif

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                 \
    } while (0)

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kClientV4 = 0x0A000001;
    constexpr UInt16 kPort     = 8080;
    constexpr UInt32 kThreads  = 8;
    constexpr UInt32 kPerThread = 200;   // connections per thread
    constexpr UInt32 kMsg      = 2048;

    std::atomic<UInt64> g_opened = 0;
    std::atomic<UInt64> g_closed = 0;
    std::atomic<UInt64> g_errors = 0;

    UInt32 PatternByte(UInt64 i) { return static_cast<Byte>((i * 29 + 11) & 0xFF); }
}

int main() {
#ifdef _MSC_VER
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
#endif
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        // Drain tx so the tx queue never grows unbounded.
        std::atomic<bool> stop = false;
        std::thread pump([&]() {
            Byte pkt[65536];
            while (!stop.load()) {
                while (0 < backend.PollTx(pkt)) {
                }
                stack.PollAckTimers();
            }
        });

        std::vector<std::thread> workers;
        for (UInt32 t = 0; t < kThreads; ++t) {
            workers.emplace_back([&stack, t]() {
                for (UInt32 i = 0; i < kPerThread; ++i) {
                    const UInt16 sport = static_cast<UInt16>(10000 + t * kPerThread + i);
                    xtcp::core::Endpoint local, remote;
                    local.family = 4;
                    local.addr[0] = kClientV4;
                    local.port = sport;
                    remote.family = 4;
                    remote.addr[0] = kServerV4;
                    remote.port = kPort;
                    const UInt64 id = stack.Connect(local, remote);
                    if (0 == id) {
                        ++g_errors;
                        continue;
                    }
                    ++g_opened;
                    std::vector<Byte> data(kMsg);
                    for (UInt32 j = 0; j < kMsg; ++j) {
                        data[j] = static_cast<Byte>(PatternByte(i * kMsg + j));
                    }
                    // Half the calls send; interleave closes to force churn.
                    if (0 == (i % 2)) {
                        stack.Send(id, data.data(), kMsg);
                    }
                    stack.Close(id);
                    ++g_closed;
                }
            });
        }
        for (auto& w : workers) {
            w.join();
        }
        stop.store(true);
        pump.join();
    }
    xtcp::buf::ShutdownPools();

    const UInt64 expect = kThreads * kPerThread;
    CHECK(g_opened == expect);
    CHECK(g_closed == expect);
    CHECK(0 == g_errors);
    std::fprintf(stderr, "test_conn_stress: opened=%llu closed=%llu errors=%llu %s\n",
                 (unsigned long long)g_opened.load(),
                 (unsigned long long)g_closed.load(),
                 (unsigned long long)g_errors.load(),
                 (0 == g_failures) ? "all passed" : "FAILED");
    return g_failures ? 1 : 0;
}

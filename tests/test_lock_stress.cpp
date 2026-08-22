/**
 * @file test_lock_stress.cpp
 * @brief Concurrent lock-stress: two back-to-back stacks driven by multiple
 *        threads simultaneously calling Send / OnPacket / PollTx / PollAckTimers.
 *        Verifies the shard/conn/backend lock order never deadlocks or
 *        livelocks (the test must finish; a deadlock hangs it), and that data
 *        flows correctly under contention.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                 \
    } while (0)

namespace {
    constexpr UInt32 kConns   = 8;
    constexpr UInt32 kRounds  = 3000;
    constexpr UInt32 kMsg     = 512;
    constexpr UInt32 kSenders = 4;

    std::atomic<bool> g_stop{false};
    std::atomic<UInt64> g_recv{0};
}

/** Pumps `from`'s tx queue into `to`'s rx handler. */
static void PumpOne(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte pkt[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending() && 4000 > ++guard) {
        const UInt32 got = from.PollTx(pkt);
        if (0 == got) {
            break;
        }
        to.Inject(pkt, got, 0x0800);
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend ba, bb;
        xtcp::XtcpStack sa(&ba), sb(&bb);

        sb.SetRecvHandler([](UInt64, const Byte*, UInt32 n) { g_recv += n; });

        // Listen on B; open kConns active connections from A.
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(sb.Listen(remote));

        std::vector<UInt64> conns;
        for (UInt32 i = 0; i < kConns; ++i) {
            xtcp::core::Endpoint local;
            local.family = 4;
            local.addr[0] = 0x0A000001;
            local.port = static_cast<UInt16>(10000 + i);
            const UInt64 id = sa.Connect(local, remote);
            CHECK(0 != id);
            conns.push_back(id);
            PumpOne(ba, bb);
            PumpOne(bb, ba);
            PumpOne(ba, bb);
        }

        // Senders: each thread sends on its own connection set (the conns
        // hash to different shards, so this exercises cross-shard parallelism).
        std::atomic<UInt64> sent{0};
        std::vector<std::thread> senders;
        for (UInt32 t = 0; t < kSenders; ++t) {
            senders.emplace_back([&sa, &conns, &sent, t]() {
                std::vector<Byte> data(kMsg);
                for (UInt32 j = 0; j < kMsg; ++j) {
                    data[j] = static_cast<Byte>((t * 31 + j) & 0xFF);
                }
                for (UInt32 r = 0; r < kRounds && !g_stop.load(); ++r) {
                    const UInt64 id = conns[(t + r) % kConns];
                    if (sa.Send(id, data.data(), kMsg)) {
                        sent += kMsg;
                    }
                }
            });
        }

        // Two pump threads: move A's tx to B and B's tx to A concurrently
        // (concurrent OnPacket + concurrent PollTx on both backends).
        std::vector<std::thread> pumps;
        for (UInt32 t = 0; t < 2; ++t) {
            pumps.emplace_back([&]() {
                while (!g_stop.load()) {
                    PumpOne(ba, bb);
                    PumpOne(bb, ba);
                    sa.PollAckTimers();
                    sb.PollAckTimers();
                }
            });
        }

        for (auto& s : senders) {
            s.join();
        }
        g_stop.store(true);
        for (auto& p : pumps) {
            p.join();
        }
        // Drain the remaining traffic.
        for (UInt32 i = 0; i < 8; ++i) {
            PumpOne(ba, bb);
            PumpOne(bb, ba);
            sa.PollAckTimers();
            sb.PollAckTimers();
        }
        CHECK(0 < sent.load());
        CHECK(0 < g_recv.load());
    }
    xtcp::buf::ShutdownPools();

    std::fprintf(stderr, "[lock] senders=%u rounds=%u recv=%llu\n",
                 kSenders, kRounds, (unsigned long long)g_recv.load());
    std::fprintf(stderr, g_failures ? "LOCK_STRESS: FAILED (%d)\n" : "LOCK_STRESS: ALL PASSED (no deadlock, no crash)\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

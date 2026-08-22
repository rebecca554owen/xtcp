/**
 * @file multi_thread.cpp
 * @brief Concurrency scaling: N threads inject segments for N distinct flows
 *        into one XtcpStack. Measures the effect of the stack-wide mutex.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kClientV4 = 0x0A000001;
    constexpr UInt16 kPort     = 8080;
    constexpr UInt32 kSegments = 200000;  // segments per worker (override via XTCP_BENCH_SEGS)
    constexpr UInt32 kMss      = 1460;

    struct WorkerCtx {
        xtcp::XtcpStack* stack;
        std::vector<Byte> seg;
        UInt64 processed = 0;
        Double seconds = 0.0;
    };

    /** Builds one IP+TCP data segment (seq=rcv_nxt fresh each time, no WS). */
    void FillSegment(std::vector<Byte>& seg, UInt16 sport, UInt32 seq, UInt32 ack, UInt32 payload_len) {
        seg.resize(40 + payload_len);
        Byte* ip = seg.data();
        ip[0] = 0x45;
        ip[1] = 0x00;
        const UInt16 total = static_cast<UInt16>(40 + payload_len);
        ip[2] = static_cast<Byte>(total >> 8); ip[3] = static_cast<Byte>(total & 0xFF);
        ip[4] = 0; ip[5] = 0;
        ip[6] = 0x40; ip[7] = 0;
        ip[8] = 64; ip[9] = 6;
        ip[10] = 0; ip[11] = 0;
        const UInt32 src = kClientV4, dst = kServerV4;
        ip[12] = static_cast<Byte>(src >> 24); ip[13] = static_cast<Byte>(src >> 16);
        ip[14] = static_cast<Byte>(src >> 8); ip[15] = static_cast<Byte>(src & 0xFF);
        ip[16] = static_cast<Byte>(dst >> 24); ip[17] = static_cast<Byte>(dst >> 16);
        ip[18] = static_cast<Byte>(dst >> 8); ip[19] = static_cast<Byte>(dst & 0xFF);
        Byte* t = ip + 20;
        t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
        t[2] = static_cast<Byte>(kPort >> 8); t[3] = static_cast<Byte>(kPort & 0xFF);
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = 0x50;
        t[13] = 0x18;  // ACK|PSH
        t[14] = 0xFF; t[15] = 0xFF;
    }
}

int main() {
    UInt32 segments = kSegments;
    if (const char* env = std::getenv("XTCP_BENCH_SEGS")) {
        segments = static_cast<UInt32>(std::strtoul(env, NULLPTR, 10));
    }
#ifdef _WIN32
    SetUnhandledExceptionFilter([](LPEXCEPTION_POINTERS ep) -> LONG {
        std::fprintf(stderr, "[crash] code=%08X address=%p\n",
                     ep->ExceptionRecord->ExceptionCode,
                     ep->ExceptionRecord->ExceptionAddress);
        std::fflush(stderr);
        void* frames[16];
        const USHORT n = CaptureStackBackTrace(1, 16, frames, NULL);
        for (USHORT f = 0; f < n; ++f) {
            std::fprintf(stderr, "  #%u %p\n", f, frames[f]);
        }
        std::fflush(stderr);
        return EXCEPTION_CONTINUE_SEARCH;
    });
#endif
    xtcp::buf::InitPools();
    std::vector<WorkerCtx> ctxs;
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        std::atomic<bool> stop = false;
        std::thread pump([&]() {
            Byte pkt[65536];
            (void)pkt;
            while (!stop.load()) {
                // Everything isolated for bisection: no PollTx, no ACK timers.
            }
        });

        // Two workers: 1 thread vs 8 threads, same total work.
        for (UInt32 n = 1; n <= 8; n *= 8) {
            std::vector<std::thread> workers;
            ctxs.clear();
            for (UInt32 i = 0; i < n; ++i) {
                WorkerCtx c;
                c.stack = &stack;
                ctxs.push_back(c);
            }
            const auto start = std::chrono::steady_clock::now();
            for (UInt32 i = 0; i < n; ++i) {
                workers.emplace_back([&ctxs, &stack, i, n, &segments]() {
                    WorkerCtx& c = ctxs[i];
                    const UInt16 sport = static_cast<UInt16>(20000 + i);
                    UInt32 seq = 1000 + i * 100000;
                    // The first segment must be a SYN so the stack opens a flow.
                    FillSegment(c.seg, sport, seq, 0, 0);
                    c.seg[20 + 13] = 0x02;  // SYN
                    xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire((UInt32)c.seg.size());
                    if (!b.IsEmpty()) {
                        std::memcpy(b.Data(), c.seg.data(), c.seg.size());
                        b.SetLen((UInt32)c.seg.size());
                        stack.OnPacket(std::move(b));
                    }
                    ++seq;
                    // Now stream data segments.
                    for (UInt32 k = 0; k < segments; ++k) {
                        FillSegment(c.seg, sport, seq, 100, kMss);
                        xtcp::buf::BufRef b2 = xtcp::buf::BufRef::Acquire((UInt32)c.seg.size());
                        if (!b2.IsEmpty()) {
                            std::memcpy(b2.Data(), c.seg.data(), c.seg.size());
                            b2.SetLen((UInt32)c.seg.size());
                            stack.OnPacket(std::move(b2));
                            ++c.processed;
                        }
                        seq += kMss;
                    }
                    std::fprintf(stderr, "worker[%u] done processed=%llu\n", i, (unsigned long long)c.processed);
                });
            }
            for (auto& w : workers) {
                w.join();
            }
            const auto end = std::chrono::steady_clock::now();
            const Double sec = std::chrono::duration<Double>(end - start).count();
            UInt64 total = 0;
            for (auto& c : ctxs) {
                total += c.processed;
            }
            const Double gbps = (0.0 < sec) ? (total * kMss * 8.0 / 1000000000.0 / sec) : 0.0;
            std::fprintf(stderr, "multi_thread: workers=%u segs=%llu sec=%.3f gbps=%.2f kpps=%.1f\n",
                         n, (unsigned long long)total, sec, gbps,
                         (0.0 < sec) ? (total / 1000.0 / sec) : 0.0);
        }
        stop.store(true);
        pump.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "multi_thread: done\n");
    return 0;
}

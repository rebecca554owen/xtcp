/**
 * @file bench_thread_e2e.cpp
 * @brief Threaded full-stack e2e throughput: N worker threads run complete
 *        TCP pipelines (handshake + bulk transfer) concurrently.
 *
 * Mode A (isolated): every worker owns its own stack pair + manual backends.
 *   No cross-thread lock contention - measures the per-core ceiling and
 *   aggregate scaling.
 * Mode B (shared): all workers share ONE stack pair (each its own conn).
 *   Measures real shard/flow lock contention at scale.
 *
 * Output: JSON lines (mode, workers, bytes, seconds, mbps, kpps).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {
    typedef std::chrono::steady_clock Clock;

    struct Bench {
        UInt64 bytes_sent = 0;
        UInt64 bytes_recv = 0;
        UInt64 pumps = 0;
    };

    void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to, UInt16 eth_type, Bench& bench) {
        // Batched drain: one backend lock serves up to 256 packets (the
        // per-packet PollTx lock was the dominant cost in the shared phase).
        Byte out[65536];
        UInt32 lens[256];
        for (;;) {
            const UInt32 n = from.PollTxBatch(out, sizeof(out), lens, 256);
            if (0 == n) {
                break;
            }
            UInt32 off = 0;
            for (UInt32 i = 0; i < n; ++i) {
                to.Inject(out + off, lens[i], eth_type);
                off += lens[i];
            }
            bench.pumps += n;
        }
    }

    // One complete transfer on an isolated stack pair. Returns Gbps.
    Double RunPipeline(UInt64 total_bytes, UInt32 chunk, UInt16 base_port) {
        xtcp::ndi::ManualBackend backend_a;
        xtcp::ndi::ManualBackend backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        Bench bench;
        UInt64 receiver_conn = 0;
        bool quickack_set = false;
        stack_b.SetRecvHandler([&bench, &receiver_conn](UInt64 conn_id, const Byte*, UInt32 len) {
            bench.bytes_recv += len;
            if (0 == receiver_conn) {
                receiver_conn = conn_id;
            }
        });

        const UInt16 eth_type = 0x0800;
        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = static_cast<UInt16>(30000 + base_port);
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = static_cast<UInt16>(20000 + base_port);

        stack_b.Listen(remote_a);
        const UInt64 conn = stack_a.Connect(local_a, remote_a);
        if (0 == conn) {
            return 0.0;
        }
        const Int32 on = 1;
        stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on));
        Pump(backend_a, backend_b, eth_type, bench);
        Pump(backend_b, backend_a, eth_type, bench);
        Pump(backend_a, backend_b, eth_type, bench);

        std::vector<Byte> payload(chunk);
        std::memset(payload.data(), 0x5A, payload.size());

        const auto start = Clock::now();
        UInt64 guard = 0;
        while (bench.bytes_recv < total_bytes) {
            bool sent_any = false;
            UInt32 inner = 0;
            while (bench.bytes_recv < total_bytes && bench.bytes_sent < total_bytes && inner < 1000000) {
                if (!stack_a.Send(conn, payload.data(), chunk)) {
                    break;
                }
                bench.bytes_sent += chunk;
                sent_any = true;
                Pump(backend_a, backend_b, eth_type, bench);
                Pump(backend_b, backend_a, eth_type, bench);
                ++inner;
            }
            if (!sent_any) {
                Pump(backend_b, backend_a, eth_type, bench);
                Pump(backend_a, backend_b, eth_type, bench);
            }
            if (0 != receiver_conn && !quickack_set) {
                stack_b.SetOption(receiver_conn, xtcp::options::kTcpQuickack, &on, sizeof(on));
                quickack_set = true;
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (1000000 < ++guard) {
                break;
            }
        }
        UInt32 drain_guard = 0;
        while (bench.bytes_recv < bench.bytes_sent && 1000000 > ++drain_guard) {
            Pump(backend_b, backend_a, eth_type, bench);
            Pump(backend_a, backend_b, eth_type, bench);
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
        const auto end = Clock::now();
        const Double seconds = std::chrono::duration<Double>(end - start).count();

        const Double mbps = (bench.bytes_recv * 8.0) / 1000000.0 / seconds;
        const Double kpps = (bench.pumps) / 1000.0 / seconds;
        std::printf("{\"mode\":\"iso\",\"worker\":%u,\"bytes\":%llu,\"seconds\":%.6f,\"mbps\":%.2f,\"kpps\":%.2f}\n",
                    base_port, (unsigned long long)bench.bytes_recv, seconds, mbps, kpps);
        return mbps;
    }

    // Shared-stack phase: N workers, ONE stack pair, one conn each.
    struct SharedCtx {
        xtcp::XtcpStack* stack;
        UInt64 conn = 0;
        std::vector<Byte> payload;
        UInt64 bytes_sent = 0;
        Double seconds = 0.0;
    };
}

int main(int argc, char** argv) {
    UInt64 total = 32ull * 1024 * 1024;  // per worker
    UInt32 chunk = 1024;
    UInt32 workers = 4;
    if (2 <= argc) {
        total = static_cast<UInt64>(std::strtoull(argv[1], NULLPTR, 10));
    }
    if (3 <= argc) {
        chunk = static_cast<UInt32>(std::strtoul(argv[2], NULLPTR, 10));
    }
    if (4 <= argc) {
        workers = static_cast<UInt32>(std::strtoul(argv[3], NULLPTR, 10));
    }
    xtcp::buf::InitPools();

    // Phase A: isolated pipelines (no cross-thread contention).
    std::vector<std::thread> threads;
    std::vector<Double> rates(workers, 0.0);
    const auto start_a = Clock::now();
    for (UInt32 w = 0; w < workers; ++w) {
        threads.emplace_back([total, chunk, w, &rates]() {
            rates[w] = RunPipeline(total, chunk, static_cast<UInt16>(w));
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    const Double sec_a = std::chrono::duration<Double>(Clock::now() - start_a).count();
    Double agg = 0.0;
    for (Double r : rates) {
        agg += r;
    }
    std::printf("{\"mode\":\"isolated\",\"workers\":%u,\"aggregate_mbps\":%.2f,\"wall_sec\":%.3f,\"sum_mbps\":%.2f}\n",
                workers, agg, sec_a, agg);

    // Phase B: shared stack pair (lock contention).
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        }
    });
    backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        }
    });
    std::atomic<UInt64> recv_total{0};
    stack_b.SetRecvHandler([&recv_total](UInt64, const Byte*, UInt32 len) {
        recv_total.fetch_add(len, std::memory_order_relaxed);
    });
    const Int32 qack_on = 1;
    stack_b.SetAcceptHandler([&stack_b, qack_on](UInt64 id, const xtcp::core::Endpoint&,
                                                 const xtcp::core::Endpoint&) {
        stack_b.SetOption(id, xtcp::options::kTcpQuickack, &qack_on, sizeof(qack_on));
        return true;
    });

    std::vector<SharedCtx> ctxs(workers);
    const UInt16 eth_type = 0x0800;
    for (UInt32 w = 0; w < workers; ++w) {
        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = static_cast<UInt16>(30000 + 100 + w);
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = static_cast<UInt16>(20000 + 100 + w);
        stack_b.Listen(remote_a);
        ctxs[w].stack = &stack_a;
        ctxs[w].conn = stack_a.Connect(local_a, remote_a);
        ctxs[w].payload.assign(chunk, 0x6B);
        const Int32 nd_on = 1;
        if (0 != ctxs[w].conn) {
            stack_a.SetOption(ctxs[w].conn, xtcp::options::kTcpNodelay, &nd_on, sizeof(nd_on));
        }
    }
    for (UInt32 w = 0; w < workers; ++w) {
        if (0 == ctxs[w].conn) {
            std::fprintf(stderr, "shared connect failed for worker %u\n", w);
            return 1;
        }
    }
    // Complete all handshakes BEFORE timing: otherwise the first transfers
    // stall on SYN/SYN+ACK that the pump has not delivered yet.
    Bench bench_hs;
    for (UInt32 r = 0; r < 100000; ++r) {
        bool all_established = true;
        for (const SharedCtx& c : ctxs) {
            if (xtcp::core::TcpState::kEstablished != c.stack->ConnectionState(c.conn)) {
                all_established = false;
                break;
            }
        }
        if (all_established) {
            break;
        }
        Pump(backend_a, backend_b, eth_type, bench_hs);
        Pump(backend_b, backend_a, eth_type, bench_hs);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
    }

    threads.clear();
    const auto start_b = Clock::now();
    for (UInt32 w = 0; w < workers; ++w) {
        threads.emplace_back([&ctxs, total, chunk, w]() {
            SharedCtx& c = ctxs[w];
            const auto t0 = Clock::now();
            const auto w_deadline = t0 + std::chrono::seconds(120);
            UInt32 fails = 0;
            while (c.bytes_sent < total && Clock::now() < w_deadline) {
                if (c.stack->Send(c.conn, c.payload.data(), chunk)) {
                    c.bytes_sent += chunk;
                    fails = 0;
                } else {
                    ++fails;
                    if (8 < fails) {
                        std::this_thread::yield();  // window full: back off
                    }
                }
            }
            c.seconds = std::chrono::duration<Double>(Clock::now() - t0).count();
        });
    }
    // Pump loop on the main thread. Runs until completion or a wall-clock
    // timeout (the single pump thread is the throughput ceiling for the
    // shared phase; under machine load it can fall behind, so a generous
    // timeout beats a fragile iteration guard).
    Bench bench_b;
    const auto pump_deadline = Clock::now() + std::chrono::seconds(60);
    UInt64 guard = 0;
    while (recv_total.load() < total * workers && Clock::now() < pump_deadline) {
        Pump(backend_a, backend_b, eth_type, bench_b);
        Pump(backend_b, backend_a, eth_type, bench_b);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        ++guard;
    }
    const bool pump_timed_out = (recv_total.load() < total * workers);
    if (pump_timed_out) {
        std::fprintf(stderr, "[shared] PUMP TIMEOUT guard=%llu recv=%llu want=%llu\n",
                     (unsigned long long)guard, (unsigned long long)recv_total.load(),
                     (unsigned long long)(total * workers));
        for (UInt32 w = 0; w < workers; ++w) {
            const SharedCtx& c = ctxs[w];
            UInt32 inflight = 0, cwnd = 0, ss = 0, wnd = 0, retx = 0;
            UInt64 rto = 0;
            UInt32 dup = 0, fr = 0, front = 0, una = 0;
            UInt16 lp = 0, rp = 0;
            if (0 != c.conn) {
                stack_a.ConnStats(c.conn, inflight, cwnd, ss, wnd, retx, rto, dup, fr, front, una, lp, rp);
            }
            std::fprintf(stderr, "[shared] TIMEOUT w%u sent=%llu inflight=%u cwnd=%u wnd=%u retx=%u rto=%llu dup=%u front=%u una=%u\n",
                         w, (unsigned long long)c.bytes_sent, inflight, cwnd, wnd, retx,
                         (unsigned long long)rto, dup, front, una);
        }
        xtcp::buf::ShutdownPools();
        return 3;
    }
    for (auto& t : threads) {
        t.join();
    }
    const Double sec_b = std::chrono::duration<Double>(Clock::now() - start_b).count();
    UInt64 sent_total = 0;
    for (UInt32 w = 0; w < workers; ++w) {
        const SharedCtx& c = ctxs[w];
        sent_total += c.bytes_sent;
        UInt32 inflight = 0, cwnd = 0, ss = 0, wnd = 0, retx = 0;
        UInt64 rto = 0;
        UInt32 dup = 0, fr = 0, front = 0, una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(c.conn, inflight, cwnd, ss, wnd, retx, rto, dup, fr, front, una, lp, rp);
        std::fprintf(stderr, "[shared] w%u sent=%llu sec=%.3f inflight=%u cwnd=%u wnd=%u retx=%u rto=%llu dup=%u\n",
                     w, (unsigned long long)c.bytes_sent, c.seconds,
                     inflight, cwnd, wnd, retx, (unsigned long long)rto, dup);
    }
    std::fprintf(stderr, "[shared] sent=%llu recv=%llu guard=%u\n",
                 (unsigned long long)sent_total, (unsigned long long)recv_total.load(), guard);
    if (sent_total != recv_total.load() || sent_total != total * workers) {
        std::fprintf(stderr, "SHARED PHASE INCOMPLETE: sent=%llu recv=%llu want=%llu\n",
                     (unsigned long long)sent_total, (unsigned long long)recv_total.load(),
                     (unsigned long long)(total * workers));
        return 2;
    }
    const Double mbps_b = (recv_total.load() * 8.0) / 1000000.0 / sec_b;
    std::printf("{\"mode\":\"shared\",\"workers\":%u,\"bytes\":%llu,\"seconds\":%.3f,\"mbps\":%.2f}\n",
                workers, (unsigned long long)recv_total.load(), sec_b, mbps_b);

    xtcp::buf::ShutdownPools();
    return 0;
}

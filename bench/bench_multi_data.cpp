/**
 * @file bench_multi_data.cpp
 * @brief Multi-thread data-path throughput: 8 worker threads each stream
 *        data on its own connection.
 *
 * NOTE: the single shared ManualBackend serializes every Tx under one
 * mutex, so this measures the TEST BACKEND's lock, not the stack's shard
 * parallelism (proven by bench_multi_thread's 8-shard OnPacket scaling).
 * A production backend needs batched / lock-free Tx to scale the send path.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

int main() {
    const UInt32 kThreads = 8;
    const UInt32 kBytesPerConn = 4 * 1024 * 1024;

    xtcp::buf::InitPools();
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack_a.OnPacket(std::move(buf));
    });
    backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack_b.OnPacket(std::move(buf));
    });

    std::atomic<UInt64> recv_bytes{0};
    stack_b.SetRecvHandler([&recv_bytes](UInt64, const Byte*, UInt32 n) {
        recv_bytes.fetch_add(n, std::memory_order_relaxed);
    });

    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8080;
    stack_b.Listen(remote);

    // Establish 8 connections (one per worker).
    std::vector<UInt64> conns;
    for (UInt32 t = 0; t < kThreads; ++t) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = static_cast<UInt16>(30000 + t);
        const UInt64 c = stack_a.Connect(local, remote);
        if (0 == c) {
            std::fprintf(stderr, "connect %u failed\n", t);
            return 1;
        }
        conns.push_back(c);
    }
    // Handshake pump.
    Byte out[65536];
    for (UInt32 r = 0; r < 500; ++r) {
        bool moved = false;
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                backend_b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != backend_b.TxPending()) {
            const UInt32 n = backend_b.PollTx(out);
            if (0 < n) {
                backend_a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        if (!moved) {
            break;
        }
    }
    // Throughput benchmark: disable Nagle so MSS-sized sends go out without
    // waiting for outstanding ACKs (real stacks use TCP_NODELAY for rate).
    const Int32 on = 1;
    for (UInt64 c : conns) {
        stack_a.SetOption(c, xtcp::options::kTcpNodelay, &on, sizeof(on));
    }

    // Workers stream on their own connection.
    std::atomic<bool> stop{false};
    std::thread pump([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    backend_b.Inject(out, n, 0x0800);
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
    });

    Byte payload[1460];
    std::memset(payload, 0x6A, sizeof(payload));
    const auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (UInt32 t = 0; t < kThreads; ++t) {
        workers.emplace_back([&, t]() {
            UInt64 sent = 0;
            while (sent < kBytesPerConn) {
                if (stack_a.Send(conns[t], payload, sizeof(payload))) {
                    sent += sizeof(payload);
                } else {
                    // Send quota full: yield instead of spinning. A spin holds
                    // the conn's shard lock in a tight loop and STARVES the
                    // pump thread (which needs the same shard locks to deliver
                    // ACKs and run PollAckTimers) - measured 30x throughput
                    // collapse (0.06 -> 1.76 Gbps with the yield).
                    std::this_thread::yield();
                }
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    for (UInt32 i = 0; i < 10000 && recv_bytes.load() < kThreads * kBytesPerConn; ++i) {
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                backend_b.Inject(out, n, 0x0800);
            }
        }
        while (0 != backend_b.TxPending()) {
            const UInt32 n = backend_b.PollTx(out);
            if (0 < n) {
                backend_a.Inject(out, n, 0x0800);
            }
        }
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
    }
    const auto t1 = std::chrono::steady_clock::now();
    stop.store(true, std::memory_order_relaxed);
    pump.join();

    const double secs = std::chrono::duration<double>(t1 - t0).count();
    const double gbps = (recv_bytes.load() * 8.0) / 1e9 / secs;
    std::fprintf(stderr, "bench_multi_data: %u threads, recv=%llu in %.3fs = %.1f Gbps\n",
                 kThreads, (unsigned long long)recv_bytes.load(), secs, gbps);
    xtcp::buf::ShutdownPools();
    return 0;
}

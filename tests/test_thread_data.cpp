/**
 * @file test_thread_data.cpp
 * @brief Concurrent data-plane integrity: multiple threads Send() on their
 *        own connections while a pump thread forwards the wire traffic;
 *        every flow's payload must arrive complete and byte-exact (per-flow
 *        CRC) - the sharded lock design must not corrupt concurrent streams.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
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

static constexpr UInt32 kThreads = 4;
static constexpr UInt32 kFlowsPerThread = 2;
static constexpr UInt32 kBytesPerFlow = 32768;

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                 std::atomic<bool>& stop) {
    Byte out[65536];
    while (!stop.load(std::memory_order_relaxed)) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    }
    // Final drain.
    while (0 != a.TxPending() || 0 != b.TxPending()) {
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x0800);
            }
        }
    }
}

int main() {
    xtcp::buf::InitPools();
    {
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

        // B-side flow bookkeeping: per-connection accepted id and CRC, with
        // the acceptance order recorded (single pump thread -> handshake
        // order matches the connect order, so order_b[i] is flow i).
        std::mutex mx;
        std::map<UInt64, UInt32> crc_b;
        std::vector<UInt64> order_b;
        stack_b.SetStateHandler([&mx, &crc_b, &order_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                std::lock_guard<std::mutex> g(mx);
                if (crc_b.end() == crc_b.find(id)) {
                    crc_b[id] = 0;
                    order_b.push_back(id);
                }
            }
        });
        stack_b.SetRecvHandler([&mx, &crc_b](UInt64 id, const Byte* d, UInt32 len) {
            std::lock_guard<std::mutex> g(mx);
            auto it = crc_b.find(id);
            if (it != crc_b.end()) {
                for (UInt32 j = 0; j < len; ++j) {
                    it->second = (it->second * 31 + d[j]) & 0x7FFFFFFF;
                }
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40091;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9097;
        CHECK(stack_b.Listen(remote));

        // Open kThreads*kFlowsPerThread connections.
        std::vector<UInt64> conn_a(kThreads * kFlowsPerThread);
        for (UInt32 t = 0; t < kThreads; ++t) {
            for (UInt32 f = 0; f < kFlowsPerThread; ++f) {
                xtcp::core::Endpoint l = local;
                l.port = static_cast<UInt16>(40091 + t * kFlowsPerThread + f);
                conn_a[t * kFlowsPerThread + f] = stack_a.Connect(l, remote);
                CHECK(0 != conn_a[t * kFlowsPerThread + f]);
            }
        }
        {
            std::atomic<bool> stop{false};
            std::thread pump(Pump, std::ref(backend_a), std::ref(backend_b),
                             std::ref(stack_a), std::ref(stack_b), std::ref(stop));
            for (UInt32 i = 0; i < 100 && crc_b.size() < kThreads * kFlowsPerThread; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            stop.store(true);
            pump.join();
        }
        CHECK(kThreads * kFlowsPerThread == crc_b.size());

        // Concurrent senders: each flow carries a distinct byte pattern.
        std::vector<std::vector<Byte>> payloads(kThreads * kFlowsPerThread);
        std::vector<UInt32> crc_expect(kThreads * kFlowsPerThread, 0);
        for (UInt32 f = 0; f < kThreads * kFlowsPerThread; ++f) {
            payloads[f].resize(kBytesPerFlow);
            for (UInt32 i = 0; i < kBytesPerFlow; ++i) {
                payloads[f][i] = static_cast<Byte>((i * (f + 3) + i / 13 + f) & 0xFF);
                crc_expect[f] = (crc_expect[f] * 31 + payloads[f][i]) & 0x7FFFFFFF;
            }
        }

        std::atomic<bool> stop{false};
        std::thread pump(Pump, std::ref(backend_a), std::ref(backend_b),
                         std::ref(stack_a), std::ref(stack_b), std::ref(stop));
        std::atomic<UInt64> total_sent{0};
        std::vector<std::thread> senders;
        for (UInt32 t = 0; t < kThreads; ++t) {
            senders.emplace_back([&, t]() {
                for (UInt32 f = 0; f < kFlowsPerThread; ++f) {
                    const UInt32 idx = t * kFlowsPerThread + f;
                    UInt64 sent = 0;
                    while (sent < kBytesPerFlow) {
                        UInt32 n = static_cast<UInt32>(kBytesPerFlow - sent);
                        if (n > 4096) {
                            n = 4096;
                        }
                        UInt32 g = 0;
                        while (!stack_a.Send(conn_a[idx], payloads[idx].data() + sent, n) &&
                               2000 > ++g) {
                            std::this_thread::sleep_for(std::chrono::microseconds(50));
                        }
                        sent += n;
                    }
                    total_sent.fetch_add(kBytesPerFlow);
                }
            });
        }
        // Wait for senders; the pump thread keeps running so the ACK clock
        // drives buffered sends to completion.
        for (auto& th : senders) {
            th.join();
        }
        for (UInt32 i = 0; i < 200; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        stop.store(true);
        pump.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        UInt32 ok = 0;
        {
            std::lock_guard<std::mutex> g(mx);
            for (UInt32 i = 0; i < order_b.size(); ++i) {
                const UInt32 idx = i % crc_expect.size();
                if (crc_b[order_b[i]] == crc_expect[idx]) {
                    ++ok;
                }
            }
        }
        std::fprintf(stderr, "[thread-data] flows=%zu crc_ok=%u\n", order_b.size(), ok);
        CHECK(kThreads * kFlowsPerThread == ok);

        for (UInt64 c : conn_a) {
            stack_a.Close(c);
        }
        for (auto& kv : crc_b) {
            stack_b.Close(kv.first);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "THREAD_DATA: FAILED (%d)\n" : "THREAD_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

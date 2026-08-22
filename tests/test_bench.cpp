/**
 * @file test_bench.cpp
 * @brief Throughput and latency baseline for the software data path over a
 *        ManualBackend (loopback). Serves as a performance checkpoint so
 *        later optimizations can be compared against a fixed number.
 *
 * RX delivery uses Inject(Packet&&) with owned pool buffers; the rx handler
 * adopts them without copying (zero-copy rx, mirroring the production data
 * path in stack.cpp). The loopback still pays one ManualBackend PollTx copy
 * (tx queue -> wire buffer) plus one harness re-own copy (wire -> pool
 * block), because PollTx only exposes a byte sink - there is no API to pop
 * the queued owned Packet. A true end-to-end zero-copy loopback would need
 * such an API; out of scope for this bench (single-file change).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/buf/bufref.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <mmsystem.h>
#if defined(_MSC_VER)
#pragma comment(lib, "winmm.lib")
#endif
#endif

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

// Delivers `data` to a backend as an owned pool buffer via Inject(Packet&&),
// so the rx handler can adopt it without copying (zero-copy rx). The payload
// is copied once here from the PollTx wire buffer into a pool block; on pool
// exhaustion the packet is dropped, matching the production rx path.
static void InjectOwned(xtcp::ndi::ManualBackend& backend, const Byte* data, UInt32 len) {
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(len);
    if (buf.IsEmpty()) {
        return;
    }
    std::memcpy(buf.Data(), data, len);
    buf.SetLen(len);
    xtcp::ndi::Packet packet;
    packet.data = buf.Data();
    packet.len = len;
    packet.eth_type = 0x0800;
    packet.owned = std::move(buf);
    backend.Inject(std::move(packet));
}

struct Harness {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a;
    xtcp::XtcpStack stack_b;
    UInt64 bytes_recv = 0;
    UInt64 conn = 0;

    Harness() : stack_a(&backend_a), stack_b(&backend_b) {
        // Zero-copy rx path, mirroring the production stack handler
        // (stack.cpp): an owned pool buffer is adopted without copying;
        // borrowed packets fall back to Acquire+memcpy.
        backend_a.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            if (NULLPTR == p.data || 0 == p.len) {
                return;
            }
            if (!p.owned.IsEmpty()) {
                p.owned.SetLen(p.len);
                stack_a.OnPacket(std::move(p.owned));
                return;
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            if (NULLPTR == p.data || 0 == p.len) {
                return;
            }
            if (!p.owned.IsEmpty()) {
                p.owned.SetLen(p.len);
                stack_b.OnPacket(std::move(p.owned));
                return;
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });
        stack_b.SetRecvHandler([this](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });
    }

    void Pump(UInt32 rounds = 1000) {
        Byte out[65536];
        for (UInt32 round = 0; round < rounds; ++round) {
            bool moved = false;
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    InjectOwned(backend_b, out, n);
                    moved = true;
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    InjectOwned(backend_a, out, n);
                    moved = true;
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (!moved) {
                return;
            }
        }
    }
};

int main() {
    xtcp::buf::InitPools();
    {
        Harness h;
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40001;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9090;
        CHECK(h.stack_b.Listen(remote));
        h.conn = h.stack_a.Connect(local, remote);
        CHECK(0 != h.conn);

        const auto t0 = std::chrono::steady_clock::now();
        h.Pump();
        const auto t1 = std::chrono::steady_clock::now();
        const double handshake_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::fprintf(stderr, "[bench] handshake: %.3f ms (3-way over loopback, incl. delayed-ACK)\n",
                     handshake_ms);

        // 1 MiB transfer. Send is window-gated; retry until accepted, drain
        // until B has everything. Real time advances via the 1 ms sleeps.
        // NOTE: on Windows the default timer resolution is ~15.6 ms, so
        // sleep_for(1ms) actually stalls ~15.6 ms per call - the window-gated
        // number would then measure the OS timer, not the stack. timeBeginPeriod
        // (winmm) restores 1 ms resolution for the timed section (the busy
        // path below proves the stack itself moves 1 MiB in ~1 ms).
#if defined(_WIN32)
        const MMRESULT timer_res = timeBeginPeriod(1);
#endif
        const UInt32 kTotal = 1024 * 1024;
        Byte payload[4096];
        std::memset(payload, 0x4C, sizeof(payload));
        const auto w0 = std::chrono::steady_clock::now();
        UInt64 accepted = 0;
        bool send_failed = false;
        for (UInt32 guard_all = 0; !send_failed && accepted < kTotal && 200000 > guard_all; ++guard_all) {
            UInt32 guard = 0;
            while (!h.stack_a.Send(h.conn, payload, sizeof(payload))) {
                h.Pump();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                if (500 <= ++guard) {
                    send_failed = true;
                    break;
                }
            }
            if (send_failed) {
                break;
            }
            accepted += sizeof(payload);
            h.Pump();
            if (0 == (guard_all % 100)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        const auto w1 = std::chrono::steady_clock::now();
        CHECK(kTotal == accepted && !send_failed);
        const double sec = std::chrono::duration<double>(w1 - w0).count();
        const double mbps = (accepted / 1048576.0) * 8.0 / sec;
        std::fprintf(stderr, "[bench] 1 MiB accepted in %.3f s -> %.1f Mbps (loopback, window-gated)\n",
                     sec, mbps);

        // Drain the buffered sends on the ACK clock.
        const auto d0 = std::chrono::steady_clock::now();
        while (h.bytes_recv < accepted) {
            h.Pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const auto d1 = std::chrono::steady_clock::now();
        CHECK(accepted == h.bytes_recv);
        const double drain_s = std::chrono::duration<double>(d1 - d0).count();
        std::fprintf(stderr, "[bench] drain %llu B delivered in %.3f s\n",
                     (unsigned long long)h.bytes_recv, drain_s);

        // Pure busy-pump data path: the same 1 MiB with no sleeps. The real
        // monotonic clock still advances (GetTickUs reads steady_clock), so
        // delayed-ACK/RTO clocks fire on schedule - this measures the CPU
        // cost of the data path itself, not the sleep cadence.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        UInt64 busy_accepted = 0;
        bool busy_send_failed = false;
        const auto b0 = std::chrono::steady_clock::now();
        for (UInt32 busy_guard = 0; !busy_send_failed && busy_accepted < kTotal && 2000000 > busy_guard; ++busy_guard) {
            UInt32 guard = 0;
            while (!h.stack_a.Send(h.conn, payload, sizeof(payload))) {
                h.Pump();
                if (500 <= ++guard) {
                    busy_send_failed = true;
                    break;
                }
            }
            if (busy_send_failed) {
                break;
            }
            busy_accepted += sizeof(payload);
            h.Pump();
        }
        const auto b1 = std::chrono::steady_clock::now();
        CHECK(kTotal == busy_accepted && !busy_send_failed);
        const double busy_s = std::chrono::duration<double>(b1 - b0).count();
        const double busy_mbps = (busy_accepted / 1048576.0) * 8.0 / busy_s;
        std::fprintf(stderr, "[bench] busy 1 MiB in %.3f s -> %.1f Mbps (pure data path, zero-copy rx, no sleeps)\n",
                     busy_s, busy_mbps);
        while (h.bytes_recv < accepted) {
            h.Pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // End-to-end echo latency (one round trip of a 64-byte payload after
        // the transfer, measured on the receive side).
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        h.stack_a.Send(h.conn, payload, 64);
        h.Pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        const auto e0 = std::chrono::steady_clock::now();
        h.stack_a.Send(h.conn, payload, 64);
        h.Pump();
        h.stack_a.PollAckTimers();
        h.stack_b.PollAckTimers();
        const auto e1 = std::chrono::steady_clock::now();
        const double echo_us = std::chrono::duration<double, std::micro>(e1 - e0).count();
        std::fprintf(stderr, "[bench] echo (local timed send->deliver): ~%.0f us\n", echo_us);

        h.stack_a.Close(h.conn);
        h.Pump();
#if defined(_WIN32)
        if (TIMERR_NOERROR == timer_res) {
            timeEndPeriod(1);
        }
#endif
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "BENCH: FAILED (%d)\n" : "BENCH: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

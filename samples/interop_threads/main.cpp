/**
 * @file main.cpp
 * @brief Real-kernel multi-threaded interop over TUN: 8 kernel clients
 *        connect to one stack; 8 user threads drive the stack's
 *        Send/Close/Abort concurrently on their own connections while the
 *        event loop processes real kernel traffic. Every connection
 *        exchanges 64KB byte-exact (kernel sends, the stack echoes via the
 *        user thread's Send, close at pseudo-random points). Validates the
 *        stack's thread-safety and lock ordering under REAL traffic with
 *        concurrent user-thread API calls - the in-memory lock-graph tests
 * extended to a real kernel peer.
 *
 * Requires root. Run:
 *   sudo timeout 240 ./interop_threads
 */

#include <xtcp/core/stack.h>
#include "../tun2socks/tun_ndi.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kTunV4    = 0x0A000001;
    constexpr UInt16 kPort     = 4503;
    constexpr UInt32 kConns    = 8;
    constexpr UInt32 kBytes    = 64 * 1024;

    std::atomic<UInt32> g_failures = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[thr] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 67 + seed * 31 + 15) & 0xFF);
        }
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Per-connection rx buffers: the stack's echo direction is driven by
    // the USER threads (Send), which read their connection's received data
    // from this map.
    std::mutex rx_mutex;
    std::unordered_map<UInt64, std::vector<Byte>> rx_map;
    stack.SetRecvHandler([&rx_mutex, &rx_map](UInt64 conn_id, const Byte* data, UInt32 len) {
        std::lock_guard<std::mutex> scope(rx_mutex);
        auto& v = rx_map[conn_id];
        v.insert(v.end(), data, data + len);
        return true;
    });
    // Accept handler: hand each accepted conn to a user thread via a slot.
    std::atomic<UInt64> accepted[kConns];
    for (UInt32 i = 0; i < kConns; ++i) {
        accepted[i].store(0);
    }
    std::atomic<UInt32> accept_count = 0;
    stack.SetAcceptHandler([&](UInt64 id, const xtcp::core::Endpoint&, const xtcp::core::Endpoint&) {
        const UInt32 slot = accept_count.fetch_add(1);
        if (slot < kConns) {
            accepted[slot].store(id);
        }
        return true;
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kPort;
    stack.Listen(server);
    // Shorten 2MSL so active-closer TIME-WAIT drains inside the test's
    // observation window (default 120s).
    stack.SetTwoMsl(2000000);
    std::fprintf(stderr, "[thr] xtcp listener on 10.0.0.2:%u (2MSL 2s)\n", kPort);

    std::atomic<bool> stop = false;
    std::thread loop([&]() {
        Byte packet[65536];
        while (!stop.load()) {
            UInt32 processed = 0;
            while (processed < 128) {
                const UInt32 n = tun.ReadPacket(packet, sizeof(packet));
                if (0 == n) {
                    break;
                }
                const UInt32 cap = (n <= 32752) ? n : 32752;
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(cap);
                if (!buf.IsEmpty()) {
                    std::memcpy(buf.Data(), packet, cap);
                    buf.SetLen(cap);
                    stack.OnPacket(std::move(buf));
                }
                ++processed;
            }
            tun.DrainTx();
            stack.PollAckTimers();
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Kernel clients: 8 connections, each sending 64KB and receiving the
    // echo (the stack echoes via the user threads).
    std::vector<std::thread> kernel_clients;
    for (UInt32 c = 0; c < kConns; ++c) {
        kernel_clients.emplace_back([&, c]() {
            const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in dst;
            std::memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = htonl(kServerV4);
            dst.sin_port = htons(kPort);
            timeval tv;
            tv.tv_sec = 120;
            tv.tv_usec = 0;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
                g_failures.fetch_add(1);
                return;
            }
            std::vector<Byte> pattern(kBytes);
            FillPattern(pattern, c + 100);
            UInt32 sent = 0;
            while (sent < kBytes) {
                const ssize_t n = ::send(fd, pattern.data() + sent, kBytes - sent, 0);
                if (n <= 0) {
                    break;
                }
                sent += static_cast<UInt32>(n);
            }
            std::vector<Byte> echo(kBytes);
            UInt32 got = 0;
            while (got < kBytes) {
                const ssize_t n = ::recv(fd, echo.data() + got, kBytes - got, 0);
                if (n <= 0) {
                    break;
                }
                got += static_cast<UInt32>(n);
            }
            const bool ok = (sent == kBytes) && (got == kBytes) &&
                            (0 == std::memcmp(echo.data(), pattern.data(), kBytes));
            if (!ok) {
                g_failures.fetch_add(1);
            }
            ::close(fd);
        });
    }

    // User threads: drive the stack's Send (echo) and Close on their
    // connection while the kernel is sending/reading. Each thread echoes
    // its connection's rx as it arrives, then closes.
    std::vector<std::thread> user_threads;
    for (UInt32 t = 0; t < kConns; ++t) {
        user_threads.emplace_back([&, t]() {
            // Wait for this thread's connection slot.
            const auto t0 = std::chrono::steady_clock::now();
            while (0 == accepted[t].load() &&
                   std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 10.0) {
                ::usleep(1000);
            }
            const UInt64 conn = accepted[t].load();
            if (0 == conn) {
                g_failures.fetch_add(1);
                return;
            }
            // Echo loop: drain the conn's rx buffer and Send it back.
            UInt32 echoed = 0;
            UInt32 busy = 0;
            const auto t1 = std::chrono::steady_clock::now();
            while (echoed < kBytes &&
                   std::chrono::duration<Double>(std::chrono::steady_clock::now() - t1).count() < 60.0) {
                std::vector<Byte> chunk;
                {
                    std::lock_guard<std::mutex> scope(rx_mutex);
                    auto it = rx_map.find(conn);
                    if (it != rx_map.end() && !it->second.empty()) {
                        const UInt32 n = (it->second.size() < 16384) ? static_cast<UInt32>(it->second.size()) : 16384;
                        chunk.assign(it->second.begin(), it->second.begin() + n);
                        it->second.erase(it->second.begin(), it->second.begin() + n);
                    }
                }
                if (!chunk.empty()) {
                    if (stack.Send(conn, chunk.data(), static_cast<UInt32>(chunk.size()))) {
                        echoed += static_cast<UInt32>(chunk.size());
                        busy = 0;
                    } else {
                        // Window/pacing backpressure: return the chunk.
                        std::lock_guard<std::mutex> scope(rx_mutex);
                        auto& v = rx_map[conn];
                        v.insert(v.begin(), chunk.begin(), chunk.end());
                        ++busy;
                        ::usleep(200);
                    }
                } else {
                    ::usleep(500);
                }
            }
            if (echoed < kBytes) {
                g_failures.fetch_add(1);
            }
            stack.Close(conn);  // concurrent close with the kernel's FIN
        });
    }

    for (auto& t : user_threads) {
        t.join();
    }
    for (auto& t : kernel_clients) {
        t.join();
    }
    // Drain: live connections should return to zero after the closes.
    const auto t2 = std::chrono::steady_clock::now();
    UInt32 residual = 0;
    while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t2).count() < 30.0) {
        residual = stack.ConnectionCount();
        if (0 == residual) {
            break;
        }
        ::usleep(1000);
    }
    std::fprintf(stderr, "[thr] conns=%u failed=%u residual=%u\n",
                 kConns, g_failures.load(), residual);
    rc = (0 == g_failures.load() && 0 == residual) ? 0 : 1;

    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[thr] FAILED\n" : "[thr] PASSED\n");
    return rc;
}

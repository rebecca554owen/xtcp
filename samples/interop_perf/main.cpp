/**
 * @file main.cpp
 * @brief Real throughput benchmark over TUN: kernel client -> xtcp server
 *        (one-way, no echo) vs pure kernel loopback, both 16 MB, timed.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "../tun2socks/tun_ndi.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kTunV4    = 0x0A000001;
    constexpr UInt16 kPort     = 4545;
    constexpr UInt64 kBytes    = 16ull * 1024 * 1024;  // 16 MB
    constexpr UInt32 kChunk    = 32768;

    std::atomic<UInt64> g_recv = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        tun.Open("xtcp0");
        tun.AssignAddress(kTunV4, 0xFFFFFF00);
        tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
    }

    Double KernelLoopback() noexcept {
        // Baseline: pure kernel TCP on loopback (127.0.0.1).
        const Int32 listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(4600);
        if (0 != ::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
            0 != ::listen(listen_fd, 4)) {
            ::close(listen_fd);
            return 0.0;
        }
        const Int32 cfd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (0 != ::connect(cfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
            ::close(cfd);
            ::close(listen_fd);
            return 0.0;
        }
        const Int32 sfd = ::accept(listen_fd, NULLPTR, NULLPTR);
        std::vector<Byte> buf(kChunk);
        std::memset(buf.data(), 0x11, buf.size());
        // Server drains in a thread; client sends concurrently.
        std::atomic<UInt64> got = 0;
        std::thread server_recv([&]() {
            while (got.load() < kBytes) {
                const ssize_t n = ::recv(sfd, buf.data(), kChunk, 0);
                if (n <= 0) {
                    break;
                }
                got += static_cast<UInt64>(n);
            }
        });
        const auto start = std::chrono::steady_clock::now();
        UInt64 sent = 0;
        while (sent < kBytes) {
            const ssize_t n = ::send(cfd, buf.data(), kChunk, 0);
            if (n <= 0) {
                break;
            }
            sent += static_cast<UInt64>(n);
        }
        server_recv.join();
        const auto end = std::chrono::steady_clock::now();
        ::close(cfd);
        ::close(sfd);
        ::close(listen_fd);
        const Double sec = std::chrono::duration<Double>(end - start).count();
        return (0.0 < sec) ? (got.load() * 8.0 / 1000000.0 / sec) : 0.0;
    }
}

int main(int argc, char** argv) {
    xtcp::buf::InitPools();
    std::vector<Byte> payload;  // silence
    (void)payload;
    // Result reported after the stack scope closes (BUG-6: no silent pass).
    UInt64 got = 0;
    bool ok = false;
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Optional per-algorithm run: argv[1] = cc name ("" default = KCC).
    if (2 <= argc && 0 != argv[1][0]) {
        stack.SetDefaultCongestionControl(argv[1]);
    }
    stack.SetRecvHandler([](UInt64, const Byte*, UInt32 len) {
        g_recv += len;
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kPort;
    stack.Listen(server);

    std::atomic<bool> stop = false;
    std::thread loop([&]() {
        // Zero-copy rx: read straight into a pool block (no intermediate copy).
        while (!stop.load()) {
            UInt32 processed = 0;
            while (processed < 128) {
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(16384);
                if (buf.IsEmpty()) {
                    break;
                }
                const UInt32 n = tun.ReadPacket(buf.Data(), 16384);
                if (0 == n) {
                    break;
                }
                buf.SetLen(n);
                stack.OnPacket(std::move(buf));
                ++processed;
            }
            tun.DrainTx();
            stack.PollAckTimers();
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Kernel client sends 16 MB to the xtcp server; the loop thread above
    // handles both RX delivery and TX drain, so no extra drain thread is
    // needed (the receiver just counts bytes in the recv handler).

    const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(kServerV4);
    dst.sin_port = htons(kPort);
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "connect fail errno=%d\n", errno);
        return 1;
    }
    std::vector<Byte> buf(kChunk);
    std::memset(buf.data(), 0x22, buf.size());
    const auto start = std::chrono::steady_clock::now();
    UInt64 sent = 0;
    while (sent < kBytes) {
        const ssize_t n = ::send(fd, buf.data(), kChunk, 0);
        if (n <= 0) {
            std::fprintf(stderr, "send fail at %llu errno=%d\n", (unsigned long long)sent, errno);
            break;
        }
        sent += static_cast<UInt64>(n);
    }
    // Wait for xtcp to receive all bytes.
    UInt64 guard = 0;
    while (g_recv.load() < kBytes && guard < 60000) {
        ::usleep(1000);
        ++guard;
    }
    const auto end = std::chrono::steady_clock::now();
    got = g_recv.load();
    const Double sec = std::chrono::duration<Double>(end - start).count();
    const Double mbps = (0.0 < sec) ? (got * 8.0 / 1000000.0 / sec) : 0.0;
    ok = (sent == kBytes) && (got == kBytes);
    std::fprintf(stderr, "XTCP: recv=%llu/%llu elapsed=%.3fs mbps=%.2f %s\n",
                 (unsigned long long)got, (unsigned long long)kBytes, sec, mbps,
                 ok ? "OK" : "INCOMPLETE");

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();

    const Double kernel = KernelLoopback();
    std::fprintf(stderr, "KERNEL loopback baseline mbps=%.2f\n", kernel);
    // Measurement example: report pass/fail from the transfer result instead
    // of silently succeeding regardless of what actually happened.
    std::fprintf(stderr, ok ? "PERF: PASSED (%llu/%llu bytes)\n"
                            : "PERF: FAILED (%llu/%llu bytes)\n",
                 (unsigned long long)got, (unsigned long long)kBytes);
    return ok ? 0 : 1;
}

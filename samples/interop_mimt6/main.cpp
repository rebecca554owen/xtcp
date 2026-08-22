/**
 * @file main.cpp
 * @brief Real-kernel IPv6 MIMT (async flow) interop over TUN: the stack runs in
 *        MIMT audit mode - every accepted connection becomes a MimtFlow
 *        whose AsyncRead/AsyncWrite echo the stream. The kernel client
 *        sends 256KB; the flow echoes it back byte-exact. Validates the
 *        async layer (flow acceptance, AsyncRead/AsyncWrite completion
 *        callbacks, DispatchMimt pumping, backpressure via the flow's rx
 *        queue) against a real kernel peer.
 *
 * Requires root. Run:
 *   sudo timeout 150 ./interop_mimt
 */

#include <xtcp/core/stack.h>
#include <xtcp/mimt/mimt.h>
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
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]     = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort     = 4499;
    constexpr UInt32 kBytes    = 256 * 1024;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::system("ip -6 addr replace fd00::1/64 dev xtcp0 2>/dev/null || true");
        const bool o3 = tun.BringUp();
        std::system("ip -6 route replace fd00::2/128 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[mimt] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, 1, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 53 + seed * 23 + 8) & 0xFF);
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
    // MIMT audit mode: every accepted connection is a MimtFlow. The flow
    // echoes every chunk it reads (chain: read -> write -> read).
    std::atomic<UInt64> echo_bytes = 0;
    std::atomic<UInt32> flow_count = 0;
    stack.StartMimt([&echo_bytes, &flow_count](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
        flow_count.fetch_add(1);
        // Chained async echo: read a chunk, write it back, read again.
        // The pump must be SELF-OWNING (shared_ptr<std::function>): a local
        // std::function capturing itself by reference dies when this callback
        // returns, leaving the flow's completion handlers a dangling target
        //.
        auto buf = std::make_shared<std::vector<Byte>>(16384);
        auto pump = std::make_shared<std::function<void()>>();
        *pump = [flow, buf, &echo_bytes, pump]() {
            flow->AsyncRead(buf->data(), static_cast<UInt32>(buf->size()),
                            [flow, buf, &echo_bytes, pump](xtcp::mimt::Result ec, UInt32 n) {
                if (xtcp::mimt::Result::kOk != ec || 0 == n) {
                    return;  // EOF / closed
                }
                echo_bytes.fetch_add(n);
                flow->AsyncWrite(buf->data(), n,
                                 [flow, pump](xtcp::mimt::Result ec2, UInt32) {
                    if (xtcp::mimt::Result::kOk == ec2) {
                        (*pump)();  // continue the echo chain
                    }
                });
            });
        };
        (*pump)();
    });
    xtcp::core::Endpoint server;
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[mimt] xtcp MIMT listener on fd00::2:%u\n", kPort);

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
            stack.DispatchMimt();  // pump the async flow completions
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Kernel client: send 256KB, receive the echo, verify byte-exact.
    const Int32 fd = ::socket(AF_INET6, SOCK_STREAM, 0);
    sockaddr_in6 dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    for (UInt32 w = 0; w < 4; ++w) {
        const UInt32 v = kServerV4[w];
        dst.sin6_addr.s6_addr[w * 4 + 0] = static_cast<Byte>(v >> 24);
        dst.sin6_addr.s6_addr[w * 4 + 1] = static_cast<Byte>(v >> 16);
        dst.sin6_addr.s6_addr[w * 4 + 2] = static_cast<Byte>(v >> 8);
        dst.sin6_addr.s6_addr[w * 4 + 3] = static_cast<Byte>(v & 0xFF);
    }
    dst.sin6_port = htons(kPort);
    timeval tv;
    tv.tv_sec = 120;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "[mimt] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::vector<Byte> pattern(kBytes);
    FillPattern(pattern, 21);
    const auto start = std::chrono::steady_clock::now();
    UInt32 sent = 0;
    while (sent < kBytes) {
        const ssize_t n = ::send(fd, pattern.data() + sent, kBytes - sent, 0);
        if (n <= 0) {
            std::fprintf(stderr, "[mimt] send fail at %u errno=%d\n", sent, errno);
            break;
        }
        sent += static_cast<UInt32>(n);
    }
    std::vector<Byte> echo(kBytes);
    UInt32 got = 0;
    while (got < kBytes) {
        const ssize_t n = ::recv(fd, echo.data() + got, kBytes - got, 0);
        if (n <= 0) {
            std::fprintf(stderr, "[mimt] recv fail at %u errno=%d\n", got, errno);
            break;
        }
        got += static_cast<UInt32>(n);
    }
    const auto end = std::chrono::steady_clock::now();
    const Double sec = std::chrono::duration<Double>(end - start).count();
    const bool match = (sent == kBytes) && (got == kBytes) &&
                       (0 == std::memcmp(echo.data(), pattern.data(), kBytes)) &&
                       (echo_bytes.load() >= kBytes);
    const Double mbps = (0.0 < sec) ? (got * 8.0 / 1000000.0 / sec) : 0.0;
    std::fprintf(stderr, "[mimt] sent=%u recv=%u match=%d flows=%u echo=%llu mbps=%.1f\n",
                 sent, got, match ? 1 : 0, flow_count.load(),
                 (unsigned long long)echo_bytes.load(), mbps);
    rc = match ? 0 : 1;

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[mimt] FAILED\n" : "[mimt] PASSED\n");
    return rc;
}

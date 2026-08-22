/**
 * @file main.cpp
 * @brief Real IPv6 latency/jitter benchmark over TUN: kernel client <-> xtcp echo.
 *        Reports RTT P50/P95/P99 and jitter for small-message round-trips.
 */

#include <xtcp/core/stack.h>
#include "../tun2socks/tun_ndi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <numeric>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]     = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort     = 4455;
    constexpr UInt32 kMsgSize  = 1024;
    constexpr UInt32 kRounds   = 2000;

    std::atomic<UInt64> g_recv = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        tun.Open("xtcp0");
        std::system("ip -6 addr add fd00::1/64 dev xtcp0 2>/dev/null || true");
        tun.BringUp();
        std::system("ip route add fd00::2/128 dev xtcp0 2>/dev/null || true");
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Echo with backpressure: a TCP app must buffer and retry when the send
    // window/cwnd is full (Send returns false). Dropping on failure silently
    // loses round-trips once congestion control gates the send path.
    std::unordered_map<UInt64, std::deque<std::vector<Byte>>> pending;
    std::mutex pending_mutex;
    auto flush_pending = [&stack, &pending, &pending_mutex]() {
        std::lock_guard<std::mutex> scope(pending_mutex);
        for (auto it = pending.begin(); it != pending.end();) {
            bool progress = true;
            while (progress && !it->second.empty()) {
                auto& front = it->second.front();
                if (stack.Send(it->first, front.data(), static_cast<UInt32>(front.size()))) {
                    it->second.pop_front();
                } else {
                    progress = false;  // this conn is window/pacing-limited
                }
            }
            if (it->second.empty()) {
                it = pending.erase(it);
            } else {
                ++it;
            }
        }
    };
    stack.SetRecvHandler([&pending, &pending_mutex, &flush_pending](UInt64 conn_id, const Byte* data, UInt32 len) {
        g_recv += len;
        {
            std::lock_guard<std::mutex> scope(pending_mutex);
            pending[conn_id].emplace_back(data, data + len);
        }
        flush_pending();
    });
    xtcp::core::Endpoint server;
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);

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
                // TUN frames are <= MTU (1500) + headers; the largest pool
                // tier is 32768 bytes with a 16-byte header, so the max
                // allocatable is 32752. Clamp: requesting more than that
                // always returns empty (silent packet drop).
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
            flush_pending();  // retry blocked echo sends when windows open (pure-ACK arrivals don't fire the recv handler)
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

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
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "connect fail errno=%d\n", errno);
        return 1;
    }
    std::vector<Byte> buf(kMsgSize);
    for (UInt32 i = 0; i < kMsgSize; ++i) {
        buf[i] = static_cast<Byte>((i * 17 + 3) & 0xFF);
    }
    std::vector<Double> rtts;
    rtts.reserve(kRounds);
    UInt32 fails = 0;
    for (UInt32 r = 0; r < kRounds; ++r) {
        const auto t0 = std::chrono::steady_clock::now();
        const ssize_t s = ::send(fd, buf.data(), kMsgSize, 0);
        if (s != (ssize_t)kMsgSize) {
            ++fails;
            continue;
        }
        std::vector<Byte> echo(kMsgSize);
        UInt32 got = 0;
        while (got < kMsgSize) {
            const ssize_t n = ::recv(fd, echo.data() + got, kMsgSize - got, 0);
            if (n <= 0) {
                break;
            }
            got += static_cast<UInt32>(n);
        }
        const auto t1 = std::chrono::steady_clock::now();
        if (got == kMsgSize && 0 == std::memcmp(echo.data(), buf.data(), kMsgSize)) {
            const Double us = std::chrono::duration<Double, std::micro>(t1 - t0).count();
            rtts.push_back(us);
        } else {
            ++fails;
        }
    }
    ::close(fd);
    stop.store(true);
    loop.join();

    std::sort(rtts.begin(), rtts.end());
    const UInt32 n = static_cast<UInt32>(rtts.size());
    const Double mean = (0 < n) ? (std::accumulate(rtts.begin(), rtts.end(), 0.0) / n) : 0.0;
    const Double p50 = (0 < n) ? rtts[static_cast<UInt32>(0.50 * (n - 1))] : 0.0;
    const Double p95 = (0 < n) ? rtts[static_cast<UInt32>(0.95 * (n - 1))] : 0.0;
    const Double p99 = (0 < n) ? rtts[static_cast<UInt32>(0.99 * (n - 1))] : 0.0;
    Double var = 0.0;
    for (Double v : rtts) {
        var += (v - mean) * (v - mean);
    }
    const Double stddev = (1 < n) ? std::sqrt(var / (n - 1)) : 0.0;
    std::fprintf(stderr,
                 "[latency] rounds=%u fails=%u mean=%.1fus p50=%.1fus p95=%.1fus p99=%.1fus jitter(stddev)=%.1fus\n",
                 n, fails, mean, p50, p95, p99, stddev);
    rc = (0 == fails && 0 < rtts.size()) ? 0 : 1;
    }
    xtcp::buf::ShutdownPools();
    return rc;
}

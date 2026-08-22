/**
 * @file main.cpp
 * @brief Real-kernel connection churn interop over TUN: rapid
 *        connect/transfer/close cycles against the stack - the kernel
 *        client opens N short-lived connections (sequential + concurrent
 *        batches), each carrying a byte-exact echo, then closes. Validates
 *        the stack's TIME-WAIT management, 4-tuple reuse, ephemeral-port
 *        handling and connection reclaim against a real kernel peer.
 *        Asserted:
 *          - every connection's echo completes byte-exact,
 *          - the stack's live-connection count returns to zero after the
 *            churn drains (TIME-WAIT reclamation), not growing with each
 *            cycle.
 *
 * Requires root. Run:
 *   sudo timeout 240 ./interop_churn
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
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]     = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort     = 4501;
    constexpr UInt32 kConns    = 300;
    constexpr UInt32 kBatch    = 8;       // concurrent batch size
    constexpr UInt32 kBytes    = 16 * 1024;

    int g_failures = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::system("ip -6 addr replace fd00::1/64 dev xtcp0 2>/dev/null || true");
        const bool o3 = tun.BringUp();
        std::system("ip -6 route replace fd00::2/128 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[churn] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, 1, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 61 + seed * 29 + 11) & 0xFF);
        }
    }

    // One kernel connection: connect, send kBytes, receive the echo,
    // verify byte-exact, close. Returns 0 on full success.
    Int32 OneConn(UInt32 seed) noexcept {
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
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
            ::close(fd);
            return 1;
        }
        std::vector<Byte> pattern(kBytes);
        FillPattern(pattern, seed);
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
        ::close(fd);
        return ok ? 0 : 2;
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
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
                    progress = false;
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
        {
            std::lock_guard<std::mutex> scope(pending_mutex);
            pending[conn_id].emplace_back(data, data + len);
        }
        flush_pending();
    });
    // The app owns the close: when the kernel's FIN arrives (CLOSE-WAIT),
    // close our side so the handshake completes and TIME-WAIT drains.
    stack.SetStateHandler([&stack](UInt64 conn_id, xtcp::core::TcpState state) {
        if (xtcp::core::TcpState::kCloseWait == state) {
            stack.Close(conn_id);
        }
    });
    xtcp::core::Endpoint server;
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[churn] xtcp listener on fd00::2:%u\n", kPort);

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
            flush_pending();
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Churn: sequential + concurrent batches of short connections.
    std::atomic<UInt32> failed = 0;
    for (UInt32 b = 0; b < kConns; b += kBatch) {
        std::vector<std::thread> batch;
        const UInt32 n_batch = (kConns - b < kBatch) ? (kConns - b) : kBatch;
        for (UInt32 i = 0; i < n_batch; ++i) {
            const UInt32 seed = b + i;
            batch.emplace_back([&failed, seed]() {
                if (0 != OneConn(seed)) {
                    failed.fetch_add(1);
                }
            });
        }
        for (auto& t : batch) {
            t.join();
        }
    }
    // Let the last close handshakes drain, then check the live-connection
    // count returns to zero (TIME-WAIT reclamation).
    const auto t0 = std::chrono::steady_clock::now();
    UInt32 conns = 0;
    while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 30.0) {
        conns = stack.ConnectionCount();
        if (0 == conns) {
            break;
        }
        ::usleep(1000);
    }
    std::fprintf(stderr, "[churn] conns=%u/%u failed=%u residual=%u\n",
                 kConns, kConns, failed.load(), conns);
    rc = (0 == failed.load() && 0 == conns) ? 0 : 1;

    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[churn] FAILED\n" : "[churn] PASSED\n");
    return rc;
}

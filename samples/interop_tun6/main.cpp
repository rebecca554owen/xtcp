/**
 * @file main.cpp
 * @brief Real kernel-stack IPv6 interop via TUN: a Linux kernel client
 *        connects to an xtcp IPv6 listener and performs a byte-verified
 *        echo round-trip, exercising the stack's IPv6 RX/TX paths
 *        (parse, checksum, GSO) against a real kernel for the first time.
 *
 * Topology:
 *   TUN iface xtcp0: fd00::1/64 (kernel side)
 *   xtcp listener:  fd00::2:4456 (virtual, routed into the TUN)
 *
 * Requires root. Run:
 *   sudo ./interop_tun6
 */

#include <xtcp/core/stack.h>
#include "../tun2socks/tun_ndi.h"

#include <atomic>
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
    constexpr UInt16 kPort = 4456;        // xtcp IPv6 listener
    constexpr UInt16 kKernelPort = 4457;  // kernel IPv6 server
    constexpr UInt32 kX2K = 256 * 1024;   // X2K payload size
    // Host-order UInt32 words (the stack's Endpoint.addr representation):
    // fd00::2 (xtcp virtual) and fd00::1 (TUN iface).
    constexpr UInt32 kXServerV6[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV6[4]     = { 0xFD000000, 0, 0, 0x00000001 };

    std::atomic<UInt64> g_recv = 0;
    std::atomic<UInt64> g_echo_ok = 0;
    std::atomic<UInt64> g_echo_fail = 0;
    std::atomic<UInt64> g_x2k_recv = 0;
    std::atomic<UInt64> g_x2k_sent = 0;

    void SetupTun6(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::fprintf(stderr, "[tun6] open=%d name=%s\n", o1 ? 1 : 0, tun.Name());
        // IPv6 address assignment: the SIOCSIFADDR ioctl path is unreliable
        // for AF_INET6 on modern kernels (the ifreq union cannot hold a
        // sockaddr_in6); use `ip -6 addr add` (netlink), the same tooling
        // the routes already use.
        char cmd[160];
        std::snprintf(cmd, sizeof(cmd),
                      "ip -6 addr add fd00::1/64 dev %s 2>/dev/null", tun.Name());
        bool addr_ok = false;
        for (UInt32 i = 0; i < 10 && !addr_ok; ++i) {
            addr_ok = (0 == std::system(cmd));
            if (!addr_ok) {
                ::usleep(100000);
            }
        }
        std::fprintf(stderr, "[tun6] addr6=%d\n", addr_ok ? 1 : 0);
        const bool o3 = tun.BringUp();
        std::fprintf(stderr, "[tun6] up=%d\n", o3 ? 1 : 0);
        std::snprintf(cmd, sizeof(cmd),
                      "ip route add fd00::2/128 dev %s 2>/dev/null", tun.Name());
        bool routed = false;
        for (UInt32 i = 0; i < 10 && !routed; ++i) {
            routed = (0 == std::system(cmd));
            if (!routed) {
                ::usleep(100000);
            }
        }
        std::fprintf(stderr, "[tun6] route=%d\n", routed ? 1 : 0);
    }
}

int main() {
    xtcp::buf::InitPools();
    UInt64 got = 0;
    bool ok = false;
    bool ok_x2k = false;
    {
        xtcp::samples::TunBackend tun;
        SetupTun6(tun);

        xtcp::XtcpStack stack(&tun);
        // Echo with backpressure (mirror of interop_tun): buffer failed
        // sends and retry on the timer path so a window-limited echo never
        // drops round-trip data.
        std::deque<std::pair<UInt64, std::vector<Byte>>> pending;
        std::mutex pending_mutex;
        auto flush_pending = [&stack, &pending, &pending_mutex]() {
            std::lock_guard<std::mutex> scope(pending_mutex);
            while (!pending.empty()) {
                auto& front = pending.front();
                if (stack.Send(front.first, front.second.data(),
                               static_cast<UInt32>(front.second.size()))) {
                    ++g_echo_ok;
                    pending.pop_front();
                } else {
                    break;
                }
            }
        };
        stack.SetRecvHandler([&stack, &pending, &pending_mutex, &flush_pending](
                                 UInt64 conn_id, const Byte* data, UInt32 len) {
            g_recv += len;
            {
                std::lock_guard<std::mutex> scope(pending_mutex);
                pending.emplace_back(conn_id, std::vector<Byte>(data, data + len));
            }
            flush_pending();
        });
        xtcp::core::Endpoint server;
        server.family = 6;
        std::memcpy(server.addr, kXServerV6, 16);
        server.port = kPort;
        if (!stack.Listen(server)) {
            std::fprintf(stderr, "IPv6 listen failed\n");
            return 1;
        }

        // Event loop: TUN rx -> stack; stack tx -> TUN; timers.
        std::atomic<bool> stop = false;
        std::thread loop([&]() {
            while (!stop.load()) {
                UInt32 processed = 0;
                while (processed < 128) {
                    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(4096);
                    if (buf.IsEmpty()) {
                        break;
                    }
                    const UInt32 n = tun.ReadPacket(buf.Data(), 4080);
                    if (0 == n) {
                        break;
                    }
                    buf.SetLen(n);
                    stack.OnPacket(std::move(buf));
                    ++processed;
                }
                tun.DrainTx();
                stack.PollAckTimers();
                flush_pending();  // retry blocked echo sends on the timer path
                if (0 == processed) {
                    ::usleep(200);
                }
            }
        });

        // Kernel client: connect to fd00::2:4456, send 512 KB with a
        // deterministic pattern, verify the echoed bytes.
        const Int32 fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) {
            std::fprintf(stderr, "v6 socket errno=%d\n", errno);
            stop.store(true);
            loop.join();
            return 1;
        }
        Int32 rcvbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        Int32 sndbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        sockaddr_in6 dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin6_family = AF_INET6;
        // The kernel socket wants the address in NETWORK byte order.
        for (UInt32 w = 0; w < 4; ++w) {
            const UInt32 v = kXServerV6[w];
            dst.sin6_addr.s6_addr[w * 4 + 0] = static_cast<Byte>(v >> 24);
            dst.sin6_addr.s6_addr[w * 4 + 1] = static_cast<Byte>(v >> 16);
            dst.sin6_addr.s6_addr[w * 4 + 2] = static_cast<Byte>(v >> 8);
            dst.sin6_addr.s6_addr[w * 4 + 3] = static_cast<Byte>(v & 0xFF);
        }
        dst.sin6_port = htons(kPort);
        if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
            std::fprintf(stderr, "v6 connect errno=%d\n", errno);
            ::close(fd);
            stop.store(true);
            loop.join();
            return 1;
        }
        constexpr UInt32 kBytes = 512 * 1024;
        std::vector<Byte> payload(kBytes);
        for (UInt32 i = 0; i < kBytes; ++i) {
            payload[i] = static_cast<Byte>((i * 31 + 7) & 0xFF);
        }
        UInt32 sent = 0;
        while (sent < kBytes) {
            const ssize_t n = ::send(fd, payload.data() + sent, kBytes - sent, 0);
            if (n <= 0) {
                std::fprintf(stderr, "v6 send fail at %u errno=%d\n", sent, errno);
                break;
            }
            sent += static_cast<UInt32>(n);
        }
        std::vector<Byte> echo(kBytes);
        UInt32 got_echo = 0;
        while (got_echo < kBytes) {
            const ssize_t n = ::recv(fd, echo.data() + got_echo, kBytes - got_echo, 0);
            if (n <= 0) {
                break;
            }
            got_echo += static_cast<UInt32>(n);
        }
        ::close(fd);
        got = g_recv.load();
        ok = (sent == kBytes) && (got_echo == kBytes) &&
             (0 == std::memcmp(echo.data(), payload.data(), kBytes));
        std::fprintf(stderr, "V6: sent=%u echoed=%u xtcp_recv=%llu %s\n",
                     sent, got_echo, (unsigned long long)got, ok ? "OK" : "MISMATCH");

        // ---- X2K: xtcp client -> kernel IPv6 server (fd00::1:4457) ----
        // The kernel server echoes; xtcp verifies the echoed bytes.
        const Int32 kfd = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (kfd < 0) {
            std::fprintf(stderr, "x2k socket errno=%d\n", errno);
            stop.store(true);
            loop.join();
            return 1;
        }
        Int32 kreuse = 1;
        ::setsockopt(kfd, SOL_SOCKET, SO_REUSEADDR, &kreuse, sizeof(kreuse));
        Int32 krcvbuf = 1048576;
        ::setsockopt(kfd, SOL_SOCKET, SO_RCVBUF, &krcvbuf, sizeof(krcvbuf));
        sockaddr_in6 kaddr;
        std::memset(&kaddr, 0, sizeof(kaddr));
        kaddr.sin6_family = AF_INET6;
        for (UInt32 w = 0; w < 4; ++w) {
            const UInt32 v = kTunV6[w];
            kaddr.sin6_addr.s6_addr[w * 4 + 0] = static_cast<Byte>(v >> 24);
            kaddr.sin6_addr.s6_addr[w * 4 + 1] = static_cast<Byte>(v >> 16);
            kaddr.sin6_addr.s6_addr[w * 4 + 2] = static_cast<Byte>(v >> 8);
            kaddr.sin6_addr.s6_addr[w * 4 + 3] = static_cast<Byte>(v & 0xFF);
        }
        kaddr.sin6_port = htons(kKernelPort);
        if (0 != ::bind(kfd, reinterpret_cast<sockaddr*>(&kaddr), sizeof(kaddr)) ||
            0 != ::listen(kfd, 4)) {
            std::fprintf(stderr, "x2k bind/listen errno=%d\n", errno);
            ::close(kfd);
            stop.store(true);
            loop.join();
            return 1;
        }
        std::fprintf(stderr, "[x2k] kernel server on fd00::1:%u, xtcp connecting\n",
                     (UInt32)kKernelPort);
        // xtcp client: connect FIRST (the kernel's accept below blocks until
        // the SYN arrives), then accept + echo on a thread.
        xtcp::core::Endpoint local6;
        local6.family = 6;
        local6.addr[0] = kXServerV6[0];
        local6.addr[1] = kXServerV6[1];
        local6.addr[2] = kXServerV6[2];
        local6.addr[3] = kXServerV6[3];
        local6.port = 50006;
        xtcp::core::Endpoint remote6;
        remote6.family = 6;
        remote6.addr[0] = kTunV6[0];
        remote6.addr[1] = kTunV6[1];
        remote6.addr[2] = kTunV6[2];
        remote6.addr[3] = kTunV6[3];
        remote6.port = kKernelPort;
        const UInt64 xconn = stack.Connect(local6, remote6);
        if (0 == xconn) {
            std::fprintf(stderr, "x2k connect failed\n");
            ::close(kfd);
            stop.store(true);
            loop.join();
            return 1;
        }
        // Accept the xtcp connection, then echo its payload back on a
        // dedicated thread (the kernel server recv+send runs concurrently
        // with the xtcp client's send loop).
        sockaddr_in6 peer6;
        socklen_t peer_len = sizeof(peer6);
        const Int32 cfd = ::accept(kfd, reinterpret_cast<sockaddr*>(&peer6), &peer_len);
        if (cfd < 0) {
            std::fprintf(stderr, "x2k accept errno=%d\n", errno);
            ::close(kfd);
            stop.store(true);
            loop.join();
            return 1;
        }
        std::vector<Byte> xecho(kX2K);
        std::atomic<UInt32> xgot{0};
        std::thread x2k_echo([&]() {
            UInt32 got = 0;
            while (got < kX2K) {
                const ssize_t n = ::recv(cfd, xecho.data() + got, kX2K - got, 0);
                if (n <= 0) {
                    break;
                }
                got += static_cast<UInt32>(n);
                xgot = got;
            }
            UInt32 sent = 0;
            while (sent < got) {
                const ssize_t n = ::send(cfd, xecho.data() + sent, got - sent, 0);
                if (n <= 0) {
                    break;
                }
                sent += static_cast<UInt32>(n);
            }
        });
        std::vector<Byte> xk_buf(kX2K, 0);      // kernel-side echo buffer
        std::vector<Byte> xrecv_buf(kX2K, 0);   // xtcp-side echo buffer
        std::atomic<UInt32> xrecv_pos{0};
        stack.SetRecvHandler([&xrecv_buf, &xrecv_pos](UInt64, const Byte* d, UInt32 len) {
            const UInt32 pos = xrecv_pos.load(std::memory_order_relaxed);
            if (pos + len <= xrecv_buf.size()) {
                std::memcpy(xrecv_buf.data() + pos, d, len);
                xrecv_pos.store(pos + len, std::memory_order_relaxed);
            }
        });
        // Wait for established.
        for (UInt32 spin = 0; spin < 5000; ++spin) {
            if (xtcp::core::TcpState::kEstablished == stack.ConnectionState(xconn)) {
                break;
            }
            ::usleep(1000);
        }
        std::vector<Byte> xpayload(kX2K);
        for (UInt32 i = 0; i < kX2K; ++i) {
            xpayload[i] = static_cast<Byte>((i * 17 + 3) & 0xFF);
        }
        UInt32 xsent = 0;
        while (xsent < kX2K) {
            const UInt32 n = (kX2K - xsent < 4096) ? (kX2K - xsent) : 4096;
            if (stack.Send(xconn, xpayload.data() + xsent, n)) {
                xsent += n;
            } else {
                ::usleep(1000);
            }
        }
        g_x2k_sent = xsent;
        // xtcp reads the kernel's echo via the recv handler.
        UInt32 xr = 0;
        while (xr < kX2K) {
            xr = xrecv_pos.load(std::memory_order_relaxed);
            if (xr >= kX2K) {
                break;
            }
            ::usleep(1000);
        }
        x2k_echo.join();
        ::close(cfd);
        ::close(kfd);
        ok_x2k = (xsent == kX2K) && (xr == kX2K) &&
                 (0 == std::memcmp(xrecv_buf.data(), xpayload.data(), kX2K));
        std::fprintf(stderr, "X2K-V6: sent=%u echoed=%u %s\n",
                     xsent, xr, ok_x2k ? "OK" : "MISMATCH");
        stop.store(true);
        loop.join();
    }
    xtcp::buf::ShutdownPools();
    const bool all_ok = ok && ok_x2k;
    std::fprintf(stderr, all_ok ? "INTEROP6: PASSED\n" : "INTEROP6: FAILED\n");
    return all_ok ? 0 : 1;
}

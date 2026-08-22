/**
 * @file main.cpp
 * @brief Bidirectional + multi-connection real interop (WSL TUN):
 *  - 4 kernel clients <-> xtcp server (echo), 256KB each
 *  - 4 xtcp clients -> kernel servers, 256KB each (echo)
 *  - Full-duplex traffic on the same connection, throughput measured.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "../tun2socks/tun_ndi.h"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <deque>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;   // 10.0.0.2 (xtcp virtual)
    constexpr UInt32 kTunV4    = 0x0A000001;   // 10.0.0.1 (TUN iface)
    constexpr UInt16 kXServerPort = 4444;      // xtcp echo server
    constexpr UInt32 kPayloadSize = 262144;    // 256 KB per direction
    constexpr UInt32 kConns = 4;

    int g_failures = 0;
    std::atomic<UInt64> g_xtcp_recv = 0;
    std::atomic<UInt64> g_echo_ok = 0;
    std::atomic<UInt64> g_echo_fail = 0;
    std::atomic<UInt64> g_tun_rx = 0;
    std::atomic<UInt64> g_tun_tx = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        tun.Open("xtcp0");
        tun.AssignAddress(kTunV4, 0xFFFFFF00);
        tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true");
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 31 + seed * 7 + 3) & 0xFF);
        }
    }

    bool CheckPattern(const std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            if (v[i] != static_cast<Byte>((i * 31 + seed * 7 + 3) & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Kernel client: connect to xtcp echo server, send 256KB, verify echo.
     */
    void KernelClient(UInt32 seed) noexcept {
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            ++g_failures;
            return;
        }
        sockaddr_in dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(kServerV4);
        dst.sin_port = htons(kXServerPort);
        // Non-blocking connect with a 5s timeout (mirrors interop_tun).
        const Int32 flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) && EINPROGRESS != errno) {
            std::fprintf(stderr, "KC: connect fail errno=%d\n", errno);
            ++g_failures;
            ::close(fd);
            return;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        const Int32 sel = ::select(fd + 1, NULLPTR, &wfds, NULLPTR, &tv);
        if (sel <= 0) {
            std::fprintf(stderr, "KC: connect timeout errno=%d\n", errno);
            ++g_failures;
            ::close(fd);
            return;
        }
        Int32 soerr = 0;
        socklen_t soerr_len = sizeof(soerr);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len);
        if (0 != soerr) {
            std::fprintf(stderr, "KC: connect SO_ERROR=%d\n", soerr);
            ++g_failures;
            ::close(fd);
            return;
        }
        ::fcntl(fd, F_SETFL, flags);  // back to blocking
        std::fprintf(stderr, "KC[%u]: connected\n", seed);
        std::vector<Byte> payload(kPayloadSize);
        FillPattern(payload, seed);
        // Send.
        UInt32 sent = 0;
        while (sent < payload.size()) {
            const ssize_t n = ::send(fd, payload.data() + sent, payload.size() - sent, 0);
            if (n <= 0) {
                std::fprintf(stderr, "KC[%u]: send fail at %u errno=%d\n", seed, sent, errno);
                ++g_failures;
                ::close(fd);
                return;
            }
            sent += static_cast<UInt32>(n);
        }
        std::fprintf(stderr, "KC[%u]: sent 256KB\n", seed);
        // Receive echo.
        std::vector<Byte> echo(kPayloadSize);
        UInt32 got = 0;
        while (got < echo.size()) {
            const ssize_t n = ::recv(fd, echo.data() + got, echo.size() - got, 0);
            if (n <= 0) {
                break;
            }
            got += static_cast<UInt32>(n);
        }
        ::close(fd);
        if (got != payload.size() || !CheckPattern(echo, seed)) {
            std::fprintf(stderr, "KC: mismatch seed=%u got=%u\n", seed, got);
            ++g_failures;
        } else {
            std::fprintf(stderr, "KC[%u]: OK %u bytes\n", seed, got);
        }
    }

    /**
     * @brief Kernel server: accept an xtcp client, receive 256KB, echo back.
     */
    void KernelServer(UInt32 seed) noexcept {
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            ++g_failures;
            return;
        }
        Int32 one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(kTunV4);
        addr.sin_port = htons(static_cast<UInt16>(4500 + seed));
        if (0 != ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
            0 != ::listen(fd, 8)) {
            std::fprintf(stderr, "KS: bind/listen fail errno=%d\n", errno);
            ++g_failures;
            ::close(fd);
            return;
        }
        sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        const Int32 cfd = ::accept(fd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (cfd < 0) {
            ++g_failures;
            ::close(fd);
            return;
        }
        std::vector<Byte> payload(kPayloadSize);
        UInt32 got = 0;
        while (got < payload.size()) {
            const ssize_t n = ::recv(cfd, payload.data() + got, payload.size() - got, 0);
            if (n <= 0) {
                break;
            }
            got += static_cast<UInt32>(n);
        }
        // Echo back.
        UInt32 sent = 0;
        while (sent < got) {
            const ssize_t n = ::send(cfd, payload.data() + sent, got - sent, 0);
            if (n <= 0) {
                break;
            }
            sent += static_cast<UInt32>(n);
        }
        ::close(cfd);
        ::close(fd);
        const bool ok = (got == payload.size() && CheckPattern(payload, seed + 100));
        std::fprintf(stderr, "KS[%u]: %u bytes %s\n", seed, got, ok ? "OK" : "MISMATCH");
        if (!ok) {
            ++g_failures;
        }
    }
}

int main() {
    auto start = std::chrono::steady_clock::now();
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Echo with proper backpressure: a TCP app must buffer and retry when
    // the send window/cwnd is full (Send returns false). Dropping on failure
    // corrupts the echo once congestion control gates the send path.
    // Per-connection queues: a paced or window-limited connection must not
    // block the other flows' echoes (a shared FIFO causes head-of-line
    // blocking - one slow conn stalls everyone behind it).
    std::unordered_map<UInt64, std::deque<std::vector<Byte>>> pending;
    std::mutex pending_mutex;
    auto flush_pending = [&stack, &pending, &pending_mutex]() {
        std::lock_guard<std::mutex> scope(pending_mutex);
        for (auto it = pending.begin(); it != pending.end();) {
            bool progress = true;
            while (progress && !it->second.empty()) {
                auto& front = it->second.front();
                if (stack.Send(it->first, front.data(), static_cast<UInt32>(front.size()))) {
                    ++g_echo_ok;
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
    // Echo only connections accepted by the xtcp echo server. Data arriving
    // on X2K client conns is the kernel's echo of our own send; echoing it
    // back would produce an echo-of-echo and unbounded pending growth.
    std::unordered_map<UInt64, UInt64> echo_server_conns;
    stack.SetAcceptHandler([&echo_server_conns, &pending_mutex](UInt64 conn_id,
                                                                const xtcp::core::Endpoint&,
                                                                const xtcp::core::Endpoint&) {
        std::lock_guard<std::mutex> scope(pending_mutex);
        echo_server_conns[conn_id] = 1;
        return true;
    });
    stack.SetRecvHandler([&pending, &pending_mutex, &flush_pending, &echo_server_conns](UInt64 conn_id, const Byte* data, UInt32 len) {
        {
            std::lock_guard<std::mutex> scope(pending_mutex);
            if (echo_server_conns.find(conn_id) == echo_server_conns.end()) {
                return;  // X2K echo path - do not re-echo
            }
            g_xtcp_recv += len;
            pending[conn_id].emplace_back(data, data + len);
        }
        flush_pending();
    });

    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kXServerPort;
    stack.Listen(server);

    std::atomic<bool> stop = false;
    std::thread loop([&]() {
        Byte packet[65536];
        auto last_diag = std::chrono::steady_clock::now();
        while (!stop.load()) {
            // Drain the TUN aggressively (batch reads) before sleeping.
            UInt32 processed = 0;
            while (processed < 128) {
                const UInt32 n = tun.ReadPacket(packet, sizeof(packet));
                if (0 == n) {
                    break;
                }
                ++g_tun_rx;
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
            const UInt32 tx = tun.DrainTx();
            if (0 < tx) {
                g_tun_tx += tx;
            }
            stack.DispatchMimt();
            stack.PollAckTimers();  // drive SYN/ACK retransmit, delayed-ACK, keepalive, TIME-WAIT timers
            flush_pending();  // retry blocked echo sends when windows open (pure-ACK arrivals don't fire the recv handler)
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<Double>(now - last_diag).count() >= 1.0) {
                UInt64 total_pending = 0;
                {
                    std::lock_guard<std::mutex> scope(pending_mutex);
                    for (const auto& kv : pending) {
                        total_pending += kv.second.size();
                    }
                }
                std::fprintf(stderr, "[diag] xrecv=%llu echo_ok=%llu pending=%llu conns=%zu\n",
                             (unsigned long long)g_xtcp_recv.load(),
                             (unsigned long long)g_echo_ok.load(),
                             (unsigned long long)total_pending,
                             pending.size());
                last_diag = now;
            }
            if (0 == processed) {
                ::usleep(100);  // idle only
            }
        }
    });

    // Kernel servers listen before xtcp clients connect.
    std::vector<std::thread> ks_threads;
    for (UInt32 i = 0; i < kConns; ++i) {
        ks_threads.emplace_back(KernelServer, i);
    }
    ::usleep(300000);  // let servers bind

    // Start kernel clients (concurrent with xtcp clients).
    std::vector<std::thread> kc_threads;
    for (UInt32 i = 0; i < kConns; ++i) {
        kc_threads.emplace_back(KernelClient, 10 + i);
    }

    // xtcp clients -> kernel servers.
    // Random source-port base per run: the kernel keeps closed connections
    // in FIN-WAIT-2 when the peer never sends FIN, and reusing the exact
    // same 4-tuple makes the new SYN collide with the lingering socket.
    const UInt16 port_base = static_cast<UInt16>(40000 + (::getpid() % 20000));
    std::vector<std::thread> xc_threads;
    for (UInt32 i = 0; i < kConns; ++i) {
        xc_threads.emplace_back([&stack, i, port_base]() {
            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = kServerV4;  // 10.0.0.2 virtual client
            local.port = static_cast<UInt16>(port_base + i);
            remote.family = 4;
            remote.addr[0] = kTunV4;
            remote.port = static_cast<UInt16>(4500 + i);
            const UInt64 conn = stack.Connect(local, remote);
            if (0 == conn) {
                ++g_failures;
                return;
            }
            std::vector<Byte> payload(kPayloadSize);
            FillPattern(payload, i + 100);
            const UInt32 chunk = 4096;
            for (UInt32 off = 0; off < payload.size(); off += chunk) {
                UInt32 retry = 0;
                while (!stack.Send(conn, payload.data() + off, chunk) && retry < 2000) {
                    ::usleep(10000);
                    ++retry;
                }
                if (retry >= 2000) {
                    std::fprintf(stderr, "XC[%u]: send stall at %u\n", i, off);
                    ++g_failures;
                    return;
                }
                ::usleep(500);
            }
            std::fprintf(stderr, "XC[%u]: sent 256KB\n", i);
            stack.Close(conn);  // FIN: clean teardown (avoids kernel FIN-WAIT-2 linger)
        });
    }

    for (auto& t : kc_threads) t.join();
    for (auto& t : xc_threads) t.join();
    for (auto& t : ks_threads) t.join();

    stop.store(true);
    loop.join();
    auto end = std::chrono::steady_clock::now();
    const Double seconds = std::chrono::duration<Double>(end - start).count();
    const UInt64 total = g_xtcp_recv.load();
    std::fprintf(stderr, "[stats] elapsed=%.2fs tun_rx=%llu tun_tx=%llu xrecv=%llu echo_ok=%llu echo_fail=%llu mbps=%.2f\n",
                 seconds,
                 (unsigned long long)g_tun_rx.load(), (unsigned long long)g_tun_tx.load(),
                 (unsigned long long)total,
                 (unsigned long long)g_echo_ok.load(), (unsigned long long)g_echo_fail.load(),
                 (0.0 < seconds) ? (total * 8.0 / 1000000.0 / seconds) : 0.0);
    }  // end scope: stack and all connections destroyed here, before pool shutdown

    xtcp::buf::ShutdownPools();

    std::fprintf(stderr, g_failures ? "BIDIR: FAILED (%d)\n" : "BIDIR: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

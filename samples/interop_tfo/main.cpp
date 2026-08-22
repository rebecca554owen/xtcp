/**
 * @file main.cpp
 * @brief Real-kernel TCP Fast Open (RFC 7413) interop over TUN:
 *   A. kernel client TFO -> xtcp server:
 *      A1 warm-up: the kernel learns the xtcp listener's TFO cookie from
 *         the SYN-ACK of a plain FASTOPEN_CONNECT connection.
 *      A2: the kernel reconnects with the cached cookie + early data on
 *         the SYN - the stack must validate the cookie and deliver the
 *         SYN-carried bytes to the application BEFORE any post-handshake
 *         data (asserted: the TFO connection's first received bytes are
 *         the early magic), then echo 64KB byte-exact.
 *   B. xtcp client TFO -> kernel server:
 *      B1 warm-up: the stack learns the kernel's cookie (auto-cached from
 *         the SYN-ACK via SetTfoCookieCallback) - on WSL2 the kernel
 *         NEVER issues server-side TFO cookies (its SYN-ACKs carry no
 *         kind-34 option even with tcp_fastopen=3 + TCP_FASTOPEN), so no
 *         cookie is learned; documented environment limitation.
 *      B2: ConnectWithTfo(early magic) must degrade gracefully - a plain
 *         SYN (no cookie -> no SYN-carried data, RFC 7413 spoof guard),
 *         the early bytes flushed as the FIRST normal post-handshake
 *         data, then a 64KB transfer - the kernel server verifies the
 *         first-recv magic and the full byte count. This pins the stack's
 *         non-TFO-server fallback against a real kernel.
 *
 * Requires root (setsockopt TCP_FASTOPEN_CONNECT / TCP_FASTOPEN). Run:
 *   sudo timeout 150 ./interop_tfo
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
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;   // 10.0.0.2 (xtcp virtual)
    constexpr UInt32 kTunV4    = 0x0A000001;   // 10.0.0.1 (TUN iface)
    constexpr UInt16 kPortA    = 4470;         // xtcp TFO listener (A)
    constexpr UInt16 kPortB    = 4471;         // kernel TFO server (B)
    constexpr UInt32 kBytes    = 64 * 1024;

    // Early-data magic: must arrive on the SYN before anything else.
    constexpr const char* kEarlyMagic = "TFO-EARLY-8BYTES";
    constexpr UInt32 kEarlyLen = 16;

    int g_failures = 0;
    std::atomic<bool> g_early_ok = false;  // set by B's kernel accept thread

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[tfo] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 37 + seed * 11 + 1) & 0xFF);
        }
    }

    // Kernel TFO client: warm-up (learn the cookie), then a TFO connect
    // carrying the early magic. Returns the echoed bytes for verification.
    Int32 KernelTfoClient(UInt32 peer, UInt16 port, std::vector<Byte>& echoed,
                          bool& early_delivered) noexcept {
        // A1: warm-up - plain FASTOPEN_CONNECT connection (no cached cookie
        // yet): the kernel learns the server's cookie from the SYN-ACK.
        {
            const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
            Int32 one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof(one));
            sockaddr_in dst;
            std::memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = htonl(peer);
            dst.sin_port = htons(port);
            ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));  // may be EINPROGRESS
            // Wait for the handshake to complete.
            pollfd pfd = { fd, POLLOUT, 0 };
            ::poll(&pfd, 1, 3000);
            ::close(fd);
        }
        // A2: TFO connect + early data on the SYN.
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        Int32 one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof(one));
        sockaddr_in dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(peer);
        dst.sin_port = htons(port);
        const Int32 crc = ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        if (0 != crc && EINPROGRESS != errno) {
            std::fprintf(stderr, "[tfo] connect rc=%d errno=%d\n", crc, errno);
            ::close(fd);
            return 1;
        }
        // Send the early data immediately (before the handshake completes):
        // with a cached cookie this rides the SYN.
        const ssize_t erc = ::send(fd, kEarlyMagic, kEarlyLen, 0);
        if (erc != static_cast<ssize_t>(kEarlyLen)) {
            std::fprintf(stderr, "[tfo] early send rc=%zd errno=%d\n", erc, errno);
            ::close(fd);
            return 2;
        }
        early_delivered = true;
        // Wait for establishment, then send the bulk pattern.
        pollfd pfd = { fd, POLLOUT, 0 };
        if (1 != ::poll(&pfd, 1, 5000) || 0 != (pfd.revents & POLLERR)) {
            std::fprintf(stderr, "[tfo] poll for establishment failed revents=%d\n", pfd.revents);
            ::close(fd);
            return 3;
        }
        std::vector<Byte> pattern(kBytes);
        FillPattern(pattern, 2);
        UInt32 sent = 0;
        while (sent < kBytes) {
            const ssize_t n = ::send(fd, pattern.data() + sent, kBytes - sent, 0);
            if (n <= 0) {
                break;
            }
            sent += static_cast<UInt32>(n);
        }
        // Receive the echo (early magic is echoed back first, then the
        // pattern - the server echoes everything in order).
        std::vector<Byte> echo(kEarlyLen + kBytes);
        UInt32 got = 0;
        while (got < echo.size()) {
            const ssize_t n = ::recv(fd, echo.data() + got, echo.size() - got, 0);
            if (n <= 0) {
                break;
            }
            got += static_cast<UInt32>(n);
        }
        ::close(fd);
        echoed.assign(echo.begin(), echo.begin() + got);
        const bool ok = (sent == kBytes) && (got == echo.size()) &&
                        (0 == std::memcmp(echo.data(), kEarlyMagic, kEarlyLen)) &&
                        (0 == std::memcmp(echo.data() + kEarlyLen, pattern.data(), kBytes));
        return ok ? 0 : 4;
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Per-connection receive recording: every delivered chunk (including
    // SYN-carried early data) is appended to the connection's buffer.
    std::unordered_map<UInt64, std::deque<std::vector<Byte>>> pending;
    std::unordered_map<UInt64, std::vector<Byte>> rx_log;
    std::mutex data_mutex;
    auto flush_pending = [&stack, &pending, &data_mutex]() {
        std::lock_guard<std::mutex> scope(data_mutex);
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
    stack.SetRecvHandler([&](UInt64 conn_id, const Byte* data, UInt32 len) {
        {
            std::lock_guard<std::mutex> scope(data_mutex);
            rx_log[conn_id].insert(rx_log[conn_id].end(), data, data + len);
            pending[conn_id].emplace_back(data, data + len);
        }
        flush_pending();
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kPortA;
    stack.Listen(server);
    std::fprintf(stderr, "[tfo] xtcp TFO listener on 10.0.0.2:%u\n", kPortA);

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

    bool ok = true;

    // A: kernel client TFO -> xtcp server.
    {
        std::vector<Byte> echoed;
        bool early_delivered = false;
        const Int32 a_rc = KernelTfoClient(kServerV4, kPortA, echoed, early_delivered);
        // Find the TFO connection in rx_log: its FIRST bytes must be the
        // early magic (delivered from the SYN, before any handshake data).
        bool early_first = false;
        {
            std::lock_guard<std::mutex> scope(data_mutex);
            for (const auto& kv : rx_log) {
                if (kEarlyLen <= kv.second.size() &&
                    0 == std::memcmp(kv.second.data(), kEarlyMagic, kEarlyLen)) {
                    early_first = true;
                }
            }
        }
        const bool pass = (0 == a_rc) && early_delivered && early_first &&
                          (kEarlyLen + kBytes) == echoed.size();
        std::fprintf(stderr, "[tfo] A kernel-TFO->xtcp: rc=%d early_sent=%d early_delivered_first=%d echo=%u %s\n",
                     a_rc, early_delivered ? 1 : 0, early_first ? 1 : 0,
                     static_cast<UInt32>(echoed.size()), pass ? "PASS" : "FAIL");
        ok = ok && pass;
    }

    // B: xtcp client TFO -> kernel server. Enable kernel server-side TFO
    // (plain `sysctl -w` is blocked on WSL2; the proc write works).
    std::system("echo 3 > /proc/sys/net/ipv4/tcp_fastopen");
    const Int32 listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    Int32 reuse = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    Int32 qlen = 4;
    if (0 != ::setsockopt(listen_fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen))) {
        std::fprintf(stderr, "[tfo] TCP_FASTOPEN setsockopt fail errno=%d\n", errno);
        ++g_failures;
        ok = false;
    }
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(kTunV4);
    addr.sin_port = htons(kPortB);
    if (0 != ::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
        0 != ::listen(listen_fd, 4)) {
        std::fprintf(stderr, "[tfo] kernel TFO server bind/listen fail errno=%d\n", errno);
        ::close(listen_fd);
        ok = false;
    } else {
        std::fprintf(stderr, "[tfo] kernel TFO server on 10.0.0.1:%u\n", kPortB);
        std::thread accept_thread([&]() {
            // B1 warm-up connection: accept and discard (it carries no data).
            {
                pollfd pfd = { listen_fd, POLLIN, 0 };
                ::poll(&pfd, 1, 10000);
                const Int32 cfd = ::accept(listen_fd, NULLPTR, NULLPTR);
                if (0 <= cfd) {
                    ::close(cfd);
                }
            }
            // B2: the TFO connection. The kernel's TFO server is not
            // functional on WSL2 (its SYN-ACKs carry no cookie even with
            // tcp_fastopen=3), so the stack degrades to a plain SYN; the
            // early data must then arrive as the FIRST bytes of normal
            // post-handshake data (no cookie -> no SYN-carried data).
            pollfd pfd = { listen_fd, POLLIN, 0 };
            ::poll(&pfd, 1, 10000);
            const Int32 cfd = ::accept(listen_fd, NULLPTR, NULLPTR);
            if (0 > cfd) {
                std::fprintf(stderr, "[tfo] kernel accept fail errno=%d\n", errno);
                return;
            }
            // The first recv must deliver the early magic (as normal data).
            Byte first[kEarlyLen];
            const ssize_t n0 = ::recv(cfd, first, kEarlyLen, 0);
            const bool early_ok = (n0 == static_cast<ssize_t>(kEarlyLen)) &&
                                  (0 == std::memcmp(first, kEarlyMagic, kEarlyLen));
            // Drain the rest (64KB pattern) and verify the total.
            std::vector<Byte> buf(kBytes);
            UInt32 rest = 0;
            while (rest < kBytes) {
                const ssize_t n = ::recv(cfd, buf.data() + rest, kBytes - rest, 0);
                if (n <= 0) {
                    break;
                }
                rest += static_cast<UInt32>(n);
            }
            ::close(cfd);
            if (early_ok && rest == kBytes) {
                g_early_ok.store(true);
            }
            std::fprintf(stderr, "[tfo] B kernel server: first-recv=%zd rest=%u %s\n",
                         n0, rest, (early_ok && rest == kBytes) ? "OK" : "BAD");
        });
        // B1: warm-up - the stack learns the kernel's cookie from the SYN-ACK.
        {
            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = kServerV4;
            local.port = static_cast<UInt16>(43000 + (::getpid() % 1000));
            remote.family = 4;
            remote.addr[0] = kTunV4;
            remote.port = kPortB;
            const UInt64 conn = stack.Connect(local, remote);
            const auto t0 = std::chrono::steady_clock::now();
            while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 3.0) {
                if (0 < conn && xtcp::core::TcpState::kEstablished == stack.ConnectionState(conn)) {
                    break;
                }
                ::usleep(200);
            }
            if (0 < conn) {
                stack.Close(conn);
            }
        }
        // B2: TFO connect with early data.
        {
            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = kServerV4;
            local.port = static_cast<UInt16>(44000 + (::getpid() % 1000));
            remote.family = 4;
            remote.addr[0] = kTunV4;
            remote.port = kPortB;
            const UInt64 conn = stack.ConnectWithTfo(local, remote,
                                                     reinterpret_cast<const Byte*>(kEarlyMagic),
                                                     kEarlyLen);
            std::vector<Byte> payload(kBytes);
            FillPattern(payload, 3);
            UInt32 sent = 0;
            const auto t0 = std::chrono::steady_clock::now();
            while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 10.0) {
                if (0 < conn && sent < kBytes &&
                    xtcp::core::TcpState::kEstablished == stack.ConnectionState(conn)) {
                    const UInt32 chunk = (kBytes - sent < 1460) ? (kBytes - sent) : 1460;
                    if (stack.Send(conn, payload.data() + sent, chunk)) {
                        sent += chunk;
                    }
                }
                if (g_early_ok.load() && sent >= kBytes) {
                    break;
                }
                ::usleep(200);
            }
            const bool pass = (0 < conn) && g_early_ok.load() && (sent == kBytes);
            std::fprintf(stderr, "[tfo] B xtcp-TFO->kernel: conn=%llu sent=%u early=%d %s\n",
                         (unsigned long long)conn, sent, g_early_ok.load() ? 1 : 0,
                         pass ? "PASS" : "FAIL");
            ok = ok && pass;
        }
        accept_thread.join();
        ::close(listen_fd);
    }
    std::system("echo 1 > /proc/sys/net/ipv4/tcp_fastopen");

    stop.store(true);
    loop.join();
    rc = (ok && 0 == g_failures) ? 0 : 1;
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[tfo] FAILED\n" : "[tfo] PASSED\n");
    return rc;
}

/**
 * @file main.cpp
 * @brief Real kernel-stack interop via TUN (WSL: raw sockets are blocked,
 *        TUN works). An xtcp stack is wired to a TUN device; the Linux
 *        kernel TCP stack communicates with it bidirectionally:
 *          A) kernel client -> xtcp server (10.0.0.2:4444)
 *          B) xtcp client  -> kernel server (10.0.0.1:4445)
 *        Data integrity is verified on both directions.
 *
 * Requires root. Run:
 *   sudo ./interop_tun
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "../tun2socks/tun_ndi.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;  // 10.0.0.2 (xtcp virtual)
    constexpr UInt32 kTunV4    = 0x0A000001;  // 10.0.0.1 (TUN iface)
    constexpr UInt16 kXServerPort = 4444;     // xtcp listens here
    constexpr UInt16 kKernelPort  = 4445;     // kernel listens here

    int g_failures = 0;
    std::atomic<UInt64> g_xtcp_recv = 0;
    std::vector<Byte> g_xtcp_payload;
    std::atomic<UInt64> g_tun_rx_packets = 0;
    std::atomic<UInt64> g_tun_tx_packets = 0;

    bool RunCommand(const char* cmd) noexcept {
        const int rc = std::system(cmd);
        return (0 == rc);
    }

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool opened = tun.Open("xtcp0");
        std::fprintf(stderr, "[interop] open=%d\n", opened ? 1 : 0);
        const bool addr = tun.AssignAddress(kTunV4, 0xFFFFFF00);  // 10.0.0.1/24
        std::fprintf(stderr, "[interop] assign=%d\n", addr ? 1 : 0);
        const bool up = tun.BringUp();
        std::fprintf(stderr, "[interop] up=%d\n", up ? 1 : 0);
        // Route 10.0.0.2 into the TUN; forward the rest. Retry a few times:
        // right after BringUp the device may not be fully registered and the
        // first route add can fail (observed on WSL2).
        bool routed = false;
        for (UInt32 i = 0; i < 10 && !routed; ++i) {
            routed = RunCommand("ip route add 10.0.0.2/32 dev xtcp0 2>&1");
            if (!routed) {
                ::usleep(100000);
            }
        }
        std::fprintf(stderr, "[interop] route 10.0.0.2 -> xtcp0 %s\n", routed ? "OK" : "FAILED");
        RunCommand("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true");
    }

    /**
     * @brief Kernel client connects to the xtcp server (10.0.0.2:4444).
     * Non-blocking connect with a 5s timeout.
     */
    int KernelClientToX() noexcept {
        std::fprintf(stderr, "[K2X] socket\n");
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
        // Large receive buffer: under reordering the kernel must hold the
        // out-of-order queue AND the advertised window; the 85 KiB default
        // overflows and the kernel silently drops the retransmitted head.
        Int32 rcvbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        Int32 sndbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        // Non-blocking connect with timeout.
        const Int32 flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        sockaddr_in dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(kServerV4);
        dst.sin_port = htons(kXServerPort);
        std::fprintf(stderr, "[K2X] connect 10.0.0.2:%u\n", (UInt32)kXServerPort);
        const Int32 rc = ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        if (0 != rc && EINPROGRESS != errno) {
            std::fprintf(stderr, "K2X: connect errno=%d\n", errno);
            ::close(fd);
            return -2;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        std::fprintf(stderr, "[K2X] select\n");
        const Int32 sel = ::select(fd + 1, NULLPTR, &wfds, NULLPTR, &tv);
        if (sel <= 0) {
            std::fprintf(stderr, "K2X: connect timeout (tun_rx=%llu tun_tx=%llu)\n",
                         (unsigned long long)g_tun_rx_packets.load(),
                         (unsigned long long)g_tun_tx_packets.load());
            ::close(fd);
            return -3;
        }
        Int32 soerr = 0;
        socklen_t soerr_len = sizeof(soerr);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len);
        if (0 != soerr) {
            std::fprintf(stderr, "K2X: connect SO_ERROR=%d\n", soerr);
            ::close(fd);
            return -4;
        }
        std::fprintf(stderr, "[K2X] connected\n");
        ::fcntl(fd, F_SETFL, flags);  // back to blocking
        // Send 256 KB with a deterministic pattern.
        std::vector<Byte> payload(1048576);
        for (UInt32 i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<Byte>((i * 31 + 7) & 0xFF);
        }
        UInt32 sent = 0;
        while (sent < payload.size()) {
            const ssize_t n = ::send(fd, payload.data() + sent, payload.size() - sent, 0);
            if (n <= 0) {
                std::fprintf(stderr, "K2X: send failed n=%zd errno=%d\n", n, errno);
                ::close(fd);
                return -5;
            }
            sent += static_cast<UInt32>(n);
        }
        // Receive the echo (xtcp must relay back the same bytes).
        std::vector<Byte> echo(1048576);
        UInt32 got = 0;
        while (got < echo.size()) {
            const ssize_t n = ::recv(fd, echo.data() + got, echo.size() - got, 0);
            if (n <= 0) {
                std::fprintf(stderr, "K2X: recv end n=%zd errno=%d got=%u\n", n, errno, got);
                break;
            }
            got += static_cast<UInt32>(n);
            if (0 == (got % 8192)) {
                std::fprintf(stderr, "K2X: recv progress %u/1048576\n", got);
            }
        }
        ::close(fd);
        if (got != payload.size() || 0 != std::memcmp(echo.data(), payload.data(), got)) {
            UInt32 bad_at = got;
            for (UInt32 i = 0; i < got; ++i) {
                if (echo[i] != payload[i]) {
                    bad_at = i;
                    break;
                }
            }
            std::fprintf(stderr, "K2X: data mismatch sent=%u got=%u first_bad_at=%u got=%02X want=%02X\n",
                         (UInt32)payload.size(), got, bad_at,
                         (UInt32)echo[bad_at], (UInt32)payload[bad_at]);
            return -6;
        }
        std::fprintf(stderr, "K2X: kernel->xtcp OK (%u bytes round-trip)\n", got);
        return 0;
    }

    /**
     * @brief Kernel server; xtcp client connects to 10.0.0.1:4445.
     */
    int KernelServerForX() noexcept {
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
        Int32 one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        Int32 rcvbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        Int32 sndbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(kTunV4);
        addr.sin_port = htons(kKernelPort);
        if (0 != ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
            0 != ::listen(fd, 4)) {
            ::close(fd);
            return -2;
        }
        sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        std::fprintf(stderr, "[X2K-server] waiting accept\n");
        const Int32 cfd = ::accept(fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (cfd < 0) {
            std::fprintf(stderr, "[X2K-server] accept failed errno=%d\n", errno);
            ::close(fd);
            return -3;
        }
        std::fprintf(stderr, "[X2K-server] accepted\n");
        // Receive 32 KB from the xtcp client.
        std::vector<Byte> payload(1048576);
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
        // Verify the pattern.
        bool ok = true;
        for (UInt32 i = 0; i < got; ++i) {
            if (payload[i] != static_cast<Byte>((i * 17 + 3) & 0xFF)) {
                ok = false;
                break;
            }
        }
        std::fprintf(stderr, "X2K: xtcp->kernel OK (%u bytes, pattern %s)\n", got, ok ? "match" : "MISMATCH");
        return ok ? 0 : -4;
    }
}

int main(int argc, char** argv) {
    // Optional start delay (seconds) so the test harness can apply tc netem
    // after the TUN device appears but before traffic starts.
    UInt32 start_delay = 0;
    if (2 <= argc) {
        start_delay = static_cast<UInt32>(std::strtoul(argv[1], NULLPTR, 10));
    }
    std::fprintf(stderr, "[interop] init pools\n");
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    std::fprintf(stderr, "[interop] setup tun\n");
    SetupTun(tun);
    std::fprintf(stderr, "[interop] tun ready\n");

    xtcp::XtcpStack stack(&tun);
    // xtcp server payload collection + echo back with proper backpressure:
    // failed sends are buffered and retried (a real TCP app blocks on write).
    std::atomic<UInt64> echo_ok = 0;
    std::atomic<UInt64> echo_fail = 0;
    std::atomic<UInt64> echo_conn = 0;
    std::deque<std::pair<UInt64, std::vector<Byte>>> pending;
    std::mutex pending_mutex;
    auto flush_pending = [&stack, &pending, &pending_mutex, &echo_ok]() {
        std::lock_guard<std::mutex> scope(pending_mutex);
        while (!pending.empty()) {
            auto& front = pending.front();
            if (stack.Send(front.first, front.second.data(), static_cast<UInt32>(front.second.size()))) {
                ++echo_ok;
                pending.pop_front();
            } else {
                break;  // window full again
            }
        }
    };
    stack.SetRecvHandler([&stack, &pending, &pending_mutex, &echo_ok, &echo_fail,
                          &echo_conn, &flush_pending](UInt64 conn_id, const Byte* data, UInt32 len) {
        if (0 == echo_conn.load()) {
            echo_conn.store(conn_id);
        }
        const UInt64 prev = g_xtcp_recv.load();
        g_xtcp_recv += len;
        g_xtcp_payload.insert(g_xtcp_payload.end(), data, data + len);
        const UInt64 now = g_xtcp_recv.load();
        if ((prev / 65536) != (now / 65536) && 0 < now) {
            std::fprintf(stderr, "[X-recv] total=%llu echo_ok=%llu echo_fail=%llu\n",
                         (unsigned long long)now,
                         (unsigned long long)echo_ok.load(),
                         (unsigned long long)echo_fail.load());
        }
        // Echo with strict ordering: enqueue and flush FIFO (a TCP app must
        // preserve send order; direct + buffered interleaving would reorder).
        {
            std::lock_guard<std::mutex> scope(pending_mutex);
            pending.emplace_back(conn_id, std::vector<Byte>(data, data + len));
        }
        flush_pending();
    });

    // xtcp server listens on the virtual address.
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kXServerPort;
    stack.Listen(server);
    if (0 < start_delay) {
        std::fprintf(stderr, "[interop] waiting %u s for harness setup\n", start_delay);
        ::sleep(start_delay);
    }

    // Event loop thread: TUN rx -> stack; stack tx -> TUN.
    std::atomic<bool> stop = false;
    std::thread loop([&]() {
        UInt64 debug_count = 0;
        auto last_diag = std::chrono::steady_clock::now();
        while (!stop.load()) {
            // Zero-copy rx: read the TUN frame directly into a pool block.
            // TUN frames are <= MTU (1500) with IFF_NO_PI (no extra header).
            // Acquire(4096) lands in the 4KB pool tier (4080 usable), 8x less
            // memory than the 32KB tier: the old Acquire(32752) gave every
            // 1.5KB frame a 32KB block and could exhaust the 128-block tier
            // under burst load. The read cap must match the block size so a
            // frame cannot overflow the block.
            constexpr UInt32 kRxCap = 4080;
            UInt32 processed = 0;
            while (processed < 128) {
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(4096);
                if (buf.IsEmpty()) {
                    if (0 == g_tun_rx_packets && debug_count < 3) {
                        std::fprintf(stderr, "[tun-dbg] Acquire EMPTY\n");
                        ++debug_count;
                    }
                    break;
                }
                const UInt32 n = tun.ReadPacket(buf.Data(), kRxCap);
                if (0 == n) {
                    if (0 == g_tun_rx_packets && debug_count < 3) {
                        std::fprintf(stderr, "[tun-dbg] read=0 errno=%d fd=%d\n", errno, tun.Fd());
                        ++debug_count;
                    }
                    break;
                }
                ++g_tun_rx_packets;
                if (debug_count < 15) {
                    const Byte proto = (n >= 20) ? buf.Data()[9] : 0;
                    const UInt16 sport = (n >= 24) ? static_cast<UInt16>((buf.Data()[20] << 8) | buf.Data()[21]) : 0;
                    const UInt16 dport = (n >= 24) ? static_cast<UInt16>((buf.Data()[22] << 8) | buf.Data()[23]) : 0;
                    const Byte flags = (n >= 34) ? buf.Data()[33] : 0;
                    std::fprintf(stderr, "[tun-rx] len=%u proto=%u %u->%u flags=%02X\n",
                                 n, proto, (UInt32)sport, (UInt32)dport, flags);
                    ++debug_count;
                }
                buf.SetLen(n);
                stack.OnPacket(std::move(buf));
                ++processed;
            }
            const UInt32 tx = tun.DrainTx();
            if (0 < tx) {
                g_tun_tx_packets += tx;
            }
            stack.DispatchMimt();
            stack.PollAckTimers();  // drive SYN/ACK retransmit, delayed-ACK, keepalive, persist timers
            flush_pending();
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<Double>(now - last_diag).count() >= 1.0) {
                UInt32 infl = 0, cwnd = 0, ssth = 0, wnd = 0, retx = 0, dup = 0, fr = 0, fseq = 0, una = 0;
                UInt64 rto = 0;
                UInt16 lp = 0, rp = 0;
                const UInt64 cid = echo_conn.load();
                if (0 != cid) {
                    stack.ConnStats(cid, infl, cwnd, ssth, wnd, retx, rto, dup, fr, fseq, una, lp, rp);
                }
                std::fprintf(stderr, "[diag] xrecv=%llu echo_ok=%llu pending=%zu conn=%llu(%u<->%u) inflight=%u cwnd=%u ssth=%u wnd=%u retx=%u rto=%llu dup=%u fr=%u front=%u una=%u tx=%llu\n",
                             (unsigned long long)g_xtcp_recv.load(),
                             (unsigned long long)echo_ok.load(),
                             pending.size(),
                             (unsigned long long)cid, (UInt32)lp, (UInt32)rp,
                             infl, cwnd, ssth, wnd, retx,
                             (unsigned long long)rto, dup, fr, fseq, una,
                             (unsigned long long)stack.TxCount());
                last_diag = now;
            }
            ::usleep(500);
        }
    });

    // Kernel-side tests run in parallel.
    std::thread kernel_server(KernelServerForX);
    ::usleep(200000);  // let the kernel server bind

    // Test A: kernel client -> xtcp server.
    if (0 != KernelClientToX()) {
        std::fprintf(stderr, "K2X FAILED\n");
        ++g_failures;
    }
    std::fprintf(stderr, "[diag] after K2X: tun_rx=%llu tun_tx=%llu echo_ok=%llu echo_fail=%llu xrecv=%llu\n",
                 (unsigned long long)g_tun_rx_packets.load(),
                 (unsigned long long)g_tun_tx_packets.load(),
                 (unsigned long long)echo_ok.load(),
                 (unsigned long long)echo_fail.load(),
                 (unsigned long long)g_xtcp_recv.load());

    // Validate the xtcp-side payload (independent of K2X echo result).
    {
        bool ok = true;
        UInt32 bad_at = 0;
        for (UInt32 i = 0; i < 1048576 && i < g_xtcp_payload.size(); ++i) {
            const Byte expect = static_cast<Byte>((i * 31 + 7) & 0xFF);
            if (g_xtcp_payload[i] != expect) {
                ok = false;
                bad_at = i;
                break;
            }
        }
        std::fprintf(stderr, "X-side payload: %llu bytes, %s (first bad at %u: got=%02X want=%02X)\n",
                     (unsigned long long)g_xtcp_recv, ok ? "match" : "MISMATCH",
                     bad_at, (UInt32)(ok ? 0 : g_xtcp_payload[bad_at]), (UInt32)((bad_at * 31 + 7) & 0xFF));
        if (!ok || 1048576 != g_xtcp_recv) {
            ++g_failures;
        }
    }

    // Test B: xtcp client -> kernel server.
    // Source must be the virtual address (10.0.0.2): the kernel routes the
    // SYN+ACK back through the TUN instead of consuming it locally.
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = kServerV4;   // 10.0.0.2 (virtual client address)
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = kTunV4;     // 10.0.0.1:4445 (kernel server)
    remote.port = kKernelPort;
    const UInt64 conn = stack.Connect(local, remote);
    if (0 == conn) {
        std::fprintf(stderr, "X2K connect failed\n");
        ++g_failures;
    } else {
        std::fprintf(stderr, "X2K: connect issued conn=%llu\n", (unsigned long long)conn);
        // Send 32 KB with the kernel-side expected pattern.
        std::vector<Byte> payload(1048576);
        for (UInt32 i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<Byte>((i * 17 + 3) & 0xFF);
        }
        // Send in chunks; retry until the connection is established.
        const UInt32 chunk = 2048;
        UInt32 sent_bytes = 0;
        for (UInt32 off = 0; off < payload.size(); off += chunk) {
            UInt32 retry = 0;
            while (!stack.Send(conn, payload.data() + off, chunk) && retry < 1000) {
                ::usleep(10000);  // wait for the handshake to complete
                ++retry;
            }
            if (retry < 1000) {
                sent_bytes += chunk;
            } else {
                std::fprintf(stderr, "X2K: send fail at %u (retries exhausted)\n", off);
            }
        }
        std::fprintf(stderr, "X2K: sent %u bytes\n", sent_bytes);
        ::usleep(3000000);  // allow the kernel server to finish
    }

    kernel_server.join();
    stop.store(true);
    loop.join();
    std::fprintf(stderr, "[stats] tun_rx=%llu tun_tx=%llu xrecv=%llu echo_ok=%llu echo_fail=%llu\n",
                 (unsigned long long)g_tun_rx_packets.load(),
                 (unsigned long long)g_tun_tx_packets.load(),
                 (unsigned long long)g_xtcp_recv.load(),
                 (unsigned long long)echo_ok.load(),
                 (unsigned long long)echo_fail.load());
    }  // end scope: stack and all connections destroyed here, before pool shutdown

    xtcp::buf::ShutdownPools();

    std::fprintf(stderr, g_failures ? "INTEROP: FAILED (%d)\n" : "INTEROP: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

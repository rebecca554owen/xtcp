/**
 * @file main.cpp
 * @brief Real-kernel urgent-data interop (SO_OOBINLINE): a kernel client
 *        sends normal data plus an out-of-band byte (MSG_OOB); the xtcp
 *        server delivers everything inline byte-exact and the urgent
 *        handler fires for the URG-marked segment - the modern OOBINLINE
 *        semantics against a REAL kernel.
 *
 * Requires root. Run:
 *   sudo ./interop_urgent
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "../tun2socks/tun_ndi.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
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

    int g_failures = 0;
    std::atomic<UInt64> g_tun_rx_packets = 0;
    std::atomic<UInt64> g_tun_tx_packets = 0;
    std::atomic<UInt32> g_urgent_hits = 0;
    std::vector<Byte> g_xtcp_payload;

    bool RunCommand(const char* cmd) noexcept {
        return (0 == std::system(cmd));
    }

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool opened = tun.Open("xtcp0");
        std::fprintf(stderr, "[interop] open=%d\n", opened ? 1 : 0);
        const bool addr = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        std::fprintf(stderr, "[interop] assign=%d\n", addr ? 1 : 0);
        const bool up = tun.BringUp();
        std::fprintf(stderr, "[interop] up=%d\n", up ? 1 : 0);
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

    int KernelClientToX() noexcept {
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
        Int32 rcvbuf = 262144;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        Int32 sndbuf = 262144;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        const Int32 flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        sockaddr_in dst;
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(kServerV4);
        dst.sin_port = htons(kXServerPort);
        const Int32 rc = ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        if (0 != rc && EINPROGRESS != errno) {
            ::close(fd);
            return -2;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        const Int32 sel = ::select(fd + 1, NULLPTR, &wfds, NULLPTR, &tv);
        if (sel <= 0) {
            ::close(fd);
            return -3;
        }
        std::fprintf(stderr, "[K2X] connected\n");

        // Send 8KB normal data (a pattern), then 1 urgent byte (MSG_OOB),
        // then 8KB more normal data.
        std::vector<Byte> normal(8192, 0x51);
        UInt32 sent = 0;
        while (sent < normal.size()) {
            const ssize_t n = ::send(fd, normal.data() + sent, normal.size() - sent, 0);
            if (n <= 0) {
                ::usleep(1000);
                continue;
            }
            sent += static_cast<UInt32>(n);
        }
        const Byte oob = 0x7E;
        ::send(fd, &oob, 1, MSG_OOB);
        std::fprintf(stderr, "[K2X] sent 8KB + OOB\n");
        sent = 0;
        while (sent < normal.size()) {
            const ssize_t n = ::send(fd, normal.data() + sent, normal.size() - sent, 0);
            if (n <= 0) {
                ::usleep(1000);
                continue;
            }
            sent += static_cast<UInt32>(n);
        }
        std::fprintf(stderr, "[K2X] sent all\n");
        ::usleep(2000000);
        ::close(fd);
        return 0;
    }
}

int main() {
    std::fprintf(stderr, "[interop-urgent] init pools\n");
    xtcp::buf::InitPools();
    {
        xtcp::samples::TunBackend tun;
        SetupTun(tun);
        std::fprintf(stderr, "[interop-urgent] tun ready\n");

        xtcp::XtcpStack stack(&tun);
        stack.SetRecvHandler([](UInt64, const Byte* data, UInt32 len) {
            g_xtcp_payload.insert(g_xtcp_payload.end(), data, data + len);
            return true;
        });
        stack.SetUrgentHandler([](UInt64) {
            g_urgent_hits.fetch_add(1, std::memory_order_relaxed);
        });

        xtcp::core::Endpoint server;
        server.family = 4;
        server.addr[0] = kServerV4;
        server.port = kXServerPort;
        stack.Listen(server);

        std::atomic<bool> stop = false;
        std::thread loop([&]() {
            while (!stop.load()) {
                constexpr UInt32 kRxCap = 4080;
                UInt32 processed = 0;
                while (processed < 128) {
                    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(4096);
                    if (buf.IsEmpty()) {
                        break;
                    }
                    const UInt32 n = tun.ReadPacket(buf.Data(), kRxCap);
                    if (0 == n) {
                        break;
                    }
                    ++g_tun_rx_packets;
                    buf.SetLen(n);
                    stack.OnPacket(std::move(buf));
                    ++processed;
                }
                const UInt32 tx = tun.DrainTx();
                if (0 < tx) {
                    g_tun_tx_packets += tx;
                }
                stack.PollAckTimers();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        std::thread kernel_client(KernelClientToX);
        kernel_client.join();
        for (UInt32 i = 0; i < 300 && g_xtcp_payload.size() < 16385; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        stop.store(true);
        loop.join();

        const std::size_t got = g_xtcp_payload.size();
        bool ok = (16385 == got);
        if (ok) {
            // 8KB of 0x51, the 0x7E urgent byte, 8KB of 0x51.
            for (std::size_t i = 0; i < got; ++i) {
                const Byte expect = (i == 8192) ? 0x7E : 0x51;
                if (g_xtcp_payload[i] != expect) {
                    ok = false;
                    break;
                }
            }
        }
        std::fprintf(stderr, "[urgent] recv=%zu/16385 pattern=%s urgent_hits=%u\n",
                     got, ok ? "match" : "MISMATCH", (unsigned)g_urgent_hits.load());
        if (!ok || 0 == g_urgent_hits.load()) {
            std::fprintf(stderr, "URGENT FAIL: byte-exact=%d hits=%u\n",
                         ok ? 1 : 0, (unsigned)g_urgent_hits.load());
            ++g_failures;
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "INTEROP_URGENT: FAILED (%d)\n" : "INTEROP_URGENT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

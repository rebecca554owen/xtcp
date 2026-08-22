/**
 * @file main.cpp
 * @brief Real-kernel TSO validation via TUN: the stack's TSO direct-send
 *        (kCapTsoTx) hands the kernel a 32KB GSO frame with a virtio_net_hdr;
 *        the kernel segments it (the real NIC behavior) and a REAL kernel
 *        socket receives the stream. The TSO proof: the super-segment leaves
 *        the TUN as ONE frame (never ~22 MSS frames), and the kernel's
 *        server receives the full 32KB byte-exact.
 *
 * Requires root. Run:
 *   sudo ./interop_tso
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
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
    constexpr UInt32 kServerV4 = 0x0A000002;  // 10.0.0.2 (xtcp virtual)
    constexpr UInt32 kTunV4    = 0x0A000001;  // 10.0.0.1 (TUN iface)
    constexpr UInt16 kKernelPort = 4445;      // kernel listens here
    constexpr UInt32 kSuperLen = 32712;       // the pool's largest super-segment

    int g_failures = 0;
    std::atomic<UInt64> g_tun_rx_packets = 0;
    std::atomic<UInt64> g_tun_tx_packets = 0;

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

    int KernelServerForX() noexcept {
        const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
        Int32 one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        Int32 rcvbuf = 1048576;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
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
            ::close(fd);
            return -3;
        }
        std::fprintf(stderr, "[X2K-server] accepted\n");
        std::vector<Byte> payload(kSuperLen);
        UInt32 got = 0;
        while (got < payload.size()) {
            const ssize_t n = ::recv(cfd, payload.data() + got, payload.size() - got, 0);
            if (n <= 0) {
                break;
            }
            got += static_cast<UInt32>(n);
        }
        ::close(cfd);
        ::close(fd);
        bool ok = true;
        for (UInt32 i = 0; i < got; ++i) {
            if (payload[i] != static_cast<Byte>((i * 17 + 3) & 0xFF)) {
                ok = false;
                break;
            }
        }
        std::fprintf(stderr, "X2K-TSO: xtcp->kernel OK (%u bytes, pattern %s)\n", got, ok ? "match" : "MISMATCH");
        if (!ok || kSuperLen != got) {
            ++g_failures;
        }
        return ok ? 0 : -4;
    }
}

int main() {
    std::fprintf(stderr, "[interop-tso] init pools\n");
    xtcp::buf::InitPools();
    {
        xtcp::samples::TunBackend tun;
        SetupTun(tun);
        std::fprintf(stderr, "[interop-tso] tun ready (tso_cap=%d mtu=%u)\n",
                     (0 != (tun.Caps() & xtcp::ndi::kCapTsoTx)) ? 1 : 0, 1500);
        if (0 == (tun.Caps() & xtcp::ndi::kCapTsoTx)) {
            std::fprintf(stderr, "FATAL: TUN TSO offload not available (TUNSETOFFLOAD failed)\n");
            ++g_failures;
            xtcp::buf::ShutdownPools();
            return g_failures ? 1 : 0;
        }

        xtcp::XtcpStack stack(&tun);
        std::thread kernel_server(KernelServerForX);

        // Event loop thread: TUN rx -> stack; stack tx -> TUN.
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

        // Grow the congestion window past the super-segment size (the
        // TSO-direct gate: empty retransmission queue + cwnd fit).
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kServerV4;
        // Random client port: the kernel keeps the previous run's connection
        // (4445:40000) in FIN-WAIT/TIME-WAIT for a while; a reused tuple
        // makes the kernel answer the new SYN with stale ACKs instead of a
        // fresh SYN+ACK.
        local.port = static_cast<UInt16>(41000 + (::getpid() % 2000));
        remote.family = 4;
        remote.addr[0] = kTunV4;
        remote.port = kKernelPort;
        const UInt64 conn = stack.Connect(local, remote);
        if (0 == conn) {
            std::fprintf(stderr, "X2K connect failed\n");
            ++g_failures;
        } else {
            // Wait for the handshake to complete before any send: a send
            // during SYN/SYN-RCVD buffers into pending_send_ and flushes as
            // MSS-sized segments, silently bypassing the TSO-direct path.
            for (UInt32 i = 0; i < 500 && xtcp::core::TcpState::kEstablished != stack.ConnectionState(conn); ++i) {
                ::usleep(20000);
            }
            if (xtcp::core::TcpState::kEstablished != stack.ConnectionState(conn)) {
                std::fprintf(stderr, "X2K: handshake did not complete (rx=%llu tx=%llu)\n",
                             (unsigned long long)g_tun_rx_packets.load(),
                             (unsigned long long)g_tun_tx_packets.load());
                ++g_failures;
            } else {
            std::vector<Byte> payload(kSuperLen);
            for (UInt32 i = 0; i < payload.size(); ++i) {
                payload[i] = static_cast<Byte>((i * 17 + 3) & 0xFF);
            }
            // Growth: 15 x 1KB small sends (slow start reaches ~25 segments).
            UInt32 growth = 0;
            for (UInt32 i = 0; i < 15; ++i) {
                if (stack.Send(conn, payload.data() + growth, 1024)) {
                    growth += 1024;
                }
                ::usleep(20000);  // let the kernel ACK (delayed-ACK is 40ms)
            }
            for (UInt32 i = 0; i < 200 && 0 < stack.ConnOutstandingSegments(conn); ++i) {
                ::usleep(20000);
            }
            std::fprintf(stderr, "X2K-TSO: growth=%u outstanding=%u\n", growth,
                         (UInt32)stack.ConnOutstandingSegments(conn));
            // The super-segment: ONE Send -> ONE TUN frame (the TSO).
            const UInt64 tx_before = g_tun_tx_packets.load();
            UInt32 sent = 0;
            for (UInt32 i = 0; i < 2000 && sent < kSuperLen - growth; ++i) {
                if (stack.Send(conn, payload.data() + growth + sent, kSuperLen - growth - sent)) {
                    sent = kSuperLen - growth;
                }
                ::usleep(10000);
            }
            std::fprintf(stderr, "X2K-TSO: super sent=%u tx_frames=%llu\n",
                         sent, (unsigned long long)(g_tun_tx_packets.load() - tx_before));
            if (kSuperLen - growth != sent) {
                ++g_failures;
            }
            // TSO proof: the super-segment left the TUN as ONE GSO frame
            // (the period also carries the SYN-ACK's ACK, so 2 = the GSO
            // frame + the 40-byte ACK; anything more means the super was
            // flushed as MSS-sized segments instead).
            if (2 != g_tun_tx_packets.load() - tx_before) {
                std::fprintf(stderr, "TSO FAIL: the super-segment was NOT one TUN frame\n");
                ++g_failures;
            }
            }
        }

        kernel_server.join();
        stop.store(true);
        loop.join();
        std::fprintf(stderr, "[stats] tun_rx=%llu tun_tx=%llu\n",
                     (unsigned long long)g_tun_rx_packets.load(),
                     (unsigned long long)g_tun_tx_packets.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "INTEROP_TSO: FAILED (%d)\n" : "INTEROP_TSO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

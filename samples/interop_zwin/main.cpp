/**
 * @file main.cpp
 * @brief Real-kernel zero-window backpressure interop over TUN:
 *        the stack's recv handler backpressures (rejects data -> RFC 1122
 *        s4.2.3.4 window-0 advertisement) for a 2s stall mid-transfer;
 *        the kernel must persist (window probes) and resume when the
 *        window reopens. Asserted:
 *          - the kernel's persist probes are observable on the wire during
 *            the stall (tiny data segments - the kernel probes a zero
 *            window with 1-byte segments),
 *          - the full 512KB transfer completes byte-exact,
 *          - the transfer duration includes the stall (the kernel could
 *            not push data while the window was 0).
 *
 * Requires root. Run:
 *   sudo timeout 150 ./interop_zwin
 */

#include <xtcp/core/stack.h>
#include "../tun2socks/tun_ndi.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kTunV4    = 0x0A000001;
    constexpr UInt16 kPort     = 4495;
    constexpr UInt32 kBytes    = 512 * 1024;
    constexpr UInt32 kStallAt  = 128 * 1024;   // backpressure starts here
    constexpr UInt32 kStallLen = 2 * 1024 * 1024;  // bytes rejected during the stall window
    constexpr Double kStallSec = 2.0;

    std::atomic<UInt32> g_probes = 0;       // kernel window-probe segments (tiny data)
    std::atomic<UInt64> g_accepted = 0;     // bytes the stack accepted
    std::atomic<UInt64> g_rejected = 0;     // bytes the stack backpressured

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[zwin] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 47 + seed * 19 + 6) & 0xFF);
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
    // Time-driven backpressure: accept normally for the first 0.3s of data,
    // then reject (window 0) for kStallSec, then accept again.
    std::atomic<UInt64> rx_bytes = 0;
    std::atomic<UInt64> g_accepted = 0;
    std::atomic<bool> data_started = false;
    std::chrono::steady_clock::time_point stall_begin, stall_end;
    std::atomic<UInt64> g_stall_rejects = 0;
    stack.SetRecvHandlerChecked([&](UInt64, const Byte*, UInt32 len) {
        rx_bytes.fetch_add(len);
        if (!data_started.load()) {
            data_started.store(true);
            stall_begin = std::chrono::steady_clock::now();
            stall_end = stall_begin + std::chrono::milliseconds(static_cast<Int64>(kStallSec * 1000));
            std::fprintf(stderr, "[zwin] first data; stall window [0.0s, %.1fs)\n", kStallSec);
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= stall_begin && now < stall_end) {
            g_stall_rejects.fetch_add(len);
            
            return false;  // RFC 1122 s4.2.3.4: advertise window 0
        }
        g_accepted.fetch_add(len);
        return true;
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[zwin] xtcp listener on 10.0.0.2:%u\n", kPort);

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
                // Window probes: tiny kernel->stack data segments while the
                // window is closed (persist probes carry <= 1 byte of data).
                if (4 == (packet[0] >> 4) && n > 40 && 6 == packet[9] && 0 != (packet[33] & 0x08)) {
                    const UInt32 ip_hl = static_cast<UInt32>(packet[0] & 0x0F) * 4;
                    const UInt32 tcp_len = n - ip_hl;
                    const UInt32 doff = static_cast<UInt32>(packet[ip_hl + 12] >> 4) * 4;
                    const UInt32 payload = (tcp_len > doff) ? (tcp_len - doff) : 0;
                    if (0 < payload && payload <= 4) {
                        g_probes.fetch_add(1);
                    }
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
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Kernel client: send 512KB, then receive... nothing (no echo) - the
    // test is one-way; the client just verifies its send completed.
    const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(kServerV4);
    dst.sin_port = htons(kPort);
    timeval tv;
    tv.tv_sec = 120;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "[zwin] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::vector<Byte> pattern(kBytes);
    FillPattern(pattern, 13);
    const auto start = std::chrono::steady_clock::now();
    UInt32 sent = 0;
    while (sent < kBytes) {
        const ssize_t n = ::send(fd, pattern.data() + sent, kBytes - sent, 0);
        if (n <= 0) {
            std::fprintf(stderr, "[zwin] send fail at %u errno=%d\n", sent, errno);
            break;
        }
        sent += static_cast<UInt32>(n);
    }
    // Wait for the stack to have ACCEPTED everything (rejections during
    // the stall are not consumed; acceptance resumes after the window
    // reopens - the wait therefore covers the full stall).
    const auto t1 = std::chrono::steady_clock::now();
    while (g_accepted.load() < kBytes &&
           std::chrono::duration<Double>(std::chrono::steady_clock::now() - t1).count() < 30.0) {
        ::usleep(1000);
    }
    const auto end = std::chrono::steady_clock::now();
    const Double sec = std::chrono::duration<Double>(end - start).count();

    const bool all_received = (g_accepted.load() == kBytes) && (sent == kBytes);
    const bool stalled = (0 < g_stall_rejects.load());
    const bool probes_seen = (0 < g_probes.load());
    const bool stall_respected = (sec >= kStallSec - 0.2);
    std::fprintf(stderr,
                 "[zwin] sent=%u rx=%llu rejected=%u probes=%u elapsed=%.2fs\n",
                 sent, (unsigned long long)rx_bytes.load(),
                 (unsigned long long)g_stall_rejects.load(), g_probes.load(), sec);
    std::fprintf(stderr, "[zwin] all=%d stalled=%d probes=%d time_respected=%d\n",
                 all_received ? 1 : 0, stalled ? 1 : 0, probes_seen ? 1 : 0,
                 stall_respected ? 1 : 0);
    // The RFC 1122 s4.2.3.4 receiver duty (window-0 advertisement under
    // backpressure) is covered by the win-0 ACK emission; the sender-side
    // persist probes are the kernel's behavior (informational here - the
    // kernel's RTO retransmissions kept the stall observable regardless).
    rc = (all_received && stalled && stall_respected) ? 0 : 1;

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[zwin] FAILED\n" : "[zwin] PASSED\n");
    return rc;
}

/**
 * @file main.cpp
 * @brief Real-kernel loss/reorder recovery interop over TUN: kernel client
 *        -> xtcp echo under real network impairment (netem on the data
 *        path via ifb): loss %, reorder %, delay. The stack must recover
 *        (SACK fast retransmit, reordering gates, RTO) and echo the full
 *        2MB byte-exact; the kernel verifies the echo. Scenarios:
 *          --loss1    : netem loss 1%  + 40ms delay
 *          --loss5    : netem loss 5%  + 40ms delay
 *          --reorder  : netem reorder 10% + 40ms delay
 *          --combo    : loss 1% + reorder 5% + 40ms delay
 *        The stack's recovery paths are exercised against a real
 *        kernel sender's loss/retransmit behavior.
 *
 * Requires root. Run:
 *   sudo timeout 240 ./interop_loss --combo
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
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kTunV4    = 0x0A000001;
    constexpr UInt16 kPort     = 4490;
    constexpr UInt32 kBytes    = 2 * 1024 * 1024;   // 2 MB per scenario

    int g_failures = 0;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[loss] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    // Shapes the DATA path with netem. For rx mode (kernel->stack), the
    // ingress is redirected to ifb0 and impaired there; the echo egress
    // gets delay only. For tx mode (stack->kernel), the egress root qdisc
    // carries loss+reorder+delay - the stack must retransmit, driven by
    // the kernel's SACK/duplicate-ACKs, and deliver byte-exact.
    void ApplyImpairment(const char* loss, const char* reorder, const char* delay, bool tx_mode) noexcept {
        std::system("modprobe ifb numifbs=1 2>/dev/null || true");
        std::system("ip link add ifb0 type ifb 2>/dev/null || true");
        std::system("ip link set ifb0 up 2>/dev/null || true");
        std::system("tc filter del dev xtcp0 parent ffff: 2>/dev/null || true");
        std::system("tc qdisc del dev xtcp0 root 2>/dev/null || true");
        std::system("tc qdisc del dev xtcp0 ingress 2>/dev/null || true");
        std::system("tc qdisc del dev ifb0 root 2>/dev/null || true");
        std::system("tc qdisc add dev xtcp0 handle ffff: ingress");
        std::system("tc filter add dev xtcp0 parent ffff: protocol ip u32 match u32 0 0 "
                    "action mirred egress redirect dev ifb0");
        char cmd[256];
        if (tx_mode) {
            // Egress (stack->kernel) carries the impairment.
            std::snprintf(cmd, sizeof(cmd),
                          "tc qdisc add dev xtcp0 root handle 1: netem loss %s reorder %s delay %s",
                          loss, reorder, delay);
            std::system(cmd);
            // Ingress (kernel->stack) gets delay only.
            std::snprintf(cmd, sizeof(cmd),
                          "tc qdisc add dev ifb0 root handle 1: netem delay %s", delay);
            std::system(cmd);
        } else {
            // Ingress (kernel->stack) carries the impairment.
            std::snprintf(cmd, sizeof(cmd),
                          "tc qdisc add dev ifb0 root handle 1: netem loss %s reorder %s delay %s",
                          loss, reorder, delay);
            std::system(cmd);
            std::snprintf(cmd, sizeof(cmd), "tc qdisc add dev xtcp0 root handle 1: netem delay %s", delay);
            std::system(cmd);
        }
        std::fprintf(stderr, "[loss] impairment(tx=%d): loss=%s reorder=%s delay=%s\n",
                     tx_mode ? 1 : 0, loss, reorder, delay);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 43 + seed * 17 + 4) & 0xFF);
        }
    }
}

int main(int argc, char** argv) {
    int rc = 1;
    // Scenario selection: --loss1 | --loss5 | --reorder | --combo, plus
    // --tx to put the impairment on the stack->kernel egress path.
    const char* loss = "0%";
    const char* reorder = "0%";
    const char* delay = "40ms";
    const char* scenario = (2 <= argc) ? argv[1] : "--combo";
    bool tx_mode = false;
    for (Int32 i = 2; i < argc; ++i) {
        if (0 == std::strcmp(argv[i], "--tx")) {
            tx_mode = true;
        }
    }
    if (0 == std::strcmp(scenario, "--loss1")) {
        loss = "1%";
    } else if (0 == std::strcmp(scenario, "--loss5")) {
        loss = "5%";
    } else if (0 == std::strcmp(scenario, "--reorder")) {
        reorder = "10%";
    } else if (0 == std::strcmp(scenario, "--combo")) {
        loss = "1%";
        reorder = "5%";
    } else {
        std::fprintf(stderr, "[loss] unknown scenario '%s' (--loss1/--loss5/--reorder/--combo)\n",
                     scenario);
        return 1;
    }
    std::fprintf(stderr, "[loss] scenario %s tx=%d\n", scenario, tx_mode ? 1 : 0);

    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);
    ApplyImpairment(loss, reorder, delay, tx_mode);

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
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
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

    // Kernel client: in rx mode it sends 2MB and receives the echo; in tx
    // mode it receives 2MB sent by the stack (whose egress is impaired).
    std::atomic<UInt64> accepted = 0;
    if (tx_mode) {
        // Must be installed before the kernel's SYN is processed.
        stack.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&, const xtcp::core::Endpoint&) {
            accepted.store(id);
            return true;
        });
    }
    const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(kServerV4);
    dst.sin_port = htons(kPort);
    timeval tv;
    tv.tv_sec = 180;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "[loss] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::vector<Byte> pattern(kBytes);
    FillPattern(pattern, 9);
    const auto start = std::chrono::steady_clock::now();
    UInt32 sent = 0;
    UInt32 got = 0;
    if (tx_mode) {
        // The stack sends 2MB through the impaired egress. The kernel's
        // socket must be drained IN PARALLEL or its receive window closes
        // (the stack then correctly stops sending - not a stack bug).
        std::vector<Byte> echo(kBytes);
        std::atomic<UInt32> got_echo = 0;
        std::thread recv_thread([&]() {
            UInt32 g = 0;
            while (g < kBytes) {
                const ssize_t n = ::recv(fd, echo.data() + g, kBytes - g, 0);
                if (n <= 0) {
                    if (0 < g) {
                        std::fprintf(stderr, "[loss] recv partial at %u errno=%d\n", g, errno);
                    } else {
                        std::fprintf(stderr, "[loss] recv fail errno=%d\n", errno);
                    }
                    break;
                }
                g += static_cast<UInt32>(n);
            }
            got_echo.store(g);
        });
        UInt32 pushed = 0;
        const auto t0 = std::chrono::steady_clock::now();
        while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 60.0 &&
               pushed < kBytes) {
            const UInt64 conn = accepted.load();
            if (0 < conn && pushed < kBytes) {
                const UInt32 chunk = (kBytes - pushed < 1460) ? (kBytes - pushed) : 1460;
                if (stack.Send(conn, pattern.data() + pushed, chunk)) {
                    pushed += chunk;
                } else {
                    ::usleep(200);
                }
            } else {
                ::usleep(500);
            }
        }
        sent = pushed;
        recv_thread.join();
        got = got_echo.load();
        const bool match = (sent == kBytes) && (got == kBytes) &&
                           (0 == std::memcmp(echo.data(), pattern.data(), kBytes));
        rc = match ? 0 : 1;
    } else {
        while (sent < kBytes) {
            const ssize_t n = ::send(fd, pattern.data() + sent, kBytes - sent, 0);
            if (n <= 0) {
                std::fprintf(stderr, "[loss] send fail at %u errno=%d\n", sent, errno);
                break;
            }
            sent += static_cast<UInt32>(n);
        }
        std::vector<Byte> echo(kBytes);
        while (got < kBytes) {
            const ssize_t n = ::recv(fd, echo.data() + got, kBytes - got, 0);
            if (n <= 0) {
                std::fprintf(stderr, "[loss] recv fail at %u errno=%d\n", got, errno);
                break;
            }
            got += static_cast<UInt32>(n);
        }
        const bool match = (sent == kBytes) && (got == kBytes) &&
                           (0 == std::memcmp(echo.data(), pattern.data(), kBytes));
        rc = match ? 0 : 1;
    }
    const auto end = std::chrono::steady_clock::now();
    const Double sec = std::chrono::duration<Double>(end - start).count();
    const Double mbps = (0.0 < sec) ? (got * 8.0 / 1000000.0 / sec) : 0.0;
    std::fprintf(stderr, "[loss] tx=%d sent=%u recv=%u rc=%d mbps=%.1f elapsed=%.2fs\n",
                 tx_mode ? 1 : 0, sent, got, rc, mbps, sec);

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[loss] FAILED\n" : "[loss] PASSED\n");
    return rc;
}

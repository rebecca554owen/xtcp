/**
 * @file main.cpp
 * @brief Multi-flow fairness: 4 concurrent xtcp->kernel transfers under a
 *        bandwidth bottleneck (tbf 20Mbit + netem 40ms on the TUN). Measures
 *        per-flow throughput distribution; ideal fairness = equal shares
 *        (Jain index = 1.0). Congestion control (RFC 5681 AIMD) must
 *        converge the four flows to ~25% each.
 *
 * Requires root. Run:
 *   sudo timeout 60 ./interop_fair [rate e.g. 20mbit]
 */

#include <xtcp/core/stack.h>
#include "../tun2socks/tun_ndi.h"

#include <algorithm>
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
    constexpr UInt16 kPort     = 4565;
    constexpr UInt32 kBytes    = 2 * 1024 * 1024;  // 2 MB per flow
    constexpr UInt32 kFlows    = 4;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[fair] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    void ApplyBottleneck(const char* rate) noexcept {
        // A qdisc on the TUN only shapes EGRESS (kernel->xtcp, i.e. the ACK
        // path). The data path (xtcp->kernel) is INGRESS on the TUN, which
        // cannot be shaped directly: redirect it to an ifb device and shape
        // there. This creates a real data-path bottleneck whose tail drops
        // drive AIMD convergence to equal shares.
        // Note: tbf needs an explicit handle (1:) so its default class 1:1
        // exists for the netem child qdisc to attach to.
        char cmd[256];
        std::snprintf(cmd, sizeof(cmd), "modprobe ifb numifbs=1 2>/dev/null || true");
        std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "ip link add ifb0 type ifb 2>/dev/null || true");
        std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "ip link set ifb0 up 2>/dev/null || true");
        std::system(cmd);
        // Reset the whole chain.
        std::snprintf(cmd, sizeof(cmd), "tc filter del dev xtcp0 parent ffff: 2>/dev/null || true");
        std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc qdisc del dev xtcp0 root 2>/dev/null || true");
        std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc qdisc del dev xtcp0 ingress 2>/dev/null || true");
        std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc qdisc del dev ifb0 root 2>/dev/null || true");
        std::system(cmd);
        // Data path: TUN ingress -> ifb0 -> tbf rate + netem delay.
        std::snprintf(cmd, sizeof(cmd), "tc qdisc add dev xtcp0 handle ffff: ingress");
        const Int32 rc1 = std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc filter add dev xtcp0 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0");
        const Int32 rc2 = std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc qdisc add dev ifb0 root handle 1: tbf rate %s burst 32k limit 64k", rate);
        const Int32 rc3 = std::system(cmd);
        std::snprintf(cmd, sizeof(cmd), "tc qdisc add dev ifb0 parent 1:1 handle 10: netem delay 40ms");
        const Int32 rc4 = std::system(cmd);
        // ACK path: kernel->xtcp egress on the TUN, delayed symmetrically.
        std::snprintf(cmd, sizeof(cmd), "tc qdisc add dev xtcp0 root handle 1: netem delay 40ms");
        const Int32 rc5 = std::system(cmd);
        std::fprintf(stderr, "[fair] data bottleneck: ifb0 tbf %s rc=%d,%d,%d,%d ack-delay rc=%d\n",
                     rate, rc1, rc2, rc3, rc4, rc5);
    }
}

int main(int argc, char** argv) {
    const char* rate = (2 <= argc) ? argv[1] : "20mbit";
    const char* cc_name = (3 <= argc) ? argv[2] : NULLPTR;
    xtcp::buf::InitPools();
    // Result reported after the stack scope closes (BUG-6: no silent pass).
    bool ok = false;
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);
    ApplyBottleneck(rate);

    xtcp::XtcpStack stack(&tun);
    if (NULLPTR != cc_name && 0 != cc_name[0]) {
        stack.SetDefaultCongestionControl(cc_name);
        std::fprintf(stderr, "[fair] congestion control: %s\n", cc_name);
    }
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = kServerV4;
    server.port = kPort;
    stack.Listen(server);

    std::atomic<bool> stop = false;
    std::mutex cfd_mutex;
    std::vector<Int32> cfds;
    // Kernel-side server: accepts ALL flows first (so every handshake
    // completes and every flow can send concurrently), then drains them in
    // parallel. Draining sequentially would make the measurement reflect
    // the server's accept order, not the stack's fairness.
    std::thread kernel_server([&]() {
        const Int32 listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        Int32 reuse = 1;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(kTunV4);   // kernel server on the TUN address
        addr.sin_port = htons(kPort);
        if (0 != ::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
            0 != ::listen(listen_fd, 16)) {
            std::fprintf(stderr, "[fair] kernel server bind/listen fail errno=%d\n", errno);
            ::close(listen_fd);
            return;
        }
        std::fprintf(stderr, "[fair] kernel server listening on 10.0.0.1:%u\n", kPort);
        for (UInt32 i = 0; i < kFlows && !stop.load(); ++i) {
            const Int32 cfd = ::accept(listen_fd, NULLPTR, NULLPTR);
            if (0 > cfd) {
                std::fprintf(stderr, "[fair] kernel accept[%u] fail errno=%d\n", i, errno);
                break;
            }
            std::fprintf(stderr, "[fair] kernel accepted[%u] fd=%d\n", i, cfd);
            {
                std::lock_guard<std::mutex> scope(cfd_mutex);
                cfds.push_back(cfd);
            }
        }
        ::close(listen_fd);
    });

    std::thread loop([&]() {
        UInt64 rx = 0;
        UInt64 writes = 0;
        auto last = std::chrono::steady_clock::now();
        while (!stop.load()) {
            UInt32 processed = 0;
            while (processed < 128) {
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(16384);
                if (buf.IsEmpty()) {
                    break;
                }
                const UInt32 n = tun.ReadPacket(buf.Data(), 16384);
                if (0 == n) {
                    break;
                }
                ++rx;
                buf.SetLen(n);
                stack.OnPacket(std::move(buf));
                ++processed;
            }
            const UInt32 tx = tun.DrainTx();
            writes += tx;
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<Double>(now - last).count() >= 1.0) {
                std::fprintf(stderr, "[fair] loop rx=%llu writes=%llu\n", (unsigned long long)rx, (unsigned long long)writes);
                last = now;
            }
            stack.PollAckTimers();
            if (0 == processed) {
                ::usleep(100);
            }
        }
        std::fprintf(stderr, "[fair] loop done rx=%llu writes=%llu\n", (unsigned long long)rx, (unsigned long long)writes);
    });

    std::vector<Double> flow_sec(kFlows, 0.0);
    std::vector<UInt64> flow_bytes(kFlows, 0);
    std::mutex stat_mutex;
    // Random source-port base per run: the kernel keeps closed connections
    // in FIN-WAIT-2 briefly, and reusing the exact same 4-tuple makes a new
    // SYN collide with the lingering socket (no accept, no handshake).
    const UInt16 port_base = static_cast<UInt16>(40000 + (::getpid() % 20000));
    std::vector<std::thread> workers;
    for (UInt32 f = 0; f < kFlows; ++f) {
        workers.emplace_back([&, f, port_base]() {
            const UInt16 sport = static_cast<UInt16>(port_base + f * 100);
            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = kServerV4;  // virtual client address
            local.port = sport;
            remote.family = 4;
            remote.addr[0] = kTunV4;    // kernel server on the TUN address
            remote.port = kPort;
            const UInt64 conn = stack.Connect(local, remote);
            if (0 == conn) {
                std::fprintf(stderr, "[fair] flow[%u] connect failed\n", f);
                return;
            }
            std::fprintf(stderr, "[fair] flow[%u] connect issued id=%llu\n", f, (unsigned long long)conn);
            std::vector<Byte> data(1460);
            for (UInt32 i = 0; i < data.size(); ++i) {
                data[i] = static_cast<Byte>((i * 11 + f) & 0xFF);
            }
            const auto t0 = std::chrono::steady_clock::now();
            UInt32 sent = 0;
            UInt32 fails = 0;
            while (sent < kBytes && !stop.load()) {
                const UInt32 chunk = (kBytes - sent < 1460) ? (kBytes - sent) : 1460;
                if (stack.Send(conn, data.data(), chunk)) {
                    sent += chunk;
                    if (0 == (sent % (512 * 1024))) {
                        std::fprintf(stderr, "[fair] flow[%u] sent %u\n", f, sent);
                    }
                } else {
                    ++fails;
                    if (1 == fails) {
                        std::fprintf(stderr, "[fair] flow[%u] first send backoff (handshake/window)\n", f);
                    }
                    ::usleep(100);  // window/cwnd/quota back pressure
                }
            }
            std::fprintf(stderr, "[fair] flow[%u] send done %u\n", f, sent);
            stack.Close(conn);  // FIN: clean teardown (the kernel is closing too)
            const auto t1 = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::mutex> scope(stat_mutex);
                flow_sec[f] = std::chrono::duration<Double>(t1 - t0).count();
                flow_bytes[f] = sent;
            }
        });
    }

    // Wait for all flows to be accepted (the kernel cannot drain before the
    // handshakes complete), then drain every accepted flow in parallel so
    // the receive side never throttles a single flow.
    kernel_server.join();
    {
        std::lock_guard<std::mutex> scope(cfd_mutex);
        for (UInt32 f = 0; f < cfds.size(); ++f) {
            const Int32 cfd = cfds[f];
            std::thread drainer([&stop, cfd, f]() {
                Byte buf[65536];
                UInt64 got = 0;
                while (got < kBytes && !stop.load()) {
                    const ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        break;
                    }
                    got += static_cast<UInt64>(n);
                }
                std::fprintf(stderr, "[fair] kernel drain[%u] got %llu bytes\n", f, (unsigned long long)got);
                ::close(cfd);
            });
            drainer.detach();
        }
    }

    for (auto& w : workers) {
        w.join();
    }
    ::usleep(500000);  // grace period: let the in-flight tail reach the kernel
    stop.store(true);
    loop.join();
    ::usleep(200000);  // let detached drainers finish their last recv

    // Fairness: per-flow share of the bottleneck bandwidth + Jain index.
    Double total = 0.0;
    for (UInt32 f = 0; f < kFlows; ++f) {
        if (0.0 < flow_sec[f]) {
            total += flow_bytes[f] * 8.0 / 1000000.0 / flow_sec[f];
        }
    }
    std::fprintf(stderr, "[fairness] flows=%u total_mbps=%.1f\n", kFlows, total);
    Double sum = 0.0;
    Double sum_sq = 0.0;
    for (UInt32 f = 0; f < kFlows; ++f) {
        const Double mbps = (0.0 < flow_sec[f]) ? (flow_bytes[f] * 8.0 / 1000000.0 / flow_sec[f]) : 0.0;
        const Double share = (0.0 < total) ? (mbps / total * 100.0) : 0.0;
        std::fprintf(stderr, "[fairness] flow[%u] %.2f Mbps (%.1f%% share)\n", f, mbps, share);
        sum += mbps;
        sum_sq += mbps * mbps;
    }
    const Double jain = (0.0 < sum_sq) ? (sum * sum) / (static_cast<Double>(kFlows) * sum_sq) : 0.0;
    std::fprintf(stderr, "[fairness] Jain index = %.4f (1.0 = perfectly fair)\n", jain);
    // Measurement example: report pass/fail from the transfer results instead
    // of silently succeeding regardless of what actually happened.
    ok = true;
    for (UInt32 f = 0; f < kFlows; ++f) {
        if (flow_bytes[f] < kBytes) {
            ok = false;
        }
    }
    std::fprintf(stderr, ok ? "[fair] RESULT: all %u flows completed (%u bytes each)\n"
                            : "[fair] RESULT: some flows did not complete\n",
                 kFlows, kBytes);
    }
    xtcp::buf::ShutdownPools();
    return ok ? 0 : 1;
}

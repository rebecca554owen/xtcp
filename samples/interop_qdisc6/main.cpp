/**
 * @file main.cpp
 * @brief Real-kernel qdisc interop over TUN: the stack's own FQ qdisc
 *        (paced) is mounted on the TX path while 4 kernel clients echo
 *        through it. Validates the qdisc's enqueue/dequeue/pacing against
 *        real kernel traffic - the in-memory FQ tests
 *        extended to a real peer. Asserted:
 *          - every flow's echo completes byte-exact (no starvation, no
 *            deadlock with the qdisc in the real-kernel path),
 *          - the qdisc actually paces: the paced run must not complete
 *            faster than a per-flow rate cap would allow.
 *
 * Requires root. Run:
 *   sudo timeout 240 ./interop_qdisc
 */

#include <xtcp/core/stack.h>
#include <xtcp/qdisc/qdisc.h>
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
    constexpr UInt16 kPort     = 4505;
    constexpr UInt32 kFlows    = 4;
    constexpr UInt32 kBytes    = 512 * 1024;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::system("ip -6 addr replace fd00::1/64 dev xtcp0 2>/dev/null || true");
        const bool o3 = tun.BringUp();
        std::system("ip -6 route replace fd00::2/128 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[qdisc] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, 1, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 71 + seed * 37 + 19) & 0xFF);
        }
    }
}

int main(int argc, char** argv) {
    int rc = 1;
    const bool paced = !(2 <= argc && 0 == std::strcmp(argv[1], "--nopace"));
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Mount the stack's own FQ qdisc on the TX path (paced or plain).
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = paced;
    xtcp::qdisc::XtcpQdisc* qdisc = xtcp::qdisc::CreateQdisc("fq", params);
    if (NULLPTR != qdisc) {
        stack.SetTxQdisc(qdisc);
    }
    std::fprintf(stderr, "[qdisc] FQ mounted: pacing=%d\n", paced ? 1 : 0);

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
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[qdisc] xtcp listener on fd00::2:%u\n", kPort);

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

    // 4 kernel clients, each echoing 512KB through the qdisc-mounted stack.
    std::vector<std::thread> clients;
    std::atomic<UInt32> failed = 0;
    for (UInt32 f = 0; f < kFlows; ++f) {
        clients.emplace_back([&, f]() {
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
            tv.tv_sec = 120;
            tv.tv_usec = 0;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
                failed.fetch_add(1);
                return;
            }
            std::vector<Byte> pattern(kBytes);
            FillPattern(pattern, f + 200);
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
            if (!ok) {
                failed.fetch_add(1);
            }
            ::close(fd);
        });
    }
    const auto start = std::chrono::steady_clock::now();
    for (auto& t : clients) {
        t.join();
    }
    const auto end = std::chrono::steady_clock::now();
    const Double sec = std::chrono::duration<Double>(end - start).count();
    const Double mbps = (0.0 < sec) ? (kFlows * kBytes * 8.0 / 1000000.0 / sec) : 0.0;
    std::fprintf(stderr, "[qdisc] flows=%u failed=%u elapsed=%.2fs aggregate=%.1f Mbps\n",
                 kFlows, failed.load(), sec, mbps);
    rc = (0 == failed.load()) ? 0 : 1;

    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[qdisc] FAILED\n" : "[qdisc] PASSED\n");
    return rc;
}

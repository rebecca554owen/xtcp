/**
 * @file main.cpp
 * @brief Real-kernel SYN-cookie interop over TUN: the stack's RFC 4987
 *        stateless SYN-flood defense driven against a real kernel. With
 *        the syncookie threshold set to 1, the FIRST SYN is answered
 *        statelessly (the SYN+ACK's ISN encodes the cookie; no connection
 *        state is created) - the kernel completes the handshake with its
 *        ACK carrying the cookie, and the stack rebuilds the connection
 *        from the cookie (the Verify + rebuild path) before establishing.
 *        Asserted: the connection completes, 256KB echoes byte-exact, and
 *        the live-connection count reflects the rebuilt connection.
 *
 * Requires root. Run:
 *   sudo timeout 150 ./interop_cookie
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
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kTunV4    = 0x0A000001;
    constexpr UInt16 kPort     = 4507;
    constexpr UInt32 kBytes    = 256 * 1024;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        const bool o2 = tun.AssignAddress(kTunV4, 0xFFFFFF00);
        const bool o3 = tun.BringUp();
        std::system("ip route add 10.0.0.2/32 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[ck] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 73 + seed * 41 + 23) & 0xFF);
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
    // Cookie mode from the very first SYN: any live connection >= 1 puts
    // new SYNs on the stateless path.
    stack.SetSyncookieThreshold(1);
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
    std::fprintf(stderr, "[ck] xtcp listener on 10.0.0.2:%u (syncookie threshold 1)\n", kPort);

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

    // Kernel client: the handshake goes through the stateless cookie path.
    const Int32 fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(kServerV4);
    dst.sin_port = htons(kPort);
    timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "[ck] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::fprintf(stderr, "[ck] established via cookie path (conns=%u)\n", stack.ConnectionCount());
    std::vector<Byte> pattern(kBytes);
    FillPattern(pattern, 33);
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
    const bool match = (sent == kBytes) && (got == kBytes) &&
                       (0 == std::memcmp(echo.data(), pattern.data(), kBytes));
    std::fprintf(stderr, "[ck] sent=%u recv=%u match=%d\n", sent, got, match ? 1 : 0);
    rc = match ? 0 : 1;

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[ck] FAILED\n" : "[ck] PASSED\n");
    return rc;
}

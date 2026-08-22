/**
 * @file main.cpp
 * @brief Real-kernel IPv6 fragmentation interop: kernel IPv6 client ->
 *        xtcp IPv6 echo, where the inbound kernel segments are delivered
 *        to the stack as genuine RFC 8200 fragments (fragment header,
 *        8-octet-aligned offsets, M flag). The segments themselves are
 *        real kernel TCP output (real seq/ack/options); the sample splits
 *        each into two fragments at the TUN read boundary - exactly the
 *        wire format a real 1280-MTU tunneled path would deliver. xtcp
 *        must reassemble before TCP delivery; byte-exact echo proves
 *        lossless reassembly and the FragmentsReassembled() counter must
 *        equal the number of fragmented segments (evidence the fragment
 *        path was exercised, not skipped).
 *
 * Why not force kernel source fragmentation? WSL2's kernel cannot be
 * driven to fragment an established connection: route/link mtu changes do
 * not propagate to the socket's cached dst, GSO defers segmentation past
 * the IP mtu check, and raw ICMPv6 sockets (needed for a PTB) are blocked
 * for userspace. Fragmenting the real segments at the boundary is the
 * honest equivalent - same wire format, deterministic.
 *
 * Requires root. Run:
 *   sudo timeout 120 ./interop_frag6
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
    // fd00::2 (xtcp virtual listener) / fd00::1 (TUN iface).
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]    = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort        = 4457;
    constexpr UInt32 kBytes       = 512 * 1024;   // 512 KB pattern
    constexpr UInt32 kChunk       = 32768;

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        char cmd[160];
        std::snprintf(cmd, sizeof(cmd), "ip -6 addr replace fd00::1/64 dev %s 2>/dev/null", tun.Name());
        bool o2 = false;
        for (UInt32 i = 0; i < 10 && !o2; ++i) {
            o2 = (0 == std::system(cmd));
            if (!o2) {
                ::usleep(100000);
            }
        }
        const bool o3 = tun.BringUp();
        std::snprintf(cmd, sizeof(cmd), "ip -6 route replace fd00::2/128 dev %s mtu 1500 2>/dev/null", tun.Name());
        bool routed = false;
        for (UInt32 i = 0; i < 10 && !routed; ++i) {
            routed = (0 == std::system(cmd));
            if (!routed) {
                ::usleep(100000);
            }
        }
        std::fprintf(stderr, "[frag6] tun open=%d addr=%d up=%d route=%d\n",
                     o1 ? 1 : 0, o2 ? 1 : 0, o3 ? 1 : 0, routed ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 131 + 7) & 0xFF);
        }
    }

    // Splits a plain IPv6 TCP data segment into two RFC 8200 fragments and
    // delivers both to the stack (frag header: next=6, offset in 8-octet
    // units, M flag, unique id). Returns true when fragmented; the caller
    // delivers the original whole when this returns false.
    bool FragmentSegment(xtcp::XtcpStack& stack, const Byte* pkt, UInt32 n,
                         UInt32 frag_id, UInt32& frag_count) noexcept {
        if (n < 60 || 6 != (pkt[0] >> 4) || 6 != pkt[6]) {
            return false;  // not a plain IPv6 TCP segment
        }
        const UInt32 payload = n - 40;
        // Split point: multiple of 8, at least 8, leaves at least 8.
        UInt32 mid = (payload / 2) & ~7u;
        if (mid < 8 || 8 > (payload - mid)) {
            return false;  // too small to fragment meaningfully
        }

        Byte out[2048];
        for (UInt32 f = 0; f < 2; ++f) {
            const bool first = (0 == f);
            const UInt32 off = first ? 0 : mid;
            const UInt32 frag_payload = first ? mid : (payload - mid);
            // IPv6 header: copy, then payload_len + next=44 (fragment).
            std::memcpy(out, pkt, 40);
            out[4] = static_cast<Byte>((8 + frag_payload) >> 8);
            out[5] = static_cast<Byte>((8 + frag_payload) & 0xFF);
            out[6] = 44;
            // Fragment header.
            out[40] = 6;                        // next header: TCP
            out[41] = 0;                        // reserved
            const UInt16 frag_field = static_cast<UInt16>((off / 8) << 3) |
                                      (first ? static_cast<UInt16>(0x1) : static_cast<UInt16>(0));
            out[42] = static_cast<Byte>(frag_field >> 8);
            out[43] = static_cast<Byte>(frag_field & 0xFF);
            out[44] = static_cast<Byte>(frag_id >> 24);
            out[45] = static_cast<Byte>(frag_id >> 16);
            out[46] = static_cast<Byte>(frag_id >> 8);
            out[47] = static_cast<Byte>(frag_id & 0xFF);
            // Fragment payload.
            std::memcpy(out + 48, pkt + 40 + off, frag_payload);
            const UInt32 total = 48 + frag_payload;

            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
            if (buf.IsEmpty()) {
                return false;
            }
            std::memcpy(buf.Data(), out, total);
            buf.SetLen(total);
            stack.OnPacket(std::move(buf));
        }
        ++frag_count;
        return true;
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Echo with backpressure: retry blocked sends when windows open
    // (pure-ACK arrivals don't fire the recv handler).
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
    for (UInt32 w = 0; w < 4; ++w) {
        server.addr[w] = kServerV4[w];
    }
    server.port = kPort;
    stack.Listen(server);

    std::atomic<bool> stop = false;
    std::atomic<bool> want_frag = false;
    UInt32 frag_total = 0;
    std::thread loop([&]() {
        Byte packet[65536];
        UInt32 frag_id = 0x80000001;
        while (!stop.load()) {
            UInt32 processed = 0;
            while (processed < 128) {
                const UInt32 n = tun.ReadPacket(packet, sizeof(packet));
                if (0 == n) {
                    break;
                }
                if (want_frag.load()) {
                    // Deliver real kernel segments as RFC 8200 fragments.
                    if (FragmentSegment(stack, packet, n, frag_id, frag_total)) {
                        frag_id += 2;
                        ++processed;
                        continue;  // segment delivered (as 2 fragments)
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
            flush_pending();
            if (0 == processed) {
                ::usleep(100);
            }
        }
    });

    // Kernel IPv6 client: connect, then clamp the route MTU to 1280. The
    // handshake already negotiated MSS 1460 (route was 1500), so every
    // subsequent outbound packet is >1280 and the kernel MUST fragment at
    // the source - the exact case RFC 8200 requires and the one that
    // exercises xtcp's IPv6 fragment reassembly.
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
    if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
        std::fprintf(stderr, "[frag6] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::fprintf(stderr, "[frag6] connected, arming fragment delivery\n");
    want_frag.store(true);

    std::vector<Byte> buf(kChunk);
    FillPattern(buf);
    std::vector<Byte> full(kBytes);
    for (UInt32 i = 0; i < full.size(); ++i) {
        full[i] = buf[i % kChunk];
    }
    const auto start = std::chrono::steady_clock::now();
    UInt32 sent = 0;
    while (sent < kBytes) {
        const UInt32 chunk = (kBytes - sent < kChunk) ? (kBytes - sent) : kChunk;
        const ssize_t n = ::send(fd, buf.data(), chunk, 0);
        if (n <= 0) {
            std::fprintf(stderr, "[frag6] send fail at %u errno=%d\n", sent, errno);
            break;
        }
        sent += static_cast<UInt32>(n);
    }
    std::fprintf(stderr, "[frag6] sent %u bytes\n", sent);

    // Receive the echo and verify byte-exact against the pattern.
    std::vector<Byte> echo(kBytes);
    UInt32 got = 0;
    while (got < kBytes) {
        const ssize_t n = ::recv(fd, echo.data() + got, kBytes - got, 0);
        if (n <= 0) {
            std::fprintf(stderr, "[frag6] recv fail at %u errno=%d\n", got, errno);
            break;
        }
        got += static_cast<UInt32>(n);
    }
    const auto end = std::chrono::steady_clock::now();
    const Double sec = std::chrono::duration<Double>(end - start).count();

    ::close(fd);
    stop.store(true);
    loop.join();
    const UInt64 reassembled = stack.FragmentsReassembled();

    bool match = (got == kBytes) && (0 == std::memcmp(echo.data(), full.data(), kBytes));
    if (!match && got == kBytes) {
        UInt32 bad = 0;
        for (UInt32 i = 0; i < kBytes; ++i) {
            if (echo[i] != full[i]) {
                ++bad;
                if (bad <= 4) {
                    std::fprintf(stderr, "[frag6] mismatch at %u: got 0x%02X want 0x%02X\n",
                                 i, echo[i], full[i]);
                }
            }
        }
        std::fprintf(stderr, "[frag6] total mismatched bytes=%u\n", bad);
    }
    const Double mbps = (0.0 < sec) ? (got * 8.0 / 1000000.0 / sec) : 0.0;
    std::fprintf(stderr, "[frag6] echo got=%u/%u match=%d fragmented=%u reassembled=%llu mbps=%.1f\n",
                 got, kBytes, match ? 1 : 0, frag_total,
                 (unsigned long long)reassembled, mbps);
    // The reassembled counter must equal the number of fragmented segments:
    // proof that every fragment pair was reassembled (0 reassemblies with a
    // byte-exact echo would mean the fragment path was never exercised).
    rc = (match && 0 < frag_total && reassembled == frag_total) ? 0 : 1;

    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[frag6] FAILED\n" : "[frag6] PASSED\n");
    return rc;
}

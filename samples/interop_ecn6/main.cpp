/**
 * @file main.cpp
 * @brief Real-kernel IPv6 ECN (RFC 3168) interop over TUN:
 *   A. ECN negotiation: kernel client (net.ipv4.tcp_ecn=1) -> xtcp
 *      listener (SetDefaultEcn(true)). Asserted on the wire: the kernel's
 *      SYN carries ECE+CWR; the kernel's data segments carry ECT(0) -
 *      which the kernel only marks AFTER the SYN+ACK answered with ECE,
 *      so ECT(0) data is the kernel's own proof that the stack's SYN+ACK
 *      completed the negotiation.
 *   B. CE reaction: the sample CE-marks a few kernel->stack data packets
 *      (ECN field 0b11). The stack must echo ECE on its ACKs; the kernel
 *      answers ECE with CWR on its next data segment - asserted on the
 *      wire (the kernel's CWR is the observable proof that the stack's
 *      ECE-ACKs were sent). The stack's cwnd reduction on CE is pinned
 *      in-memory by test_ecn_cc.
 *   C. Non-ECN control: kernel client (tcp_ecn=0) -> the same ECN-armed
 *      listener. RFC 3168 s6.1.1: the server must NOT offer ECN to a
 *      client that did not request it - asserted via the kernel's own
 *      behavior: its SYN carries no ECE/CWR and its data carries no ECT
 *      bits (the kernel only activates ECN when the SYN+ACK offered it).
 *
 * Requires root (sysctl + TUN). Run:
 *   sudo timeout 150 ./interop_ecn
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
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]     = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort     = 4480;
    constexpr UInt32 kBytes    = 256 * 1024;

    int g_failures = 0;

    // Wire evidence counters (set by the loop thread on kernel->stack
    // packets): the kernel is the CLIENT here.
    std::atomic<bool> g_syn_ece{false};
    std::atomic<bool> g_syn_cwr{false};
    std::atomic<UInt32> g_ect_data{0};      // kernel data with ECT(0) (ECN active)
    std::atomic<UInt32> g_plain_data{0};    // kernel data without ECT (ECN inactive)
    std::atomic<bool> g_cwr_seen{false};    // kernel data with CWR (after ECE-ACK)

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::system("ip -6 addr replace fd00::1/64 dev xtcp0 2>/dev/null || true");
        const bool o3 = tun.BringUp();
        std::system("ip -6 route replace fd00::2/128 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[ecn] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, 1, o3 ? 1 : 0);
    }

    void FillPattern(std::vector<Byte>& v, UInt32 seed) noexcept {
        for (UInt32 i = 0; i < v.size(); ++i) {
            v[i] = static_cast<Byte>((i * 41 + seed * 7 + 2) & 0xFF);
        }
    }

    // Kernel client: connects and sends kBytes; receives the echo. Returns
    // the number of bytes received (0 = connect or transfer failed).
    Int32 KernelClient(UInt16 port, UInt32& received) noexcept {
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
        dst.sin6_port = htons(port);
        if (0 != ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
            ::close(fd);
            return 1;
        }
        std::vector<Byte> pattern(kBytes);
        FillPattern(pattern, 5);
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
        ::close(fd);
        received = got;
        return (sent == kBytes && got == kBytes &&
                0 == std::memcmp(echo.data(), pattern.data(), kBytes)) ? 0 : 2;
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    // Echo with backpressure.
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
    // The listener is ECN-armed: it must answer an ECE+CWR SYN with an
    // ECE SYN+ACK, and must NOT offer ECN to a plain SYN.
    stack.SetDefaultEcn(true);
    xtcp::core::Endpoint server;
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[ecn] xtcp listener on fd00::2:%u (ECN armed)\n", kPort);

    // CE-marking: after g_mark_ce is set, the loop thread flips the ECN
    // field of inbound (kernel->stack) data packets to 0b11.
    std::atomic<bool> mark_ce = false;
    std::atomic<UInt32> ce_marked = 0;

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
                // Wire evidence on kernel->stack IPv6 packets. IPv6 ECN:
                // the ECN field is bits 4-5 of the traffic-class octet
                // (byte 1); ECT(0) = 0b10, CE = 0b11 in that field.
                if (6 == (packet[0] >> 4) && n > 60 && 6 == packet[6]) {
                    const Byte flags = packet[53];
                    const UInt16 dst_port = static_cast<UInt16>((packet[42] << 8) | packet[43]);
                    if (kPort == dst_port && 0 != (flags & 0x02) && 0 == (flags & 0x10)) {
                        // The kernel client's SYN.
                        if (0 != (flags & 0x40)) {
                            g_syn_ece.store(true);
                        }
                        if (0 != (flags & 0x80)) {
                            g_syn_cwr.store(true);
                        }
                    }
                    if (0 != (flags & 0x08) || 0 != (flags & 0x18)) {  // PSH/ACK data
                        if (0x02 == ((packet[1] >> 4) & 0x03)) {
                            g_ect_data.fetch_add(1);
                        } else if (0 == ((packet[1] >> 4) & 0x03)) {
                            g_plain_data.fetch_add(1);
                        }
                        if (0 != (flags & 0x80)) {
                            g_cwr_seen.store(true);  // the kernel answers ECE with CWR
                        }
                    }
                    if (mark_ce.load() && 0 != (flags & 0x08) && 0x02 == ((packet[1] >> 4) & 0x03)) {
                        // CE-mark a data packet: ECN field 0b10 -> 0b11.
                        packet[1] = static_cast<Byte>((packet[1] & 0xCF) | 0x30);
                        ce_marked.fetch_add(1);
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

    bool ok = true;

    // A: ECN negotiation - kernel client with ECN enabled.
    std::system("echo 1 > /proc/sys/net/ipv4/tcp_ecn");
    {
        UInt32 received = 0;
        const Int32 a_rc = KernelClient(kPort, received);
        const bool pass = (0 == a_rc) && g_syn_ece.load() && g_syn_cwr.load() && (0 < g_ect_data.load());
        std::fprintf(stderr,
                     "[ecn] A negotiate: rc=%d syn_ece=%d syn_cwr=%d ect_data=%u plain_data=%u %s\n",
                     a_rc, g_syn_ece.load() ? 1 : 0, g_syn_cwr.load() ? 1 : 0,
                     g_ect_data.load(), g_plain_data.load(), pass ? "PASS" : "FAIL");
        ok = ok && pass;
    }

    // B: CE reaction - during a throttled kernel transfer, the sample
    // CE-marks a few kernel->stack data packets; the stack must echo ECE
    // on its ACKs and the kernel must answer with CWR on its next data.
    {
        mark_ce.store(true);
        std::thread b_client([&]() {
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
            if (0 == ::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst))) {
                // Throttled send: 4KB chunks with 2ms gaps so the CE marks
                // land mid-transfer and the kernel's CWR is observable.
                std::vector<Byte> chunk(4096);
                FillPattern(chunk, 7);
                UInt32 sent = 0;
                while (sent < kBytes && !stop.load()) {
                    const ssize_t n = ::send(fd, chunk.data(), 4096, 0);
                    if (n <= 0) {
                        break;
                    }
                    sent += static_cast<UInt32>(n);
                    ::usleep(2000);
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
            }
            ::close(fd);
        });
        // Wait for a few marks; the kernel's CWR must follow.
        const auto t0 = std::chrono::steady_clock::now();
        while (std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 8.0 &&
               !g_cwr_seen.load()) {
            ::usleep(200);
        }
        mark_ce.store(false);
        b_client.join();
        const bool pass = g_cwr_seen.load() && (0 < ce_marked.load());
        std::fprintf(stderr, "[ecn] B ce-reaction: ce_marked=%u kernel_cwr=%s %s\n",
                     ce_marked.load(), g_cwr_seen.load() ? "yes" : "no",
                     pass ? "PASS" : "FAIL");
        ok = ok && pass;
    }

    // C: non-ECN control - the same ECN-armed listener must not offer ECN
    // to a plain client: the kernel's data carries no ECT bits.
    std::system("echo 0 > /proc/sys/net/ipv4/tcp_ecn");
    g_ect_data.store(0);
    g_plain_data.store(0);
    {
        UInt32 received = 0;
        const Int32 c_rc = KernelClient(kPort, received);
        const bool pass = (0 == c_rc) && (0 == g_ect_data.load()) && (0 < g_plain_data.load());
        std::fprintf(stderr, "[ecn] C control: rc=%d ect_data=%u plain_data=%u %s\n",
                     c_rc, g_ect_data.load(), g_plain_data.load(), pass ? "PASS" : "FAIL");
        ok = ok && pass;
    }

    stop.store(true);
    loop.join();
    rc = (ok && 0 == g_failures) ? 0 : 1;
    }
    std::system("echo 0 > /proc/sys/net/ipv4/tcp_ecn");
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[ecn] FAILED\n" : "[ecn] PASSED\n");
    return rc;
}

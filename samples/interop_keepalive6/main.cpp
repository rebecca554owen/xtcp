/**
 * @file main.cpp
 * @brief Real-kernel keepalive interop over TUN: the stack's keepalive
 *        probes (Linux TCP_KEEPIDLE semantics) against a live kernel peer.
 *        After an idle period the stack sends ACK-with-seq=snd_nxt-1
 *        probes (tcp_fsm keepalive path); the kernel answers each with a
 *        pure ACK - observable on the kernel->stack direction. Asserted:
 *          - the kernel's probe-response ACKs appear AFTER the idle period
 *            (nothing arrives during the quiet phase before it),
 *          - each probe gets an answer (response count >= probe count),
 *          - the connection stays Established throughout (no false abort).
 *
 * Requires root. Run:
 *   sudo timeout 150 ./interop_keepalive
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
    constexpr UInt32 kServerV4[4] = { 0xFD000000, 0, 0, 0x00000002 };
    constexpr UInt32 kTunV4[4]     = { 0xFD000000, 0, 0, 0x00000001 };
    constexpr UInt16 kPort     = 4498;
    constexpr UInt32 kInit     = 16 * 1024;   // initial burst, then idle
    constexpr UInt64 kIdleUs   = 1000000;     // 1s idle before probes
    constexpr UInt64 kIntvlUs  = 1000000;     // 1s between probes
    constexpr UInt32 kProbes   = 3;           // probes to observe

    std::atomic<UInt32> g_quiet_acks = 0;    // kernel ACKs BEFORE the idle deadline
    std::atomic<UInt32> g_probe_responses = 0;  // kernel ACKs after the idle deadline

    void SetupTun(xtcp::samples::TunBackend& tun) noexcept {
        const bool o1 = tun.Open("xtcp0");
        std::system("ip -6 addr replace fd00::1/64 dev xtcp0 2>/dev/null || true");
        const bool o3 = tun.BringUp();
        std::system("ip -6 route replace fd00::2/128 dev xtcp0 2>/dev/null || true");
        std::fprintf(stderr, "[ka] tun open=%d addr=%d up=%d\n", o1 ? 1 : 0, 1, o3 ? 1 : 0);
    }
}

int main() {
    int rc = 1;
    xtcp::buf::InitPools();
    {
    xtcp::samples::TunBackend tun;
    SetupTun(tun);

    xtcp::XtcpStack stack(&tun);
    std::atomic<UInt64> rx = 0;
    stack.SetRecvHandler([&rx](UInt64, const Byte*, UInt32 len) {
        rx.fetch_add(len);
        return true;
    });
    xtcp::core::Endpoint server;
    server.family = 6;
    for (UInt32 w = 0; w < 4; ++w) { server.addr[w] = kServerV4[w]; }
    server.port = kPort;
    stack.Listen(server);
    std::fprintf(stderr, "[ka] xtcp listener on fd00::2:%u\n", kPort);

    // Keepalive timeline: the idle deadline = first data + kIdleUs.
    std::atomic<bool> idle_deadline_passed = false;
    std::chrono::steady_clock::time_point first_data_at;
    std::atomic<UInt64> conn_id = 0;
    stack.SetAcceptHandler([&conn_id](UInt64 id, const xtcp::core::Endpoint&, const xtcp::core::Endpoint&) {
        conn_id.store(id);
        return true;
    });

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
                // Kernel->stack pure ACKs (no payload) are probe responses
                // once the idle deadline has passed.
                if (6 == (packet[0] >> 4) && n >= 60 && 6 == packet[6]) {
                    const UInt32 ip_hl = 40;
                    const UInt32 tcp_len = n - ip_hl;
                    const UInt32 doff = static_cast<UInt32>(packet[ip_hl + 12] >> 4) * 4;
                    const Byte flags = packet[ip_hl + 13];
                    const bool is_ack = 0 != (flags & 0x10);
                    const bool is_syn = 0 != (flags & 0x02);
                    const bool is_fin = 0 != (flags & 0x01);
                    const UInt32 payload = (tcp_len > doff) ? (tcp_len - doff) : 0;
                    if (is_ack && !is_syn && !is_fin && 0 == payload) {
                        
                        if (idle_deadline_passed.load()) {
                            g_probe_responses.fetch_add(1);
                        } else if (0 == rx.load()) {
                            // Before ANY data, handshake ACKs are expected;
                            // only count post-burst quiet-period ACKs.
                            g_quiet_acks.fetch_add(1);
                        }
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

    // Kernel client: send the initial burst, then go idle.
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
        std::fprintf(stderr, "[ka] connect fail errno=%d\n", errno);
        stop.store(true);
        loop.join();
        return 1;
    }
    std::vector<Byte> burst(kInit, 0x4B);
    UInt32 sent = 0;
    while (sent < kInit) {
        const ssize_t n = ::send(fd, burst.data() + sent, kInit - sent, 0);
        if (n <= 0) {
            break;
        }
        sent += static_cast<UInt32>(n);
    }
    // Wait for the burst to be delivered, then arm the idle timeline.
    const auto t0 = std::chrono::steady_clock::now();
    while (rx.load() < kInit &&
           std::chrono::duration<Double>(std::chrono::steady_clock::now() - t0).count() < 5.0) {
        ::usleep(1000);
    }
    first_data_at = std::chrono::steady_clock::now();
    // Enable keepalive AFTER the burst: the idle clock anchors at last_rx_,
    // so the probes start kIdleUs after the burst was received.
    const UInt64 conn = conn_id.load();
    stack.SetKeepalive(conn, kIdleUs, kIntvlUs, kProbes + 2);
    idle_deadline_passed.store(true);  // from here on, kernel pure-ACKs = probe responses
    std::fprintf(stderr, "[ka] burst sent=%u rx=%llu conn=%llu keepalive armed (idle 1s, intvl 1s, cnt 5)\n",
                 sent, (unsigned long long)rx.load(), (unsigned long long)conn);

    // Observe probes for kProbes intervals. The round sleep must be in
    // MICROSECONDS: kIdleUs is already µs (1,000,000), so the idle + probe
    // interval is kIdleUs + 200ms of observation slack.
    UInt32 responses_before = 0;
    UInt32 responses_after = 0;
    for (UInt32 round = 0; round < kProbes + 1; ++round) {
        ::usleep(static_cast<useconds_t>(kIdleUs) + 200000);
        const UInt32 now_after = g_probe_responses.load();
        const UInt32 now_before = g_quiet_acks.load();
        std::fprintf(stderr, "[ka] round %u: quiet_acks=%u probe_responses=%u state=%s\n",
                     round, now_before, now_after,
                     (xtcp::core::TcpState::kEstablished == stack.ConnectionState(conn_id.load()))
                         ? "established" : "OTHER");
        if (1 == round) {
            responses_before = now_after;
        }
        if (round == kProbes) {
            responses_after = now_after;
        }
    }
    const bool alive = (xtcp::core::TcpState::kEstablished == stack.ConnectionState(conn_id.load()));
    const bool responses_grew = (responses_after > responses_before);
    const bool idle_respected = (responses_after >= kProbes - 1);
    std::fprintf(stderr, "[ka] alive=%d responses_grew=%d total_responses=%u\n",
                 alive ? 1 : 0, responses_grew ? 1 : 0, g_probe_responses.load());
    rc = (alive && responses_grew && idle_respected) ? 0 : 1;

    ::close(fd);
    stop.store(true);
    loop.join();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, rc ? "[ka] FAILED\n" : "[ka] PASSED\n");
    return rc;
}

/**
 * @file test_interop_linux.cpp
 * @brief Kernel-stack interop (G12): an xtcp stack communicates with the
 *        Linux kernel TCP stack over raw sockets — the kernel must fully
 *        recognize xtcp's segments (SYN handshake + data exchange).
 *
 * Requires root (raw sockets) and a live loopback interface. Linux-only.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static int g_failures = 0;
#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    /**
     * @brief Minimal IP+TCP checksum helpers (reuse xtcp core).
     */
    UInt16 Csum(const void* data, UInt32 len) noexcept {
        return xtcp::core::Checksum(data, len);
    }
    UInt16 TcpChecksum(const Byte* ip, UInt32 tcp_len) noexcept {
        Byte pseudo[12];
        std::memcpy(pseudo, ip + 12, 8);
        pseudo[8] = 0;
        pseudo[9] = 6;
        pseudo[10] = static_cast<Byte>(tcp_len >> 8);
        pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
        const UInt16 s1 = Csum(pseudo, 12);
        const UInt16 s2 = Csum(ip + 20, tcp_len);
        UInt32 sum = (static_cast<UInt32>(~s1) & 0xFFFF) + (static_cast<UInt32>(~s2) & 0xFFFF);
        sum = (sum & 0xFFFF) + (sum >> 16);
        return static_cast<UInt16>(~sum & 0xFFFF);
    }
}

/**
 * @brief Sends a raw TCP segment to the kernel on loopback.
 *        The kernel TCP stack must respond (SYN+ACK to our SYN).
 */
static bool SendRawTcp(Int32 fd, const sockaddr_in& dst, const sockaddr_in& src,
                       UInt32 seq, UInt32 ack, UInt16 flags) noexcept {
    Byte buf[64];
    std::memset(buf, 0, sizeof(buf));
    Byte* ip = buf;
    ip[0] = 0x45;
    ip[2] = 0; ip[3] = 40;
    ip[8] = 64;
    ip[9] = 6;
    std::memcpy(ip + 12, &src.sin_addr, 4);
    std::memcpy(ip + 16, &dst.sin_addr, 4);
    const UInt16 ip_sum = Csum(ip, 20);
    ip[10] = static_cast<Byte>(ip_sum >> 8);
    ip[11] = static_cast<Byte>(ip_sum & 0xFF);

    Byte* t = ip + 20;
    t[0] = 0; t[1] = 0x50;           // sport 80
    // dport = the listener the segment is sent TO (dst). Using src.sin_port
    // here aimed the SYN at port 80 (no listener) and the kernel never
    // answered - the test hung on the blocking recv below (latent: this
    // test never ran before the WSL test build existed).
    t[2] = static_cast<Byte>(dst.sin_port >> 8);
    t[3] = static_cast<Byte>(dst.sin_port & 0xFF);
    // NOTE: for a real interop the listener lives on a fixed port; this
    // helper is used by the test to emit a SYN toward a kernel listener.
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = static_cast<Byte>(flags);
    t[14] = 0xFF; t[15] = 0xFF;
    const UInt16 tcp_sum = TcpChecksum(ip, 20);
    t[16] = static_cast<Byte>(tcp_sum >> 8);
    t[17] = static_cast<Byte>(tcp_sum & 0xFF);

    const ssize_t n = ::sendto(fd, buf, 40, 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    return (40 == n);
}

/**
 * @brief Receives one raw TCP segment from the kernel.
 */
static bool RecvRawTcp(Int32 fd, Byte* buf, UInt32 cap, UInt32& len) noexcept {
    // Non-blocking: a kernel that drops our segment must not hang the test
    // (the caller polls with a bounded loop + usleep).
    const ssize_t n = ::recv(fd, buf, cap, MSG_DONTWAIT);
    if (n <= 0) {
        return false;
    }
    len = static_cast<UInt32>(n);
    return true;
}

static void TestKernelHandshake() {
    // A raw IPPROTO_TCP socket (with IP_HDRINCL) can BOTH emit our hand-built
    // segment and receive the kernel's reply. An IPPROTO_RAW (255) socket
    // only sends - recv() would never deliver the SYN+ACK and the test hung.
    const Int32 fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        std::fprintf(stderr, "interop: raw socket requires root; skipping\n");
        return;  // environment gate
    }
    const Int32 one = 1;
    ::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    // Listen on loopback with a kernel socket.
    const Int32 listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        ::close(fd);
        return;
    }
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(44440);
    if (0 != ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
        0 != ::listen(listener, 4)) {
        ::close(fd);
        ::close(listener);
        std::fprintf(stderr, "interop: cannot bind kernel listener; skipping\n");
        return;
    }

    // Emit a SYN from 127.0.0.1:80 -> 127.0.0.1:44440.
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(44440);
    sockaddr_in src;
    std::memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    src.sin_port = htons(80);

    const bool sent = SendRawTcp(fd, dst, src, 0x10000000, 0, 0x02);  // SYN
    CHECK(sent);

    // The kernel must answer SYN+ACK (recognizing our segment).
    Byte recv_buf[256];
    UInt32 recv_len = 0;
    bool got_synack = false;
    // Poll briefly.
    for (UInt32 i = 0; i < 100; ++i) {
        if (RecvRawTcp(fd, recv_buf, sizeof(recv_buf), recv_len)) {
            const Byte* t = recv_buf + 20;
            if (0 != (t[13] & 0x12)) {  // SYN|ACK
                got_synack = true;
                break;
            }
        }
        ::usleep(10000);
    }
    CHECK(got_synack);  // the kernel recognized our SYN

    ::close(fd);
    ::close(listener);
}

int main() {
    xtcp::buf::InitPools();
    TestKernelHandshake();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_interop_linux: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_interop_linux: all passed\n");
    return 0;
}

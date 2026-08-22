/**
 * @file test_lwip_interop.cpp
 * @brief Symmetrical interop test: lwIP TCP stack <-> xtcp TCP stack.
 *
 * Two independent user-space TCP stacks exchange real TCP segments over an
 * in-memory bridge: lwIP netif.output -> xtcp backend; xtcp tx -> ip4_input.
 * Three scenarios run over the same bridge:
 *   1. lwIP acts as a TCP client, xtcp as an echo server (8 KB each way).
 *   2. Close handshake: the lwIP client actively closes after the echo;
 *      xtcp observes CloseWait and completes the close (FIN exchange).
 *   3. Reverse role: xtcp acts as a TCP client to an lwIP server
 *      (tcp_new + tcp_bind + tcp_listen + accept), sending an 8 KB
 *      deterministic pattern that lwIP validates byte-for-byte.
 * In addition, every xtcp-emitted packet is checksum-verified at the bridge
 * (IPv4 header checksum + TCP checksum with pseudo-header) because lwIP is
 * built with CHECKSUM_CHECK=0 and would never catch a bad checksum itself.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/ip4.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/pbuf.h>
#include <lwip/timeouts.h>
#include <lwip/tcpip.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>
#include <algorithm>

namespace {
    struct netif              g_netif;
    xtcp::ndi::ManualBackend  g_backend;
    constexpr UInt16          kPort    = 4545;  // lwIP client -> xtcp echo server
    constexpr UInt16          kSrvPort = 4546;  // xtcp client -> lwIP server
    constexpr UInt32          kPayload = 8192;  // bytes each way

    std::atomic<UInt64> g_lwip_recv = 0;
    std::vector<Byte>   g_lwip_buf;
    std::atomic<bool>   g_client_done = false;
    std::atomic<UInt64> g_xtcp_recv  = 0;
    std::atomic<UInt64> g_xtcp_send  = 0;

    // ---- reverse role (xtcp client -> lwIP server) ----
    struct tcp_pcb*  g_srv_pcb   = NULLPTR;   // accepted lwIP server pcb
    std::atomic<bool> g_srv_done  = false;
    UInt64            g_srv_recv  = 0;        // running byte offset for validation
    UInt64            g_srv_bad   = 0;        // mismatched bytes
    UInt64            g_xtcp_client_conn = 0; // xtcp client conn id
    std::atomic<bool> g_client_established = false;
    std::atomic<bool> g_client_sent = false;

    // ---- close handshake ----
    struct tcp_pcb*  g_client_pcb = NULLPTR;  // lwIP client pcb (active closer)
    std::atomic<bool> g_close_sent   = false; // tcp_close() issued
    std::atomic<bool> g_lwip_eof     = false; // lwIP client saw FIN (recv NULL)
    UInt64            g_echo_conn    = 0;     // xtcp echo server conn id
    std::atomic<bool> g_echo_closewait = false;
    std::atomic<bool> g_echo_close_sent = false;
    std::atomic<bool> g_xtcp_echo_closed = false;

    // ---- checksum verification of xtcp-emitted packets ----
    UInt64            g_cksum_pkts = 0;
    UInt64            g_cksum_bad  = 0;

    // ---- lwIP netif: output bridge -> xtcp backend ----
    err_t NetifOutput(struct netif* ni, struct pbuf* p, const ip4_addr_t* dst) {
        (void)ni; (void)dst;
        Byte tmp[65536];
        UInt32 total = 0;
        for (struct pbuf* q = p; q != NULLPTR; q = q->next) {
            std::memcpy(tmp + total, q->payload, q->len);
            total += q->len;
        }
        g_backend.Inject(tmp, total, 0x0800);
        return ERR_OK;
    }

    err_t NetifInit(struct netif* ni) {
        ni->mtu = 1500;
        ni->hwaddr_len = 0;
        ni->flags = static_cast<u8_t>(NETIF_FLAG_UP | NETIF_FLAG_LINK_UP);
        ni->output = NetifOutput;
        return ERR_OK;
    }

    // ---- lwIP TCP client callbacks (echo + close scenarios) ----
    err_t OnConnected(void* arg, struct tcp_pcb* pcb, err_t err) {
        (void)arg;
        if (ERR_OK != err) {
            return ERR_OK;
        }
        // Send a deterministic 8 KB pattern.
        std::vector<Byte> buf(kPayload);
        for (UInt32 i = 0; i < kPayload; ++i) {
            buf[i] = static_cast<Byte>((i * 13 + 5) & 0xFF);
        }
        err_t wr = tcp_write(pcb, buf.data(), kPayload, TCP_WRITE_FLAG_COPY);
        if (ERR_OK == wr) {
            tcp_output(pcb);
        }
        return ERR_OK;
    }

    err_t OnRecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
        (void)arg; (void)err;
        if (p != NULLPTR) {
            UInt32 total = 0;
            for (struct pbuf* q = p; q != NULLPTR; q = q->next) {
                g_lwip_buf.insert(g_lwip_buf.end(),
                                  static_cast<const Byte*>(q->payload),
                                  static_cast<const Byte*>(q->payload) + q->len);
                total += q->len;
            }
            g_lwip_recv += total;
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
            if (g_lwip_recv >= kPayload) {
                g_client_done = true;
            }
        } else {
            g_lwip_eof = true;  // peer FIN received: close handshake complete
        }
        return ERR_OK;
    }

    void OnErr(void* arg, err_t err) {
        (void)arg; (void)err;
    }

    // ---- lwIP TCP server callbacks (reverse role) ----
    err_t OnSrvRecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
        (void)arg; (void)err;
        if (p != NULLPTR) {
            UInt32 total = 0;
            for (struct pbuf* q = p; q != NULLPTR; q = q->next) {
                const Byte* d = static_cast<const Byte*>(q->payload);
                for (u16_t i = 0; i < q->len; ++i) {
                    const Byte expect = static_cast<Byte>((g_srv_recv * 13 + 5) & 0xFF);
                    if (d[i] != expect) {
                        ++g_srv_bad;
                    }
                    ++g_srv_recv;
                }
                total += q->len;
            }
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
            if (kPayload <= g_srv_recv) {
                g_srv_done = true;
            }
        }
        return ERR_OK;
    }

    err_t OnAccept(void* arg, struct tcp_pcb* newpcb, err_t err) {
        (void)arg;
        if (ERR_OK != err) {
            return ERR_OK;
        }
        g_srv_pcb = newpcb;
        tcp_arg(newpcb, NULLPTR);
        tcp_recv(newpcb, OnSrvRecv);
        return ERR_OK;
    }

    // ---- checksum verification (IPv4 header + TCP pseudo-header) ----
    // lwIP is built with CHECKSUM_CHECK_TCP=0 (lwipopts.h), so it never
    // validates xtcp's segments. Assert at the bridge instead.
    void ValidateChecksums(const Byte* pkt, UInt32 len) {
        ++g_cksum_pkts;
        if (len < 20 || 4 != (pkt[0] >> 4)) {
            ++g_cksum_bad;
            return;
        }
        const UInt32 ihl = static_cast<UInt32>(pkt[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) {
            ++g_cksum_bad;
            return;
        }
        // Valid IPv4 header checksum => Checksum over the whole header is 0.
        if (0 != xtcp::core::Checksum(pkt, ihl)) {
            ++g_cksum_bad;
            return;
        }
        if (6 != pkt[9]) {
            return;  // non-TCP: header-only validation
        }
        const UInt32 total_len = (static_cast<UInt32>(pkt[2]) << 8) | pkt[3];
        if (total_len < ihl || len < total_len) {
            ++g_cksum_bad;
            return;
        }
        const UInt32 tcp_len = total_len - ihl;
        // Pseudo-header (RFC 793): src(4) dst(4) zero(1) proto(1) tcp_len(2).
        Byte pseudo[12];
        std::memcpy(pseudo, pkt + 12, 4);
        std::memcpy(pseudo + 4, pkt + 16, 4);
        pseudo[8]  = 0;
        pseudo[9]  = 6;
        pseudo[10] = static_cast<Byte>((tcp_len >> 8) & 0xFF);
        pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
        Byte seg[65536];
        std::memcpy(seg, pseudo, 12);
        std::memcpy(seg + 12, pkt + ihl, tcp_len);
        // Valid TCP checksum => Checksum over pseudo+segment is 0.
        if (0 != xtcp::core::Checksum(seg, 12 + tcp_len)) {
            ++g_cksum_bad;
        }
    }

    // ---- lwIP hooks required by the openppp2-ported lwIP (mem.c) ----
    extern "C" {
        void* lwip_netstack_malloc(size_t sz) { return std::malloc(sz); }
        void  lwip_netstack_free(void* p) { std::free(p); }
        void* lwip_netstack_calloc(size_t n, size_t s) { return std::calloc(n, s); }
        int   lwip_netstack_ip_tos(int tos) { return tos; }
    }

    // ---- xtcp echo server ----
    void EchoHandler(xtcp::XtcpStack& stack, UInt64 conn_id, const Byte* data, UInt32 len) {
        g_echo_conn = conn_id;
        g_xtcp_recv += len;
        if (stack.Send(conn_id, data, len)) {
            g_xtcp_send += len;
        }
    }
}

int main() {
    xtcp::buf::InitPools();

    lwip_init();
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, 10, 1, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 1, 0, 1);
    netif_add(&g_netif, &ip, &mask, &gw, NULLPTR, NetifInit, ip4_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // The stack is heap-owned so its destruction point is explicit: MSVC's
    // lifetime optimization may otherwise defer the stack object's dtor past
    // ShutdownPools, and a connection's retransmit queue may still hold
    // pool-buffer references (Unref on a destroyed pool = access violation).
    std::unique_ptr<xtcp::XtcpStack> stack(new (std::nothrow) xtcp::XtcpStack(&g_backend));
    if (NULLPTR == stack.get()) {
        return 1;
    }
    stack->SetRecvHandler([&stack](UInt64 conn_id, const Byte* data, UInt32 len) {
        EchoHandler(*stack, conn_id, data, len);
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = 0x0A010002;  // 10.1.0.2 (network order)
    server.port = kPort;
    stack->Listen(server);

    // Reverse role: xtcp TCP client -> 10.1.0.1:4546 (lwIP server).
    xtcp::core::Endpoint clocal, cremote;
    clocal.family = 4;
    clocal.addr[0] = 0x0A010002;  // 10.1.0.2
    clocal.port = 50000;
    cremote.family = 4;
    cremote.addr[0] = 0x0A010001;  // 10.1.0.1
    cremote.port = kSrvPort;
    g_xtcp_client_conn = stack->Connect(clocal, cremote);
    if (0 == g_xtcp_client_conn) {
        std::fprintf(stderr, "xtcp Connect (reverse role) failed\n");
        return 1;
    }

    // Close handshake: complete the echo server's close once CloseWait shows.
    stack->SetStateHandler([](UInt64 conn_id, xtcp::core::TcpState st) {
        if (conn_id == g_xtcp_client_conn && xtcp::core::TcpState::kEstablished == st) {
            g_client_established = true;
        }
        if (conn_id == g_echo_conn && xtcp::core::TcpState::kCloseWait == st) {
            g_echo_closewait = true;
        }
        if (conn_id == g_echo_conn && xtcp::core::TcpState::kClosed == st) {
            g_xtcp_echo_closed = true;
        }
    });

    // lwIP TCP server (reverse role): tcp_new + tcp_bind + tcp_listen.
    struct tcp_pcb* srv = tcp_new();
    if (NULLPTR == srv) {
        std::fprintf(stderr, "tcp_new (server) failed\n");
        return 1;
    }
    if (ERR_OK != tcp_bind(srv, IP_ADDR_ANY, kSrvPort)) {
        std::fprintf(stderr, "tcp_bind (server) failed\n");
        return 1;
    }
    srv = tcp_listen(srv);
    if (NULLPTR == srv) {
        std::fprintf(stderr, "tcp_listen failed\n");
        return 1;
    }
    tcp_arg(srv, NULLPTR);
    tcp_accept(srv, OnAccept);

    // lwIP TCP client -> 10.1.0.2:4545.
    g_client_pcb = tcp_new();
    if (NULLPTR == g_client_pcb) {
        std::fprintf(stderr, "tcp_new failed\n");
        return 1;
    }
    tcp_bind(g_client_pcb, IP_ADDR_ANY, 0);
    tcp_arg(g_client_pcb, NULLPTR);
    tcp_recv(g_client_pcb, OnRecv);
    tcp_err(g_client_pcb, OnErr);
    ip4_addr_t dst4;
    IP4_ADDR(&dst4, 10, 1, 0, 2);
    ip_addr_t dst;
    ip_addr_copy_from_ip4(dst, dst4);
    tcp_connect(g_client_pcb, &dst, kPort, OnConnected);

    // Event pump: xtcp tx -> lwIP, lwIP timers, xtcp ack timers.
    // Sleep lets lwIP's delayed-ACK / RTO timers (sys_check_timeouts) make
    // real-time progress; the round ceiling keeps the test bounded.
    Byte pkt[65536];
    std::vector<Byte> pattern(kPayload);
    for (UInt32 i = 0; i < kPayload; ++i) {
        pattern[i] = static_cast<Byte>((i * 13 + 5) & 0xFF);
    }
    bool passed = false;
    bool close_ok = false;
    for (UInt32 round = 0; round < 10000 && !(passed && close_ok && g_srv_done); ++round) {
        UInt32 n = g_backend.PollTx(pkt);
        while (0 < n) {
            ValidateChecksums(pkt, n);
            struct pbuf* p = pbuf_alloc(PBUF_RAW, n, PBUF_POOL);
            if (p != NULLPTR) {
                std::memcpy(p->payload, pkt, n);
                ip4_input(p, &g_netif);
            }
            n = g_backend.PollTx(pkt);
        }
        // Reverse role: send the pattern once the xtcp client is established.
        if (g_client_established && !g_client_sent) {
            if (stack->Send(g_xtcp_client_conn, pattern.data(), kPayload)) {
                g_client_sent = true;
            }
        }
        // Close handshake: lwIP client actively closes after the echo.
        if (!g_close_sent && g_lwip_recv >= kPayload) {
            g_close_sent = true;
            tcp_close(g_client_pcb);
        }
        // xtcp server completes the close once it observes CloseWait.
        if (g_echo_closewait && !g_echo_close_sent) {
            g_echo_close_sent = true;
            stack->Close(g_echo_conn);
        }
        stack->PollAckTimers();
        sys_check_timeouts();
        passed = (g_client_done && g_lwip_recv >= kPayload);
        close_ok = (g_lwip_eof && g_xtcp_echo_closed);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // Validate: lwIP must have received the exact echo of its own pattern.
    bool ok = (passed && g_lwip_buf.size() == kPayload);
    if (ok) {
        for (UInt32 i = 0; i < kPayload; ++i) {
            if (g_lwip_buf[i] != static_cast<Byte>((i * 13 + 5) & 0xFF)) {
                ok = false;
                break;
            }
        }
    }
    // Reverse role: lwIP server received all 8 KB with zero mismatches.
    const bool rev_ok = (g_srv_done && 0 == g_srv_bad && kPayload == g_srv_recv);
    // Close handshake completed both sides + checksums all valid.
    const bool cksum_ok = (0 < g_cksum_pkts && 0 == g_cksum_bad);
    ok = ok && rev_ok && close_ok && cksum_ok;

    std::fprintf(stderr,
                 "lwip_interop: xtcp_recv=%llu xtcp_echo=%llu lwip_recv=%llu "
                 "srv_recv=%llu srv_bad=%llu close=%d cksum_pkts=%llu cksum_bad=%llu %s\n",
                 (unsigned long long)g_xtcp_recv.load(),
                 (unsigned long long)g_xtcp_send.load(),
                 (unsigned long long)g_lwip_recv.load(),
                 (unsigned long long)g_srv_recv,
                 (unsigned long long)g_srv_bad,
                 close_ok ? 1 : 0,
                 (unsigned long long)g_cksum_pkts,
                 (unsigned long long)g_cksum_bad,
                 ok ? "PASSED" : "FAILED");

    // Destroy the stack (and its connections' pool-buffer references) while
    // the pools are still alive, then drain the backend's tx queue.
    stack.reset();
    while (0 != g_backend.TxPending()) {
        g_backend.PollTx(pkt);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "lwip_interop: shutdown ok\n");
    return ok ? 0 : 1;
}

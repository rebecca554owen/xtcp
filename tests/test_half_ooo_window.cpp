/**
 * @file test_half_ooo_window.cpp
 * @brief Half-close out-of-order buffering must respect the receive-window
 *        check. During FIN-WAIT-1/2 the closing side keeps processing peer
 *        data (RFC 793 half-close) via ProcessClosingData; like the
 *        Established path (tcp_fsm.cpp:1874-1889) it must drop data outside
 *        [rcv_nxt_, rcv_nxt_+rcv_wnd_) - never buffer or deliver it. A flood
 *        of window-external out-of-order segments must leave the half-close
 *        transfer intact and must not deadlock the closing connection.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            return;
        }
    }
}

// Injects a window-external out-of-order data segment directly into the
// victim stack (same wire layout as test_ooo_flood.cpp's InjectOoo:
// IPv4 20 + TCP 20 + payload, flags byte pkt[33] = 0x18).
static void InjectOoo(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port, UInt32 seq, UInt32 payload_len) {
    const UInt32 total = 20 + 20 + payload_len;
    std::vector<Byte> pkt(total);
    std::memset(pkt.data(), 0xCC, total);
    pkt[0] = 0x45;
    pkt[2] = static_cast<Byte>(total >> 8); pkt[3] = static_cast<Byte>(total);
    pkt[9] = 6;                              // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt.data() + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = static_cast<Byte>(seq >> 24); tcp[5] = static_cast<Byte>(seq >> 16);
    tcp[6] = static_cast<Byte>(seq >> 8);  tcp[7] = static_cast<Byte>(seq);
    tcp[12] = 0x50;                          // data offset 5
    tcp[13] = 0x18;                          // PSH + ACK
    tcp[14] = 0x40; tcp[15] = 0x00;          // window 16384
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
    std::memcpy(buf.Data(), pkt.data(), total);
    buf.SetLen(total);
    victim.OnPacket(std::move(buf));
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        UInt64 recv_a = 0;
        UInt32 crc_a = 0;
        stack_a.SetRecvHandler([&recv_a, &crc_a](UInt64, const Byte* d, UInt32 len) {
            recv_a += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_a = (crc_a * 31 + d[i]) & 0x7FFFFFFF;
            }
        });
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40291;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9131;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);

        // A closes first: FIN-WAIT-1/2 (RFC 793 half-close).
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[half-ooo-window] A mid-close state=%d\n", (int)mid);
        CHECK(xtcp::core::TcpState::kFinWait1 == mid || xtcp::core::TcpState::kFinWait2 == mid);

        const UInt32 kTotal = 8192;
        const UInt32 kExtra = 4096;
        const UInt32 kAll = kTotal + kExtra;
        std::vector<Byte> payload(kAll);
        for (UInt32 i = 0; i < kAll; ++i) {
            payload[i] = static_cast<Byte>((i * 23 + i / 5) & 0xFF);
        }
        auto SendFrom = [&](const Byte* d, UInt32 len) -> bool {
            UInt32 sent = 0;
            while (sent < len) {
                UInt32 n = len - sent;
                if (n > 2048) {
                    n = 2048;
                }
                UInt32 tries = 0;
                while (!stack_b.Send(conn_b, d + sent, n) && 500 > ++tries) {
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                if (500 <= tries) {
                    return false;
                }
                sent += n;
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            return true;
        };

        // Baseline half-close transfer: B (CLOSE-WAIT) sends 8192 B.
        CHECK(SendFrom(payload.data(), kTotal));
        for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[half-ooo-window] A_recv baseline=%llu\n", (unsigned long long)recv_a);
        CHECK(kTotal == recv_a);

        // Flood: 500 window-external out-of-order segments into A (the
        // closing side). seq starts at 0x60000000, far beyond
        // rcv_nxt_ + rcv_wnd_; ProcessClosingData must drop each one
        // (consistent with Established), never deliver or buffer it.
        for (UInt32 i = 0; i < 500; ++i) {
            InjectOoo(stack_a, 0x0A000002, 0x0A000001, 9131, 40291,
                      0x60000000u + i * 2048u, 1024);
        }
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState after_flood = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[half-ooo-window] A state after flood=%d recv=%llu\n",
                     (int)after_flood, (unsigned long long)recv_a);
        CHECK(kTotal == recv_a);   // window-external flood never delivered
        CHECK(xtcp::core::TcpState::kFinWait1 == after_flood ||
              xtcp::core::TcpState::kFinWait2 == after_flood);  // no spurious transition
        CHECK(1 == stack_a.ConnectionCount());  // connection still alive
        CHECK(1 == stack_b.ConnectionCount());

        // Post-flood progress: B sends another 4096 B - in-order half-close
        // delivery must be unaffected (no reassembly starvation, no deadlock).
        CHECK(SendFrom(payload.data() + kTotal, kExtra));
        for (UInt32 i = 0; i < 500 && recv_a < kAll; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[half-ooo-window] A_recv total=%llu\n", (unsigned long long)recv_a);
        CHECK(kAll == recv_a);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kAll; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_a);

        // B closes: A must still reach TIME-WAIT - the FIN path is alive
        // (no deadlock from the window-external flood).
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[half-ooo-window] A final state=%d\n", (int)end);
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "HALF_OOO_WINDOW: FAILED (%d)\n" : "HALF_OOO_WINDOW: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

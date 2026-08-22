/**
 * @file test_timewait_rst.cpp
 * @brief RFC 793: a connection in TIME-WAIT ignores inbound RST segments -
 *        the 2MSL wait is not cut short, and the connection is still
 *        reclaimed once the deadline elapses.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
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

static void InjectRst(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;                 // total length
    pkt[9] = 6;                              // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = 0x00; tcp[5] = 0x00; tcp[6] = 0x00; tcp[7] = 0x01;  // seq = 1
    tcp[13] = 0x04;                          // RST
    tcp[12] = 0x50;                          // data offset 5
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
    victim.OnPacket(std::move(buf));
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(30000);
        stack_b.SetTwoMsl(30000);
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
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40051;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9093;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[tw-rst] after close: A=%d\n",
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn));

        // RFC 793: TIME-WAIT ignores RST; the 2MSL wait is not cut short.
        InjectRst(stack_a, 0x0A000002, 0x0A000001, 9093, 40051);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[tw-rst] after RST: A=%d\n",
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn));

        // 2MSL elapses: reclaimed normally.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[tw-rst] after 2MSL: A=%d\n",
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TIMEWAIT_RST: FAILED (%d)\n" : "TIMEWAIT_RST: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

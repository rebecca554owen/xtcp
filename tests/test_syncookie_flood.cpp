/**
 * @file test_syncookie_flood.cpp
 * @brief RFC 4987 SYN-cookie flood defense at the stack level: once live
 *        connections reach the threshold, the listener answers SYNs
 *        statelessly (no connection state, no memory growth under flood),
 *        and a legitimate client still completes the handshake via its
 *        cookie ACK and exchanges data intact.
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

static void InjectSyn(xtcp::XtcpStack& victim, UInt32 src_ip, UInt16 src_port,
                      UInt32 dst_ip, UInt16 dst_port) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[9] = 6;
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = 0x00; tcp[5] = 0x00; tcp[6] = 0x10; tcp[7] = 0x00;  // seq 0x100000
    tcp[12] = 0x50; tcp[13] = 0x02;          // SYN
    tcp[14] = 0x40; tcp[15] = 0x00;          // window
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
        UInt64 conn_b = 0;
        UInt64 bytes_recv = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

        // Cookie mode kicks in once one live connection exists.
        stack_b.SetSyncookieThreshold(1);

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40111;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9099;
        CHECK(stack_b.Listen(remote));

        // First legitimate connection (below threshold): normal handshake.
        const UInt64 conn1 = stack_a.Connect(local, remote);
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));

        // Flood: 500 spoofed SYNs. Cookie mode answers statelessly - the
        // connection count must not grow with the flood.
        const UInt32 before = stack_b.ConnectionCount();
        for (UInt32 i = 0; i < 500; ++i) {
            InjectSyn(stack_b, 0x0B000001 + i, static_cast<UInt16>(10000 + i % 5000),
                      0x0A000002, 9099);
        }
        Pump(backend_a, backend_b, stack_a, stack_b);
        const UInt32 after = stack_b.ConnectionCount();
        std::fprintf(stderr, "[syncookie-flood] conns before=%u after=%u\n", before, after);
        CHECK(before == after);  // stateless cookie answers: no state growth

        // Second legitimate connection (above threshold): completes via the
        // cookie ACK path and still carries data.
        local.port = 40112;
        const UInt64 conn2 = stack_a.Connect(local, remote);
        CHECK(0 != conn2);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[syncookie-flood] conn2 A=%d B=%llu\n",
                     (int)stack_a.ConnectionState(conn2), (unsigned long long)conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn2));
        CHECK(0 != conn_b);

        const UInt32 kTotal = 4096;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 7) & 0xFF);
        }
        UInt64 sent = 0;
        for (UInt32 round = 0; round < 8 && sent < kTotal; ++round) {
            UInt32 n = static_cast<UInt32>(kTotal - sent);
            if (n > 2048) {
                n = 2048;
            }
            UInt32 g = 0;
            while (!stack_a.Send(conn2, payload.data() + sent, n) && 300 > ++g) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            sent += n;
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == sent);
        for (UInt32 i = 0; i < 500 && bytes_recv < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[syncookie-flood] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        stack_a.Close(conn1);
        stack_a.Close(conn2);
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYNCOOKIE_FLOOD: FAILED (%d)\n" : "SYNCOOKIE_FLOOD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

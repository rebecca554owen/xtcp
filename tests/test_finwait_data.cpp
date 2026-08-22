/**
 * @file test_finwait_data.cpp
 * @brief FIN-WAIT receive path with peer data trailing our FIN (RFC 793
 *        half-close): after A closes (FIN-WAIT-1/2), B still sends a large
 *        payload and then its FIN. A must deliver every byte exactly once
 *        and reach TIME-WAIT. Regression: the FinWait1/2 FIN handler must
 *        NOT rewind rcv_nxt_ after ProcessClosingData advanced it past the
 *        delivered data - a rewind would re-ACK delivered bytes, make the
 *        peer retransmit them, and A would deliver duplicates (recv > total).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

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
        // B's conn id MUST be captured from SetStateHandler - each stack
        // generates its own ids, never assume conn_b == conn_a + 1.
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40251;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9113;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // A closes first: its FIN goes out and A enters FIN-WAIT-1/2. B is
        // still able to send (half-close) and answers with data + FIN.
        stack_a.Close(conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn_a);
        std::fprintf(stderr, "[finwait-data] A mid-close state=%d\n", (int)mid);
        CHECK(xtcp::core::TcpState::kFinWait1 == mid || xtcp::core::TcpState::kFinWait2 == mid);

        // B sends a multi-segment payload (2048+) - its FIN follows on the
        // wire after the data - then closes (Last-ACK).
        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 29 + i / 3) & 0xFF);
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            UInt32 n = kTotal - sent;
            if (n > 2048) {
                n = 2048;
            }
            UInt32 g = 0;
            while (!stack_b.Send(conn_b, payload.data() + sent, n) && 500 > ++g) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            sent += n;
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[finwait-data] A_recv=%llu\n", (unsigned long long)recv_a);
        // Exactly kTotal: fewer = lost, more = duplicated delivery (the
        // regression this test guards: a FIN that rewinds rcv_nxt_ makes the
        // peer retransmit already-delivered bytes).
        CHECK(kTotal == recv_a);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_a);

        // Let B's FIN (sent after its data) reach A, closing the exchange.
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn_a);
        std::fprintf(stderr, "[finwait-data] A final state=%d\n", (int)end);
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FINWAIT_DATA: FAILED (%d)\n" : "FINWAIT_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

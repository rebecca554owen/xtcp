/**
 * @file test_fin_data.cpp
 * @brief FIN carrying data (RFC 793 half-close): the peer sends its final
 *        data segment with the FIN flag set. The data must be delivered in
 *        full before CLOSE-WAIT, and the remaining close sequence completes.
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
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        UInt64 conn_a = 0, conn_b = 0;
        stack_b.SetStateHandler([&stack_b, &conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40191;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9107;
        CHECK(stack_b.Listen(remote));
        conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // B sends its final payload with the FIN flag in one segment, then
        // closes (its Close waits for app data already flushed).
        const UInt32 kTotal = 5120;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 17 + i / 7) & 0xFF);
        }
        // Send in 2048-byte chunks; the last chunk accompanies the FIN.
        UInt64 sent = 0;
        while (sent < kTotal) {
            UInt32 n = static_cast<UInt32>(kTotal - sent);
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
        // B closes now; its Close flushes pending and the FIN follows the data.
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[fin-data] A_recv=%llu\n", (unsigned long long)recv_a);
        CHECK(kTotal == recv_a);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_a);

        // A observed CLOSE-WAIT (peer's FIN with data) and closes back.
        stack_a.Close(conn_a);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const xtcp::core::TcpState st_a = stack_a.ConnectionState(conn_a);
        std::fprintf(stderr, "[fin-data] final A=%d\n", (int)st_a);
        CHECK(xtcp::core::TcpState::kTimeWait == st_a || xtcp::core::TcpState::kClosed == st_a);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FIN_DATA: FAILED (%d)\n" : "FIN_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


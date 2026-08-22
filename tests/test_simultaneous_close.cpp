/**
 * @file test_simultaneous_close.cpp
 * @brief Simultaneous close with data in flight: both ends send large
 *        buffers and Close() at the same time. The FIN must follow the data
 *        (RFC 793), retransmission must cover both, and both sides reach a
 *        clean final state with every byte delivered intact.
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

static void PumpFor(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                    xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32 ms) {
    for (UInt32 i = 0; i < ms; i += 5) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        Pump(a, b, sa, sb);
    }
    Pump(a, b, sa, sb);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(20000);
        stack_b.SetTwoMsl(20000);
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

        UInt64 recv_a = 0, recv_b = 0;
        UInt32 crc_a = 0, crc_b = 0;
        stack_a.SetRecvHandler([&recv_a, &crc_a](UInt64, const Byte* d, UInt32 len) {
            recv_a += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_a = (crc_a * 31 + d[i]) & 0x7FFFFFFF;
            }
        });
        stack_b.SetRecvHandler([&recv_b, &crc_b](UInt64, const Byte* d, UInt32 len) {
            recv_b += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_b = (crc_b * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40081;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9096;
        UInt64 conn_a = 0, conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        CHECK(stack_b.Listen(remote));
        conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);

        // Both sides fire large sends (buffered, not yet fully flushed).
        const UInt32 kTotal = 32768;
        std::vector<Byte> pay_a(kTotal), pay_b(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            pay_a[i] = static_cast<Byte>((i * 3 + i / 17) & 0xFF);
            pay_b[i] = static_cast<Byte>((i * 11 + i / 29) & 0xFF);
        }
        UInt64 sent_a = 0, sent_b = 0;
        for (UInt32 round = 0; round < 64 && (sent_a < kTotal || sent_b < kTotal); ++round) {
            if (sent_a < kTotal) {
                UInt32 n = static_cast<UInt32>(kTotal - sent_a);
                if (n > 4096) {
                    n = 4096;
                }
                UInt32 g = 0;
                while (!stack_a.Send(conn_a, pay_a.data() + sent_a, n) && 300 > ++g) {
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                sent_a += n;
            }
            if (sent_b < kTotal) {
                UInt32 n = static_cast<UInt32>(kTotal - sent_b);
                if (n > 4096) {
                    n = 4096;
                }
                UInt32 g = 0;
                while (!stack_b.Send(conn_b, pay_b.data() + sent_b, n) && 300 > ++g) {
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                sent_b += n;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == sent_a && kTotal == sent_b);

        // Simultaneous close from both ends with data still in flight.
        stack_a.Close(conn_a);
        stack_b.Close(conn_b);
        PumpFor(backend_a, backend_b, stack_a, stack_b, 200);

        // Both sides must deliver the full peer payload intact.
        std::fprintf(stderr, "[simclose] recvA=%llu recvB=%llu\n",
                     (unsigned long long)recv_a, (unsigned long long)recv_b);
        CHECK(kTotal == recv_a && kTotal == recv_b);
        UInt32 crc_e_a = 0, crc_e_b = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_e_a = (crc_e_a * 31 + pay_b[i]) & 0x7FFFFFFF;
            crc_e_b = (crc_e_b * 31 + pay_a[i]) & 0x7FFFFFFF;
        }
        std::fprintf(stderr, "[simclose] crcA recv=%u exp=%u | crcB recv=%u exp=%u\n",
                     crc_a, crc_e_a, crc_b, crc_e_b);
        CHECK(crc_a == crc_e_a && crc_b == crc_e_b);

        // Both reach a terminal state (TIME-WAIT or closed) without leaking.
        const xtcp::core::TcpState st_a = stack_a.ConnectionState(conn_a);
        const xtcp::core::TcpState st_b = stack_b.ConnectionState(conn_b);
        std::fprintf(stderr, "[simclose] A=%d B=%d\n", (int)st_a, (int)st_b);
        CHECK(xtcp::core::TcpState::kTimeWait == st_a || xtcp::core::TcpState::kClosed == st_a);
        CHECK(xtcp::core::TcpState::kTimeWait == st_b || xtcp::core::TcpState::kClosed == st_b);

        // 2MSL elapses: both sides reclaimed.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (UInt32 i = 0; i < 20; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[simclose] after 2MSL A=%u B=%u\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount());
        CHECK(0 == stack_a.ConnectionCount());
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SIMULTANEOUS_CLOSE: FAILED (%d)\n" : "SIMULTANEOUS_CLOSE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


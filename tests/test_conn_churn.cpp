/**
 * @file test_conn_churn.cpp
 * @brief Connection lifecycle churn: 1000 connect->transfer->close cycles
 *        on the same stacks. Every cycle must deliver its payload intact and
 *        the connection count must return to zero (no leaks, no state
 *        pollution between connections).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _MSC_VER
#include <crtdbg.h>
#endif

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
#ifdef _MSC_VER
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
#endif
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
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });
        UInt64 total_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetRecvHandler([&total_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            total_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40131;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9101;
        CHECK(stack_b.Listen(remote));

        constexpr UInt32 kCycles = 1000;
        constexpr UInt32 kBytes = 2048;
        UInt32 crc_expect_total = 0;
        for (UInt32 cycle = 0; cycle < kCycles; ++cycle) {
            xtcp::core::Endpoint l = local;
            l.port = static_cast<UInt16>(40131 + (cycle % 2000));
            const UInt64 conn = stack_a.Connect(l, remote);
            CHECK(0 != conn);
            Pump(backend_a, backend_b, stack_a, stack_b);

            std::vector<Byte> payload(kBytes);
            for (UInt32 i = 0; i < kBytes; ++i) {
                payload[i] = static_cast<Byte>((i + cycle) & 0xFF);
                crc_expect_total = (crc_expect_total * 31 + payload[i]) & 0x7FFFFFFF;
            }
            UInt32 sent = 0;
            for (UInt32 round = 0; round < 8 && sent < kBytes; ++round) {
                UInt32 n = kBytes - sent;
                if (n > 1024) {
                    n = 1024;
                }
                UInt32 g = 0;
                while (!stack_a.Send(conn, payload.data() + sent, n)) {
                    if (300 <= ++g) {
                        break;
                    }
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                if (300 <= g) {
                    break;
                }
                sent += n;
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            CHECK(kBytes == sent);

            stack_a.Close(conn);
            for (UInt32 i = 0; i < 30; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            if (0 == (cycle % 100)) {
                std::fprintf(stderr, "[churn] cycle=%u conns=%u recv=%llu\n",
                             cycle, (UInt32)stack_a.ConnectionCount(),
                             (unsigned long long)total_recv);
            }
        }

        // Drain until every expected byte has arrived AND both stacks have
        // reclaimed all connections (no fixed round budget, so a slow final
        // ACK clock or a pending 2MSL reclamation cannot starve the
        // assertions); only bail out if no progress of any kind is made for
        // a long stretch — a genuine delivery/leak failure must be reported
        // by the CHECKs below, not hidden by an infinite loop.
        const UInt64 recv_expect = static_cast<UInt64>(kCycles) * kBytes;
        UInt32 stalls = 0;
        while (total_recv < recv_expect || 0 != stack_a.ConnectionCount() ||
               0 != stack_b.ConnectionCount()) {
            const UInt64 before_recv = total_recv;
            const UInt32 before_a = stack_a.ConnectionCount();
            const UInt32 before_b = stack_b.ConnectionCount();
            Pump(backend_a, backend_b, stack_a, stack_b);
            if (total_recv == before_recv && before_a == stack_a.ConnectionCount() &&
                before_b == stack_b.ConnectionCount()) {
                if (10000 <= ++stalls) {
                    std::fprintf(stderr, "[churn] drain stalled recv=%llu/%llu "
                                         "conns_a=%u conns_b=%u\n",
                                 (unsigned long long)total_recv,
                                 (unsigned long long)recv_expect,
                                 (UInt32)stack_a.ConnectionCount(),
                                 (UInt32)stack_b.ConnectionCount());
                    break;
                }
            } else {
                stalls = 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const UInt32 conns_a = stack_a.ConnectionCount();
        const UInt32 conns_b = stack_b.ConnectionCount();
        std::fprintf(stderr, "[churn] final A=%u B=%u recv=%llu crc_recv=%u crc_exp=%u\n",
                     conns_a, conns_b, (unsigned long long)total_recv, crc_recv, crc_expect_total);
        CHECK(0 == conns_a);
        CHECK(0 == conns_b);
        CHECK(kCycles * kBytes == total_recv);
        CHECK(crc_expect_total == crc_recv);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CONN_CHURN: FAILED (%d)\n" : "CONN_CHURN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

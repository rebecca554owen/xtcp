/**
 * @file test_wscale_transfer.cpp
 * @brief Window-scaling + large transfer + loss recovery: the scaled send
 *        window (>= 256 KiB) carries a 256 KiB payload across a lossy link;
 *        SACK/RTO recovery completes the transfer and the bytes arrive
 *        intact.
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

static UInt32 g_drop_every = 0;
static UInt32 g_drop_count = 0;
static UInt32 g_tx_seen = 0;

static void PumpLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                if (0 != g_drop_every && 0 == (g_tx_seen % g_drop_every)) {
                    ++g_drop_count;
                } else {
                    b.Inject(out, n, 0x0800);
                }
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
        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        // Payload pattern is (i*9 + i/41) & 0xFF (see the fill loop below), so
        // the handler can detect where the delivered stream first diverges.
        UInt64 g_div_offset = 0;  // first divergent offset (0 = none yet)
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv, &g_div_offset](UInt64, const Byte* d, UInt32 len) {
            const UInt64 base = bytes_recv;
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                const UInt64 off = base + i;
                const Byte expect = static_cast<Byte>((off * 9 + off / 41) & 0xFF);
                if (0 == g_div_offset && expect != d[i]) {
                    g_div_offset = off;
                }
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40121;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9100;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        PumpLossy(backend_a, backend_b, stack_a, stack_b);

        // 256 KiB transfer with 12.5% loss. The window scale factor applies
        // automatically; a 65535-byte unscaled window could never carry this
        // in flight, so delivery validates the scaled window too.
        const UInt32 kTotal = 262144;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
        }
        UInt64 accepted = 0;
        g_drop_every = 8;
        UInt32 guard = 0;
        while (accepted < kTotal && 400000 > ++guard) {
            UInt32 n = static_cast<UInt32>(kTotal - accepted);
            if (n > 4096) {
                n = 4096;
            }
            // Time-based retry budget: a 500-try guard with a 1ms sleep is
            // 500ms on Linux but ~7.8s on Windows (default 15.6ms sleep
            // granularity) - loss recovery needs 200ms+ RTO cycles, so the
            // tight guard only ever failed on Linux. Measure wall-clock time
            // instead so both platforms get the same 10s budget.
            const auto send_t0 = std::chrono::steady_clock::now();
            UInt32 tries = 0;
            while (!stack_a.Send(conn, payload.data() + accepted, n) &&
                   10000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - send_t0).count() &&
                   100000 > ++tries) {
                PumpLossy(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            accepted += n;
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == accepted);
        // Time-based drain budget (same Linux/Windows semantics as the send
        // guard above: 3000 x 1ms retries is 3s on Linux but ~47s on Windows).
        const auto drain_t0 = std::chrono::steady_clock::now();
        for (UInt32 i = 0; i < 300000 && bytes_recv < kTotal &&
                30000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - drain_t0).count(); ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[wscale-transfer] dropped=%u received=%llu div_offset=%llu\n",
                     g_drop_count, (unsigned long long)bytes_recv, (unsigned long long)g_div_offset);
        CHECK(kTotal == bytes_recv);
        CHECK(0 < g_drop_count);

        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_recv);
        std::fprintf(stderr, "[wscale-transfer] crc recv=%u exp=%u\n", crc_recv, crc_expect);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WSCALE_TRANSFER: FAILED (%d)\n" : "WSCALE_TRANSFER: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

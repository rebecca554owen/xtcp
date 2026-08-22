/**
 * @file test_md5_loss.cpp
 * @brief TCP-MD5 (RFC 2385) over a lossy link: a large transfer with packet
 *        loss (SACK/RTO recovery) stays intact and MD5-validated on both
 *        sides - the per-segment signature survives retransmission.
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

// A->B is lossy: every g_drop_every-th packet is dropped (then counted and
// silently swallowed instead of delivered). B->A is lossless.
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
                    ++g_drop_count;  // drop: never delivered
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
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        const Byte key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9094;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        PumpLossy(backend_a, backend_b, stack_a, stack_b);

        // 64 KiB transfer with 12.5% loss on A->B.
        const UInt32 kTotal = 65536;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 7 + i / 97) & 0xFF);
        }
        UInt32 accepted = 0;
        g_drop_every = 8;
        UInt32 guard = 0;
        while (accepted < kTotal && 200000 > ++guard) {
            UInt32 n = kTotal - accepted;
            if (n > 2048) {
                n = 2048;
            }
            UInt32 tries = 0;
            while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
                PumpLossy(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            accepted += n;
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == accepted);
        for (UInt32 i = 0; i < 2000 && bytes_recv < kTotal; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[md5-loss] dropped=%u received=%llu\n",
                     g_drop_count, (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);
        CHECK(0 < g_drop_count);  // the loss was actually exercised

        // Verify content: recompute the expected CRC over the payload.
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        std::fprintf(stderr, "[md5-loss] crc recv=%u expect=%u\n", crc_recv, crc_expect);
        CHECK(crc_expect == crc_recv);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_LOSS: FAILED (%d)\n" : "MD5_LOSS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

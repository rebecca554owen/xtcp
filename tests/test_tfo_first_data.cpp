/**
 * @file test_tfo_first_data.cpp
 * @brief RFC 7413 first fast-open connection (no cached cookie): the early
 *        data the caller hands to ConnectWithTfo must still arrive intact -
 *        the stack buffers it and flushes it once the handshake completes,
 *        instead of sending cookie-less SYN-carried data the server refuses.
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
        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40151;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9103;
        CHECK(stack_b.Listen(remote));

        // First-ever fast-open connect: no cached cookie. The early data is
        // handed in at connect time.
        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 3 + i / 19) & 0xFF);
        }
        const UInt32 kEarly = 64;
        const UInt64 conn = stack_a.ConnectWithTfo(local, remote, payload.data(), kEarly);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[tfo-first] A=%d recv=%llu\n",
                     (int)stack_a.ConnectionState(conn), (unsigned long long)bytes_recv);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // The early data must already be delivered (flushed on Established).
        CHECK(kEarly <= bytes_recv);

        // Send the rest; everything arrives intact.
        UInt32 sent = kEarly;
        for (UInt32 round = 0; round < 16 && sent < kTotal; ++round) {
            UInt32 n = kTotal - sent;
            if (n > 2048) {
                n = 2048;
            }
            UInt32 g = 0;
            while (!stack_a.Send(conn, payload.data() + sent, n) && 300 > ++g) {
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
        std::fprintf(stderr, "[tfo-first] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_recv);
        std::fprintf(stderr, "[tfo-first] crc recv=%u exp=%u\n", crc_recv, crc_expect);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_FIRST_DATA: FAILED (%d)\n" : "TFO_FIRST_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

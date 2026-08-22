/**
 * @file test_close_recv.cpp
 * @brief FIN-WAIT receive path (RFC 793 half-close): after the local side
 *        closes, the peer's remaining data must still be delivered intact
 *        while the local side waits in FIN-WAIT-1/2 - the closing side keeps
 *        processing inbound segments.
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
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40211;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9109;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);

        // A closes first (its FIN goes out); B, now in CLOSE-WAIT, still
        // replies with a large payload before closing (RFC 793 half-close).
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[close-recv] A mid-close state=%d\n", (int)mid);
        CHECK(xtcp::core::TcpState::kFinWait1 == mid || xtcp::core::TcpState::kFinWait2 == mid);

        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 23 + i / 5) & 0xFF);
        }
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
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[close-recv] A_recv=%llu\n", (unsigned long long)recv_a);
        CHECK(kTotal == recv_a);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_a);

        // Let B's FIN (sent after its data) reach A.
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[close-recv] A final state=%d\n", (int)end);
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSE_RECV: FAILED (%d)\n" : "CLOSE_RECV: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

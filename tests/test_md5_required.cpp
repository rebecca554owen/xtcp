/**
 * @file test_md5_required.cpp
 * @brief A listener with a TCP-MD5 key (RFC 2385) must refuse clients that
 *        do not sign their segments - the connection is rejected cleanly
 *        (RST) rather than silently stranding the client in a half-open
 *        state. A client that presents the correct key connects normally.
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
        stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

        const Byte key[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40161;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9104;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));

        // A plain client (no MD5) must be cleanly rejected.
        const UInt64 plain = stack_a.Connect(local, remote);
        CHECK(0 != plain);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState plain_state = stack_a.ConnectionState(plain);
        std::fprintf(stderr, "[md5-req] plain client A=%d B_conns=%u\n",
                     (int)plain_state, (UInt32)stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kClosed == plain_state);

        // An MD5 client with the correct key connects normally and transfers.
        xtcp::core::Endpoint l = local;
        l.port = 40162;
        const UInt64 conn = stack_a.ConnectWithMd5(l, remote, key, sizeof(key));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[md5-req] md5 client A=%d\n",
                     (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        const UInt32 kTotal = 4096;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 7) & 0xFF);
        }
        UInt32 sent = 0;
        for (UInt32 round = 0; round < 8 && sent < kTotal; ++round) {
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
        std::fprintf(stderr, "[md5-req] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_REQUIRED: FAILED (%d)\n" : "MD5_REQUIRED: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

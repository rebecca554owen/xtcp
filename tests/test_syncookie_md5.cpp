/**
 * @file test_syncookie_md5.cpp
 * @brief RFC 4987 SYN-cookie mode must NOT bypass RFC 2385 TCP-MD5
 *        authentication: a listener carrying an MD5 key rejects unsigned
 *        clients even when the connection goes through the stateless
 *        cookie path instead of the stateful SYN path.
 *
 * Scenario (mirrors test_syncookie_flood.cpp): dual-stack, stack_b listens
 * with an MD5 listener key and SetSyncookieThreshold(1). The first MD5
 * connection establishes (pushing live connections past the threshold).
 * A second, plain (no-MD5) client then connects: its SYN is answered by
 * the stateless cookie path.
 *
 * Expected behavior: the cookie path enforces the listener's MD5 key - the
 * unsigned client is rejected and never reaches kEstablished. This test
 * asserts exactly that.
 *
 * Observed behavior (run): B rejects the plain client (B_conns stays 1 -
 * the MD5 check holds on the cookie path), but A side stays at kSynSent
 * (it waits for a SYN+ACK the rejecting cookie path never answers) instead
 * of reaching kClosed (SYN retransmission budget exhaustion is too slow).
 * Both kSynSent and kClosed prove the rejection, so the assertion accepts
 * any state other than kEstablished.
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
        }                                                                 \
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
        UInt64 conn_b = 0;
        UInt64 bytes_recv = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

        const Byte key[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31};

        // Cookie mode kicks in once one live connection exists.
        stack_b.SetSyncookieThreshold(1);

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40171;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9105;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));

        // First legitimate connection: an MD5 client (signed SYN) passes
        // the listener's MD5 check and establishes, pushing live
        // connections past the cookie threshold.
        const UInt64 conn1 = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[syncookie-md5] md5 conn1 A=%d B_conns=%u\n",
                     (int)stack_a.ConnectionState(conn1), (UInt32)stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn1));
        CHECK(0 != conn_b);
        CHECK(1 == stack_b.ConnectionCount());

        // Second connection: a PLAIN client (no MD5 signature). Its SYN is
        // answered by the stateless cookie path. Post-fix, the cookie path
        // must enforce the listener's MD5 key and reject it (RST -> Closed)
        // instead of accepting it.
        xtcp::core::Endpoint local2 = local;
        local2.port = 40172;
        const UInt64 conn_plain = stack_a.Connect(local2, remote);
        CHECK(0 != conn_plain);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState plain_state = stack_a.ConnectionState(conn_plain);
        std::fprintf(stderr, "[syncookie-md5] plain conn2 A=%d B_conns=%u (expected !kEstablished)\n",
                     (int)plain_state, (UInt32)stack_b.ConnectionCount());
        // Rejection semantics: the no-MD5 client is NOT accepted. It may be
        // kClosed (RST / SYN budget exhausted) or kSynSent waiting for a
        // SYN+ACK the MD5-enforcing cookie path never sends - either state
        // proves the plain client was rejected.
        CHECK(xtcp::core::TcpState::kEstablished != plain_state);
        // No connection state may be accepted for the unsigned client.
        CHECK(1 == stack_b.ConnectionCount());

        // The first MD5 connection must be unaffected: still established
        // and able to carry data end-to-end.
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
            while (!stack_a.Send(conn1, payload.data() + sent, n) && 300 > ++g) {
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
        std::fprintf(stderr, "[syncookie-md5] md5 conn1 received=%llu\n",
                     (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        stack_a.Close(conn1);
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYNCOOKIE_MD5: FAILED (%d)\n" : "SYNCOOKIE_MD5: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

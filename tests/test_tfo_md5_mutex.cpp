/**
 * @file test_tfo_md5_mutex.cpp
 * @brief TFO (RFC 7413) and TCP-MD5 (RFC 2385) are mutually exclusive at the
 *        option layer: BuildSegmentPacket drops the TFO cookie option whenever
 *        MD5 signing is active (tcp_fsm.cpp:72 - the option area would
 *        overflow). A client that combines fast-open early data with a
 *        connection-level MD5 key must still complete the handshake and
 *        deliver every byte - the fast-open early data degrades to the
 *        buffered-and-flushed path instead of being silently lost
 *        (post-fix expectation: "TFO degrades, data stays intact").
 *
 * API note: the MD5 key must be live BEFORE the SYN is emitted (Linux
 * TCP_MD5SIG is configured before connect()). ConnectWithTfo builds and
 * hands its SYN to the backend synchronously, so a SetMd5Key() issued after
 * ConnectWithTfo would never sign the SYN and an MD5-required listener
 * (test_md5_required) would refuse the connection. This test therefore
 * composes the same "fast-open early data on an MD5-signed connection" intent
 * with ConnectWithMd5 (key pre-configured) + TfoSendSynData (early data on
 * the SYN), plus a cached TFO cookie so the fast-open SYN-carried-data path
 * is actually exercised.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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
        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 len) {
            received.append(reinterpret_cast<const char*>(d), len);
        });

        const Byte key[16] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40171;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9105;

        // B: an MD5-required listener (the key must be set before Listen so
        // every accepted connection inherits it and refuses unsigned SYNs).
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        CHECK(stack_b.Listen(remote));

        // A: simulate a cached TFO cookie (learned from a prior handshake) so
        // the fast-open SYN-carried-data path in SendSynWithData engages. The
        // cookie bytes are irrelevant to this test: with MD5 active the TFO
        // option is dropped from the SYN anyway, so B never validates it.
        const Byte cookie[8] = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33};
        stack_a.SetTfoCookieFor(remote, cookie);

        const UInt32 kTotal = 8192;
        const UInt32 kEarly = 64;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 3 + i / 19) & 0xFF);
        }

        // Fast-open early data on an MD5-signed connection: ConnectWithMd5
        // pre-configures the key before the SYN, TfoSendSynData attaches the
        // early data. BuildSegmentPacket then sees md5_key AND tfo_cookie and
        // must drop the TFO option (mutual exclusion) without losing the data.
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        CHECK(stack_a.TfoSendSynData(conn, payload.data(), kEarly));
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[tfo-md5-mutex] A=%d recv=%zu\n",
                     (int)stack_a.ConnectionState(conn), received.size());
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Send the rest; everything (early + later) must arrive intact.
        UInt64 sent = kEarly;
        for (UInt32 round = 0; round < 16 && sent < kTotal; ++round) {
            UInt32 n = static_cast<UInt32>(kTotal - sent);
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
        for (UInt32 i = 0; i < 500 && received.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[tfo-md5-mutex] received=%zu\n", received.size());

        // KEY ASSERTION: no byte lost to the TFO<->MD5 mutual exclusion.
        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[tfo-md5-mutex] all %u bytes verified\n", kTotal);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_MD5_MUTEX: FAILED (%d)\n" : "TFO_MD5_MUTEX: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

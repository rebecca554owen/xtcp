/**
 * @file test_md5_gso.cpp
 * @brief TCP-MD5 (RFC 2385) with large sends: a connection signing every
 *        segment must survive the tx boundary. The GSO segmentation path
 *        rebuilds TCP headers and must not strip the MD5 option - a signed
 *        connection's super-segment send must be delivered intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        const Byte key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        // The listener's MD5 key must be set before the handshake so the
        // accepted connection inherits it (its ACKs carry the signature).
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        CHECK(stack_b.Listen(remote));
        // The client pre-configures the key so its SYN is signed too
        // (Linux TCP_MD5SIG is set before connect()).
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Send in super-segments larger than the MSS: the tx boundary must
        // not break the signature (GSO rebuilds headers).
        constexpr UInt32 kTotal = 16 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 5 + 9) & 0xFF));
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 4096) ? (kTotal - sent) : 4096;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 200 && received.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[md5-gso] sent=%u recv=%zu MD5-signed super-segments OK\n",
                     sent, received.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_GSO: FAILED (%d)\n" : "MD5_GSO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

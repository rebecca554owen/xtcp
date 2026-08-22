/**
 * @file test_tfo_full.cpp
 * @brief RFC 7413 full flow: first connection obtains the TFO cookie from
 *        the SYN+ACK; a reconnection sends SYN + cookie + early data; the
 *        server validates the cookie and delivers the data. A cookie-less
 *        SYN+data is rejected (spoof protection).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <string>

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
    for (UInt32 round = 0; round < 500; ++round) {
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));

        // First connection: the server's SYN+ACK carries a TFO cookie.
        UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Reconnect with fast-open data: the SYN carries the cookie learned
        // from the first handshake (cached per peer) plus the early data.
        // Use a fresh local port so the first connection's TIME-WAIT (2MSL)
        // does not swallow the SYN (RFC 793 2MSL protection).
        const char* early = "tfo-cookie-data";
        xtcp::core::Endpoint tfo_local = local;
        tfo_local.port = 40002;
        conn = stack_a.ConnectWithTfo(tfo_local, remote,
                                      reinterpret_cast<const Byte*>(early),
                                      static_cast<UInt32>(std::strlen(early)));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // The cookie was validated and the early data delivered.
        CHECK(early == received);
        std::fprintf(stderr, "[tfo-full] cookie-validated early data delivered\n");

        // Close and reconnect WITHOUT a cookie: a spoofed SYN+data for a
        // peer we never handshaked with must be rejected. A compliant client
        // buffers early data until the cookie is known, so inject the
        // cookie-less SYN+data directly to prove the server drops it.
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const size_t before = received.size();
        xtcp::core::Endpoint spoof_remote = remote;
        spoof_remote.port = 8081;
        CHECK(stack_b.Listen(spoof_remote));
        {
            // IP(20) + TCP(20) + payload; SYN set, no TFO option.
            const char* spoof_data = "spoofed-early";
            const UInt32 plen = static_cast<UInt32>(std::strlen(spoof_data));
            const UInt32 total = 40 + plen;
            std::vector<Byte> pkt(total);
            std::memset(pkt.data(), 0, total);
            pkt[0] = 0x45;
            pkt[2] = static_cast<Byte>(total >> 8); pkt[3] = static_cast<Byte>(total);
            pkt[9] = 6;
            pkt[12] = 0x0A; pkt[13] = 0x00; pkt[14] = 0x00; pkt[15] = 0x01;
            pkt[16] = 0x0A; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x02;
            Byte* tcp = pkt.data() + 20;
            tcp[0] = 0x9C; tcp[1] = 0x41;                    // 40001
            tcp[2] = 0x1F; tcp[3] = 0x91;                    // 8081
            tcp[4] = 0x12; tcp[5] = 0x34; tcp[6] = 0x56; tcp[7] = 0x78;
            tcp[12] = 0x50; tcp[13] = 0x02;                  // SYN
            tcp[14] = 0x40; tcp[15] = 0x00;
            std::memcpy(pkt.data() + 40, spoof_data, plen);
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
            std::memcpy(buf.Data(), pkt.data(), total);
            buf.SetLen(total);
            stack_b.OnPacket(std::move(buf));
        }
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(before == received.size());  // spoofed early data dropped
        std::fprintf(stderr, "[tfo-full] cookie-less SYN data rejected (spoof protected)\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_FULL: FAILED (%d)\n" : "TFO_FULL: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

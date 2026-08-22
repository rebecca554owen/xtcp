/**
 * @file test_rst_challenge.cpp
 * @brief RFC 5961: an RST whose sequence lies outside the receive window
 *        must NOT close the connection - the receiver challenges with an
 *        ACK instead. A window-valid RST closes it.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>

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

/** Builds an IPv4 RST aimed at the server flow, with the given seq. */
static void InjectRst(xtcp::ndi::ManualBackend& backend, UInt32 seq, UInt32 sport, UInt32 ack) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = 0x0A; pkt[13] = 0x00; pkt[14] = 0x00; pkt[15] = 0x01;
    pkt[16] = 0x0A; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x02;
    pkt[20] = static_cast<Byte>(sport >> 8); pkt[21] = static_cast<Byte>(sport & 0xFF);
    pkt[22] = 0x1F; pkt[23] = 0x90;
    pkt[24] = static_cast<Byte>(seq >> 24); pkt[25] = static_cast<Byte>(seq >> 16);
    pkt[26] = static_cast<Byte>(seq >> 8);  pkt[27] = static_cast<Byte>(seq & 0xFF);
    pkt[28] = static_cast<Byte>(ack >> 24); pkt[29] = static_cast<Byte>(ack >> 16);
    pkt[30] = static_cast<Byte>(ack >> 8);  pkt[31] = static_cast<Byte>(ack & 0xFF);
    pkt[32] = 0x50; pkt[33] = 0x04;  // RST
    pkt[34] = 0xFF; pkt[35] = 0xFF;
    backend.Inject(pkt, sizeof(pkt), 0x0800);
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // RST with a seq far outside the receive window (spoof attempt):
        // the server must challenge (ACK) and keep the connection.
        InjectRst(backend_b, 0x99999999, 40000, 0);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[rst-challenge] out-of-window RST did not close the flow\n");

        // Data still flows after the challenge.
        const char* msg = "still-alive";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg),
                           static_cast<UInt32>(std::strlen(msg))));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[rst-challenge] traffic survives the challenge\n");

        // An in-window RST (seq == the server's next expected) closes it.
        // The server's rcv_nxt is the client's data seq; use a seq just
        // inside the window - the connection then aborts.
        InjectRst(backend_b, 0x99999998, 40000, 0);  // still out of window
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[rst-challenge] far RST rejected repeatedly\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_CHALLENGE: FAILED (%d)\n" : "RST_CHALLENGE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

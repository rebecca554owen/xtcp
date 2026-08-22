/**
 * @file test_mimt_connect_flow.cpp
 * @brief Ghost-flow regression: a CLIENT connection created on a MIMT stack
 *        must NOT get a mimt flow (its rx routes via recv_handler_ instead).
 *        Pre-fix: BindDataPath created a flow for EVERY connection while
 *        mimt_on_flow_ was set - a client connect produced a phantom flow
 *        stamped with the connect's ephemeral key that the async router
 *        silently dropped, absorbing all rx data (silent loss + backpressure
 *        stalls past the 1MB cap).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <memory>
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

        UInt32 flows_created = 0;  // A's mimt_on_flow_ invocations
        UInt32 a_recv = 0;         // A's recv_handler_ deliveries
        UInt64 b_side = 0;         // B's accepted conn id (from A's connect)
        stack_a.StartMimt([&flows_created](std::shared_ptr<xtcp::mimt::MimtFlow>) {
            ++flows_created;
        });
        stack_a.SetRecvHandler([&a_recv](UInt64, const Byte*, UInt32 len) { a_recv += len; });
        stack_b.SetStateHandler([&b_side](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st && 0 == b_side) {
                b_side = id;
            }
        });

        xtcp::core::Endpoint ep_a, ep_b;
        ep_a.family = 4;
        ep_a.addr[0] = 0x0A000001;
        ep_a.port = 9090;
        ep_b.family = 4;
        ep_b.addr[0] = 0x0A000002;
        ep_b.port = 8080;
        CHECK(stack_a.Listen(ep_a));
        CHECK(stack_b.Listen(ep_b));

        // A (MIMT on) initiates a CLIENT connection to B: no phantom flow.
        const UInt64 conn_a = stack_a.Connect(ep_a, ep_b);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 == flows_created);  // the connect must NOT create a flow

        // B sends data to the accepted side of A's client connection: it must
        // arrive via A's recv_handler_ (no ghost flow to absorb it).
        CHECK(0 != b_side);
        const Byte payload[64] = {0x11, 0x22, 0x33};
        CHECK(stack_b.Send(b_side, payload, sizeof(payload)));
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[mimt-connect] after client rx: flows=%u a_recv=%u\n", flows_created, a_recv);
        CHECK(0 == flows_created);             // no ghost flow for the client conn
        CHECK(sizeof(payload) == a_recv);      // rx arrived via the recv handler

        // A third-party ACCEPT on A's listener still creates exactly one flow.
        xtcp::core::Endpoint ep_c;
        ep_c.family = 4;
        ep_c.addr[0] = 0x0A000003;
        ep_c.port = 6000;
        const UInt64 conn_c = stack_b.Connect(ep_c, ep_a);
        CHECK(0 != conn_c);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[mimt-connect] after accept flows=%u\n", flows_created);
        CHECK(1 == flows_created);  // exactly one flow: the listener accept
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_CONNECT_FLOW: FAILED (%d)\n" : "MIMT_CONNECT_FLOW: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

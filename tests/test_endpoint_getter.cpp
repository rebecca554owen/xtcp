/**
 * @file test_endpoint_getter.cpp
 * @brief Endpoint query API (F1): GetLocalEndpoint / GetRemoteEndpoint.
 *        Verifies the exact bound local endpoint is observable (including
 *        the ephemeral port assigned by a port=0 Connect, which previously
 *        had no address-level export), and that a client's local endpoint
 *        matches the peername seen by the server.
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

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                 UInt16 eth_type, xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    UInt32 guard = 0;
    bool moved = false;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, eth_type);
        moved = true;
        if (1000 < ++guard) {
            break;
        }
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
    // Yield only when traffic moved (the ACK clock needs real time); an
    // idle poll returns immediately - a 1ms sleep per idle round costs
    // ~15.6ms on Windows (clock granularity).
    if (moved) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static void WaitEstablished(xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt64 conn,
                            xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb) {
    for (UInt32 i = 0; i < 1000 && xtcp::core::TcpState::kEstablished !=
                                        sa.ConnectionState(conn); ++i) {
        Pump(ba, bb, 0x0800, sa, sb);
        Pump(bb, ba, 0x0800, sa, sb);
    }
}

// Explicit local port: both endpoints must round-trip exactly.
static void TestExplicitPort() {
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
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    CHECK(stack_b.Listen(remote));

    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    xtcp::core::Endpoint got;
    CHECK(stack_a.GetLocalEndpoint(conn, got));
    CHECK(got.family == local.family);
    CHECK(got.addr[0] == local.addr[0]);
    CHECK(got.port == local.port);

    CHECK(stack_a.GetRemoteEndpoint(conn, got));
    CHECK(got.family == remote.family);
    CHECK(got.addr[0] == remote.addr[0]);
    CHECK(got.port == remote.port);

    WaitEstablished(stack_a, stack_b, conn, backend_a, backend_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
}

// port=0 Connect: GetLocalEndpoint must expose the assigned ephemeral port
// (the address/port have no other export path today).
static void TestEphemeralPort() {
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
    local.addr[0] = 0xC0A80103;
    local.port = 0;  // ephemeral
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9001;
    CHECK(stack_b.Listen(remote));

    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    xtcp::core::Endpoint got;
    CHECK(stack_a.GetLocalEndpoint(conn, got));
    CHECK(0 != got.port);                              // ephemeral assigned
    CHECK(49152 <= got.port);                          // IANA dynamic range
    CHECK(got.addr[0] == local.addr[0]);               // address preserved
    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
    UInt64 rto_deadline = 0;
    UInt32 dup_acks = 0, fast_rec = 0, front_seq = 0, snd_una = 0;
    UInt16 stats_local_port = 0, stats_remote_port = 0;
    stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                      rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                      stats_local_port, stats_remote_port);
    CHECK(got.port == stats_local_port);               // agrees with ConnStats

    CHECK(stack_a.GetRemoteEndpoint(conn, got));
    CHECK(got.family == remote.family);
    CHECK(got.addr[0] == remote.addr[0]);
    CHECK(got.port == remote.port);

    WaitEstablished(stack_a, stack_b, conn, backend_a, backend_b);
}

// Unknown conn ids: both getters return false and leave the output untouched.
static void TestUnknownConn() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::core::Endpoint sentinel;
    sentinel.family = 9;
    sentinel.port = 9999;
    xtcp::core::Endpoint got = sentinel;
    CHECK(!stack_a.GetLocalEndpoint(12345, got));
    CHECK(got.family == sentinel.family && got.port == sentinel.port);  // untouched
    got = sentinel;
    CHECK(!stack_a.GetRemoteEndpoint(12345, got));
    CHECK(got.family == sentinel.family && got.port == sentinel.port);  // untouched
}

// Server-side peername: the accepted connection's remote endpoint must match
// the client's bound local endpoint (address + ephemeral port).
static void TestServerPeer() {
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

    UInt64 accepted = 0;
    stack_b.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&,
                                         const xtcp::core::Endpoint&) {
        accepted = id;
        return true;
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80104;
    local.port = 0;  // ephemeral
    remote.family = 4;
    remote.addr[0] = 0x0A000003;
    remote.port = 9101;
    CHECK(stack_b.Listen(remote));

    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    WaitEstablished(stack_a, stack_b, conn, backend_a, backend_b);
    CHECK(0 != accepted);

    xtcp::core::Endpoint client_local, server_peer, server_local;
    CHECK(stack_a.GetLocalEndpoint(conn, client_local));
    CHECK(stack_b.GetRemoteEndpoint(accepted, server_peer));
    CHECK(stack_b.GetLocalEndpoint(accepted, server_local));
    // The server's peername must be the client's bound local endpoint.
    CHECK(server_peer.addr[0] == client_local.addr[0]);
    CHECK(server_peer.port == client_local.port);
    // The server's local endpoint is the listener it accepted on.
    CHECK(server_local.addr[0] == remote.addr[0]);
    CHECK(server_local.port == remote.port);
}

int main() {
    xtcp::buf::InitPools();
    TestExplicitPort();
    TestEphemeralPort();
    TestUnknownConn();
    TestServerPeer();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ENDPOINT_GETTER: FAILED (%d)\n"
                                    : "ENDPOINT_GETTER: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

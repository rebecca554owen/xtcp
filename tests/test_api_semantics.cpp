/**
 * @file test_api_semantics.cpp
 * @brief Zero-coverage API semantics:
 *  1. ConnectionExists - the stack.h:254 contract: tells "never existed /
 *     already reaped" apart from "exists in kClosed", which ConnectionState
 *     alone cannot (it reports kClosed for missing ids too).
 *  2. EndpointKey - the stack.h:66 invariant: stable hash shared by the
 *     listener MD5 / TFO cookie caches and the async accept routing, so a
 *     listener endpoint and the flows it accepts hash to the same key.
 *     Verifies determinism, port / address-family / address sensitivity and
 *     the MimtFlow::ListenerKey == EndpointKey(listener) routing premise.
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
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, eth_type);
        if (1000 < ++guard) {
            break;
        }
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

static void WaitEstablished(xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt64 conn,
                            xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb) {
    for (UInt32 i = 0; i < 1000 && xtcp::core::TcpState::kEstablished !=
                                        sa.ConnectionState(conn); ++i) {
        Pump(ba, bb, 0x0800, sa, sb);
        Pump(bb, ba, 0x0800, sa, sb);
    }
}

// ConnectionExists lifecycle: never-exists vs alive vs closed-then-reaped.
static void TestConnectionExists() {
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

    // "Never existed": 0xFFFFFFFF never allocated -> false, and ConnectionState
    // reports kClosed (the exact ambiguity ConnectionExists resolves).
    CHECK(!stack_a.ConnectionExists(0xFFFFFFFFu));
    CHECK(!stack_b.ConnectionExists(0xFFFFFFFFu));
    CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(0xFFFFFFFFu));

    UInt64 accepted = 0;
    stack_b.SetAcceptHandler([&accepted](UInt64 id, const xtcp::core::Endpoint&,
                                         const xtcp::core::Endpoint&) {
        accepted = id;
        return true;
    });

    // Fast TIME-WAIT reclamation so the Close phase observes the reap.
    stack_a.SetTwoMsl(20000);
    stack_b.SetTwoMsl(20000);

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80110;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000010;
    remote.port = 9100;
    CHECK(stack_b.Listen(remote));

    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    // Live immediately after Connect (conn allocated, SYN pending).
    CHECK(stack_a.ConnectionExists(conn));
    CHECK(xtcp::core::TcpState::kSynSent == stack_a.ConnectionState(conn));

    WaitEstablished(stack_a, stack_b, conn, backend_a, backend_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
    CHECK(stack_a.ConnectionExists(conn));
    CHECK(stack_b.ConnectionExists(accepted));

    // Close both sides. Right after Close() the connection is still live
    // (FinWait1) - reclamation is driven by PollAckTimers, not by Close().
    stack_a.Close(conn);
    CHECK(stack_a.ConnectionExists(conn));

    // Drive the FIN exchange + TIME-WAIT until both stacks reap everything.
    for (UInt32 i = 0; i < 1000 && (0 != stack_a.ConnectionCount() ||
                                    0 != stack_b.ConnectionCount()); ++i) {
        Pump(backend_a, backend_b, 0x0800, stack_a, stack_b);
        Pump(backend_b, backend_a, 0x0800, stack_a, stack_b);
        if (0 != accepted && i > 50) {
            stack_b.Close(accepted);
        }
    }
    CHECK(0 == stack_a.ConnectionCount());
    CHECK(0 == stack_b.ConnectionCount());

    // "Already reaped": the id is gone. ConnectionState can only say kClosed
    // (same as for a never-existing id); ConnectionExists distinguishes.
    CHECK(!stack_a.ConnectionExists(conn));
    CHECK(!stack_b.ConnectionExists(accepted));
    CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
}

// EndpointKey invariants: deterministic, port / family / address sensitive.
static void TestEndpointKey() {
    xtcp::core::Endpoint ep;
    ep.family = 4;
    ep.addr[0] = 0xC0A80101;
    ep.port = 8080;

    // Determinism: repeated calls must be equal (stable routing key).
    const UInt64 k1 = xtcp::EndpointKey(ep);
    const UInt64 k2 = xtcp::EndpointKey(ep);
    const UInt64 k3 = xtcp::EndpointKey(ep);
    CHECK(k1 == k2);
    CHECK(k2 == k3);

    // Port sensitivity: same address, different port -> different key.
    xtcp::core::Endpoint other = ep;
    other.port = 8081;
    CHECK(xtcp::EndpointKey(ep) != xtcp::EndpointKey(other));
    other.port = 1;
    CHECK(xtcp::EndpointKey(ep) != xtcp::EndpointKey(other));

    // Address-family sensitivity: family 4 vs 6 hash differently even with the
    // same low address word and port (family enters the hash seed and the
    // word count differs: 1 vs 4).
    xtcp::core::Endpoint v6;
    v6.family = 6;
    v6.addr[0] = 0xC0A80101;
    v6.port = 8080;
    CHECK(xtcp::EndpointKey(ep) != xtcp::EndpointKey(v6));

    // Address sensitivity: same family+port, different address -> different key.
    xtcp::core::Endpoint moved = ep;
    moved.addr[0] = 0xC0A80102;
    CHECK(xtcp::EndpointKey(ep) != xtcp::EndpointKey(moved));
}

// Routing premise: a MIMT flow accepted on a listener carries the listener's
// EndpointKey, so async accept routing finds the right per-listener handler.
static void TestListenerKeyRouting() {
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

    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    stack_b.StartMimt([&flow](std::shared_ptr<xtcp::mimt::MimtFlow> f) { flow = f; });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000020;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000021;
    remote.port = 8080;
    CHECK(stack_b.Listen(remote));

    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    for (UInt32 r = 0; r < 200 && !flow; ++r) {
        Pump(backend_a, backend_b, 0x0800, stack_a, stack_b);
        Pump(backend_b, backend_a, 0x0800, stack_a, stack_b);
        stack_b.DispatchMimt();
    }
    CHECK(flow);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    // The flow's routing key must be the listener endpoint's hash: the async
    // layer routes the accept by flow->ListenerKey() == EndpointKey(local).
    CHECK(0 != flow->ListenerKey());
    CHECK(xtcp::EndpointKey(remote) == flow->ListenerKey());
}

int main() {
    xtcp::buf::InitPools();
    TestConnectionExists();
    TestEndpointKey();
    TestListenerKeyRouting();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "API_SEMANTICS: FAILED (%d)\n"
                                    : "API_SEMANTICS: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_async_listen_dup.cpp
 * @brief AsyncListen duplicate-listen regression test: a second AsyncListen on
 *        the same (family, port) must NOT clobber the first listener's accept
 *        callback.
 *
 * Context: XtcpStack::Listen() returns false for a duplicate endpoint (Linux
 * EADDRINUSE semantics, stack.cpp:335-345). AsyncListen has a void signature
 * (async.h:52), so it cannot propagate that failure to the caller - the async
 * proxy fix is to keep the previous accept_cb_ untouched when Listen() fails
 * (async.cpp:79-83). This test proves the observable consequence: after the
 * second (failing) AsyncListen, a connection to the port is still delivered to
 * the FIRST callback, and never to the second one.
 *
 * Key assertions:
 *   1. First AsyncListen registers: a duplicate raw Listen() on the same port
 *      returns false (EADDRINUSE) - XtcpStack::IsListening is private, so the
 *      first Listen's success is proven by that duplicate rejection.
 *   2. The accept is delivered only via Poll(), and only to the first callback
 *      (accepted_first == true, accepted_second == false).
 *   3. A second Poll() fires nothing (strict 1:1, no double dispatch).
 *   4. Data flows through the accepted flow (first listener is functional).
 *   5. A second client connect is still accepted by the FIRST callback -
 *      the old callback survives the failed duplicate Listen.
 */

#include <xtcp/async/async.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <memory>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to, UInt16 eth_type) {
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
}

static void TestAsyncListenDupNotOverwrite() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);

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

    // B listens on remote (10.0.0.1:9443); A connects from local ports.
    xtcp::core::Endpoint local, local2, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40040;
    local2.family = 4;
    local2.addr[0] = 0xC0A80102;
    local2.port = 40041;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 9443;

    // First listener: the callback that must survive.
    bool accepted_first = false;
    int first_count = 0;
    std::shared_ptr<xtcp::mimt::MimtFlow> flow_first;
    stack_b.AsyncListen(remote, [&](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
        accepted_first = true;
        ++first_count;
        flow_first = std::move(f);
    });

    // Second AsyncListen on the same port: Listen() fails (EADDRINUSE), so the
    // old accept_cb_ must be retained - this callback must NEVER fire.
    bool accepted_second = false;
    stack_b.AsyncListen(remote, [&](std::shared_ptr<xtcp::mimt::MimtFlow>) {
        accepted_second = true;
    });

    // Stack-level proof the first AsyncListen actually registered the listener
    // (void AsyncListen cannot return the result to the caller). If the first
    // Listen had failed, this duplicate raw Listen would succeed; it returning
    // false proves the first registration holds. IsListening is private, so
    // this duplicate-rejection is the observable proxy.
    CHECK(!stack_b.Stack().Listen(remote));

    // Client 1: connect to the port, complete the handshake.
    const UInt64 conn1 = stack_a.Stack().Connect(local, remote);
    CHECK(0 != conn1);
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);
    Pump(backend_a, backend_b, 0x0800);
    // Accept is async: pending until B polls.
    CHECK(!accepted_first);

    // Poll() dispatches the accept via the FIRST (retained) callback.
    CHECK(0 < stack_b.Poll());
    CHECK(accepted_first);
    CHECK(NULLPTR != flow_first);
    CHECK(!accepted_second);

    // Strict 1:1: no further accepts pending, second Poll fires nothing.
    CHECK(0 == stack_b.Poll());

    // Data flows through the accepted flow (first listener functional).
    const char payload[] = "listen-dup-ok";
    CHECK(stack_a.Stack().Send(conn1, reinterpret_cast<const Byte*>(payload),
                               sizeof(payload) - 1));
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);

    bool read_done = false;
    Byte buf[64];
    CHECK(xtcp::mimt::Result::kOk == flow_first->AsyncRead(buf, sizeof(buf),
                                                           [&](xtcp::mimt::Result, UInt32 n) {
                                                               read_done = true;
                                                               CHECK(sizeof(payload) - 1 == n);
                                                           }));
    stack_b.Poll();
    CHECK(read_done);
    CHECK(0 == std::memcmp(buf, payload, sizeof(payload) - 1));

    // Client 2: a fresh connection is still accepted by the FIRST callback -
    // the old callback survived the failed duplicate Listen.
    const UInt64 conn2 = stack_a.Stack().Connect(local2, remote);
    CHECK(0 != conn2);
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);
    Pump(backend_a, backend_b, 0x0800);
    CHECK(0 < stack_b.Poll());
    CHECK(2 == first_count);
    CHECK(accepted_first);
    CHECK(!accepted_second);
}

int main() {
    xtcp::buf::InitPools();
    TestAsyncListenDupNotOverwrite();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_listen_dup: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_listen_dup: all passed\n");
    return 0;
}

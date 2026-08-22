/**
 * @file test_async.cpp
 * @brief Async Proactor layer tests: AsyncConnect completion via Poll (async
 *        dispatch), AsyncListen accept delivery, data through the stack.
 */

#include <xtcp/async/async.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>

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

static void TestAsyncConnect() {
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

    // B listens; A connects asynchronously.
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    stack_b.AsyncListen(remote, [](std::shared_ptr<xtcp::mimt::MimtFlow>) {});

    bool connect_done = false;
    UInt64 conn_id = 0;
    stack_a.AsyncConnect(local, remote, [&](xtcp::mimt::Result ec, UInt64 id) {
        connect_done = true;
        conn_id = id;
        CHECK(xtcp::mimt::Result::kOk == ec);
    });

    // Handshake: connect must NOT complete synchronously.
    CHECK(!connect_done);
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);
    Pump(backend_a, backend_b, 0x0800);
    CHECK(!connect_done);  // still pending until Poll()

    // Poll() fires the completion asynchronously.
    CHECK(0 < stack_a.Poll());
    CHECK(connect_done);
    CHECK(0 != conn_id);
}

static void TestAsyncListenAccept() {
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

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    bool accepted = false;
    std::shared_ptr<xtcp::mimt::MimtFlow> flow;
    stack_b.AsyncListen(remote, [&](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
        accepted = true;
        flow = std::move(f);
    });

    const UInt64 conn = stack_a.Stack().Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);
    Pump(backend_a, backend_b, 0x0800);
    // Accept is async: pending until B polls.
    CHECK(!accepted);
    CHECK(0 < stack_b.Poll());
    CHECK(accepted);
    CHECK(NULLPTR != flow);

    // Data flows through the accepted MIMT flow.
    const char payload[] = "async-ok";
    CHECK(stack_a.Stack().Send(conn, reinterpret_cast<const Byte*>(payload), sizeof(payload) - 1));
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);

    bool read_done = false;
    Byte buf[64];
    CHECK(xtcp::mimt::Result::kOk == flow->AsyncRead(buf, sizeof(buf),
                                                     [&](xtcp::mimt::Result, UInt32 n) {
                                                         read_done = true;
                                                         CHECK(sizeof(payload) - 1 == n);
                                                     }));
    stack_b.Poll();
    CHECK(read_done);
    CHECK(0 == std::memcmp(buf, payload, sizeof(payload) - 1));
}

int main() {
    xtcp::buf::InitPools();
    TestAsyncConnect();
    TestAsyncListenAccept();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async: all passed\n");
    return 0;
}

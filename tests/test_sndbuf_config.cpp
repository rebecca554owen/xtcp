/**
 * @file test_sndbuf_config.cpp
 * @brief : the stack-level SetSndBuf configures the per-connection
 *        send-buffer quota (in-flight bound) - mirroring SetRcvBuf. Without
 *        it the fixed 64 KiB quota caps the sender's in-flight and defeats
 *        a large configured receive window on high-BDP paths. The quota is
 *        observed as Send() rejecting chunks past the bound until the flush
 *        drains.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/tcp.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
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
    for (UInt32 round = 0; round < 2000; ++round) {
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

static void TestDirectFsmQuota() {
    // Direct FSM: a 16 KiB quota rejects a second 16 KiB chunk while the
    // first sits buffered (pending 16384 + 16384 > 16384).
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    auto sink = [](xtcp::buf::BufRef&&) {};
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200, sink);
    conn.SetSndBuf(16384);

    std::vector<Byte> chunk(16384, 0x5C);
    CHECK(conn.SendData(chunk.data(), 16384, 0));
    CHECK(!conn.SendData(chunk.data(), 16384, 0));  // quota exhausted
    std::fprintf(stderr, "[sndbuf] direct-FSM quota enforced\n");
}

static void TestStackLevelQuota() {
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
    std::atomic<UInt64> b_recv{0};
    stack_b.SetRecvHandlerChecked([&b_recv](UInt64, const Byte*, UInt32 len) {
        b_recv.fetch_add(len, std::memory_order_relaxed);
        return true;
    });

    stack_a.SetSndBuf(16384);  // stack-level send quota

    xtcp::core::Endpoint la, lb;
    la.family = 4;
    la.addr[0] = 0x0A000001;
    la.port = 40260;
    lb.family = 4;
    lb.addr[0] = 0x0A000002;
    lb.port = 9260;
    CHECK(stack_b.Listen(lb));
    const UInt64 conn = stack_a.Connect(la, lb);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, stack_a, stack_b);
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    // The configured quota (16 KiB) bounds the accepted-but-unflushed bytes:
    // the second 16 KiB chunk is rejected until the first flushes.
    std::vector<Byte> chunk(16384, 0x5D);
    CHECK(stack_a.Send(conn, chunk.data(), 16384));
    CHECK(!stack_a.Send(conn, chunk.data(), 16384));  // quota: pending 16384 + 16384 > 16384

    // Drain: the flush + ACK clock free the quota and the full stream lands.
    UInt32 sent = 16384, guard = 0;
    while (sent < 2 * 16384 && 100000 > ++guard) {
        if (stack_a.Send(conn, chunk.data(), 16384)) {
            sent += 16384;
        } else {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(2 * 16384 == sent);
    for (UInt32 i = 0; i < 400 && b_recv.load(std::memory_order_relaxed) < 2 * 16384; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::fprintf(stderr, "[sndbuf] stack-level quota: sent=%u recv=%llu\n", sent,
                 (unsigned long long)b_recv.load());
    CHECK(2 * 16384 == b_recv.load(std::memory_order_relaxed));
}

int main() {
    xtcp::buf::InitPools();
    TestDirectFsmQuota();
    TestStackLevelQuota();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SNDBUF_CONFIG: FAILED (%d)\n" : "SNDBUF_CONFIG: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_mimt_stack_lifetime.cpp
 * @brief MIMT BUG-3 regression: a mimt::MimtFlow delivered to the app may
 *        OUTLIVE its owning XtcpStack. The stack destructor must close every
 *        flow (pending async ops complete with kClosed, 1:1 pairing) before
 *        the shards are freed, so a late Dispatch()/AsyncWrite() on the
 *        surviving flow is a safe kClosed no-op - NOT a use-after-free on
 *        the freed shards.
 *
 *        Validated under ASan (build-asan-win): the pre-fix code crashed
 *        with a heap-use-after-free on the late Dispatch.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <memory>
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
    std::shared_ptr<xtcp::mimt::MimtFlow> survivor;
    UInt32 late_writes = 0;   // completions after stack destruction
    UInt32 late_reads = 0;
    Byte late_buf[64];
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
        // B is the MIMT side: every accepted flow is handed to the app.
        stack_b.StartMimt([&survivor](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
            survivor = flow;  // the app keeps ONE flow past the stack's life
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9090;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(NULLPTR != survivor);  // the app received the flow
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Park a read + a write on the flow while the stack is alive.
        CHECK(xtcp::mimt::Result::kOk == survivor->AsyncRead(
            late_buf, sizeof(late_buf), [&](xtcp::mimt::Result, UInt32) { ++late_reads; }));
        CHECK(xtcp::mimt::Result::kOk == survivor->AsyncWrite(
            late_buf, 8, [&](xtcp::mimt::Result, UInt32) { ++late_writes; }));
    }
    // The stacks are DESTROYED here; the survivor flow must be inert now.
    CHECK(NULLPTR != survivor);

    survivor->Dispatch();  // pre-fix: heap-use-after-free on the freed shards
    const xtcp::mimt::Result r = survivor->AsyncWrite(late_buf, 8, NULLPTR);
    std::fprintf(stderr, "[mimt-lifetime] late AsyncWrite=%d late_reads=%u late_writes=%u\n",
                 static_cast<int>(r), late_reads, late_writes);
    CHECK(xtcp::mimt::Result::kClosed == r);  // the flow is inert: kClosed, no crash
    CHECK(1 == late_reads);   // the parked read completed exactly once (kClosed)
    CHECK(1 == late_writes);  // the parked write completed exactly once (kClosed)

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_STACK_LIFETIME: FAILED (%d)\n" : "MIMT_STACK_LIFETIME: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

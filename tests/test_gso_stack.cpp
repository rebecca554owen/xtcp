/**
 * @file test_gso_stack.cpp
 * @brief Software GSO wired into the tx boundary: SendData builds one
 *        super-segment per window, XtcpStack::Emit segments it into
 *        MSS-sized packets. The receiver must get the full payload in
 *        order, and every packet on the wire must be <= MSS + headers.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kClientV4 = 0x0A000001;
    constexpr UInt16 kPort     = 4546;
    std::atomic<UInt32> g_max_pkt{0};  // largest packet observed on the wire
}

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        if (p.len > g_max_pkt.load(std::memory_order_relaxed)) {
            g_max_pkt.store(p.len, std::memory_order_relaxed);
        }
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

/** Pumps until both queues drain; polls both stacks' timers. */
static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb, UInt32 rounds = 2000) {
    Byte out[65536];
    for (UInt32 round = 0; round < rounds; ++round) {
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
        Wire(backend_a, backend_b, stack_a, stack_b);

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kClientV4;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = kServerV4;
        remote.port = kPort;

        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // 48 KB in a handful of super-segment sends (larger than the 64 KB
        // send buffer? No - 48 KB fits; the point is each Send call exceeds
        // the 1460-byte MSS and must be segmented at the tx boundary).
        constexpr UInt32 kTotal = 48 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 7 + 3) & 0xFF));
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 8192) ? (kTotal - sent) : 8192;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // Drain with real time for the delayed-ACK clock.
        for (UInt32 i = 0; i < 200 && received.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b, 500);
        }

        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        const UInt32 max_pkt = g_max_pkt.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[gso] sent=%u recv=%zu max_pkt=%u (MSS cap 1460+40=1500)\n",
                     sent, received.size(), max_pkt);
        // Every data packet must respect the negotiated MSS (1500 total).
        CHECK(1500 >= max_pkt);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "GSO_STACK: FAILED (%d)\n" : "GSO_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

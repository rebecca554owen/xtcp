/**
 * @file test_ephemeral.cpp
 * @brief Connect with local.port == 0 must bind an ephemeral port (IANA
 *        dynamic range) like an unbound Linux socket - the SYN must carry
 *        a real source port and the flow must establish.
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

        std::atomic<bool> accepted{false};
        stack_b.SetAcceptHandler([&accepted](UInt64, const xtcp::core::Endpoint& remote,
                                             const xtcp::core::Endpoint&) {
            accepted.store(0 != remote.port, std::memory_order_relaxed);
            return true;
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 0;  // unbound: ask for an ephemeral port
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // The peer saw a real (non-zero) source port on the accepted flow.
        CHECK(accepted.load(std::memory_order_relaxed));

        // The local port is observable through the connection stats.
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[ephemeral] local_port=%u remote_port=%u\n", lp, rp);
        CHECK(0 != lp);
        CHECK(49152 <= lp);

        // A second unbound connect gets a different ephemeral port.
        const UInt64 conn2 = stack_a.Connect(local, remote);
        CHECK(0 != conn2);
        UInt16 lp2 = 0;
        stack_a.ConnStats(conn2, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp2, rp);
        CHECK(0 != lp2 && lp2 != lp);
        std::fprintf(stderr, "[ephemeral] second port=%u\n", lp2);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "EPHEMERAL: FAILED (%d)\n" : "EPHEMERAL: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

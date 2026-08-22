/**
 * @file test_mimt_multi_flow.cpp
 * @brief MIMT multi-flow concurrency: 4 audit flows run simultaneously through
 *        the same stack. Each flow carries a distinct byte pattern; the audit
 *        layer must deliver each stream to its own flow (no crosstalk), and
 *        the per-flow write sink must echo each stream back to the correct
 *        peer connection. Dispatch correctness: every flow advances on the
 *        dispatch loop and every AsyncRead/AsyncWrite completion fires
 *        exactly once (1:1 pairing).
 *
 * Isolation proof (three independent layers):
 *   1. Per-flow data is self-consistent: every byte read by a flow equals the
 *      flow's own first byte (no mixing of two streams inside one flow).
 *   2. The set of first-bytes across the 4 flows is exactly {A,B,C,D}: each
 *      flow received a distinct stream (no duplication, no loss).
 *   3. Each client connection receives back exactly its own pattern: the echo
 *      returned to conn f is all 'A'+f, proving the write sink is bound to the
 *      correct flow -> connection (no cross-connection echo).
 *
 * Core assertion: multi-flow MIMT isolation is complete.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <functional>
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

/**
 * @brief Per-flow audit statistics (isolated: each flow has its own state, so
 *        cross-flow contamination would show up as a failed self-consistency
 *        check or a first-byte collision, not as an aggregate off-by-N).
 */
struct FlowStat {
    std::atomic<UInt32> bytes_read{0};    // bytes the auditor read on this flow
    std::atomic<UInt32> bytes_written{0}; // bytes echoed back by this flow
    std::atomic<UInt32> read_cbs{0};      // AsyncRead completions (must be 1:1 with writes)
    std::atomic<UInt32> write_cbs{0};     // AsyncWrite completions
    std::atomic<bool>   first_set{false};
    std::atomic<Byte>   first_byte{0};
    std::atomic<bool>   uniform{true};    // every byte read == first byte (isolation)
};

constexpr UInt32 kPayload = 2048;
constexpr UInt32 kFlows = 4;

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

        // ---- B side: MIMT audit mode, 4 independent flows --------------
        std::atomic<UInt32> flows_accepted{0};
        std::vector<std::shared_ptr<FlowStat>> stats(kFlows);

        std::function<void(std::shared_ptr<xtcp::mimt::MimtFlow>,
                           std::shared_ptr<FlowStat>,
                           std::shared_ptr<std::vector<Byte>>)> read_loop;
        read_loop = [&read_loop](std::shared_ptr<xtcp::mimt::MimtFlow> flow,
                                 std::shared_ptr<FlowStat> st,
                                 std::shared_ptr<std::vector<Byte>> buf) {
            // Auditor loop: read the next chunk, verify it is uniform (only
            // bytes of this flow's own pattern), echo it back, keep reading.
            flow->AsyncRead(buf->data(), static_cast<UInt32>(buf->size()),
                            [flow, st, buf, &read_loop](xtcp::mimt::Result, UInt32 n) {
                                if (0 == n) {
                                    return;  // EOF: flow done
                                }
                                st->read_cbs.fetch_add(1, std::memory_order_relaxed);
                                const Byte b0 = buf->data()[0];
                                if (!st->first_set.load(std::memory_order_relaxed)) {
                                    st->first_set.store(true, std::memory_order_relaxed);
                                    st->first_byte.store(b0, std::memory_order_relaxed);
                                }
                                const Byte expect = st->first_byte.load(std::memory_order_relaxed);
                                for (UInt32 i = 0; i < n; ++i) {
                                    if (buf->data()[i] != expect) {
                                        st->uniform.store(false, std::memory_order_relaxed);
                                    }
                                }
                                st->bytes_read.fetch_add(n, std::memory_order_relaxed);
                                flow->AsyncWrite(buf->data(), n,
                                                 [st](xtcp::mimt::Result, UInt32 written) {
                                                     st->write_cbs.fetch_add(1, std::memory_order_relaxed);
                                                     st->bytes_written.fetch_add(written, std::memory_order_relaxed);
                                                 });
                                if (st->bytes_read.load(std::memory_order_relaxed) < kPayload) {
                                    read_loop(flow, st, buf);
                                }
                            });
        };
        stack_b.StartMimt([&](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
            const UInt32 idx = flows_accepted.fetch_add(1, std::memory_order_relaxed);
            if (idx < kFlows) {
                auto st = std::make_shared<FlowStat>();
                stats[idx] = st;
                read_loop(flow, st, std::make_shared<std::vector<Byte>>(2048));
            }
        });

        // ---- A side: 4 clients, each sending a distinct pattern ---------
        std::vector<UInt64> conns(kFlows, 0);
        std::vector<std::atomic<UInt32>> echo_got(kFlows);
        std::vector<std::atomic<bool>> echo_ok(kFlows);
        for (UInt32 f = 0; f < kFlows; ++f) {
            echo_got[f].store(0);
            echo_ok[f].store(true);
        }
        // Every echo byte arriving at conn f must be 'A'+f (the pattern that
        // conn f sent). Any cross-connection echo trips this check.
        stack_a.SetRecvHandler([&](UInt64 conn_id, const Byte* data, UInt32 len) {
            UInt32 f = kFlows;
            for (UInt32 i = 0; i < kFlows; ++i) {
                if (conns[i] == conn_id) {
                    f = i;
                    break;
                }
            }
            if (kFlows == f) {
                return;
            }
            const Byte expect = static_cast<Byte>('A' + f);
            for (UInt32 i = 0; i < len; ++i) {
                if (data[i] != expect) {
                    echo_ok[f].store(false, std::memory_order_relaxed);
                }
            }
            echo_got[f].fetch_add(len, std::memory_order_relaxed);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9230;
        CHECK(stack_b.Listen(remote));

        std::vector<Byte> payload(kPayload);
        for (UInt32 f = 0; f < kFlows; ++f) {
            local.port = static_cast<UInt16>(40360 + f);
            conns[f] = stack_a.Connect(local, remote);
            CHECK(0 != conns[f]);
            std::memset(payload.data(), 'A' + f, kPayload);
            CHECK(stack_a.Send(conns[f], payload.data(), kPayload));
        }

        // Drive the audit dispatch loop until every flow is complete.
        UInt32 dispatched = 0;
        bool done = false;
        for (UInt32 r = 0; r < 1000 && !done; ++r) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            dispatched += stack_b.DispatchMimt();
            stack_a.DispatchMimt();
            done = true;
            for (UInt32 f = 0; f < kFlows; ++f) {
                if (!stats[f]) {
                    done = false;  // flow not yet accepted
                    continue;
                }
                if (kPayload != stats[f]->bytes_read.load(std::memory_order_relaxed)) {
                    done = false;
                }
                if (kPayload != echo_got[f].load(std::memory_order_relaxed)) {
                    done = false;
                }
            }
        }

        // ---- Verification -------------------------------------------------
        std::fprintf(stderr, "[mimt-multi-flow] flows=%u dispatched=%u\n",
                     flows_accepted.load(), dispatched);
        CHECK(kFlows == flows_accepted.load());
        // Dispatch advanced the audit layer (at least one completion fired).
        CHECK(0 < dispatched);

        bool seen[26] = { false };
        for (UInt32 f = 0; f < kFlows; ++f) {
            if (!stats[f]) {
                continue;  // accepted-flow count already checked below
            }
            const UInt32 rd = stats[f]->bytes_read.load(std::memory_order_relaxed);
            const UInt32 wr = stats[f]->bytes_written.load(std::memory_order_relaxed);
            const UInt32 rc = stats[f]->read_cbs.load(std::memory_order_relaxed);
            const UInt32 wc = stats[f]->write_cbs.load(std::memory_order_relaxed);
            std::fprintf(stderr,
                         "  flow[%u] read=%u written=%u read_cbs=%u write_cbs=%u "
                         "first=0x%02X uniform=%d echo=%u echo_ok=%d\n",
                         f, rd, wr, rc, wc,
                         (UInt32)stats[f]->first_byte.load(std::memory_order_relaxed),
                         stats[f]->uniform.load(std::memory_order_relaxed) ? 1 : 0,
                         echo_got[f].load(std::memory_order_relaxed),
                         echo_ok[f].load(std::memory_order_relaxed) ? 1 : 0);

            // 1. Data complete: the auditor read exactly this flow's payload.
            CHECK(kPayload == rd);
            // 2. Self-consistency: every byte read == this flow's first byte.
            CHECK(stats[f]->uniform.load(std::memory_order_relaxed));
            CHECK(stats[f]->first_set.load(std::memory_order_relaxed));
            // 3. Distinct stream: first bytes are exactly one each of A/B/C/D.
            const int first = stats[f]->first_byte.load(std::memory_order_relaxed) - 'A';
            CHECK(0 <= first && first < 26);
            if (0 <= first && first < 26) {
                CHECK(!seen[first]);
                seen[first] = true;
            }
            // 4. Echo complete and callback-correct (1:1 read/write pairing).
            CHECK(kPayload == wr);
            CHECK(0 < rc && rc == wc);
            // 5. Cross-connection isolation: conn f got back only its own pattern.
            CHECK(kPayload == echo_got[f].load(std::memory_order_relaxed));
            CHECK(echo_ok[f].load(std::memory_order_relaxed));
        }
        // All 4 distinct first-bytes present (A/B/C/D).
        for (UInt32 f = 0; f < kFlows; ++f) {
            CHECK(seen[f]);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_MULTI_FLOW: FAILED (%d)\n"
                                    : "MIMT_MULTI_FLOW: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

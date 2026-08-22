/**
 * @file test_scale_shard_balance.cpp
 * @brief Connection distribution across shards (scalability): thousands of
 *        connections to the same listener (varying source ports) must be
 *        spread over the stack's shards, not all squeezed onto one shard.
 *
 *        The stack routes each new connection to a shard via
 *        ShardOf(flow key) (src/core/stack.cpp:240-249) and encodes the shard
 *        index in the TOP BYTE of the returned conn_id (include/xtcp/core/
 *        stack.h: "conn_id encodes the shard"; src/core/stack.cpp:331-332,
 *        390, 742, 843). The shard of any connection is therefore derivable
 *        from the public Connect() handle alone:
 *
 *            shard_index = static_cast<UInt32>(conn_id >> 56)
 *
 *        Stats API used (no per-shard accessor is public):
 *          - XtcpStack::kShardCount  (public constexpr; shard count = 8)
 *          - XtcpStack::TxCount()    (aggregate tx across all shards)
 *          - XtcpStack::ConnectionCount() (aggregate live connections)
 *          - XtcpStack::Connect()    (returns the shard-encoded conn_id)
 *          - XtcpStack::ConnectionState() / ConnStats() (per-conn diag)
 *
 *        This test asserts the per-shard histogram derived from conn_id and
 *        additionally proves the data plane is alive on multiple shards by
 *        sending on one connection per used shard.
 */

#include <xtcp/core/stack.h>
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
    for (UInt32 round = 0; round < 1000; ++round) {
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
        constexpr UInt32 kConns = 3000;
        const UInt32 kShards = xtcp::XtcpStack::kShardCount;
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(5000);
        stack_b.SetTwoMsl(5000);
        UInt32 closewait_fired = 0;
        stack_b.SetStateHandler([&stack_b, &closewait_fired](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                ++closewait_fired;
                stack_b.Close(id);
            }
        });
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
        local.addr[0] = 0x0A000001;
        local.port = 40181;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9106;
        CHECK(stack_b.Listen(remote));

        // Establish kConns connections (source ports cycle, so the flow-key
        // hash sees a spread of ports - same scenario as test_scale.cpp).
        std::vector<UInt64> conns;
        conns.reserve(kConns);
        const UInt32 batch = 200;
        for (UInt32 base = 0; base < kConns; base += batch) {
            const UInt32 n = (kConns - base < batch) ? (kConns - base) : batch;
            for (UInt32 i = 0; i < n; ++i) {
                xtcp::core::Endpoint l = local;
                l.port = static_cast<UInt16>(40181 + ((base + i) % 30000));
                const UInt64 c = stack_a.Connect(l, remote);
                CHECK(0 != c);
                conns.push_back(c);
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[balance] established=%zu A=%u B=%u\n",
                     conns.size(), (UInt32)stack_a.ConnectionCount(),
                     (UInt32)stack_b.ConnectionCount());
        CHECK(kConns == conns.size());
        CHECK(kConns <= stack_a.ConnectionCount());
        CHECK(0 < stack_a.TxCount());  // handshake traffic was emitted

        // --- Per-shard histogram from the public conn_id encoding ---
        std::vector<UInt32> shard_counts(kShards, 0);
        std::vector<UInt64> first_on_shard(kShards, 0);
        for (UInt64 c : conns) {
            const UInt32 s = static_cast<UInt32>(c >> 56);  // shard index in top byte
            CHECK(s < kShards);
            ++shard_counts[s];
            if (0 == first_on_shard[s]) {
                first_on_shard[s] = c;
            }
        }
        UInt32 distinct = 0, sum = 0, max_load = 0, min_load = kConns;
        for (UInt32 s = 0; s < kShards; ++s) {
            if (0 < shard_counts[s]) ++distinct;
            sum += shard_counts[s];
            if (max_load < shard_counts[s]) max_load = shard_counts[s];
            if (shard_counts[s] < min_load) min_load = shard_counts[s];
            std::fprintf(stderr, "[balance] shard %u: %u conns\n", s, shard_counts[s]);
        }
        const UInt32 expected = kConns / kShards;
        std::fprintf(stderr, "[balance] distinct=%u max=%u min=%u expected=%u\n",
                     distinct, max_load, min_load, expected);
        CHECK(kConns == sum);

        // Core requirement: connections are NOT all squeezed onto one shard.
        CHECK(2 <= distinct);
        // Reasonable spread. Under a uniform hash these bounds sit ~20 sigma
        // away from any realistic outcome; a collapse onto few shards fails.
        CHECK(max_load <= 2 * expected);
        CHECK(expected / 10 <= min_load);

        // Data-plane proof: one connection per used shard moves data.
        UInt64 recv = 0;
        stack_b.SetRecvHandler([&recv](UInt64, const Byte*, UInt32 len) { recv += len; });
        std::vector<Byte> payload(128, 0x5A);
        for (UInt32 s = 0; s < kShards; ++s) {
            if (0 == shard_counts[s]) continue;
            UInt32 guard = 0;
            while (!stack_a.Send(first_on_shard[s], payload.data(), 128) && 500 > ++guard) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        for (UInt32 i = 0; i < 200 && recv < 128 * distinct; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[balance] multi-shard data recv=%llu expect=%u\n",
                     (unsigned long long)recv, 128 * distinct);
        CHECK(128 * distinct == recv);

        // Idle sweep cost at scale (log only; the per-shard sweep lists keep
        // PollAckTimers cheap regardless of skew - indirect perf evidence).
        const UInt32 kRounds = 20;
        const auto t0 = std::chrono::steady_clock::now();
        for (UInt32 r = 0; r < kRounds; ++r) {
            stack_a.PollAckTimers();
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double us_per_poll =
            std::chrono::duration<double, std::micro>(t1 - t0).count() / kRounds;
        std::fprintf(stderr, "[balance] idle poll %.1f us per sweep (%u conns)\n",
                     us_per_poll, (UInt32)stack_a.ConnectionCount());

        for (UInt64 c : conns) {
            stack_a.Close(c);
        }
        for (UInt32 i = 0; i < 800; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            if (0 == stack_a.ConnectionCount() && 0 == stack_b.ConnectionCount()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::fprintf(stderr, "[balance] after close A=%u B=%u closewait_fired=%u\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount(),
                     closewait_fired);
        CHECK(0 == stack_a.ConnectionCount());
        CHECK(0 == stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SCALE_SHARD_BALANCE: FAILED (%d)\n"
                                    : "SCALE_SHARD_BALANCE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

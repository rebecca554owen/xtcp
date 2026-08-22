/**
 * @file test_qdisc_batch.cpp
 * @brief F2/F3 coverage for the H4 batch tx work:
 *          F2  - FQ batch + deficit multi-flow drain (qdisc-ops level,
 *                deterministic): one drain emits >1 packet across flows,
 *                a flow with insufficient deficit is skipped and reports
 *                next_pacing == now so the stack re-polls immediately (no
 *                loss), the pacing deadline is exact (now + len*8/rate),
 *                and per-flow order survives across the batch boundary.
 *          F3a - MSS=256 peer + 32752-byte transfer: full bytes in order,
 *                CRC match, every wire packet <= 20(IP)+20(TCP)+256 = 296.
 *          F3b - kTxBatchMax=64 boundary: 128 pre-queued qdisc packets plus
 *                one live send drain as TxBatch(64)+TxBatch(64)+TxBatch(1)
 *                (129 packets in 3 batch calls) with order/content intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/options/options.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
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

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;
    constexpr UInt32 kClientV4 = 0x0A000001;

    /** Standard wired dual-stack pump (matches test_qdisc_pacing). */
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

    /** CRC-32 (IEEE) over a byte range. */
    static UInt32 Crc32(const Byte* data, UInt32 len) noexcept {
        UInt32 crc = 0xFFFFFFFFu;
        for (UInt32 i = 0; i < len; ++i) {
            crc ^= data[i];
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
            }
        }
        return ~crc;
    }

    /** IPv4 packet: offset of the TCP payload (IP header + TCP header, both
     *  with any negotiated options). */
    static UInt32 TcpPayloadOffset(const Byte* p) noexcept {
        const UInt32 ip_off = static_cast<UInt32>(p[0] & 0x0F) * 4;
        const UInt32 tcp_off = static_cast<UInt32>(p[ip_off + 12] >> 4) * 4;
        return ip_off + tcp_off;
    }

    /** Owned pool buffer filled with `marker`; data[0]=0x45 (IPv4) so the
     *  stack's eth_type probe (DrainTxQdisc) never misreads it. */
    static xtcp::buf::BufRef MakeFakePkt(Byte marker, UInt32 len) noexcept {
        xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(len);
        if (p.IsEmpty()) {
            return p;
        }
        Byte* b = p.Data();
        for (UInt32 i = 0; i < len; ++i) {
            b[i] = marker;
        }
        b[0] = 0x45;
        p.SetLen(len);
        return p;
    }
}

// ---------------------------------------------------------------------------
// F2: batch + deficit multi-flow (deterministic, qdisc-ops level)
// ---------------------------------------------------------------------------
struct DrainOutcome {
    std::vector<UInt32> lens;
    std::vector<Byte>   markers;
    xtcp::core::TimePoint     final_next = 0;
    UInt32              immediate_repoll = 0;  // empty dequeue with next==now while backlog
    UInt32              packets = 0;
};

static DrainOutcome DrainAll(xtcp::qdisc::XtcpQdisc* q, xtcp::core::TimePoint now) {
    DrainOutcome o;
    for (UInt32 guard = 0; guard < 2048; ++guard) {
        xtcp::core::TimePoint n = 0;
        xtcp::buf::BufRef p = q->ops->dequeue(q, now, &n);
        if (p.IsEmpty()) {
            if (0 != n && n <= now && q->ops->has_backlog(q)) {
                // Deficit skip: the flow lacks credit this round, so it asks
                // for an immediate re-poll (next_pacing == now) rather than
                // stranding the packet. Keep draining - that is the re-poll.
                ++o.immediate_repoll;
                continue;
            }
            o.final_next = n;
            return o;
        }
        o.lens.push_back(p.Len());
        o.markers.push_back(p.Data()[1]);
        ++o.packets;
    }
    return o;
}

static void TestBatchDeficitMultiFlow() {
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = true;
    params.max_flow_queue = 1000;
    params.max_global_queue = 100000;
    xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != fq);

    const UInt64 kRate = 1000000000ull;                       // 1 Gbps flow pacing
    constexpr xtcp::core::TimePoint T0 = 10000000;                  // arbitrary epoch (us)
    constexpr UInt64 kGate = (1500ull * 8000000ull) / 1000000000ull;  // 1500 B -> 12 us

    // Two flows share the qdisc; A enqueues first so DRR visits A before B.
    CHECK(0 == fq->ops->enqueue(fq, 1001, MakeFakePkt(0xA0, 1500)));
    CHECK(0 == fq->ops->enqueue(fq, 1001, MakeFakePkt(0xA1, 1500)));
    CHECK(0 == fq->ops->enqueue(fq, 1002, MakeFakePkt(0xB0, 1500)));
    CHECK(0 == fq->ops->enqueue(fq, 1002, MakeFakePkt(0xB1, 1500)));
    CHECK(0 == fq->ops->set_pacing_rate(fq, 1001, kRate));
    CHECK(0 == fq->ops->set_pacing_rate(fq, 1002, kRate));

    // Drain 1 at T0: both flows are eligible and each owns one quantum-sized
    // segment, so ONE drain round emits TWO packets (cross-flow batch > 1).
    DrainOutcome d1 = DrainAll(fq, T0);
    CHECK(2 == d1.packets);
    CHECK(2 == d1.lens.size());
    CHECK(1500 == d1.lens[0] && 1500 == d1.lens[1]);
    CHECK(0xA0 == d1.markers[0] && 0xB0 == d1.markers[1]);  // per-flow order kept
    CHECK(T0 + kGate == d1.final_next);                     // pacing deadline exact

    // The pacing gate must hold packets back until the deadline elapses.
    DrainOutcome g = DrainAll(fq, T0 + kGate - 1);
    CHECK(0 == g.packets);
    CHECK(T0 + kGate == g.final_next);

    // After the deadline: deficit is exhausted (0) so both flows are skipped
    // first (next == now -> immediate re-poll), then both remaining packets
    // go out. Nothing is lost, order is preserved across the batch boundary.
    DrainOutcome d2 = DrainAll(fq, T0 + kGate);
    CHECK(2 == d2.packets);
    CHECK(0xA1 == d2.markers[0] && 0xB1 == d2.markers[1]);
    CHECK(1 <= d2.immediate_repoll);   // deficit skip -> next_pacing == now
    CHECK(!fq->ops->has_backlog(fq));  // all four packets drained: no loss

    std::fprintf(stderr,
                 "[f2] d1=%u[%02x%02x] gate=%llu d2=%u[%02x%02x] skip=%u backlog=%d\n",
                 d1.packets, d1.markers.size() > 0 ? d1.markers[0] : 0,
                 d1.markers.size() > 1 ? d1.markers[1] : 0,
                 (unsigned long long)(T0 + kGate), d2.packets,
                 d2.markers.size() > 0 ? d2.markers[0] : 0,
                 d2.markers.size() > 1 ? d2.markers[1] : 0,
                 d2.immediate_repoll, fq->ops->has_backlog(fq) ? 1 : 0);
    xtcp::qdisc::DestroyQdisc(fq);
}

// ---------------------------------------------------------------------------
// F3: kTxBatchMax=64 boundary
// ---------------------------------------------------------------------------

// A backend that records every TxBatch call's size (ManualBackend is final,
// so this wraps one instead of deriving from it).
class CountingBackend final : public xtcp::ndi::Backend {
public:
    xtcp::ndi::ManualBackend inner;

    void ResetCounters() noexcept {
        call_idx_ = 0;
        batch_total_ = 0;
        for (UInt32 i = 0; i < 8; ++i) {
            sizes_[i] = 0;
        }
    }
    UInt32 BatchCalls() const noexcept { return call_idx_; }
    UInt32 BatchTotal() const noexcept { return batch_total_; }
    UInt32 BatchSize(UInt32 i) const noexcept { return (i < 8) ? sizes_[i] : 0; }

    bool Tx(xtcp::ndi::Packet&& p) noexcept override { return inner.Tx(std::move(p)); }
    UInt32 TxBatch(xtcp::ndi::Packet* p, UInt32 count) noexcept override {
        const UInt32 i = call_idx_;
        if (i < 8) {
            sizes_[i] = count;
        }
        ++call_idx_;
        batch_total_ += count;
        return inner.TxBatch(p, count);
    }
    void SetRxHandler(xtcp::ndi::RxHandler h) noexcept override { inner.SetRxHandler(std::move(h)); }
    xtcp::ndi::BackendCaps Caps() const noexcept override { return inner.Caps(); }

private:
    UInt32 call_idx_ = 0;
    UInt32 batch_total_ = 0;
    UInt32 sizes_[8] = {0, 0, 0, 0, 0, 0, 0, 0};
};

static void TestMss256Transfer() {
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

    std::string received;
    UInt64 b_conn = 0;
    stack_b.SetRecvHandler([&received, &b_conn](UInt64 cid, const Byte* d, UInt32 n) {
        if (0 == b_conn) {
            b_conn = cid;
        }
        received.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = kClientV4;
    local.port = 40208;
    remote.family = 4;
    remote.addr[0] = kServerV4;
    remote.port = 4548;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, stack_a, stack_b);

    // Force the peer MSS to 256 on the sender after the handshake (the
    // SYN+ACK's own MSS option would otherwise overwrite it to 1460).
    const Int32 mss = 256;
    CHECK(stack_a.SetOption(conn, xtcp::options::kTcpMaxseg, &mss, sizeof(mss)));
    CHECK(256 == stack_a.ConnPeerMss(conn));
    const Int32 quickack = 1;
    if (0 != b_conn) {
        stack_b.SetOption(b_conn, xtcp::options::kTcpQuickack, &quickack, sizeof(quickack));
    }

    constexpr UInt32 kTotal = 32752;
    std::string payload;
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload.push_back(static_cast<char>((i * 31 + 7) & 0xFF));
    }

    UInt32 max_a_pkt = 0;
    Byte out[65536];
    UInt32 sent = 0;
    UInt32 guard = 0;
    while (sent < kTotal && 200000 > ++guard) {
        if (sent < kTotal && stack_a.Send(conn,
                reinterpret_cast<const Byte*>(payload.data() + sent), kTotal - sent)) {
            sent = kTotal;
        }
        bool moved = true;
        for (UInt32 sub = 0; moved && sub < 100; ++sub) {
            moved = false;
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    if (n > max_a_pkt) {
                        max_a_pkt = n;
                    }
                    backend_b.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (moved) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }
    for (UInt32 i = 0; i < 500 && received.size() < kTotal; ++i) {
        bool moved = false;
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n) {
                if (n > max_a_pkt) {
                    max_a_pkt = n;
                }
                backend_b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        while (0 != backend_b.TxPending()) {
            const UInt32 n = backend_b.PollTx(out);
            if (0 < n) {
                backend_a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        if (!moved) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    CHECK(kTotal == received.size());
    CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
    const UInt32 crc_src = Crc32(reinterpret_cast<const Byte*>(payload.data()), kTotal);
    const UInt32 crc_rcv = Crc32(reinterpret_cast<const Byte*>(received.data()),
                                 static_cast<UInt32>(received.size()));
    CHECK(crc_src == crc_rcv);
    CHECK(296 >= max_a_pkt);  // 20(IP) + 20(TCP) + 256(MSS)

    std::fprintf(stderr, "[f3a] sent=%u recv=%zu crc=0x%08x max_a_pkt=%u (cap 296)\n",
                 sent, received.size(), crc_rcv, max_a_pkt);
}

static void TestBatchBoundary64() {
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = false;  // deterministic: one drain takes everything
    params.max_flow_queue = 1000;
    params.max_global_queue = 100000;
    xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != fq);

    CountingBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
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
    stack_a.SetTxQdisc(fq);

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = kClientV4;
    local.port = 40209;
    remote.family = 4;
    remote.addr[0] = kServerV4;
    remote.port = 4549;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a.inner, backend_b, stack_a, stack_b);  // handshake through qdisc

    backend_a.ResetCounters();  // ignore handshake-era TxBatch(1) drains

    // Pre-queue 128 packets across 128 distinct flows (one per flow). FQ's
    // DRR deficit lets each flow yield its single packet in one drain round,
    // so 128 packets come out of ONE DrainTxQdisc call - exactly the >64
    // case that must flush at the kTxBatchMax=64 boundary.
    for (UInt32 i = 0; i < 128; ++i) {
        CHECK(0 == fq->ops->enqueue(fq, conn + 1000 + i,
                                    MakeFakePkt(static_cast<Byte>((i * 31 + 7) & 0xFF), 60)));
    }
    CHECK(fq->ops->has_backlog(fq));

    // One live 1-byte send triggers SendOne -> DrainTxQdisc. The drain sees
    // 129 packets (this segment in the conn flow + 128 pre-queued flows) and
    // must flush at the kTxBatchMax=64 boundary: 64 + 64 + 1 in three
    // TxBatch calls.
    const Byte one = 0x42;
    CHECK(stack_a.Send(conn, &one, 1));

    CHECK(3 == backend_a.BatchCalls());
    CHECK(129 == backend_a.BatchTotal());
    CHECK(64 == backend_a.BatchSize(0));
    CHECK(64 == backend_a.BatchSize(1));
    CHECK(1 == backend_a.BatchSize(2));

    // Order and content across the batches: fakes 0..127 (their flows were
    // active ahead of the conn flow, which DRR detached after the handshake
    // drain) then the live segment last.
    Byte out[100000];
    UInt32 lens[200];
    const UInt32 n = backend_a.inner.PollTxBatch(out, sizeof(out), lens, 200);
    CHECK(129 == n);
    UInt32 off = 0;
    for (UInt32 i = 0; i < 128; ++i) {
        CHECK(60 == lens[i]);
        CHECK(0x45 == out[off]);                                    // IPv4 header kept
        CHECK(static_cast<Byte>((i * 31 + 7) & 0xFF) == out[off + 1]);  // per-flow order
        off += lens[i];
    }
    CHECK(41 <= lens[128]);  // 20(IP)+20(TCP)+1 payload, plus any negotiated options
    CHECK(one == out[off + TcpPayloadOffset(out + off)]);  // live segment payload
    CHECK(!fq->ops->has_backlog(fq));

    std::fprintf(stderr,
                 "[f3b] tx_batch_calls=%u total=%u sizes=[%u,%u,%u] polled=%u backlog=%d\n",
                 backend_a.BatchCalls(), backend_a.BatchTotal(),
                 backend_a.BatchSize(0), backend_a.BatchSize(1), backend_a.BatchSize(2),
                 n, fq->ops->has_backlog(fq) ? 1 : 0);
    xtcp::qdisc::DestroyQdisc(fq);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::qdisc::RegisterFqDefault();
        TestBatchDeficitMultiFlow();  // F2
        TestMss256Transfer();         // F3a
        TestBatchBoundary64();        // F3b
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "QDISC_BATCH: FAILED (%d)\n" : "QDISC_BATCH: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_fastrec_undo.cpp
 * @brief Linux tcp_try_undo_recovery semantics: a fast-recovery entry driven
 *        by duplicate ACKs WITHOUT SACK blocks carries no confirmed-loss
 *        signal, so when the recovery completes cleanly the pre-cut cwnd is
 *        restored. A SACK-driven entry (real gaps) never undoes.
 *
 *        Scenario: A<->B established (both negotiate SACK, but the test
 *        injects RAW duplicate ACKs without SACK blocks from B's tuple).
 *        3 dup-ACKs -> A enters fast recovery (no-SACK entry, cwnd cut) and
 *        retransmits the front. A fresh cumulative ACK from B (real B data
 *        flow) then resolves the recovery -> the exit must restore cwnd to
 *        the pre-entry value.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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

/** Pumps A's tx into B ONLY (B's ACKs stay queued): keeps A's data in
 *  retrans_queue_ while the raw dup-ACKs are injected. */
static void PumpOneWay(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                       xtcp::XtcpStack& sa) {
    Byte out[65536];
    for (UInt32 round = 0; round < 50; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        if (!moved) {
            return;
        }
    }
}

/** Raw ACK (no SACK) from B's tuple, with the given ack number. */
static void InjectDupAck(xtcp::ndi::ManualBackend& backend, UInt32 seq, UInt32 ack) {
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, 9090, 40061, seq, ack, 0x10);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
}

static UInt32 ConnCwnd(xtcp::XtcpStack& s, UInt64 conn) {
    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
    UInt64 rto_deadline = 0;
    UInt32 front_seq = 0, snd_una = 0;
    UInt16 lp = 0, rp = 0;
    s.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                dup, fast, front_seq, snd_una, lp, rp);
    return cwnd;
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
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Some in-flight data so the retransmit has a front segment. The
        // one-way pump keeps A's segment in retrans_queue_ (B's ACK stays
        // queued) while the raw dup-ACKs are injected.
        Byte payload[4096];
        std::memset(payload, 0x5A, sizeof(payload));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        PumpOneWay(backend_a, backend_b, stack_a);

        const UInt32 cwnd_before = ConnCwnd(stack_a, conn);
        std::fprintf(stderr, "[undo] cwnd before = %u\n", cwnd_before);
        CHECK(0 < cwnd_before);

        // Three RAW duplicate ACKs (no SACK blocks) from B's tuple: A enters
        // fast recovery with the no-SACK entry (undo candidate) and
        // retransmits the front. The dup-ACKs carry a stale ack (snd_una -
        // the data start) so the cumulative ACK never advances.
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
        UInt64 rto_deadline = 0;
        UInt32 front_seq = 0, snd_una = 0;
        UInt16 lp = 0, rp = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt32 dup_ack_val = snd_una;
        const UInt32 dup_seq_val = 0x50001000u;  // any in-window seq from B
        for (UInt32 i = 0; i < 3; ++i) {
            InjectDupAck(backend_a, dup_seq_val, dup_ack_val);
        }
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[undo] after injection: retx=%u dup=%u fast=%u cwnd=%u ssth=%u\n",
                     retx, dup, fast, cwnd, ssthresh);
        CHECK(1 <= retx);  // the entry retransmitted the front

        // Let the REAL B data flow resolve the recovery: B's genuine ACK (for
        // the 4KB, queued during PumpOneWay) reaches A, the cumulative ACK
        // advances past the front, the recovery exits cleanly, and the
        // no-SACK undo restores the pre-cut cwnd (which then grows on the
        // ACK clock, so cwnd_after >= cwnd_before).
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const UInt32 cwnd_after = ConnCwnd(stack_a, conn);
        std::fprintf(stderr, "[undo] cwnd after recovery = %u (before %u)\n", cwnd_after, cwnd_before);
        CHECK(cwnd_before <= cwnd_after);  // restored (or grew) - never left halved

        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FASTREC_UNDO: FAILED (%d)\n" : "FASTREC_UNDO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

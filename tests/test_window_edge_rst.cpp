/**
 * @file test_window_edge_rst.cpp
 * @brief RFC 5961 receive-window BOUNDARY RST handling on a real dual-stack
 *        connection.
 *
 * The receive window is the half-open interval [rcv_nxt, rcv_nxt + rcv_wnd):
 *   - RST seq == rcv_nxt            (window START, inclusive)  -> honored
 *   - RST seq inside (rcv_nxt, end)                            -> honored
 *   - RST seq == rcv_nxt + rcv_wnd  (window END, exclusive)    -> CHALLENGED
 *
 * Established RST case (tcp_fsm.cpp:1845-1855):
 *     valid = (seq == rcv_nxt_) ||
 *             (SeqLt(rcv_nxt_, seq) && SeqLt(seq, rcv_nxt_ + rcv_wnd_));
 *     valid  -> Transition(kClosed)
 *     !valid -> SendChallengeAck()      // RFC 5961, connection stays alive
 *
 * rcv_wnd_ is fixed at kDefaultWindow == 65535 (tcp_fsm.cpp:528) and never
 * shrinks in this stack, so after a quiet handshake A's receive window is
 * exactly [B_ISS+1, B_ISS+1+65535), with B_ISS sniffed from the SYN+ACK on
 * the wire.
 *
 * Reference: test_rst_established_valid.cpp (dual-stack RST injection +
 * challenge-ACK counting) and test_seqwrap_rst.cpp (unit-level RFC 1982
 * boundary geometry). This test pins the NON-wrapped dual-stack boundary:
 *
 *   Scenario 1 (window END): RST seq = rcv_nxt + rcv_wnd must be CHALLENGED,
 *     not honored: A stays kEstablished, emits exactly ONE challenge ACK, the
 *     two connections stay healthy, and a full 16 KiB transfer still
 *     completes afterwards. A subsequent VALID RST (seq == rcv_nxt) still
 *     closes A.
 *   Scenario 2 (last in-window slot): RST seq = rcv_nxt + rcv_wnd - 1 must be
 *     HONORED: A closes with NO challenge ACK.
 *   Scenario 3 (window START): RST seq == rcv_nxt must be HONORED: A closes
 *     with NO challenge ACK.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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
        }                                                                 \
    } while (0)

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

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

/** Builds an IPv4 RST from B (src_ip:src_port) toward A (dst_ip:dst_port)
 *  with the given seq and injects it into A's backend. Valid checksums so
 *  the RST is honored under the checksum-validate build too. */
static void InjectRstToA(xtcp::ndi::ManualBackend& backend, UInt32 seq,
                         UInt16 sport, UInt16 dport) {
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, sport, dport, seq, 0, 0x04);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
}

/** Drains a backend's Tx queue and counts TCP packets carrying the ACK flag. */
static UInt32 DrainAckCount(xtcp::ndi::ManualBackend& backend) {
    Byte out[65536];
    UInt32 acks = 0;
    while (0 != backend.TxPending()) {
        const UInt32 n = backend.PollTx(out);
        if (n < 40) {
            continue;
        }
        const UInt32 ip_hlen = static_cast<UInt32>(out[0] & 0x0F) * 4;
        const Byte* tcp = out + ip_hlen;
        if (0 != (tcp[13] & 0x10)) {  // ACK flag
            ++acks;
        }
    }
    return acks;
}

/** Deterministic payload fill for the post-challenge transfer. */
static void FillPayload(Byte* d, UInt32 len, UInt32 seed) {
    UInt32 x = seed;
    for (UInt32 i = 0; i < len; ++i) {
        x = x * 1664525u + 1013904223u;
        d[i] = static_cast<Byte>(x >> 24);
    }
}

/** One dual-stack handshake fixture; the peer (B) ISS is sniffed from the
 *  SYN+ACK on the wire so the receive window can be computed exactly. */
struct Fixture {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a, stack_b;
    UInt64 conn_a = 0, conn_b = 0;
    UInt32 iss_b = 0;
    std::vector<Byte> recv_b;

    Fixture(UInt16 local_port, UInt16 remote_port) : stack_a(&backend_a), stack_b(&backend_b) {
        backend_a.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                iss_b = Load32BE(p.data + 20 + 4);  // SYN+ACK seq == B's ISS
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        stack_b.SetRecvHandler([this](UInt64, const Byte* d, UInt32 len) {
            recv_b.insert(recv_b.end(), d, d + len);
        });
        stack_b.SetStateHandler([this](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = local_port;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = remote_port;
        CHECK(stack_b.Listen(remote));
        conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(0 != iss_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
    }

    /** A's receive frontier: the peer's current send seq (B_ISS + 1). */
    UInt32 RcvNxt() const { return iss_b + 1u; }
    /** The window END (exclusive): rcv_nxt + rcv_wnd with rcv_wnd == 65535. */
    UInt32 WindowEnd() const { return RcvNxt() + 65535u; }

    /** Sends 16 KiB from A and pumps until B has it all (byte-exact). */
    void Transfer16K() {
        const UInt32 kTotal = 16384;
        std::vector<Byte> payload(kTotal);
        FillPayload(payload.data(), kTotal, 0x12345678u);
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 n = kTotal - sent;
            UInt32 tries = 0;
            while (!stack_a.Send(conn_a, payload.data() + sent, n) && 500 > ++tries) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            sent += n;
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == sent);
        for (UInt32 i = 0; i < 3000 && recv_b.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kTotal == recv_b.size());
        CHECK(0 == std::memcmp(recv_b.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[window-edge-rst] 16 KiB survived the boundary challenge\n");
    }
};

int main() {
    xtcp::buf::InitPools();

    {
        // ---- Scenario 1: RST seq == rcv_nxt + rcv_wnd (window END). ----
        // The boundary seq is OUTSIDE the half-open window -> RFC 5961
        // challenge ACK, connection kept alive.
        Fixture f(40184, 9125);
        const UInt32 rcv_nxt = f.RcvNxt();
        const UInt32 wnd_end = f.WindowEnd();

        // Cross-check the sniffed frontier against B's real send state.
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
        UInt64 rto_deadline = 0; UInt32 dup_acks = 0, fast_rec = 0;
        UInt32 front_seq = 0, snd_una = 0; UInt16 lp = 0, rp = 0;
        f.stack_b.ConnStats(f.conn_b, inflight, cwnd, ssthresh, snd_wnd, retx,
                            rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                            lp, rp);
        CHECK(rcv_nxt == snd_una);
        std::fprintf(stderr,
                     "[window-edge-rst] rcv_nxt=%u wnd=65535 wnd_end=%u "
                     "(B snd_una=%u)\n",
                     rcv_nxt, wnd_end, snd_una);

        // The boundary RST: seq exactly at the (exclusive) window end.
        InjectRstToA(f.backend_a, wnd_end, 9125, 40184);
        CHECK(xtcp::core::TcpState::kEstablished == f.stack_a.ConnectionState(f.conn_a));
        CHECK(1 == DrainAckCount(f.backend_a));  // RFC 5961 challenge ACK
        CHECK(2 == f.stack_a.ConnectionCount() + f.stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kEstablished == f.stack_b.ConnectionState(f.conn_b));
        std::fprintf(stderr, "[window-edge-rst] boundary RST challenged, A alive\n");

        // Connection health: a full 16 KiB transfer still completes.
        f.Transfer16K();

        // A subsequent VALID RST (seq == rcv_nxt) still closes A: the boundary
        // challenge did not poison the connection.
        InjectRstToA(f.backend_a, rcv_nxt, 9125, 40184);
        CHECK(xtcp::core::TcpState::kClosed == f.stack_a.ConnectionState(f.conn_a));
        std::fprintf(stderr,
                     "[window-edge-rst] valid RST (seq==rcv_nxt) after boundary "
                     "challenge still closes A\n");
    }

    {
        // ---- Scenario 2: RST seq == rcv_nxt + rcv_wnd - 1 (last in-window
        // slot) must be HONORED: A closes, no challenge ACK. ----
        Fixture f(40185, 9126);
        const UInt32 last_in = f.WindowEnd() - 1u;
        InjectRstToA(f.backend_a, last_in, 9126, 40185);
        CHECK(xtcp::core::TcpState::kClosed == f.stack_a.ConnectionState(f.conn_a));
        CHECK(0 == DrainAckCount(f.backend_a));
        std::fprintf(stderr, "[window-edge-rst] last in-window slot RST closed A\n");
    }

    {
        // ---- Scenario 3: RST seq == rcv_nxt (window START, inclusive) must
        // be HONORED: A closes, no challenge ACK. ----
        Fixture f(40187, 9127);
        const UInt32 start = f.RcvNxt();
        InjectRstToA(f.backend_a, start, 9127, 40187);
        CHECK(xtcp::core::TcpState::kClosed == f.stack_a.ConnectionState(f.conn_a));
        CHECK(0 == DrainAckCount(f.backend_a));
        std::fprintf(stderr, "[window-edge-rst] window-start RST closed A\n");
    }

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WINDOW_EDGE_RST: FAILED (%d)\n" : "WINDOW_EDGE_RST: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

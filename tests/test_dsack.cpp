/**
 * @file test_dsack.cpp
 * @brief RFC 2883 D-SACK: when a retransmission was unnecessary (the
 *        original segment was merely reordered and arrives after the
 *        fast-retransmit), the peer's first SACK block covers data at or
 *        below the cumulative frontier - a duplicate. The sender detects
 *        the duplicate, proves the recovery was spurious, and UNDOES the
 *        congestion-window cut: the pre-cut window is restored instead of
 *        limping through recovery at ssthresh.
 *
 * The scenario is driven deterministically: the burst's 2nd frame is held
 * (network reorder), frames 1 and 3 are delivered, the sender's time-based
 * recovery (RFC 8985 RACK) retransmits frame 2 - and that RETRANSMIT is
 * captured rather than delivered. Only then is the ORIGINAL frame 2
 * delivered (in-order, PAWS-clean), so the later retransmit is a duplicate
 * and the peer D-SACKs it. The test then verifies the sender's cwnd is
 * back at (or beyond) the pre-recovery value - the spurious cut was undone.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

static UInt32 TcpSeqOf(const Byte* p, UInt32 n) {
    const UInt32 ihl = static_cast<UInt32>(p[0] & 0x0F) * 4;
    if (n < ihl + 8) {
        return 0;
    }
    return (static_cast<UInt32>(p[ihl + 4]) << 24) |
           (static_cast<UInt32>(p[ihl + 5]) << 16) |
           (static_cast<UInt32>(p[ihl + 6]) << 8) |
           static_cast<UInt32>(p[ihl + 7]);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // Recovery-path timing test (RTO/dup-ACK window): pin Reno so the
        // rate-based KCC default does not shift the recovery timing.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
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
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });

        Byte out[65536];
        // Frame 2 of the burst is held (network reorder); the sender's
        // recovery retransmit of frame 2 is captured (not delivered).
        int big_idx = 0;
        UInt32 held_seq = 0;
        Byte held[2048];
        UInt32 held_len = 0;
        bool held_stored = false;
        Byte retx[2048];
        UInt32 retx_len = 0;
        bool retx_stored = false;
        auto pump = [&](bool capture_retx) {
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    if (n >= 1400) {
                        const UInt32 seq = TcpSeqOf(out, n);
                        if (capture_retx && 0 != held_seq && seq == held_seq) {
                            std::memcpy(retx, out, n);
                            retx_len = n;
                            retx_stored = true;
                        } else {
                            if (!held_stored && 1 == big_idx) {
                                std::memcpy(held, out, n);
                                held_len = n;
                                held_stored = true;
                                held_seq = seq;
                            } else {
                                backend_b.Inject(out, n, 0x0800);
                            }
                            ++big_idx;
                        }
                    } else {
                        backend_b.Inject(out, n, 0x0800);
                    }
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        const UInt64 conn = stack_a.Connect(client_ep, server_ep);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump(false);
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Baseline: 8KB delivered, queue drained, SACK negotiated. The
        // baseline uses 1024-byte sends - never a big (>=1400) frame - so
        // the burst's three full-MSS frames are the first big frames seen.
        const UInt32 kBase = 8 * 1024;
        std::vector<Byte> payload(kBase + 8 * 1024, 0x33);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kBase; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump(false);
        }
        CHECK(kBase == sent);
        for (UInt32 i = 0; i < 500 && b_recv.load() < kBase; ++i) {
            pump(false);
        }
        CHECK(kBase == b_recv.load());
        for (UInt32 i = 0; i < 500 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        xtcp::XtcpStack::ConnInfo pre;
        CHECK(stack_a.ConnGetInfo(conn, pre));

        // Three full-MSS frames; the 2nd is held (reordered). The sender's
        // recovery (RACK) retransmits it - the retransmit is captured, not
        // delivered, so the ORIGINAL can be delivered first and the
        // retransmit becomes the duplicate the receiver D-SACKs.
        sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < 3 * 1460; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));  // pacing window
            if (stack_a.Send(conn, payload.data() + kBase + sent, 1460)) {
                sent += 1460;
            } else {
                pump(false);
            }
        }
        CHECK(3 * 1460 == sent);
        // Let the RACK reorder window elapse so the time-based loss verdict
        // (the missing frame's age exceeds min-RTT/4, floored at 1ms) is
        // guaranteed to fire when the SACK-gap ACK reaches the sender. The
        // RTO floor is 200ms, so this window cannot be preempted by the
        // retransmission timer.
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        // Deliver frames 1 and 3 (frame 2 held), then keep pumping until the
        // sender's recovery retransmit of frame 2 is captured. The ACKs for
        // frames 1/3 carry the SACK gap; RACK declares frame 2 lost and
        // retransmits it - the retransmit matches the held frame's seq.
        for (UInt32 i = 0; i < 500 && !retx_stored; ++i) {
            pump(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(held_stored);
        CHECK(retx_stored);
        // The held frame carries the ORIGINAL (now stale) TSval - rewrite it
        // to a fresh millisecond so the receiver's PAWS check (RFC 7323 R1)
        // does not drop the in-order arrival (the real-world duplicate is a
        // retransmit carrying a fresh TSval per RFC 7323 s5.3). The TSopt is
        // located by parsing the TCP option list (its offset depends on the
        // negotiated MSS/SACK/WS options, so a hardcoded offset is wrong),
        // and the TCP checksum is recomputed incrementally (RFC 1624): under
        // XTCP_CHECKSUM_VALIDATE an invalid checksum is dropped before the
        // state machine ever sees the segment.
        {
            const UInt32 ihl = static_cast<UInt32>(held[0] & 0x0F) * 4;
            const UInt32 tcp_off = ihl;           // TCP header start
            const UInt32 data_off = ihl + (static_cast<UInt32>(held[tcp_off + 12] >> 4) * 4);
            UInt32 ts_val_off = 0;
            for (UInt32 o = tcp_off + 20; o + 1 < data_off;) {
                const Byte kind = held[o];
                if (0 == kind || 1 == kind) {     // EOL / NOP
                    ++o;
                    continue;
                }
                if (o + 1 >= data_off) {
                    break;
                }
                const Byte len = held[o + 1];
                if (8 == kind && 10 == len) {     // TSopt
                    ts_val_off = o + 2;           // tsval field
                    break;
                }
                if (len < 2) {
                    break;
                }
                o += len;
            }
            if (0 != ts_val_off) {
                const UInt32 csum_off = tcp_off + 16;  // checksum field
                UInt16 old_csum = 0;
                std::memcpy(&old_csum, held + csum_off, 2);
                const UInt32 now_ms = static_cast<UInt32>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count() & 0xFFFFFFFF);
                // RFC 1624 incremental update over the 4 tsval bytes:
                // HC' = ~(~HC + ~m + m') applied per 16-bit word.
                UInt32 sum = (~old_csum & 0xFFFF);
                for (UInt32 w = 0; w < 2; ++w) {
                    const UInt16 old_w = static_cast<UInt16>(
                        (held[ts_val_off + w * 2] << 8) | held[ts_val_off + w * 2 + 1]);
                    held[ts_val_off + w * 2]     = static_cast<Byte>(now_ms >> (24 - w * 16));
                    held[ts_val_off + w * 2 + 1] = static_cast<Byte>(now_ms >> (16 - w * 16));
                    const UInt16 new_w = static_cast<UInt16>(
                        (held[ts_val_off + w * 2] << 8) | held[ts_val_off + w * 2 + 1]);
                    sum += (~old_w & 0xFFFF) + new_w;
                    while (0 != (sum >> 16)) {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                const UInt16 new_csum = static_cast<UInt16>(~sum & 0xFFFF);
                std::memcpy(held + csum_off, &new_csum, 2);
            }
        }
        // Deliver the ORIGINAL frame 2 (fills the gap in order), then the
        // retransmit (a duplicate the peer already has -> D-SACK).
        backend_b.Inject(held, held_len, 0x0800);
        backend_b.Inject(retx, retx_len, 0x0800);
        for (UInt32 i = 0; i < 300; ++i) {
            pump(false);
            if (b_recv.load() >= kBase + 3 * 1460 &&
                0 == backend_a.TxPending() && 0 == backend_b.TxPending()) {
                break;  // data delivered AND the D-SACK ACK reached the sender
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kBase + 3 * 1460 == b_recv.load());
        for (UInt32 i = 0; i < 300 && 0 < stack_a.ConnOutstandingSegments(conn); ++i) {
            pump(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));
        xtcp::XtcpStack::ConnInfo post;
        CHECK(stack_a.ConnGetInfo(conn, post));
        // The D-SACK undid the cut: the cwnd is back at (or beyond) the
        // pre-recovery value, NOT limping at ssthresh.
        CHECK(pre.cwnd <= post.cwnd);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "DSACK: FAILED (%d)\n" : "DSACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

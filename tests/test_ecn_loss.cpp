/**
 * @file test_ecn_loss.cpp
 * @brief RFC 3168 ECN combined with loss and retransmission on the data
 *        path, plus the RFC 3168 rule that a retransmitted SYN must not
 *        carry the ECN offer.
 *
 * Scenario 1 (core): both stacks negotiate ECN (SetDefaultEcn(true) on
 * both sides, applied before the handshake); a 256 KiB transfer runs over
 * a lossy link. PumpLossy drops every 8th packet observed on the A->B
 * wire (mirroring test_wscale_transfer.cpp); SACK/RTO recovery restores
 * the transfer. Retransmitted data segments are byte-identical clones of
 * the originals (RetransmitFront / RetransmitEarliestMissing re-emit
 * seg.data.Clone()), so the negotiated ECT(0) IP marking is preserved on
 * every retransmission and the receiver delivers the full payload intact.
 *
 * Core assertions: data integrity (bytes + CRC) and loss recovery (drops
 * observed, retransmissions observed, and every data segment - original
 * or retransmitted - still carries the negotiated ECT(0) marking in its IP
 * header, never ECE (RFC 3168: data marking is ECT; ECE is ACK-only).
 *
 * Scenario 2 (RFC 3168 s6.1.1): a lost SYN is retransmitted by the RTO
 * timer. The retransmitted SYN must NOT carry the ECE offer (the original
 * may already have been marked by a router). The retransmit path drops the
 * ECE bit (tcp_fsm.cpp:1023-1024; the retransmitted SYN is emitted bare at
 * tcp_fsm.cpp:1037/1040 without the ECE flag), so this check is GREEN.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
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
    // Wire observers. backend_a's RxHandler (resp. tx queue) sees B->A
    // (resp. A->B) traffic; flags live at byte 33 (IPv4 20 + TCP byte 13).
    // ECE = 0x40, SYN = 0x02, SYN+ACK = 0x12, data (PSH) = 0x08.
    UInt32 g_tx_seen = 0;        // packets observed on A->B
    UInt32 g_drop_every = 0;     // drop every Nth A->B packet (0 = none)
    UInt32 g_drop_count = 0;     // packets actually dropped (blackholed)
    bool g_syn_ece = false;      // A's SYN carried the ECE offer
    bool g_synack_ece = false;   // B's SYN+ACK echoed the ECE offer
    UInt32 g_data_total = 0;     // A->B data segments (first-seen seq)
    UInt32 g_data_ect = 0;       // ... with ECT(0) in the IP header
    UInt32 g_data_ece = 0;       // ... wrongly carrying ECE
    UInt32 g_retx_total = 0;     // A->B retransmitted data segments
    UInt32 g_retx_ect = 0;       // ... with ECT(0) in the IP header
    UInt32 g_retx_ece = 0;       // ... wrongly carrying ECE
    bool g_syn_retx_ece = false; // the retransmitted SYN carried ECE (RFC 3168)
}

/**
 * @brief Pumps A's tx into B and B's tx into A, dropping every g_drop_every
 *        packet observed on the A->B path (retransmissions included, exactly
 *        like test_wscale_transfer.cpp). While polling it also observes the
 *        wire: handshake ECE negotiation and, for data segments, whether a
 *        sequence number is first-seen (original) or repeated (retransmit)
 *        and whether ECE is present.
 */
static void PumpLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                      std::set<UInt32>& seen_seqs) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                if (n > 34) {
                    const Byte flags = out[33];
                    if (0 != (flags & 0x02) && 0 != (flags & 0x40)) {
                        g_syn_ece = true;       // A's SYN offered ECN
                    }
                    if (0 != (flags & 0x12) && 0 != (flags & 0x40)) {
                        g_synack_ece = true;    // B's SYN+ACK echoed ECN
                    }
                    if (0 != (flags & 0x08)) {
                        // Data segment: seq at bytes 24-27 (IPv4 20 + TCP 4).
                        // RFC 3168 marks data with ECT(0) in the IP header
                        // (byte 1 low 2 bits = 0b10); ECE is reserved for ACKs.
                        const UInt32 seq = (static_cast<UInt32>(out[24]) << 24) |
                                           (static_cast<UInt32>(out[25]) << 16) |
                                           (static_cast<UInt32>(out[26]) << 8) |
                                           static_cast<UInt32>(out[27]);
                        const bool ect = 0x02 == (out[1] & 0x03);
                        const bool ece = 0 != (flags & 0x40);
                        if (seen_seqs.end() != seen_seqs.find(seq)) {
                            ++g_retx_total;     // repeated seq = retransmit
                            if (ect) {
                                ++g_retx_ect;
                            }
                            if (ece) {
                                ++g_retx_ece;
                            }
                        } else {
                            seen_seqs.insert(seq);
                            ++g_data_total;     // first-seen = original
                            if (ect) {
                                ++g_data_ect;
                            }
                            if (ece) {
                                ++g_data_ece;
                            }
                        }
                    }
                }
                if (0 != g_drop_every && 0 == (g_tx_seen % g_drop_every)) {
                    ++g_drop_count;             // blackhole: never injected
                } else {
                    b.Inject(out, n, 0x0800);
                }
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

/** RFC 3168 ECN + loss + retransmission on the data path (core scenario). */
static void Scenario1LossyTransfer() {
    g_tx_seen = 0;
    g_drop_every = 0;
    g_drop_count = 0;
    g_syn_ece = false;
    g_synack_ece = false;
    g_data_total = 0;
    g_data_ect = 0;
    g_data_ece = 0;
    g_retx_total = 0;
    g_retx_ect = 0;
    g_retx_ece = 0;

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
    UInt64 bytes_recv = 0;
    UInt32 crc_recv = 0;
    stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
        bytes_recv += len;
        for (UInt32 i = 0; i < len; ++i) {
            crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
        }
    });
    std::set<UInt32> seen_seqs;

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40140;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9120;
    // Both sides request ECN before the handshake (stack-wide default
    // applied at connection creation, before the SYN goes out).
    stack_a.SetDefaultEcn(true);
    stack_b.SetDefaultEcn(true);
    // Recovery-path timing (12.5% loss + RTO/retransmit windows): pin Reno
    // so the rate-based KCC default does not shift the recovery timing.
    stack_a.SetDefaultCongestionControl("");
    stack_b.SetDefaultCongestionControl("");
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);

    // Handshake ECN negotiation happened in both directions.
    std::fprintf(stderr, "[ecn-loss] SYN-ECE=%s SYNACK-ECE=%s\n",
                 g_syn_ece ? "yes" : "no", g_synack_ece ? "yes" : "no");
    CHECK(g_syn_ece);
    CHECK(g_synack_ece);

    // 256 KiB transfer with 12.5% wire loss (every 8th A->B packet).
    const UInt32 kTotal = 262144;
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
    }
    UInt64 accepted = 0;
    g_drop_every = 8;
    UInt32 guard = 0;
    while (accepted < kTotal && 400000 > ++guard) {
        UInt32 n = static_cast<UInt32>(kTotal - accepted);
        if (n > 4096) {
            n = 4096;
        }
        // Time-based retry budget: a 500-try guard with a 1ms sleep is 500ms
        // on Linux but ~7.8s on Windows (default 15.6ms sleep granularity) -
        // loss recovery needs 200ms+ RTO cycles, so the tight guard only
        // ever failed on Linux. Measure wall-clock time instead so both
        // platforms get the same 10s budget.
        const auto send_t0 = std::chrono::steady_clock::now();
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + accepted, n) &&
               10000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - send_t0).count() &&
               100000 > ++tries) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
    }
    CHECK(kTotal == accepted);
    // Time-based drain budget (same Linux/Windows semantics as the send
    // guard above: 3000 x 1ms retries is 3s on Linux but ~47s on Windows).
    const auto drain_t0 = std::chrono::steady_clock::now();
    for (UInt32 i = 0; i < 300000 && bytes_recv < kTotal &&
            30000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - drain_t0).count(); ++i) {
        PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::fprintf(stderr, "[ecn-loss] dropped=%u received=%llu\n",
                 g_drop_count, (unsigned long long)bytes_recv);

    // Core assertion 1: loss was actually injected on the wire.
    CHECK(0 < g_drop_count);
    // Core assertion 2: the full payload was delivered (loss recovery).
    CHECK(kTotal == bytes_recv);

    UInt32 crc_expect = 0;
    for (UInt32 i = 0; i < kTotal; ++i) {
        crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
    }
    // Core assertion 3: data integrity.
    CHECK(crc_expect == crc_recv);
    std::fprintf(stderr, "[ecn-loss] crc recv=%u exp=%u\n", crc_recv, crc_expect);

    // Recovery really used retransmission (stack-level retransmit counter).
    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
    UInt64 rto_deadline = 0;
    UInt32 front_seq = 0, snd_una = 0;
    UInt16 lp = 0, rp = 0;
    stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline, dup, fast,
                      front_seq, snd_una, lp, rp);
    std::fprintf(stderr, "[ecn-loss] retx=%u data=%u/%u ect retx=%u/%u ece=%u/%u\n",
                 retx, g_data_ect, g_data_total, g_retx_ect, g_retx_total, g_data_ece, g_retx_ece);
    CHECK(0 < retx);              // retransmission recovery actually happened
    CHECK(0 < g_retx_total);      // retransmitted data segments hit the wire

    // ECN marking consistency (RFC 3168): EVERY data segment - original or
    // retransmitted - carries ECT(0) in the IP header. Retransmissions are
    // byte-identical clones, so ECT is preserved end to end. ECE must never
    // appear on a data segment (congestion reporting is ACK-only).
    CHECK(g_data_total == g_data_ect);
    CHECK(g_retx_total == g_retx_ect);
    CHECK(0 < g_data_ect);
    CHECK(0 == g_data_ece);
    CHECK(0 == g_retx_ece);

    stack_a.Close(conn);
    for (UInt32 i = 0; i < 100; ++i) {
        PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
    }
}

/** RFC 3168 s6.1.1: a retransmitted SYN must not carry the ECE offer. */
static void Scenario2SynRetransmitEce() {
    g_syn_ece = false;
    g_synack_ece = false;
    g_syn_retx_ece = false;
    g_drop_every = 0;  // this scenario must be lossless (only the SYN is blackholed)

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
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40142;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9122;
    stack_a.SetDefaultEcn(true);
    stack_b.SetDefaultEcn(true);
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);

    // Grab A's original SYN from its tx queue, record the ECE offer, then
    // blackhole it (never injected into B) so the RTO timer must retransmit.
    Byte out[65536];
    UInt32 syn_len = 0;
    UInt32 guard = 0;
    while (0 != backend_a.TxPending() && 20000 > ++guard) {
        const UInt32 n = backend_a.PollTx(out);
        if (0 < n && n > 34 && 0 != (out[33] & 0x02)) {
            syn_len = n;
            break;
        }
    }
    CHECK(0 < syn_len);
    g_syn_ece = 0 != (out[33] & 0x40);
    CHECK(g_syn_ece);  // the original SYN offered ECN (SetDefaultEcn(true))

    // Wait for the RTO-driven SYN retransmission (~1s: rto_ default, single
    // initial arm). The retransmission is emitted into backend_a's tx queue.
    Byte retx[65536];
    UInt32 retx_len = 0;
    bool got_retx = false;
    for (UInt32 i = 0; i < 400 && !got_retx; ++i) {
        stack_a.PollAckTimers();
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(retx);
            if (0 < n && n > 34 && 0 != (retx[33] & 0x02)) {
                retx_len = n;
                got_retx = true;
                break;
            }
        }
        if (!got_retx) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    CHECK(got_retx);
    if (got_retx) {
        g_syn_retx_ece = 0 != (retx[33] & 0x40);
        std::fprintf(stderr, "[ecn-loss] retransmitted SYN ECE=%s\n",
                     g_syn_retx_ece ? "yes" : "no");
        // RFC 3168 s6.1.1: the ECN offer (ECE+CWR) persists on the
        // retransmitted SYN - dropping it would make a lost-SYN handshake
        // silently lose the negotiation (the server sees a non-ECN SYN).
        // Linux keeps the offer on SYN retransmissions (tcp_ecn_send).
        CHECK(g_syn_retx_ece);

        // Complete the handshake with the retransmitted SYN.
        std::set<UInt32> seen_seqs;
        backend_b.Inject(retx, retx_len, 0x0800);
        for (UInt32 i = 0; i < 300; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(g_synack_ece);  // B still echoed the ECE offer

        // The connection works end to end after the retransmitted SYN.
        const UInt32 kLen = 8192;
        std::string payload(kLen, 'X');
        UInt32 sent = 0;
        UInt32 sguard = 0;
        while (sent < kLen && 40000 > ++sguard) {
            const UInt32 chunk = kLen - sent;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (UInt32 i = 0; i < 500 && received.size() < payload.size(); ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b, seen_seqs);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(payload == received);  // receive complete after SYN retransmit
    }
    stack_a.Close(conn);
}

int main() {
    xtcp::buf::InitPools();
    {
        Scenario1LossyTransfer();
        Scenario2SynRetransmitEce();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ECN_LOSS: FAILED (%d)\n" : "ECN_LOSS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

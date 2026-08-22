/**
 * @file test_retx_windowshrink.cpp
 * @brief Window shrink + packet loss combined: with the peer's window
 *        collapsed to 1 byte, FlushPendingSend trickles the buffered payload
 *        one byte per window update. When that trickled byte is lost on the
 *        wire, the RTO retransmission and the 1-byte window must not deadlock
 *        each other - recovery has to complete and the connection must stay
 *        healthy (byte-exact delivery, Established on both ends, bounded
 *        retransmissions, and a follow-up transfer still works).
 *
 * Structure (mirrors test_window_shrink.cpp's InjectWindow, test_window_sndwl.cpp's
 * real-snd_una baseline, and test_wscale_transfer.cpp's PumpLossy):
 *   1. Dual-stack handshake; sniff B's ISS from the SYN+ACK.
 *   2. Baseline 128 B transferred loss-free -> a legal snd_una benchmark.
 *   3. Inject a window=1 ACK (ack = the REAL snd_una, seq > the SND.WL2 anchor,
 *      i.e. a genuinely NEW segment that passes the RFC 793 SND.WL guard) ->
 *      snd_wnd_ collapses to 1.
 *   4. Send 4096 B -> buffered; FlushPendingSend emits exactly ONE byte
 *      (涓流 trickle). The first trickled byte is dropped on the wire
 *      (deterministic loss while the window is still 1), then every 16th
 *      A->B packet is dropped.
 *   5. Recovery: RTO retransmits the trickled byte (the window stays 1 until
 *      the peer ACKs), the real ACK restores the window, the rest flushes,
 *      and SACK/RTO recover the burst drops.
 *   6. Verify byte-exact delivery + connection health + bounded retx, then a
 *      follow-up transfer (window restored) and a clean close.
 *
 * Core assertion: loss recovery during a window shrink does not hang - the
 * bounded pump loop only exits when every byte arrives (a hang burns the loop
 * budget and FAILs).
 *
 * Not registered in CMakeLists (user: create only this file).
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
static bool g_synack_patched = false;  // B's SYN+ACK patched to WSOPT=0 (unscaled)

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static const UInt32 kLocalAddr = 0x0A000001;   // A: 10.0.0.1
static const UInt32 kRemoteAddr = 0x0A000002;  // B: 10.0.0.2
static const UInt16 kLocalPort = 40300;
static const UInt16 kRemotePort = 9140;

static UInt32 g_b_iss = 0;          // B's ISS, sniffed from the SYN+ACK
static UInt32 g_tx_seen = 0;        // every A->B packet (drop_every counter)
static UInt32 g_dropped = 0;        // packets black-holed
static bool   g_armed = false;      // start dropping the first data segment
static bool   g_target_done = false;// the window=1 trickle byte has been dropped
static UInt32 g_first_trickle_len = 0;  // wire size of the window=1 trickle byte

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

/** Injects an ACK (seq, ack, window) sourced from B into A's rx backend. */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 seq,
                         UInt32 window) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = static_cast<Byte>(kRemoteAddr >> 24); pkt[13] = static_cast<Byte>(kRemoteAddr >> 16);
    pkt[14] = static_cast<Byte>(kRemoteAddr >> 8);  pkt[15] = static_cast<Byte>(kRemoteAddr);
    pkt[16] = static_cast<Byte>(kLocalAddr >> 24);  pkt[17] = static_cast<Byte>(kLocalAddr >> 16);
    pkt[18] = static_cast<Byte>(kLocalAddr >> 8);   pkt[19] = static_cast<Byte>(kLocalAddr);
    pkt[20] = static_cast<Byte>(kRemotePort >> 8);  pkt[21] = static_cast<Byte>(kRemotePort);
    pkt[22] = static_cast<Byte>(kLocalPort >> 8);   pkt[23] = static_cast<Byte>(kLocalPort);
    pkt[24] = static_cast<Byte>(seq >> 24);         pkt[25] = static_cast<Byte>(seq >> 16);
    pkt[26] = static_cast<Byte>(seq >> 8);          pkt[27] = static_cast<Byte>(seq);
    pkt[28] = static_cast<Byte>(ack >> 24);         pkt[29] = static_cast<Byte>(ack >> 16);
    pkt[30] = static_cast<Byte>(ack >> 8);          pkt[31] = static_cast<Byte>(ack & 0xFF);
    pkt[32] = 0x50;
    pkt[33] = 0x10;  // ACK only
    pkt[34] = static_cast<Byte>(window >> 8); pkt[35] = static_cast<Byte>(window & 0xFF);
    // Valid checksums: a zero-checksum ACK is dropped under the
    // checksum-validate build and the window never changes.
    xtcp::harness::FillIp4Checksum(pkt);
    xtcp::harness::FillTcp4Checksum(pkt, pkt + 20, 20);
    backend.Inject(pkt, sizeof(pkt), 0x0800);
}

/** Loss-free pump for handshake / baseline. */
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
                // Keep the connection UNSCALED (raw window-field injection).
                if (!g_synack_patched) {
                    g_synack_patched = xtcp::harness::PatchSynAckUnscaled(out, n);
                }
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
 * Lossy pump for the trickle phase. Drops (a) the first A->B data segment
 * seen while armed - the single window=1 trickle byte - and (b) every 16th
 * A->B packet afterwards. B->A always passes. This reproduces "a 1-byte
 * window trickling data across a lossy link": the trickled byte vanishes and
 * the retransmission must fight the still-collapsed window to recover.
 */
static void PumpTrickleLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                             xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 4; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                bool drop = false;
                if (g_armed && !g_target_done && 40 < n) {
                    // The very first trickled byte: deterministic window=1 loss.
                    g_target_done = true;
                    g_first_trickle_len = n;
                    drop = true;
                } else if (0 == (g_tx_seen % 16)) {
                    drop = true;
                }
                if (drop) {
                    ++g_dropped;
                } else {
                    b.Inject(out, n, 0x0800);
                }
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                if (!g_synack_patched) {
                    g_synack_patched = xtcp::harness::PatchSynAckUnscaled(out, n);
                }
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

        std::vector<Byte> received;
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (0 == g_b_iss && p.len >= 40 && 0 != (p.data[20 + 13] & 0x02)) {
                g_b_iss = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
            }
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

        UInt64 conn_b = 0;
        bool b_closewait = false;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 len) {
            received.insert(received.end(), d, d + len);
        });
        stack_b.SetStateHandler([&conn_b, &b_closewait](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            } else if (xtcp::core::TcpState::kCloseWait == st && id == conn_b) {
                b_closewait = true;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = kLocalAddr;
        local.port = kLocalPort;
        remote.family = 4;
        remote.addr[0] = kRemoteAddr;
        remote.port = kRemotePort;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(0 != g_b_iss);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        // ---- Baseline: establish a legal snd_una benchmark (test_window_sndwl). ----
        const UInt32 kBaseline = 128;
        std::vector<Byte> baseline(kBaseline);
        for (UInt32 i = 0; i < kBaseline; ++i) {
            baseline[i] = static_cast<Byte>((i * 3 + 1) & 0xFF);
        }
        CHECK(stack_a.Send(conn, baseline.data(), kBaseline));
        for (UInt32 i = 0; i < 300 && received.size() < kBaseline; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kBaseline == received.size());
        CHECK(0 == std::memcmp(received.data(), baseline.data(), kBaseline));

        // Settle: wait until the baseline is fully ACKed (inflight==0). The
        // peer's delayed ACK arrives ~40ms after the last segment, so a
        // window-collapse ACK injected while inflight>0 would be a stale dup
        // ACK - and the peer's later genuine ACK (advancing ack past
        // snd_wl1_) would legally restore the window to 65535, making the
        // trickle assertion below physically impossible. Only inject after
        // the baseline is fully acknowledged.
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        for (UInt32 i = 0; i < 300; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
            if (0 == inflight) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt32 snd_una_base = snd_una;
        CHECK(0 == inflight);
        CHECK(0 < snd_wnd);
        std::fprintf(stderr, "[retx-windowshrink] handshake+baseline snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_base, snd_wnd);

        // ---- Collapse the peer window to 1 (SND.WL: a genuinely new segment). ----
        InjectWindow(backend_a, snd_una_base, g_b_iss + 1000, 1);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[retx-windowshrink] after window=1 ACK: snd_wnd=%u\n", snd_wnd);
        CHECK(1 == snd_wnd);

        // ---- Trickle the payload across the 1-byte window under loss. ----
        const UInt32 kPayload = 4096;
        std::vector<Byte> payload(kPayload);
        for (UInt32 i = 0; i < kPayload; ++i) {
            payload[i] = static_cast<Byte>((i * 7 + i / 11) & 0xFF);
        }
        CHECK(stack_a.Send(conn, payload.data(), kPayload));  // buffered: window=1
        g_armed = true;
        g_target_done = false;
        const UInt32 kExpect = kBaseline + kPayload;
        UInt32 guard = 0;
        while (received.size() < kExpect && 3000 > ++guard) {
            PumpTrickleLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // advance RTO clock
        }
        std::fprintf(stderr,
                     "[retx-windowshrink] trickle len=%u dropped=%u rounds=%u received=%zu\n",
                     g_first_trickle_len, g_dropped, guard, received.size());

        // Core assertion: recovery during window shrink did NOT hang. The
        // bounded loop above only exits on full delivery (or budget exhaust).
        CHECK(kExpect == received.size());
        CHECK(0 == std::memcmp(received.data(), baseline.data(), kBaseline));
        CHECK(0 == std::memcmp(received.data() + kBaseline, payload.data(), kPayload));

        // The window=1 trickle byte really was 1 byte on the wire and was lost.
        CHECK(g_target_done);
        CHECK(41 == g_first_trickle_len);   // IP 20 + TCP 20 + 1 payload byte
        CHECK(1 <= g_dropped);

        // Connection healthy: still Established, all data ACKed (inflight 0),
        // bounded retransmissions (recovery happened, no retx storm / no
        // kMaxDataRetries close). Settle the final delayed ACK first so the
        // inflight gauge drains to 0 (the delivery loop exits on B's recv
        // count, which may precede A processing the last cumulative ACK).
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        for (UInt32 i = 0; i < 100 && 0 != inflight; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        CHECK(0 == inflight);
        CHECK(0 < retx);
        CHECK(retx < 100);
        CHECK(1 == stack_a.ConnectionCount());
        CHECK(1 == stack_b.ConnectionCount());
        std::fprintf(stderr, "[retx-windowshrink] post-recovery retx=%u snd_wnd=%u\n", retx, snd_wnd);

        // ---- Follow-up transfer after the shrink+loss episode: connection lives. ----
        InjectWindow(backend_a, snd_una, g_b_iss + 2000, 65535);  // restore the window
        const UInt32 kFollow = 512;
        std::vector<Byte> follow(kFollow);
        for (UInt32 i = 0; i < kFollow; ++i) {
            follow[i] = static_cast<Byte>((i * 11 + 3) & 0xFF);
        }
        CHECK(stack_a.Send(conn, follow.data(), kFollow));
        for (UInt32 i = 0; i < 300 && received.size() < kExpect + kFollow; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kExpect + kFollow == received.size());
        CHECK(0 == std::memcmp(received.data() + kExpect, follow.data(), kFollow));

        // ---- Clean close: FIN crosses, no hang. ----
        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100 && !b_closewait; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(b_closewait);  // B received A's FIN -> healthy bidirectional close
        std::fprintf(stderr, "[retx-windowshrink] close: B closewait=%d\n", b_closewait ? 1 : 0);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RETX_WINDOWSHRINK: FAILED (%d)\n"
                                    : "RETX_WINDOWSHRINK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

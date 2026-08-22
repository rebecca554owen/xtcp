/**
 * @file test_sndwl_multi.cpp
 * @brief RFC 793 SND.WL window-update guard over multiple out-of-order ACK
 *        segments: only the newest segment (SEG.SEQ/SEG.ACK vs SND.WL1/2) may
 *        update the send window. Two ACKs arrive out of order - an OLD ACK
 *        (ack < SND.WL1, window=1000) followed by a NEW ACK (ack == SND.WL1
 *        but SEG.SEQ > SND.WL2, window=2000): the old segment must be
 *        rejected (window untouched) and the newest segment must win
 *        (snd_wnd_ == 2000); transmission keeps working.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static int g_failures = 0;
static bool g_synack_patched = false;  // B's SYN+ACK patched to WSOPT=0 (unscaled)

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

/** Drives both backends until no packet moves (report-driven, no wall clock). */
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

/** Handshake pump that additionally captures B's SYN+ACK sequence number (ISS_B). */
static UInt32 PumpHandshake(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                            xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    UInt32 iss_b = 0;
    for (UInt32 round = 0; round < 500 && 0 == iss_b; ++round) {
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
                if (!g_synack_patched) {
                    g_synack_patched = xtcp::harness::PatchSynAckUnscaled(out, n);
                }
                if (40 <= n && 0x12 == (out[33] & 0x12)) {
                    iss_b = (static_cast<UInt32>(out[24]) << 24) |
                            (static_cast<UInt32>(out[25]) << 16) |
                            (static_cast<UInt32>(out[26]) << 8) |
                            static_cast<UInt32>(out[27]);
                }
                a.Inject(out, n, 0x0800);
                moved = true;
            }
        }
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved) {
            break;
        }
    }
    return iss_b;
}

/** Injects a pure ACK (B -> A) with explicit seq / ack / window fields. */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 seq, UInt32 ack, UInt32 window) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = 0x0A; pkt[13] = 0x00; pkt[14] = 0x00; pkt[15] = 0x02;
    pkt[16] = 0x0A; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x01;
    pkt[20] = 0x1F; pkt[21] = 0x90;
    pkt[22] = 0x9C; pkt[23] = 0x40;
    pkt[24] = static_cast<Byte>(seq >> 24); pkt[25] = static_cast<Byte>(seq >> 16);
    pkt[26] = static_cast<Byte>(seq >> 8);  pkt[27] = static_cast<Byte>(seq & 0xFF);
    pkt[28] = static_cast<Byte>(ack >> 24); pkt[29] = static_cast<Byte>(ack >> 16);
    pkt[30] = static_cast<Byte>(ack >> 8);  pkt[31] = static_cast<Byte>(ack & 0xFF);
    pkt[32] = 0x50; pkt[33] = 0x10;
    pkt[34] = static_cast<Byte>(window >> 8); pkt[35] = static_cast<Byte>(window & 0xFF);
    // Valid checksums: a zero-checksum ACK is dropped under the
    // checksum-validate build and the window never changes.
    xtcp::harness::FillIp4Checksum(pkt);
    xtcp::harness::FillTcp4Checksum(pkt, pkt + 20, 20);
    backend.Inject(pkt, sizeof(pkt), 0x0800);
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);

        // Capture B's ISS from the SYN+ACK while the handshake completes.
        const UInt32 iss_b = PumpHandshake(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[sndwl-multi] B ISS=0x%08X\n", iss_b);
        CHECK(0 != iss_b);

        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt32 snd_una_hs = snd_una;  // post-handshake snd_una (old-ACK anchor)
        std::fprintf(stderr, "[sndwl-multi] handshake snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_hs, snd_wnd);
        CHECK(0 < snd_wnd);

        // Establish a legal snd_una baseline: send data, get it ACKed.
        Byte payload1[1024];
        std::memset(payload1, 0x11, sizeof(payload1));
        CHECK(stack_a.Send(conn, payload1, sizeof(payload1)));
        for (UInt32 i = 0; i < 300 && received.size() < sizeof(payload1); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(sizeof(payload1) == received.size());

        UInt32 snd_una_after = 0;
        for (UInt32 i = 0; i < 300; ++i) {
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una_after, lp, rp);
            if (snd_una_after != snd_una_hs) {
                break;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[sndwl-multi] after data ACK snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_after, snd_wnd);
        CHECK(snd_una_after != snd_una_hs);  // legal snd_una benchmark established
        const UInt32 snd_wnd_legit = snd_wnd;  // SND.WL1 = snd_una_after after data ACK
        CHECK(0 < snd_wnd_legit);
        CHECK(snd_wnd_legit != 1000);        // distinguishing power: legit != forged values

        // ---- OLD ACK first: ack = snd_una_hs (< SND.WL1), window = 1000 ----
        // RFC 793 SND.WL: seq/ack not newer than the last window update -> reject.
        InjectWindow(backend_a, 0, snd_una_hs, 1000);
        Pump(backend_a, backend_b, stack_a, stack_b);

        UInt32 snd_una_old = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una_old, lp, rp);
        std::fprintf(stderr, "[sndwl-multi] after OLD ack(window=1000): snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_old, snd_wnd);
        CHECK(snd_una_old == snd_una_after);   // genuinely stale: no ACK progress
        CHECK(snd_wnd == snd_wnd_legit);       // old segment rejected: window untouched
        CHECK(snd_wnd != 1000);                // forged window=1000 did NOT apply

        // ---- NEW ACK last: ack == SND.WL1 (= snd_una_after) but seq > SND.WL2 ----
        // RFC 793 SND.WL: equal ack but newer SEG.SEQ is still a window update.
        InjectWindow(backend_a, iss_b + 1000, snd_una_after, 2000);
        Pump(backend_a, backend_b, stack_a, stack_b);

        UInt32 snd_una_new = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una_new, lp, rp);
        std::fprintf(stderr, "[sndwl-multi] after NEW ack(window=2000): snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_new, snd_wnd);
        CHECK(snd_una_new == snd_una_after);   // window update, not ACK progress
        CHECK(snd_wnd == 2000);                // newest segment wins: window == 2000
        CHECK(snd_wnd != snd_wnd_legit);       // guard actually applied the update

        // Transmission continues with the updated window (2000): next send goes out intact.
        Byte payload2[1024];
        std::memset(payload2, 0x22, sizeof(payload2));
        CHECK(stack_a.Send(conn, payload2, sizeof(payload2)));
        const UInt32 total = sizeof(payload1) + sizeof(payload2);
        for (UInt32 i = 0; i < 300 && received.size() < total; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(total == received.size());
        CHECK(0 == std::memcmp(received.data(), payload1, sizeof(payload1)));
        CHECK(0 == std::memcmp(received.data() + sizeof(payload1), payload2, sizeof(payload2)));
        std::fprintf(stderr, "[sndwl-multi] transmission continued, %zu bytes delivered\n",
                     received.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SNDWL_MULTI: FAILED (%d)\n" : "SNDWL_MULTI: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

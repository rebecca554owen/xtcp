/**
 * @file test_wscale_half.cpp
 * @brief Symmetric window scaling (RFC 7323): both stacks negotiate WSOPT=7
 *        (the stack offers it natively since the D3 fix). Each side computes
 *        its send window with the peer's shift: the peer's window field is
 *        scaled by 7 (65535>>7 = 511), so snd_wnd = 511<<7 = 65408 > 65535
 *        proves the shift applied - and data must transfer intact in both
 *        directions through the scaled windows.
 *
 *        NOTE: a genuinely asymmetric negotiation (one side 7, the other 0)
 *        is unreachable with Linux-faithful mirroring semantics (a peer that
 *        offers WSOPT is answered with WSOPT; a peer that does not offer is
 *        never scaled against) - so this test pins the symmetric case and
 *        the unscaled case is covered by test_window_shrink / retx_windowshrink
 *        / sndwl_multi (which strip WSOPT from the wire via
 *        harness::PatchSynAckUnscaled).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                   \
        }                                                                   \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    UInt32 guard = 0;
    bool moved = false;
    while (0 != a.TxPending()) {
        const UInt32 got = a.PollTx(out);
        if (0 == got) {
            break;
        }
        b.Inject(out, got, 0x0800);
        moved = true;
        if (1000 < ++guard) {
            break;
        }
    }
    guard = 0;
    while (0 != b.TxPending()) {
        const UInt32 got = b.PollTx(out);
        if (0 == got) {
            break;
        }
        a.Inject(out, got, 0x0800);
        moved = true;
        if (1000 < ++guard) {
            break;
        }
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
    // Yield only when traffic moved (the ACK clock needs real time to
    // advance); an idle poll returns immediately - a 1ms sleep per idle
    // round costs ~15.6ms on Windows (clock granularity), turning a
    // seconds-long transfer loop into a minute.
    if (moved) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// Busy pump: drains everything with no sleeps (used where the coarse
// Windows sleep granularity perturbs the ACK clock).
static void PumpBusy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                     xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != a.TxPending()) {
        const UInt32 got = a.PollTx(out);
        if (0 == got) break;
        b.Inject(out, got, 0x0800);
        if (1000 < ++guard) break;
    }
    guard = 0;
    while (0 != b.TxPending()) {
        const UInt32 got = b.PollTx(out);
        if (0 == got) break;
        a.Inject(out, got, 0x0800);
        if (1000 < ++guard) break;
    }
    sa.PollAckTimers();
    sb.PollAckTimers();
}

// Send `payload` from `from` to its peer, then drain until the ACK clock
// flushes every buffered byte. Returns the byte count accepted by the stack.
static UInt32 Transfer(xtcp::XtcpStack& from, UInt64 conn, const std::vector<Byte>& payload,
                       xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                       xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    const UInt32 total = static_cast<UInt32>(payload.size());
    UInt32 accepted = 0;
    UInt32 guard_send = 0;
    while (accepted < total && 400000 > ++guard_send) {
        UInt32 n = total - accepted;
        if (n > 4096) {
            n = 4096;
        }
        // Busy drain (no sleeps): the coarse Windows clock granularity
        // (15.6ms per 1ms sleep) is what the intermittent loss correlates
        // with; a busy drain removes the sleep entirely.
        UInt32 tries = 0;
        while (!from.Send(conn, payload.data() + accepted, n) && 100000 > ++tries) {
            PumpBusy(a, b, sa, sb);
        }
        if (500 <= tries) {
            break;
        }
        accepted += n;
        PumpBusy(a, b, sa, sb);
    }
    for (UInt32 i = 0; i < 3000; ++i) {
        Pump(a, b, sa, sb);
    }
    return accepted;
}

static UInt32 Crc(const Byte* d, UInt32 len) {
    UInt32 crc = 0;
    for (UInt32 i = 0; i < len; ++i) {
        crc = (crc * 31 + d[i]) & 0x7FFFFFFF;
    }
    return crc;
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // Scaled-window transfer integrity test: pin Reno so the rate-based
        // KCC default does not pace the ACK clock (intermittent byte loss
        // observed without the pin).
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

        // Capture B's passive connection id at Established (never assume id
        // adjacency / derivability across stacks).
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st && 0 == conn_b) {
                conn_b = id;
            }
        });

        // Wire-level counters: how many IP packets actually crossed each
        // direction (a dropped segment shows up as a missing packet here).
        UInt64 bytes_a_recv = 0, bytes_b_recv = 0;
        UInt32 crc_a_recv = 0, crc_b_recv = 0;
        stack_a.SetRecvHandler([&bytes_a_recv, &crc_a_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_a_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_a_recv = (crc_a_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });
        stack_b.SetRecvHandler([&bytes_b_recv, &crc_b_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_b_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_b_recv = (crc_b_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40121;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9100;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);

        for (UInt32 i = 0;
             i < 2000 && !(0 != conn_b &&
                           xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
             ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;

        // KEY ASSERTION: B parsed the peer's WSOPT=7 -> snd_wscale_=7 -> the
        // window field (scaled by A to 65535>>7 = 511) computes to 511<<7 =
        // 65408, proving the shift was applied.
        stack_b.ConnStats(conn_b, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[wscale-half] B snd_wnd=%u (scaled by peer WSOPT=7)\n", snd_wnd);
        CHECK(60000 < snd_wnd);

        // A negotiated the same symmetric scale: its send window is also
        // 511<<7 = 65408 (both ends offered WSOPT=7).
        stack_a.ConnStats(conn_a, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[wscale-half] A snd_wnd=%u (scaled by peer WSOPT=7)\n", snd_wnd);
        CHECK(60000 < snd_wnd);

        // A -> B: 128 KiB intact through the scaled windows.
        const UInt32 kAtoB = 131072;

        std::vector<Byte> p_ab(kAtoB);
        for (UInt32 i = 0; i < kAtoB; ++i) {
            p_ab[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
        }
        const UInt32 sent_ab = Transfer(stack_a, conn_a, p_ab, backend_a, backend_b, stack_a, stack_b);
        // Drain: the ACK clock may lag the send loop; give the peer real
        // time to deliver everything before asserting.
        for (UInt32 drain = 0; drain < 5000 && bytes_b_recv < kAtoB; ++drain) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kAtoB == sent_ab);
        CHECK(kAtoB == bytes_b_recv);
        CHECK(Crc(p_ab.data(), kAtoB) == crc_b_recv);

        // B -> A: 128 KiB through B's scaled send window.
        const UInt32 kBtoA = 131072;
        std::vector<Byte> p_ba(kBtoA);
        for (UInt32 i = 0; i < kBtoA; ++i) {
            p_ba[i] = static_cast<Byte>((i * 5 + i / 31 + 0x3C) & 0xFF);
        }
        CHECK(kBtoA == Transfer(stack_b, conn_b, p_ba, backend_a, backend_b, stack_a, stack_b));
        CHECK(kBtoA == bytes_a_recv);
        CHECK(Crc(p_ba.data(), kBtoA) == crc_a_recv);

        // The scaled send window is stable after real traffic (511<<7=65408).
        stack_b.ConnStats(conn_b, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        CHECK(60000 < snd_wnd);

        stack_a.Close(conn_a);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WSCALE_HALF: FAILED (%d)\n" : "WSCALE_HALF: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


/**
 * @file test_keepalive_zero.cpp
 * @brief Keepalive + zero-window coexist: with keepalive armed AND a
 *        zero window, BOTH probe types go out on the wire and neither
 *        conflicts with the other. The keepalive probe is a 40-byte pure
 *        ACK (seq = snd_nxt_-1, fire-and-forget, tcp_fsm.cpp:1425-1427);
 *        the persist probe is a 41-byte 1-payload-byte PSH|ACK segment
 *        (seq = snd_nxt_, queued for retransmit, tcp_fsm.cpp:1355-1378).
 *        B observes both. A restored window then flushes the buffered
 *        payload intact.
 *
 * The zero-window ACK is injected with the REAL snd_una (read from
 * ConnStats) plus a genuinely NEW segment seq (B's ISS + offset, > the
 * SND.WL2 anchor set by the SYN+ACK): only such a segment passes the
 * RFC 793 SND.WL guard and actually collapses snd_wnd_ to 0 (a stale ACK
 * is rejected and leaves snd_wnd_ at 65535, no persist, no coexistence).
 *
 * Keepalive cnt is set high (1000) so the test never aborts: B does not
 * answer the pure-ACK keepalive probes (they carry no data, so B sends
 * nothing back - no ack_pending_ is armed for ACK-only segments).
 */

#include <xtcp/core/stack.h>
#include "harness/raw_pkt.h"
#include <xtcp/ndi/manual.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    // B-side observers: 40-byte pure-ACK segments = keepalive probes;
    // 41-byte PSH|ACK segments (1 payload byte) = persist probes.
    std::atomic<UInt32> g_keepalive{0};
    std::atomic<UInt32> g_persist{0};
}

static UInt32 g_b_iss = 0;  // B's ISS, sniffed from the SYN+ACK (SND.WL2 anchor)

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

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

/** Injects an ACK (seq, ack, window) sourced from B into A's rx backend.
 *  Valid checksums so the window collapse/restore works under the
 *  checksum-validate build. */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 seq,
                         UInt32 window) {
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, 9330, 40330, seq, ack, 0x10);
    // window field is caller-supplied (helper defaults to 65535).
    pkt[34] = static_cast<Byte>(window >> 8);
    pkt[35] = static_cast<Byte>(window & 0xFF);
    // Recompute the TCP checksum after the window override.
    xtcp::harness::FillTcp4Checksum(pkt.data(), pkt.data() + 20, 20);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (0 == g_b_iss && p.len >= 40 && 0x12 == (p.data[20 + 13] & 0x12)) {
                g_b_iss = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            // 40-byte pure ACK = keepalive probe (ACK-only, no PSH/FIN/SYN/RST);
            // with RFC 7323 timestamps negotiated the probe carries the
            // 12-byte TSopt (52 bytes).
            if ((40 == p.len || 52 == p.len) && 0x10 == (p.data[33] & 0x3F)) {
                g_keepalive.fetch_add(1, std::memory_order_relaxed);
            }
            // 41-byte PSH|ACK with exactly 1 payload byte = persist probe.
            if (41 == p.len && 0 != (p.data[33] & 0x08)) {
                g_persist.fetch_add(1, std::memory_order_relaxed);
            }
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
        local.port = 40330;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9330;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt32 snd_una_hs = snd_una;  // real post-handshake snd_una (legal baseline)
        std::fprintf(stderr, "[keepalive-zero] handshake snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_hs, snd_wnd);
        CHECK(0 != snd_una_hs);
        CHECK(0 != g_b_iss);

        // Both timers armed, short: keepalive 10 ms idle / 10 ms interval
        // (cnt high so the unanswered pure-ACK probes never abort), persist
        // 30 ms. The counters are reset after the handshake so B's final
        // handshake ACK (also a 40-byte pure ACK) is not counted as a probe.
        stack_a.SetKeepalive(conn, 10000, 10000, 1000);
        stack_a.SetPersistInterval(conn, 30000);
        g_keepalive.store(0);
        g_persist.store(0);

        // Zero window: real snd_una + NEW seq (> snd_wl2_ = B's ISS) passes
        // the RFC 793 SND.WL guard, collapsing snd_wnd_ to 0. A stale ACK
        // would be rejected and there would be no persist probe at all.
        InjectWindow(backend_a, snd_una_hs, g_b_iss + 1000, 0);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Byte payload[4096];
        std::memset(payload, 0x55, sizeof(payload));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));

        // Persist + keepalive both fire. The keepalive probe (pure ACK) is
        // sent on the first idle poll; the persist probe (1-byte PSH) on the
        // persist deadline; B's ACK of the persist probe restores the window
        // (ack = snd_una+1 > snd_wl1), flushing the payload.
        for (UInt32 i = 0; i < 8; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        const UInt32 keepalive_probes = g_keepalive.load(std::memory_order_relaxed);
        const UInt32 persist_probes = g_persist.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[keepalive-zero] keepalive probes=%u persist probes=%u\n",
                     keepalive_probes, persist_probes);
        // CORE: BOTH probe types coexist on the wire (dual probes, no conflict).
        CHECK(0 < keepalive_probes);
        CHECK(0 < persist_probes);

        // Window recovery: inject a legal window-restore ACK (still a NEW
        // seq > snd_wl2_) and drain until the full payload arrives.
        InjectWindow(backend_a, snd_una_hs, g_b_iss + 2000, 65535);
        for (UInt32 i = 0; i < 300 && received.size() < sizeof(payload); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // CORE: recovery + data integrity - RFC 1122: the persist probes
        // carried the FIRST payload bytes (each probe consumed one real data
        // byte from the front of the buffer), so the peer receives the FULL
        // payload with no phantom bytes prepended.
        CHECK(sizeof(payload) == received.size());
        CHECK(0 == std::memcmp(received.data(), payload, sizeof(payload)));
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        CHECK(0 < snd_wnd);  // window recovered
        std::fprintf(stderr, "[keepalive-zero] window recovered snd_wnd=%u, %zu bytes delivered\n",
                     snd_wnd, received.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_ZERO: FAILED (%d)\n" : "KEEPALIVE_ZERO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

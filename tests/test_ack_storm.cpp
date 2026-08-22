/**
 * @file test_ack_storm.cpp
 * @brief ACK-flood defense: 200 forged pure ACKs (random out-of-bounds ack +
 *        window=0) must not kill the connection, must not collapse the send
 *        window, and the transmission must continue intact.
 *
 * Attack model: a spoofed ACK flood against the sender (A). Each garbage ACK
 * advertises window=0. Its ack field is drawn from the two out-of-bounds
 * regions of the legal ACK window [snd_una_, snd_nxt_]:
 *   - ack < snd_una_ : a STALE ACK - must be rejected by the RFC 793 SND.WL
 *     window-update guard (tcp_fsm.cpp:1866-1872) so the forged window=0
 *     never reaches snd_wnd_.
 *   - ack > snd_nxt_ : an ACK for data we never sent - must be rejected by
 *     OnAckReceived's out-of-range check (tcp_fsm.cpp:1037-1039) so snd_una_
 *     never jumps forward and the send window never collapses.
 *
 * The two defenses must compose: whatever the ack value, a garbage ACK must
 * leave the connection healthy, snd_una_ unchanged, snd_wnd_ untouched, and
 * the following transmission fully delivered.
 *
 * Core assertions: connection alive after the flood + window not collapsed +
 * transmission continues to completion (byte count + memcmp).
 *
 * FIX LANDED (post-fix behavior verified here): the SND.WL window update now
 * applies only when ack is not beyond snd_nxt_ (the ack-validity gate in the
 * window-update path, tcp_fsm.cpp:2439). An out-of-bounds ack (ack > snd_nxt_)
 * can no longer pass the guard to collapse snd_wnd_ or advance snd_wl1_ past
 * every genuine window-update ACK - the forged zero window is not sticky and
 * the buffered send drains normally. The two guards compose: snd_una_ stays
 * unchanged, snd_wnd_ untouched, and the following transmission fully
 * delivered.
 */

#include <xtcp/core/stack.h>
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
    constexpr UInt16 kAPort = 40267;   // A's local port
    constexpr UInt16 kBPort = 9171;    // B's listen/remote port
    constexpr UInt32 kPartial = 4096;  // bytes transferred before the flood
    constexpr UInt32 kMore = 16384;    // bytes transferred after the flood
    constexpr UInt32 kGarbage = 200;   // forged pure ACKs injected
    std::atomic<UInt32> g_b_iss{0};    // B's ISS, sniffed from the SYN+ACK
}

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

// Deterministic LCG: the flood is "random" but reproducible.
static UInt32 g_seed = 0x9E3779B9u;
static UInt32 NextRand() {
    g_seed = g_seed * 1664525u + 1013904223u;
    return g_seed;
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

/** Injects a forged pure ACK (seq, ack, window) sourced from B into A. */
static void InjectGarbageAck(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 seq,
                             UInt32 window) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = 0x0A; pkt[13] = 0x00; pkt[14] = 0x00; pkt[15] = 0x02;  // src = B
    pkt[16] = 0x0A; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x01;  // dst = A
    pkt[20] = static_cast<Byte>(kBPort >> 8); pkt[21] = static_cast<Byte>(kBPort & 0xFF);
    pkt[22] = static_cast<Byte>(kAPort >> 8); pkt[23] = static_cast<Byte>(kAPort & 0xFF);
    pkt[24] = static_cast<Byte>(seq >> 24); pkt[25] = static_cast<Byte>(seq >> 16);
    pkt[26] = static_cast<Byte>(seq >> 8);  pkt[27] = static_cast<Byte>(seq);
    pkt[28] = static_cast<Byte>(ack >> 24); pkt[29] = static_cast<Byte>(ack >> 16);
    pkt[30] = static_cast<Byte>(ack >> 8);  pkt[31] = static_cast<Byte>(ack & 0xFF);
    pkt[32] = 0x50; pkt[33] = 0x10;  // hdr_len=5, pure ACK
    pkt[34] = static_cast<Byte>(window >> 8); pkt[35] = static_cast<Byte>(window & 0xFF);
    backend.Inject(pkt, sizeof(pkt), 0x0800);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (0 == g_b_iss.load() && p.len >= 40 && 0x12 == (p.data[20 + 13] & 0x12)) {
                g_b_iss.store(Load32BE(p.data + 20 + 4));  // SYN+ACK seq = B's ISS
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = kAPort;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = kBPort;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // 1) Partial transfer: establishes the legal snd_una / snd_wnd baseline.
        Byte payload1[kPartial];
        std::memset(payload1, 0x11, sizeof(payload1));
        CHECK(stack_a.Send(conn, payload1, sizeof(payload1)));
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        for (UInt32 i = 0; i < 300; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                              dup, fast, front_seq, snd_una, lp, rp);
            if (0 == inflight && sizeof(payload1) <= received.size()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // delayed-ACK clock
        }
        std::fprintf(stderr, "[ack-storm] partial: received=%zu snd_una=0x%08X snd_wnd=%u inflight=%u\n",
                     received.size(), snd_una, snd_wnd, inflight);
        CHECK(sizeof(payload1) == received.size());   // partial transfer intact
        CHECK(0 == inflight);                          // fully ACKed: snd_nxt_ == snd_una_
        CHECK(0 < snd_wnd);                            // legal non-zero window baseline
        CHECK(0 != g_b_iss.load());
        const UInt32 snd_una_legit = snd_una;
        const UInt32 snd_nxt = snd_una;                // inflight == 0: snd_nxt_ == snd_una_
        const UInt32 snd_wnd_legit = snd_wnd;

        // 2) ACK flood: 200 forged pure ACKs, window=0, ack drawn at random
        //    from OUTSIDE [snd_una_, snd_nxt_]. Even index = stale (below),
        //    odd index = acknowledges unsent data (above).
        const UInt32 b_iss = g_b_iss.load();
        for (UInt32 i = 0; i < kGarbage; ++i) {
            const UInt32 delta = 1 + (NextRand() % 1000000u);
            const UInt32 ack = (0 == (i & 1)) ? (snd_una_legit - delta)
                                              : (snd_nxt + delta);
            InjectGarbageAck(backend_a, ack, b_iss + delta, 0);
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        // 3) The combination defense must leave the connection healthy, the
        //    ACK accounting untouched, and the window fully intact.
        UInt32 snd_una_flood = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una_flood, lp, rp);
        std::fprintf(stderr, "[ack-storm] flood: state=%d conns=%llu snd_una=0x%08X snd_wnd=%u inflight=%u\n",
                     static_cast<int>(stack_a.ConnectionState(conn)),
                     static_cast<unsigned long long>(stack_a.ConnectionCount()),
                     snd_una_flood, snd_wnd, inflight);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));  // alive
        CHECK(1 == stack_a.ConnectionCount());
        CHECK(snd_una_flood == snd_una_legit);         // no spurious ACK progress
        CHECK(0 < snd_wnd);                            // window not collapsed to 0
        CHECK(snd_wnd == snd_wnd_legit);               // garbage window update rejected

        // 4) Transmission continues: the next send goes out and arrives intact.
        Byte payload2[kMore];
        std::memset(payload2, 0x22, sizeof(payload2));
        CHECK(stack_a.Send(conn, payload2, sizeof(payload2)));
        const UInt32 total = sizeof(payload1) + sizeof(payload2);
        for (UInt32 i = 0; i < 2000 && received.size() < total; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // delayed-ACK clock
        }
        std::fprintf(stderr, "[ack-storm] continue: received=%zu/%u\n", received.size(), total);
        CHECK(total == received.size());               // transmission complete
        CHECK(0 == std::memcmp(received.data(), payload1, sizeof(payload1)));
        CHECK(0 == std::memcmp(received.data() + sizeof(payload1), payload2, sizeof(payload2)));
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));  // still healthy
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ACK_STORM: FAILED (%d)\n" : "ACK_STORM: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

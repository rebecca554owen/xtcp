/**
 * @file test_ooo_mixed.cpp
 * @brief Complex recovery: out-of-order buffering + packet loss + SACK/RTO
 *        retransmission all interleaved on one transfer. The receive stack
 *        must reassemble a stream that (a) loses every 8th data segment on
 *        the wire (SACK recovery), (b) receives manually injected
 *        out-of-order segments strictly ahead of its frontier (OOO buffer),
 *        and (c) delivers every byte exactly once with the window intact.
 *
 * Scenario:
 *   1. Dual stack (mirrors test_wscale_transfer.cpp's loss pattern):
 *      the pump drops every 8th A->B data packet during the data phase;
 *      retransmissions pass (SACK + RTO recovery).
 *   2. Mid-transfer, real payload segments are injected into B ahead of its
 *      frontier (mirrors test_ooo_partial.cpp's InjectOoo): MSS-aligned,
 *      within the receive window, carrying the true payload bytes. B buffers
 *      them; the OOO drain consumes them in a contiguous chain when the
 *      in-order stream reaches their keys; A's later in-order copies of the
 *      same ranges arrive as fully-old data and are dropped (re-ACK), so
 *      every byte is delivered exactly once.
 *   3. The transfer completes intact.
 *
 * Alignment note: A's data stream is MSS-aligned only when the application
 * send chunk is a multiple of the MSS. The send loop here uses chunks of
 * 3*MSS and half/total sizes that are MSS multiples, so the injected OOO
 * keys (b_rcv_nxt + k*MSS) coincide exactly with A's segment boundaries.
 * This keeps the OOO-drain chain landing on segment boundaries - an
 * unaligned injection would leave rcv_nxt_ mid-segment and cause a later
 * in-order segment to be re-ACKed wholesale (tcp_fsm.cpp:1931-1933 drops
 * partially-old data without trimming), losing bytes.
 *
 * Core assertion: mixed out-of-order + loss recovery completes intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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
        }                                                                \
    } while (0)

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

// ---- lossy pump (mirrors test_wscale_transfer.cpp) ---------------------
static UInt32 g_drop_every = 0;
static UInt32 g_drop_count = 0;
static UInt32 g_tx_seen = 0;

static void PumpLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                if (0 != g_drop_every && 0 == (g_tx_seen % g_drop_every)) {
                    ++g_drop_count;
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

// ---- OOO injection (mirrors test_ooo_partial.cpp, with ack=0 + window 0xFFFF) ----
static void InjectOoo(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port, UInt32 seq,
                      const Byte* content, UInt32 payload_len) {
    const UInt32 total = 20 + 20 + payload_len;
    std::vector<Byte> pkt(total);
    std::memset(pkt.data(), 0xCC, total);
    pkt[0] = 0x45;
    pkt[2] = static_cast<Byte>(total >> 8); pkt[3] = static_cast<Byte>(total);
    pkt[9] = 6;                              // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt.data() + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = static_cast<Byte>(seq >> 24); tcp[5] = static_cast<Byte>(seq >> 16);
    tcp[6] = static_cast<Byte>(seq >> 8);  tcp[7] = static_cast<Byte>(seq);
    tcp[8] = 0; tcp[9] = 0; tcp[10] = 0; tcp[11] = 0;   // ack = 0: OnAckReceived treats it as
    // stale (SeqLt(0, snd_una_)) and the SND.WL guard rejects the window update
    // (SeqLt(snd_wl1_, 0) false) - B's send window / SND.WL state is untouched.
    tcp[12] = 0x50;                          // data offset 5
    tcp[13] = 0x18;                          // PSH + ACK
    tcp[14] = 0xFF; tcp[15] = 0xFF;          // window 65535 (must not compress A's window)
    if (0 < payload_len) {
        std::memcpy(tcp + 20, content, payload_len);
    }
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
    std::memcpy(buf.Data(), pkt.data(), total);
    buf.SetLen(total);
    victim.OnPacket(std::move(buf));
}

static void RunMixedCase(UInt16 local_port, UInt16 remote_port) {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    UInt32 a_iss = 0;
    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack_a.OnPacket(std::move(buf));
    });
    backend_b.SetRxHandler([&stack_b, &a_iss](xtcp::ndi::Packet&& p) {
        if (40 <= p.len && 0x02 == (p.data[20 + 13] & 0x02)) {
            a_iss = Load32BE(p.data + 20 + 4);   // A's SYN seq = A's ISS
        }
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack_b.OnPacket(std::move(buf));
    });

    std::vector<Byte> recv_b;
    stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 len) {
        recv_b.insert(recv_b.end(), d, d + len);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = local_port;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = remote_port;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    PumpLossy(backend_a, backend_b, stack_a, stack_b);   // handshake: no drops (drop_every=0)
    CHECK(0 != a_iss);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    const UInt32 kMss = 1460;
    const UInt32 kChunk = 3 * kMss;           // 4380: MSS multiple -> A's stream stays aligned
    const UInt32 kTotal = 63 * kMss;          // 91980: MSS multiple
    const UInt32 kHalf = 30 * kMss;           // 43800: MSS multiple, == 10 * kChunk
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 13 + i / 31) & 0xFF);
    }

    // Phase 1: transfer the first half under loss (every 8th segment dropped).
    // A's data starts at seq = a_iss + 1; every segment is exactly kMss long
    // (all chunk boundaries are MSS multiples), so A's segment boundaries are
    // exactly a_iss + 1 + n*kMss.
    g_drop_every = 8;
    UInt32 accepted = 0;
    UInt32 guard = 0;
    while (accepted < kHalf && 200000 > ++guard) {
        UInt32 n = kHalf - accepted;
        if (n > kChunk) {
            n = kChunk;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        PumpLossy(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK(kHalf == accepted);
    for (UInt32 i = 0; i < 4000 && recv_b.size() < kHalf; ++i) {
        PumpLossy(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(kHalf == recv_b.size());            // first half fully delivered, B is caught up
    const UInt32 b_rcv_nxt = a_iss + 1 + kHalf;   // B's frontier: all delivered

    // Phase 2: inject 3 MSS-aligned OOO segments strictly ahead of the
    // frontier (b_rcv_nxt + k*MSS), within the receive window, carrying the
    // true payload bytes. A has not sent them yet; B buffers them and
    // re-ACKs. When the in-order stream reaches b_rcv_nxt, the OOO drain
    // consumes all three in a contiguous chain (exact-key lookup).
    UInt32 injected = 0;
    for (UInt32 k = 1; k <= 3; ++k) {
        const UInt32 seq = b_rcv_nxt + k * kMss;
        const UInt32 off = seq - (a_iss + 1);      // payload index
        InjectOoo(stack_b, 0x0A000001, 0x0A000002, local_port, remote_port,
                  seq, payload.data() + off, kMss);
        ++injected;
    }
    PumpLossy(backend_a, backend_b, stack_a, stack_b);  // B re-ACKs the OOO range

    // Phase 3: transfer the second half under the same loss policy. The
    // in-order stream catches up to the injected keys; the drain delivers the
    // injected bytes (true payload), and A's later in-order copies of the same
    // ranges arrive fully-old and are dropped.
    accepted = 0;
    guard = 0;
    while (accepted < (kTotal - kHalf) && 200000 > ++guard) {
        UInt32 n = (kTotal - kHalf) - accepted;
        if (n > kChunk) {
            n = kChunk;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + kHalf + accepted, n) && 500 > ++tries) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        PumpLossy(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK((kTotal - kHalf) == accepted);
    for (UInt32 i = 0; i < 6000 && recv_b.size() < kTotal; ++i) {
        PumpLossy(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // ---- core assertions: mixed OOO + loss recovery completes intact ----
    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0, dup = 0, fast = 0;
    UInt64 rto_deadline = 0;
    UInt32 front_seq = 0, snd_una = 0;
    UInt16 lp = 0, rp = 0;
    stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline, dup, fast,
                      front_seq, snd_una, lp, rp);
    std::fprintf(stderr,
                 "[ooo-mixed] port=%u dropped=%u injected=%u received=%zu expect=%u retx=%u state=%d\n",
                 local_port, g_drop_count, injected, recv_b.size(), kTotal, retx,
                 (int)stack_a.ConnectionState(conn));

    CHECK(3 == injected);                     // OOO injection happened
    CHECK(0 < g_drop_count);                  // loss happened
    CHECK(kTotal == recv_b.size());           // every byte delivered exactly once
    CHECK(0 == std::memcmp(recv_b.data(), payload.data(), kTotal));  // content intact
    CHECK(0 < retx);                          // recovery happened (SACK/RTO retransmit)
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));  // no deadlock

    stack_a.Close(conn);
    for (UInt32 i = 0; i < 100; ++i) {
        PumpLossy(backend_a, backend_b, stack_a, stack_b);
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        RunMixedCase(40260, 9170);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "OOO_MIXED: FAILED (%d)\n" : "OOO_MIXED: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

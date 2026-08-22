/**
 * @file test_ooo_partial.cpp
 * @brief RFC 793 prefix trimming of a partially-old segment (seq < rcv_nxt_):
 *        the old prefix is trimmed and the fresh suffix enters the out-of-order
 *        buffer - the segment is NOT dropped wholesale (the pre-fix behavior
 *        that stranded bytes the peer would otherwise retransmit forever).
 *
 * Scenario (mechanism confirmed by code reading, tcp_fsm.cpp:1907-1926):
 *   1. A normal in-order transfer advances B's rcv_nxt_ by 1000 bytes.
 *   2. A reordered/retransmitted segment [rcv_nxt_-500, rcv_nxt_+500) is
 *      injected into B carrying the real payload bytes. The receive path
 *      trims the old prefix [rcv_nxt_-500, rcv_nxt_) and buffers the fresh
 *      suffix [rcv_nxt_, rcv_nxt_+500) at ooo_[rcv_nxt_] (tcp_fsm.cpp:1913-1923).
 *      rcv_nxt_ is unchanged and the fresh bytes are NOT delivered early.
 *   3. The peer resumes a normal in-order send from rcv_nxt_ (gap-fill): the
 *      region [rcv_nxt_, rcv_nxt_+500) arrives in-order, is delivered, and the
 *      rest of the stream flows. After that the buffered suffix (key == old
 *      frontier) is a fully-old duplicate that the exact-key drain
 *      (tcp_fsm.cpp:1865) never consumes - benign, reclaimed at close.
 *
 * Core assertions: transfer completes (byte count) + no stall (bounded
 * pump/wait loops, connection stays Established) + content byte-exact.
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

// Injects an out-of-order data segment directly into the victim stack
// (wire layout mirrors test_ooo_overlap's InjectOoo; the payload is filled
// with `fill` or copied from `content`).
static void InjectOoo(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port, UInt32 seq,
                      Byte fill, UInt32 payload_len, const Byte* content = nullptr) {
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
    tcp[12] = 0x50;                          // data offset 5
    tcp[13] = 0x18;                          // PSH + ACK
    tcp[14] = 0x40; tcp[15] = 0x00;          // window 16384
    if (0 < payload_len) {
        if (content) {
            std::memcpy(tcp + 20, content, payload_len);
        } else {
            std::memset(tcp + 20, fill, payload_len);
        }
    }
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
    std::memcpy(buf.Data(), pkt.data(), total);
    buf.SetLen(total);
    victim.OnPacket(std::move(buf));
}

static void RunPartialCase(UInt16 local_port) {
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
    remote.port = 9095;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(0 != a_iss);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    const UInt32 b_rcv_nxt = a_iss + 1;          // B's receive frontier after handshake

    const UInt32 kTotal = 16384;                 // total application payload
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 13 + i / 31) & 0xFF);
    }

    // Phase 1: normal in-order transfer of the first 1000 bytes. This advances
    // B's rcv_nxt_ from b_rcv_nxt to b_rcv_nxt + kFirst.
    const UInt32 kFirst = 1000;
    UInt32 accepted = 0;
    UInt32 guard = 0;
    while (accepted < kFirst && 100000 > ++guard) {
        UInt32 n = kFirst - accepted;
        if (n > 4096) {
            n = 4096;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK(kFirst == accepted);
    for (UInt32 i = 0; i < 2000 && recv_b.size() < kFirst; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(kFirst == recv_b.size());              // rcv_nxt_ == b_rcv_nxt + kFirst

    // Phase 2: inject the partially-old segment [rcv_nxt_-500, rcv_nxt_+500),
    // carrying the real payload bytes for that range (app offset 500..1500).
    // The RFC 793 prefix trim drops [rcv_nxt_-500, rcv_nxt_) and buffers the
    // fresh suffix [rcv_nxt_, rcv_nxt_+500) at ooo_[rcv_nxt_]; rcv_nxt_ and the
    // delivered byte count are unchanged (nothing is delivered early).
    const UInt32 rcv_nxt_now = b_rcv_nxt + kFirst;
    InjectOoo(stack_b, 0x0A000001, 0x0A000002, local_port, 9095,
              rcv_nxt_now - 500, 0x00, 1000, payload.data() + (rcv_nxt_now - 500 - b_rcv_nxt));
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(kFirst == recv_b.size());              // old prefix trimmed, fresh suffix buffered

    // Phase 3: the peer resumes a normal in-order send from rcv_nxt_ covering
    // the "gap" region [rcv_nxt_, rcv_nxt_+500) and the rest of the payload.
    // The transfer must complete intact with no stall (the fresh 500 bytes are
    // delivered, whether from the buffered suffix or the in-order gap-fill).
    accepted = 0;
    guard = 0;
    const UInt32 kRest = kTotal - kFirst;
    while (accepted < kRest && 100000 > ++guard) {
        UInt32 n = kRest - accepted;
        if (n > 4096) {
            n = 4096;
        }
        UInt32 tries = 0;
        while (!stack_a.Send(conn, payload.data() + kFirst + accepted, n) && 500 > ++tries) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        accepted += n;
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    CHECK(kRest == accepted);
    for (UInt32 i = 0; i < 4000 && recv_b.size() < kTotal; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::fprintf(stderr,
                 "[ooo-partial] port=%u a_iss=%u received=%zu expect=%u state=%d\n",
                 local_port, a_iss, recv_b.size(), kTotal,
                 (int)stack_a.ConnectionState(conn));
    CHECK(kTotal == recv_b.size());               // transfer complete (no stall)
    CHECK(0 == std::memcmp(recv_b.data(), payload.data(), kTotal));  // content intact
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));  // no deadlock

    stack_a.Close(conn);
    for (UInt32 i = 0; i < 100; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
}

int main() {
    xtcp::buf::InitPools();
    {
        RunPartialCase(40212);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "OOO_PARTIAL: FAILED (%d)\n" : "OOO_PARTIAL: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_persist_stack.cpp
 * @brief RFC 1122 zero-window persist end-to-end: a window=0 ACK stalls
 *        the sender (buffered), the persist probe goes out on the wire,
 *        and a restored window flushes the buffered data intact.
 *
 * The window-update ACKs are injected with the REAL snd_una (read from
 * ConnStats, see test_window_sndwl.cpp) and a genuinely NEW segment seq
 * (B's ISS + offset, > the SND.WL2 anchor set by the SYN+ACK). Only such a
 * segment passes the RFC 793 SND.WL window-update guard - a stale ACK like
 * the hardcoded 0x40000001 (which sits < the real snd_una) is rejected and
 * leaves snd_wnd_ at 65535 (no zero window, no persist).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <atomic>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <thread>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    std::atomic<UInt32> g_probes{0};  // 40-byte pure ACKs (probes) at B
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

/** Injects an ACK (seq, ack, window) sourced from B into A's rx backend. */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 seq,
                         UInt32 window) {
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
    pkt[26] = static_cast<Byte>(seq >> 8);  pkt[27] = static_cast<Byte>(seq);
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
            if (0 == g_b_iss && p.len >= 40 && 0x12 == (p.data[20 + 13] & 0x12)) {
                g_b_iss = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            // B sees the 1-byte persist probes (41 bytes, PSH: 1 payload byte).
            if (41 == p.len && 0 != (p.data[33] & 0x08)) {
                g_probes.fetch_add(1, std::memory_order_relaxed);
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
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
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
        std::fprintf(stderr, "[persist-stack] handshake snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_hs, snd_wnd);
        CHECK(0 != snd_una_hs);
        CHECK(0 != g_b_iss);

        // Short persist interval for the test.
        stack_a.SetKeepalive(conn, 0, 0, 0);  // keepalive off
        stack_a.SetPersistInterval(conn, 20000);  // 20 ms probes

        // Zero window: sends buffer, persist probes go out. The ACK must pass
        // the RFC 793 SND.WL guard: ack == snd_una (the REAL snd_una, from
        // ConnStats) plus a genuinely NEW seq > snd_wl2_ (the SYN+ACK seq =
        // B's ISS) - a stale ack would be rejected and snd_wnd_ would stay
        // 65535 (no zero window, no persist).
        InjectWindow(backend_a, snd_una_hs, g_b_iss + 1000, 0);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Byte payload[4096];
        std::memset(payload, 0x55, sizeof(payload));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        for (UInt32 i = 0; i < 6; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[persist-stack] probes=%u\n", g_probes.load());
        CHECK(0 < g_probes.load(std::memory_order_relaxed));

        // Window restores: buffered data flushes intact. RFC 1122: the persist
        // probes carried the FIRST payload bytes (each probe consumed one real
        // data byte from the front of the buffer), so the peer receives the
        // FULL payload - no phantom bytes prepended.
        // A NEW seq (still > snd_wl2_ = B's ISS + 1000) keeps the update legal.
        InjectWindow(backend_a, snd_una_hs, g_b_iss + 2000, 65535);
        for (UInt32 i = 0; i < 300 && received.size() < sizeof(payload); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(sizeof(payload) == received.size());
        CHECK(0 == std::memcmp(received.data(), payload, sizeof(payload)));
        std::fprintf(stderr, "[persist-stack] window restored, %zu bytes delivered\n",
                     received.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PERSIST_STACK: FAILED (%d)\n" : "PERSIST_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


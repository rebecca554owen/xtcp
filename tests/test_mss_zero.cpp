/**
 * @file test_mss_zero.cpp
 * @brief Peer advertises MSS=0 (abnormal). RFC 1122 §4.2.2.6 maps an MSS
 *        option of 0 to the IPv4 default of 536 in SetPeerMss, so the
 *        connection must still work: no divide-by-zero in cwnd math, no
 *        infinite send loop, and the peer receives the whole transfer in
 *        <=536-byte segments.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>
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
    // Largest packet observed on A's tx wire during the data phase
    // (an MSS=536 peer must never make A emit a data segment above
    // 20(IP)+20(TCP)+536 = 576 bytes; a buggy MSS=0 -> huge segments
    // or a divide-by-zero would show up here).
    std::atomic<UInt32> g_max_a_pkt{0};
}

int main() {
    xtcp::buf::InitPools();
    {
        // A = active opener (its peer advertises MSS=0 via a crafted
        //     SYN+ACK), B = real listening server that must receive the
        //     full transfer.
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

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40012;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 8080;
        CHECK(stack_b.Listen(b_local));

        // A connects: its SYN goes straight to backend_a's tx queue.
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);

        // Grab A's SYN and read its TCP seq (IPv4 20 + TCP seq at +4).
        Byte a_syn[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(a_syn);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 a_syn_seq = (static_cast<UInt32>(a_syn[24]) << 24) |
                                 (static_cast<UInt32>(a_syn[25]) << 16) |
                                 (static_cast<UInt32>(a_syn[26]) << 8) |
                                 static_cast<UInt32>(a_syn[27]);
        std::fprintf(stderr, "[mss0] A SYN seq=%08x\n", a_syn_seq);

        // Deliver A's SYN to the real server so B builds its passive
        // connection (and emits its own SYN+ACK, whose seq we need).
        backend_b.Inject(a_syn, n, 0x0800);
        Byte b_sa[65536];
        UInt32 b_sa_len = 0;
        while (0 != backend_b.TxPending()) {
            b_sa_len = backend_b.PollTx(b_sa);
            if (0 != b_sa_len) {
                break;
            }
        }
        CHECK(0 != b_sa_len);
        const UInt32 b_iss = (static_cast<UInt32>(b_sa[24]) << 24) |
                             (static_cast<UInt32>(b_sa[25]) << 16) |
                             (static_cast<UInt32>(b_sa[26]) << 8) |
                             static_cast<UInt32>(b_sa[27]);
        std::fprintf(stderr, "[mss0] B SYN+ACK seq=%08x (iss)\n", b_iss);

        // Craft the SYN+ACK A will see: seq=B's iss (so A's ack lands on
        // B's snd_nxt), MSS option = 0 (kind 2, len 4, value 0). Window
        // 65535 so A's send path is not zero-window. WSOPT=7 mirrors A's
        // own offer (RFC 7323 mirroring): without it A stays unscaled while
        // B's stack scales its advertised window (rcv_wscale_=7 from A's
        // SYN), and A would misread every window field as 511 (trickle
        // stall - the pre-mirror test failed on Linux).
        // Valid checksums: a zero-checksum SYN+ACK is dropped under the
        // checksum-validate build and the handshake never completes.
        std::vector<Byte> synack = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 8080, 40012, b_iss, a_syn_seq + 1, 0x12);
        synack.push_back(2); synack.push_back(4); synack.push_back(0x00); synack.push_back(0x00);  // MSS = 0
        synack.push_back(3); synack.push_back(3); synack.push_back(0x07);                            // WSOPT = 7
        synack.push_back(1);                                                                         // NOP pad
        synack[2] = 0; synack[3] = 48;   // IP total length
        synack[20 + 12] = 0x70;          // data offset 7 (28-byte header)
        xtcp::harness::FillIp4Checksum(synack.data());
        xtcp::harness::FillTcp4Checksum(synack.data(), synack.data() + 20, 28);
        backend_a.Inject(synack.data(), static_cast<UInt32>(synack.size()), 0x0800);

        // A completes the handshake: peer MSS must be clamped to 256.
        stack_a.PollAckTimers();
        CHECK(1 == stack_a.ConnectionCount());
        CHECK(1 == stack_b.ConnectionCount());
        const UInt16 peer_mss = stack_a.ConnPeerMss(conn_a);
        std::fprintf(stderr, "[mss0] A peer MSS=%u (MSS=0 clamped to 536)\n", peer_mss);
        CHECK(536 == peer_mss);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // Forward A's handshake ACK to B, then transfer 16 KiB.
        constexpr UInt32 kTotal = 16 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 31 + 7) & 0xFF));
        }
        Byte out[65536];
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(out);
            if (0 < n && n > g_max_a_pkt.load(std::memory_order_relaxed)) {
                g_max_a_pkt.store(n, std::memory_order_relaxed);
            }
            backend_b.Inject(out, n, 0x0800);
        }
        UInt32 sent = 0;
        UInt32 guard = 0;
        while (sent < kTotal && 200000 > ++guard) {
            const UInt32 chunk = (kTotal - sent < 8192) ? (kTotal - sent) : 8192;
            if (stack_a.Send(conn_a,
                             reinterpret_cast<const Byte*>(payload.data() + sent),
                             chunk)) {
                sent += chunk;
            }
            // A -> B data + B -> A ACKs (delayed-ACK needs the 40 ms clock).
            bool moved = true;
            for (UInt32 sub = 0; moved && sub < 100; ++sub) {
                moved = false;
                while (0 != backend_a.TxPending()) {
                    n = backend_a.PollTx(out);
                    if (0 < n && n > g_max_a_pkt.load(std::memory_order_relaxed)) {
                        g_max_a_pkt.store(n, std::memory_order_relaxed);
                    }
                    backend_b.Inject(out, n, 0x0800);
                    moved = true;
                }
                while (0 != backend_b.TxPending()) {
                    n = backend_b.PollTx(out);
                    if (0 < n) {
                        backend_a.Inject(out, n, 0x0800);
                        moved = true;
                    }
                }
                stack_a.PollAckTimers();
                stack_b.PollAckTimers();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        std::fprintf(stderr, "[mss0] sent=%u\n", sent);
        for (UInt32 i = 0; i < 500 && received.size() < kTotal; ++i) {
            bool moved = false;
            while (0 != backend_a.TxPending()) {
                n = backend_a.PollTx(out);
                if (0 < n && n > g_max_a_pkt.load(std::memory_order_relaxed)) {
                    g_max_a_pkt.store(n, std::memory_order_relaxed);
                }
                backend_b.Inject(out, n, 0x0800);
                moved = true;
            }
            while (0 != backend_b.TxPending()) {
                n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (!moved) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        // B received the entire transfer (connection is fully functional
        // despite the peer's MSS=0 advertisement).
        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        std::fprintf(stderr, "[mss0] B received %u bytes complete\n",
                     static_cast<UInt32>(received.size()));

        // MSS clamp is enforced on the wire: A never emitted a data segment
        // above 20(IP)+20(TCP)+536(MSS) = 576 bytes. A non-clamped MSS=0
        // (or a divide-by-zero / runaway loop) breaks this invariant.
        const UInt32 max_pkt = g_max_a_pkt.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[mss0] max A tx packet=%u (cap 576)\n", max_pkt);
        CHECK(576 >= max_pkt);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MSS_ZERO: FAILED (%d)\n" : "MSS_ZERO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

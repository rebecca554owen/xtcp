/**
 * @file test_persist_handshake.cpp
 * @brief RFC 1122 s4.2.2.17 (audit M1): data buffered during the handshake
 *        (SYN_SENT) completing against a ZERO window must arm the persist
 *        timer and probe - the pre-fix flush requeued behind the zero window
 *        with no persist deadline, so NOTHING went on the wire and a lost
 *        window-update ACK deadlocked the flow forever.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt32 ReadSeq(const Byte* pkt) {
    return (static_cast<UInt32>(pkt[24]) << 24) | (static_cast<UInt32>(pkt[25]) << 16) |
           (static_cast<UInt32>(pkt[26]) << 8) | static_cast<UInt32>(pkt[27]);
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

        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40997;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9097;
        CHECK(stack_b.Listen(b_local));

        // A connects and sends 4096 bytes BEFORE the handshake completes
        // (queued in pending_send_ during SYN_SENT - full client semantics).
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Byte payload[4096];
        std::memset(payload, 0x5A, sizeof(payload));
        CHECK(stack_a.Send(conn_a, payload, sizeof(payload)));

        // Grab A's SYN; deliver it to B; grab B's SYN+ACK but DO NOT deliver
        // it - craft a SYN+ACK with window 0 instead (the zero-window peer).
        Byte pkt[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 a_syn_seq = ReadSeq(pkt);
        backend_b.Inject(pkt, n, 0x0800);
        while (0 != backend_b.TxPending()) {
            n = backend_b.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 b_iss = ReadSeq(pkt);

        // Crafted SYN+ACK: seq = B's iss, ack = A's SYN seq + 1, WINDOW 0.
        std::vector<Byte> synack = xtcp::harness::BuildIp4Tcp(
            0x0A000002, 0x0A000001, 9097, 40997, b_iss, a_syn_seq + 1, 0x12);
        synack.push_back(3); synack.push_back(3); synack.push_back(0x07);  // WSOPT = 7 (mirror)
        synack.push_back(1);                                               // NOP pad
        synack[2] = 0; synack[3] = 44;   // 20 IP + 24 TCP
        synack[20 + 12] = 0x60;          // data offset 6
        synack[20 + 14] = 0x00;          // window = 0
        synack[20 + 15] = 0x00;
        xtcp::harness::FillIp4Checksum(synack.data());
        xtcp::harness::FillTcp4Checksum(synack.data(), synack.data() + 20, 24);
        backend_a.Inject(synack.data(), static_cast<UInt32>(synack.size()), 0x0800);

        // Established with snd_wnd_ = 0: the 4096 buffered bytes cannot
        // flush. Pre-fix: nothing armed, nothing ever sent. Post-fix: the
        // persist timer arms and the 1-byte probe goes out after
        // persist_interval_ (1 s default).
        stack_a.PollAckTimers();
        stack_a.PollAckTimers();
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        std::fprintf(stderr, "[persist-handshake] established with zero window\n");

        // Pump until a probe segment appears on A's wire (bounded).
        bool probe_seen = false;
        for (UInt32 i = 0; i < 400 && !probe_seen; ++i) {
            stack_a.PollAckTimers();
            while (0 != backend_a.TxPending()) {
                n = backend_a.PollTx(pkt);
                if (0 != n) {
                    const UInt32 ip_total = (static_cast<UInt32>(pkt[2]) << 8) | pkt[3];
                    const UInt32 payload_len = ip_total - 20 - 20;
                    std::fprintf(stderr, "[persist-handshake] t=%ums segment payload=%u\n",
                                 i, payload_len);
                    if (1 == payload_len) {
                        probe_seen = true;  // the 1-byte window probe
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::fprintf(stderr, "[persist-handshake] probe_seen=%d\n", probe_seen ? 1 : 0);
        CHECK(probe_seen);  // CORE: the zero-window persist probe fires
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "PERSIST_HANDSHAKE: FAILED (%d)\n" : "PERSIST_HANDSHAKE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

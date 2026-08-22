/**
 * @file test_window_sndwl.cpp
 * @brief RFC 793 SND.WL window-update guard: only an ACK that is newer than
 *        the last window-updating ACK may update the send window. A stale /
 *        out-of-order ACK (ack < snd_una) carrying a forged window=0 must NOT
 *        collapse snd_wnd_ (garbage-ACK window-shrink attack); the sender
 *        keeps its window and transmission continues.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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

/** Injects an ACK with the given window into `backend` (A side, from B). */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 window) {
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
    pkt[24] = 0; pkt[25] = 0; pkt[26] = 0; pkt[27] = 0;
    pkt[28] = static_cast<Byte>(ack >> 24); pkt[29] = static_cast<Byte>(ack >> 16);
    pkt[30] = static_cast<Byte>(ack >> 8);  pkt[31] = static_cast<Byte>(ack & 0xFF);
    pkt[32] = 0x50; pkt[33] = 0x10;
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
        Pump(backend_a, backend_b, stack_a, stack_b);

        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast;
        UInt64 rto_deadline;
        UInt32 front_seq, snd_una;
        UInt16 lp, rp;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        const UInt32 snd_una_hs = snd_una;  // post-handshake snd_una (legal baseline)
        std::fprintf(stderr, "[sndwl] handshake snd_una=0x%08X snd_wnd=%u\n", snd_una_hs, snd_wnd);
        CHECK(0 < snd_wnd);

        // Establish a legal snd_una benchmark: send data, get it ACKed.
        Byte payload1[1024];
        std::memset(payload1, 0x11, sizeof(payload1));
        CHECK(stack_a.Send(conn, payload1, sizeof(payload1)));
        for (UInt32 i = 0; i < 300 && received.size() < sizeof(payload1); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
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
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // advance delayed-ACK clock
        }
        std::fprintf(stderr, "[sndwl] after data ACK snd_una=0x%08X snd_wnd=%u\n", snd_una_after, snd_wnd);
        CHECK(snd_una_after != snd_una_hs);  // legal snd_una benchmark established
        const UInt32 snd_wnd_legit = snd_wnd;
        CHECK(0 < snd_wnd_legit);

        // Stale / out-of-order ACK (ack < snd_una) with a forged window=0:
        // RFC 793 SND.WL says this ACK must not update the send window.
        InjectWindow(backend_a, snd_una_hs, 0);
        Pump(backend_a, backend_b, stack_a, stack_b);

        UInt32 snd_una_probe = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una_probe, lp, rp);
        std::fprintf(stderr, "[sndwl] after stale window=0 ACK: snd_una=0x%08X snd_wnd=%u\n",
                     snd_una_probe, snd_wnd);
        CHECK(snd_una_probe == snd_una_after);  // genuinely stale: no ACK progress
        CHECK(snd_wnd == snd_wnd_legit);        // window update rejected (SND.WL guard)
        CHECK(0 < snd_wnd);                     // window not collapsed to 0

        // Transmission continues: the next send goes out and arrives intact.
        Byte payload2[2048];
        std::memset(payload2, 0x22, sizeof(payload2));
        CHECK(stack_a.Send(conn, payload2, sizeof(payload2)));
        const UInt32 total = sizeof(payload1) + sizeof(payload2);
        for (UInt32 i = 0; i < 300 && received.size() < total; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // delayed-ACK clock
        }
        CHECK(total == received.size());
        CHECK(0 == std::memcmp(received.data(), payload1, sizeof(payload1)));
        CHECK(0 == std::memcmp(received.data() + sizeof(payload1), payload2, sizeof(payload2)));
        std::fprintf(stderr, "[sndwl] transmission continued, %zu bytes delivered\n",
                     received.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WINDOW_SNDWL: FAILED (%d)\n" : "WINDOW_SNDWL: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_ts_paws.cpp
 * @brief RFC 7323 PAWS (Protection Against Wrapped Sequences): once the
 *        timestamps are negotiated, a segment whose TSval is older than
 *        TsRecent must be DROPPED even when its sequence number is
 *        perfectly in-order - without PAWS, a segment from before the 2^32
 *        sequence wrap is indistinguishable from new data (at 100Gbps a
 *        wrap takes ~34 seconds). The test negotiates the TSopt, streams
 *        data, injects an in-order segment with a stale TSval, and asserts
 *        it is silently dropped while the fresh stream continues.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // TSval wrap-boundary test: segment timing must be deterministic;
        // pin Reno so the rate-based KCC default does not shift the ACK
        // clock across the 24-bit wrap edge.
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

        std::atomic<UInt64> b_recv{0};
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });

        // The pump also re-injects A's segments so the test can inject the
        // stale-ts frame at the exact frontier.
        Byte out[65536];
        auto pump = [&]() {
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    backend_b.Inject(out, n, 0x0800);
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        const UInt64 conn = stack_a.Connect(client_ep, server_ep);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Stream 8KB so ts_recent_ advances (the peer's TSvals are the
        // millisecond clock, strictly increasing).
        const UInt32 kTotal = 8 * 1024;
        std::vector<Byte> payload(kTotal, 0x7B);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(kTotal == sent);
        CHECK(kTotal == b_recv.load());
        CHECK(0 == stack_a.ConnOutstandingSegments(conn));

        // Capture B's receive frontier from the ACK A last received: send 1
        // byte, drain the ACK back, parse its ack field (= rcv_nxt_ - 1).
        UInt32 frontier = 0;
        if (stack_a.Send(conn, payload.data(), 1)) {
            for (UInt32 i = 0; i < 100 && 0 == frontier; ++i) {
                pump();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                while (0 != backend_b.TxPending()) {
                    const UInt32 n = backend_b.PollTx(out);
                    if (0 < n && n >= 40) {
                        const Byte* t = out + 20;
                        frontier = (t[8] << 24) | (t[9] << 16) | (t[10] << 8) | t[11];
                        frontier -= 1;  // the probe byte itself
                    }
                }
            }
        }
        CHECK(0 != frontier);
        std::fprintf(stderr, "[paws] frontier=%08X\n", frontier);

        // Inject an IN-ORDER segment (seq == the exact frontier) carrying a
        // STALE TSval (ts=0, far older than ts_recent_). Without PAWS it
        // would be accepted as fresh data; PAWS must drop it silently.
        const UInt32 total = 20 + 32 + 512;
        Byte frame[1024];
        std::memset(frame, 0, sizeof(frame));
        frame[0] = 0x45;
        frame[2] = static_cast<Byte>(total >> 8);
        frame[3] = static_cast<Byte>(total & 0xFF);
        frame[8] = 64;
        frame[9] = 6;
        frame[12] = 0x0A; frame[13] = 0x00; frame[14] = 0x00; frame[15] = 0x01;
        frame[16] = 0xC0; frame[17] = 0xA8; frame[18] = 0x01; frame[19] = 0x02;
        frame[20] = 0x01; frame[21] = 0xBB;
        frame[22] = 0x9C; frame[23] = 0x40;
        frame[24] = static_cast<Byte>(frontier >> 24);
        frame[25] = static_cast<Byte>(frontier >> 16);
        frame[26] = static_cast<Byte>(frontier >> 8);
        frame[27] = static_cast<Byte>(frontier & 0xFF);
        frame[32] = 0x80;  // data offset 8 words
        frame[33] = 0x18;  // ACK|PSH
        frame[40] = 8;     // kind: TSopt
        frame[41] = 10;    // length
        // tsval = 0 (stale: SeqLt(0, ts_recent_)), tsecr = 0.
        frame[50] = 1;     // NOP
        frame[51] = 1;     // NOP
        std::memset(frame + 52, 0x7B, 512);  // payload

        const UInt64 recv_before = b_recv.load();
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
        CHECK(!buf.IsEmpty());
        std::memcpy(buf.Data(), frame, total);
        buf.SetLen(total);
        xtcp::ndi::Packet p;
        p.data = buf.Data();
        p.len = total;
        p.owned = std::move(buf);
        backend_b.Inject(std::move(p));
        pump();
        // PAWS must have dropped the stale frame: no bytes delivered.
        CHECK(recv_before == b_recv.load());

        // The connection is still healthy: fresh data flows.
        sent = 0;
        for (UInt32 i = 0; i < 3000 && sent < 2048; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        CHECK(2048 == sent);
        // The TLP-probe's dup-ACK gives the RTTM a real sample, arming the
        // ACK-clock pacing whose deadline can briefly gate the second
        // segment's flush. Wait out the pacing window before asserting.
        for (UInt32 i = 0; i < 200 && b_recv.load() < recv_before + 2048; ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(recv_before + 2048 == b_recv.load());
        std::fprintf(stderr, "[paws] stale dropped, fresh stream ok, total=%llu\n",
                     (unsigned long long)b_recv.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TS_PAWS: FAILED (%d)\n" : "TS_PAWS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_urgent.cpp
 * @brief RFC 793 urgent data (SO_OOBINLINE): an URG segment's payload
 *        rides the normal stream (delivered inline, byte-exact) and the
 *        application's urgent handler fires exactly once per URG segment.
 *        The urgent pointer semantics are informational in modern stacks;
 *        the notification is the out-of-band signal the app uses.
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
        // Timing-sensitive (the 1-byte frontier probe must leave on the ACK
        // clock): pin Reno so the default KCC's pacing gate cannot stall the
        // probe under load.
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
        std::atomic<UInt32> urgent_hits{0};
        stack_b.SetRecvHandler([&b_recv](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            return true;
        });
        stack_b.SetUrgentHandler([&urgent_hits](UInt64) {
            urgent_hits.fetch_add(1, std::memory_order_relaxed);
        });

        auto pump = [&]() {
            Byte out[65536];
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

        // Send 4KB (the first 2KB normal, then mark the next segment URG by
        // delivering it with the URG flag set).
        const UInt32 kTotal = 4 * 1024;
        std::vector<Byte> payload(kTotal, 0x5E);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));  // thrust the wall clock (pacing gate)
        }
        CHECK(kTotal == sent);
        CHECK(kTotal == b_recv.load());

        // Inject an URG segment directly: seq == the frontier, URG|PSH|ACK,
        // 256 bytes. The app must receive the bytes inline AND the urgent
        // handler must fire exactly once.
        const UInt32 total = 20 + 20 + 256;
        Byte frame[512];
        std::memset(frame, 0, sizeof(frame));
        frame[0] = 0x45;
        frame[2] = static_cast<Byte>(total >> 8);
        frame[3] = static_cast<Byte>(total & 0xFF);
        frame[8] = 64;
        frame[9] = 6;
        frame[12] = 0xC0; frame[13] = 0xA8; frame[14] = 0x01; frame[15] = 0x02;  // src = A's local
        frame[16] = 0x0A; frame[17] = 0x00; frame[18] = 0x00; frame[19] = 0x01;  // dst = server
        frame[20] = 0x9C; frame[21] = 0x40;  // sport 40000 (A's port)
        frame[22] = 0x01; frame[23] = 0xBB;  // dport 443 (server)
        // The sequence = the receiver's frontier. Derive it from the last
        // ACK A received (poll B's tx for the ACK of the last data).
        Byte out[65536];
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
                    }
                }
            }
        }
        CHECK(0 != frontier);
        std::fprintf(stderr, "[urgent] frontier=%08X\n", frontier);
        frame[24] = static_cast<Byte>(frontier >> 24);
        frame[25] = static_cast<Byte>(frontier >> 16);
        frame[26] = static_cast<Byte>(frontier >> 8);
        frame[27] = static_cast<Byte>(frontier & 0xFF);
        frame[32] = 0x50;  // data offset 5 (20-byte header)
        frame[33] = 0x38;  // URG|PSH|ACK
        frame[34] = 0xFF;  // urgent pointer (informational)
        frame[35] = 0x00;
        std::memset(frame + 40, 0x5E, 256);
        // XTCP_CHECKSUM_VALIDATE builds drop segments with invalid
        // checksums: fill the IPv4 header checksum and the TCP checksum
        // (pseudo-header included) of this hand-built frame.
        {
            frame[10] = 0;
            frame[11] = 0;
            {
                UInt32 sum = 0;
                for (UInt32 i = 0; i < 20; i += 2) {
                    sum += static_cast<UInt32>((frame[i] << 8) | frame[i + 1]);
                    while (0 != (sum >> 16)) {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                const UInt16 csum = static_cast<UInt16>(~sum & 0xFFFF);
                frame[10] = static_cast<Byte>(csum >> 8);
                frame[11] = static_cast<Byte>(csum & 0xFF);
            }
            const UInt32 tcp_len = total - 20;
            Byte pseudo[12];
            pseudo[0] = frame[12]; pseudo[1] = frame[13];
            pseudo[2] = frame[14]; pseudo[3] = frame[15];
            pseudo[4] = frame[16]; pseudo[5] = frame[17];
            pseudo[6] = frame[18]; pseudo[7] = frame[19];
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = static_cast<Byte>(tcp_len >> 8);
            pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
            frame[20 + 16] = 0;
            frame[20 + 17] = 0;
            {
                UInt32 sum = 0;
                for (UInt32 i = 0; i < 12; i += 2) {
                    sum += static_cast<UInt32>((pseudo[i] << 8) | pseudo[i + 1]);
                    while (0 != (sum >> 16)) {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                for (UInt32 i = 0; i < tcp_len; i += 2) {
                    sum += static_cast<UInt32>((frame[20 + i] << 8) | frame[20 + i + 1]);
                    while (0 != (sum >> 16)) {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                }
                const UInt16 csum = static_cast<UInt16>(~sum & 0xFFFF);
                frame[20 + 16] = static_cast<Byte>(csum >> 8);
                frame[20 + 17] = static_cast<Byte>(csum & 0xFF);
            }
        }

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

        // The urgent bytes arrived inline and the notification fired once.
        CHECK(recv_before + 256 == b_recv.load());
        CHECK(1 == urgent_hits.load());
        std::fprintf(stderr, "[urgent] recv=%llu hits=%u\n",
                     (unsigned long long)b_recv.load(), (unsigned)urgent_hits.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "URGENT: FAILED (%d)\n" : "URGENT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

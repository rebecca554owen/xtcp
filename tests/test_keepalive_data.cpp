/**
 * @file test_keepalive_data.cpp
 * @brief Keepalive + periodic data-transfer interaction (dual-stack).
 *
 * Scenario (mirrors test_keepalive.cpp semantics at the stack level):
 *   1) Data refresh prevents probes: while the application sends 256 B
 *      every 20 ms, every inbound segment (A's data on B, B's ACKs on A)
 *      refreshes last_rx_ (tcp_fsm.cpp:1689-1691), so the keepalive idle
 *      timer never expires - no probe fires, no Abort, both connections
 *      stay Established for the whole 200 ms run.
 *   2) A fired probe does not interfere with data: after an idle gap that
 *      lets the keepalive fire, the probe (a pure ACK, seq = snd_nxt_-1)
 *      is answered by the peer and the resumed data stream still arrives
 *      intact.
 *
 * Core assertions: connection alive (kEstablished on both sides) and
 * data integrity (byte count + CRC).
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

static bool g_count_probes = false;   // only count A->B probes during data phases
static UInt32 g_a_probes = 0;         // A->B pure-ACK (keepalive probe) count

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                if (g_count_probes && n >= 40 && 4 == (out[0] >> 4) && 6 == out[9]) {
                    const UInt32 ip_hdr = (out[0] & 0x0F) * 4;
                    const UInt32 tcp_hdr = ((out[ip_hdr + 12] >> 4) & 0x0F) * 4;
                    if (n >= ip_hdr + tcp_hdr && 0 == (n - ip_hdr - tcp_hdr)) {
                        ++g_a_probes;
                    }
                }
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

/** Rolling CRC over the sent stream: the same 256-byte chunk repeated.
 *  Stream byte at position i equals chunk[i % chunkLen], where chunk[j] =
 *  (j * 7 + j / 13) & 0xFF.  A continuous ramp would only match chunk[0..]. */
static UInt32 CrcPattern(UInt32 count, UInt32 chunkLen) {
    UInt32 crc = 0;
    for (UInt32 i = 0; i < count; ++i) {
        const UInt32 j = i % chunkLen;
        const Byte b = static_cast<Byte>((j * 7 + j / 13) & 0xFF);
        crc = (crc * 31 + b) & 0x7FFFFFFF;
    }
    return crc;
}

int main() {
    xtcp::buf::InitPools();

    const UInt32 kChunk = 256;
    const UInt32 kIdleUs = 80000;    // short idle: an idle conn aborts ~170 ms in
    const UInt32 kIntvlUs = 30000;
    const UInt32 kCnt = 3;
    const UInt32 kRunMs = 200;

    // ---- Scenario 1: data flow (256 B / 20 ms) prevents probes/Abort ----
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
        UInt64 conn_b = 0;
        UInt32 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40321;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9216;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        stack_a.SetKeepalive(conn_a, kIdleUs, kIntvlUs, kCnt);
        stack_b.SetKeepalive(conn_b, kIdleUs, kIntvlUs, kCnt);
        Int32 on = 1;
        CHECK(stack_a.SetOption(conn_a, xtcp::options::kTcpNodelay, &on, sizeof(on)));

        // Drain handshake residue, then count A->B probes only from here.
        Pump(backend_a, backend_b, stack_a, stack_b);
        g_count_probes = true;
        g_a_probes = 0;

        std::vector<Byte> chunk(kChunk);
        for (UInt32 i = 0; i < kChunk; ++i) {
            chunk[i] = static_cast<Byte>((i * 7 + i / 13) & 0xFF);
        }
        UInt32 sent = 0;
        const auto t_start = std::chrono::steady_clock::now();
        const auto t_end = t_start + std::chrono::milliseconds(kRunMs);
        auto next_send = t_start + std::chrono::milliseconds(20);
        while (std::chrono::steady_clock::now() < t_end) {
            if (std::chrono::steady_clock::now() >= next_send) {
                CHECK(stack_a.Send(conn_a, chunk.data(), kChunk));
                sent += kChunk;
                next_send += std::chrono::milliseconds(20);
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        g_count_probes = false;
        for (UInt32 i = 0; i < 300 && bytes_recv < sent; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        std::fprintf(stderr, "[ka-data] sent=%u recv=%u a_probes=%u\n",
                     sent, bytes_recv, g_a_probes);
        // Connection alive: data flow prevented probe -> no Abort.
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        // Data refresh kept last_rx_ fresh: no keepalive probe was emitted.
        CHECK(0 == g_a_probes);
        // Data integrity: byte count + content.
        CHECK(sent == bytes_recv);
        CHECK(CrcPattern(sent, kChunk) == crc_recv);
    }

    // ---- Scenario 2: a fired probe does not interfere with data ----
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
        UInt64 conn_b = 0;
        UInt32 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40322;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9217;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn_a = stack_a.Connect(local, remote);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        stack_a.SetKeepalive(conn_a, kIdleUs, kIntvlUs, kCnt);
        stack_b.SetKeepalive(conn_b, kIdleUs, kIntvlUs, kCnt);
        Int32 on = 1;
        CHECK(stack_a.SetOption(conn_a, xtcp::options::kTcpNodelay, &on, sizeof(on)));
        Pump(backend_a, backend_b, stack_a, stack_b);

        std::vector<Byte> chunk(kChunk);
        for (UInt32 i = 0; i < kChunk; ++i) {
            chunk[i] = static_cast<Byte>((i * 7 + i / 13) & 0xFF);
        }

        // Phase 1: baseline data (3 chunks at 20 ms cadence).
        UInt32 sent = 0;
        g_count_probes = true;
        g_a_probes = 0;
        const auto t0 = std::chrono::steady_clock::now();
        auto next_send = t0 + std::chrono::milliseconds(20);
        const auto t_end = t0 + std::chrono::milliseconds(60);
        while (std::chrono::steady_clock::now() < t_end) {
            if (std::chrono::steady_clock::now() >= next_send) {
                CHECK(stack_a.Send(conn_a, chunk.data(), kChunk));
                sent += kChunk;
                next_send += std::chrono::milliseconds(20);
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (UInt32 i = 0; i < 100 && bytes_recv < sent; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(sent == bytes_recv);

        // Phase 2: idle gap > idle (80 ms) with keepalive armed: a probe
        // fires and is answered - it must NOT kill the connection.
        const auto t_gap = std::chrono::steady_clock::now() + std::chrono::milliseconds(120);
        while (std::chrono::steady_clock::now() < t_gap) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[ka-data] probe gap a_probes=%u\n", g_a_probes);
        CHECK(0 < g_a_probes);  // keepalive is armed: it fired during the gap
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));

        // Phase 3: resume data - the earlier probe must not have disturbed
        // the stream (byte count + CRC over the whole transfer).
        const auto t1 = std::chrono::steady_clock::now();
        next_send = t1;
        const auto t_end2 = t1 + std::chrono::milliseconds(100);
        while (std::chrono::steady_clock::now() < t_end2) {
            if (std::chrono::steady_clock::now() >= next_send) {
                CHECK(stack_a.Send(conn_a, chunk.data(), kChunk));
                sent += kChunk;
                next_send += std::chrono::milliseconds(20);
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        g_count_probes = false;
        for (UInt32 i = 0; i < 300 && bytes_recv < sent; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        std::fprintf(stderr, "[ka-data] post-gap sent=%u recv=%u\n", sent, bytes_recv);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        CHECK(sent == bytes_recv);
        CHECK(CrcPattern(sent, kChunk) == crc_recv);
    }

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "KEEPALIVE_DATA: FAILED (%d)\n" : "KEEPALIVE_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

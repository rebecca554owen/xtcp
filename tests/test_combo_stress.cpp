/**
 * @file test_combo_stress.cpp
 * @brief Combined stress: two scenarios in one binary.
 *
 * Scenario A - 4 concurrent bidirectional flows, 2 closed mid-way
 *   (half-close mix):
 *   4 connections stream 64 KiB A->B and B->A simultaneously. Mid-transfer,
 *   2 of them are closed from A (data in flight, FIN goes out); B answers on
 *   the half-close receive side (CLOSE-WAIT -> B Close). The surviving 2
 *   connections must deliver their full 64 KiB in BOTH directions intact
 *   (byte count + CRC), and every connection must be reclaimed
 *   (ConnectionCount == 0 on both stacks after the 2*MSL drain).
 *
 * Scenario B - single flow under packet loss, recovery intact:
 *   One connection streams 192 KiB A->B through a path that blackholes every
 *   100th FIRST-SEEN data segment (retransmissions pass, per
 *   test_multi_drop.cpp). The stream must recover (SACK/RTO) and deliver the
 *   full payload (byte count + CRC), with the loss demonstrably having
 *   occurred (>= 1 segment dropped).
 *
 * Both scenarios stay well under 60 s: transfers are bounded by chunked
 * Send with retry, and every drain loop is capped (Pump rounds <= 1000,
 * 1 ms sleeps).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                 \
    } while (0)

namespace {
    constexpr UInt32 kChunk = 1460;
}

// Lossless pump: drain both directions + advance timers (test_mixed_load).
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

// Lossy pump: drop every Nth first-seen data segment (test_multi_drop).
static void PumpDropEvery(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                          UInt32 drop_every, UInt32& seen, std::vector<UInt32>& dropped_seqs) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        const bool data = (got > 33) && (0 != (out[33] & 0x08));
        bool drop = false;
        if (data && 0 != drop_every) {
            const UInt32 seq = (static_cast<UInt32>(out[24]) << 24) |
                               (static_cast<UInt32>(out[25]) << 16) |
                               (static_cast<UInt32>(out[26]) << 8) |
                               static_cast<UInt32>(out[27]);
            const bool is_retx =
                std::find(dropped_seqs.begin(), dropped_seqs.end(), seq) != dropped_seqs.end();
            if (!is_retx && 0 == ((++seen) % drop_every)) {
                drop = true;
            }
            if (drop) {
                dropped_seqs.push_back(seq);
            }
        }
        if (drop) {
            continue;  // blackhole
        }
        to.Inject(out, got, 0x0800);
        if (20000 < ++guard) {
            break;
        }
    }
}

// Send one kChunk slice with bounded retry; pumps after each attempt.
template <typename TPump>
static bool SendChunk(xtcp::XtcpStack& st, UInt64 id, const Byte* data, UInt32 n,
                      TPump& pump) {
    UInt32 g = 0;
    while (!st.Send(id, data, n) && 500 > ++g) {
        pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return 500 > g;
}

static void RunScenarioA() {
    constexpr UInt32 kConns = 4;
    constexpr UInt32 kBytes = 64 * 1024;
    constexpr UInt32 kHalf = kBytes / 2;

    xtcp::ndi::ManualBackend ba, bb;
    xtcp::XtcpStack sa(&ba), sb(&bb);
    sa.SetTwoMsl(20000);
    sb.SetTwoMsl(20000);
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });

    std::mutex mx;
    std::map<UInt64, UInt32> crc_ra, crc_rb;
    std::map<UInt64, UInt64> bytes_ra, bytes_rb;
    std::vector<UInt64> order_b;

    sb.SetStateHandler([&mx, &order_b, &sb](UInt64 id, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kEstablished == st) {
            std::lock_guard<std::mutex> g(mx);
            order_b.push_back(id);
        }
        if (xtcp::core::TcpState::kCloseWait == st) {
            sb.Close(id);
        }
    });
    sb.SetRecvHandler([&mx, &crc_rb, &bytes_rb](UInt64 id, const Byte* d, UInt32 len) {
        std::lock_guard<std::mutex> g(mx);
        bytes_rb[id] += len;
        UInt32& crc = crc_rb[id];
        for (UInt32 j = 0; j < len; ++j) {
            crc = (crc * 31 + d[j]) & 0x7FFFFFFF;
        }
    });
    sa.SetRecvHandler([&mx, &crc_ra, &bytes_ra](UInt64 id, const Byte* d, UInt32 len) {
        std::lock_guard<std::mutex> g(mx);
        bytes_ra[id] += len;
        UInt32& crc = crc_ra[id];
        for (UInt32 j = 0; j < len; ++j) {
            crc = (crc * 31 + d[j]) & 0x7FFFFFFF;
        }
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 41000;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9200;
    CHECK(sb.Listen(remote));

    // Distinct payload per flow in each direction.
    std::vector<std::vector<Byte>> pa(kConns), pb(kConns);
    std::vector<UInt32> crc_a_exp(kConns, 0), crc_b_exp(kConns, 0);
    for (UInt32 f = 0; f < kConns; ++f) {
        pa[f].resize(kBytes);
        pb[f].resize(kBytes);
        for (UInt32 i = 0; i < kBytes; ++i) {
            pa[f][i] = static_cast<Byte>((i * (f + 1) + i / 3 + f * 7) & 0xFF);
            crc_a_exp[f] = (crc_a_exp[f] * 31 + pa[f][i]) & 0x7FFFFFFF;
            pb[f][i] = static_cast<Byte>((i * 13 + i / (f + 2) + f * 5 + 1) & 0xFF);
            crc_b_exp[f] = (crc_b_exp[f] * 31 + pb[f][i]) & 0x7FFFFFFF;
        }
    }

    // Open all 4 connections, handshake in SYN order.
    std::vector<UInt64> conns(kConns);
    for (UInt32 f = 0; f < kConns; ++f) {
        local.port = static_cast<UInt16>(41000 + f);
        conns[f] = sa.Connect(local, remote);
        CHECK(0 != conns[f]);
    }
    for (UInt32 i = 0; i < 300 && order_b.size() < kConns; ++i) {
        Pump(ba, bb, sa, sb);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(kConns == order_b.size());
    const std::vector<UInt64> conn_b = order_b;  // acceptance order == open order

    auto pump = [&]() { Pump(ba, bb, sa, sb); };

    // Phase 1: A->B half on all 4.
    std::vector<UInt64> sent_a(kConns, 0);
    for (UInt32 f = 0; f < kConns; ++f) {
        while (sent_a[f] < kHalf) {
            const UInt32 n = static_cast<UInt32>(
                std::min<UInt64>(kChunk, kHalf - sent_a[f]));
            CHECK(SendChunk(sa, conns[f], pa[f].data() + sent_a[f], n, pump));
            sent_a[f] += n;
            pump();
        }
    }
    // Phase 2: B->A half on all 4.
    std::vector<UInt64> sent_b(kConns, 0);
    for (UInt32 f = 0; f < kConns; ++f) {
        while (sent_b[f] < kHalf) {
            const UInt32 n = static_cast<UInt32>(
                std::min<UInt64>(kChunk, kHalf - sent_b[f]));
            CHECK(SendChunk(sb, conn_b[f], pb[f].data() + sent_b[f], n, pump));
            sent_b[f] += n;
            pump();
        }
    }
    // Phase 3: close 2 connections mid-way (data in flight, FIN goes out).
    sa.Close(conns[1]);
    sa.Close(conns[3]);
    for (UInt32 i = 0; i < 200; ++i) {
        pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // Phase 4/5: complete the surviving 2 connections (0, 2) to full 64 KiB.
    for (UInt32 f = 0; f < kConns; f += 2) {
        while (sent_a[f] < kBytes) {
            const UInt32 n = static_cast<UInt32>(
                std::min<UInt64>(kChunk, kBytes - sent_a[f]));
            CHECK(SendChunk(sa, conns[f], pa[f].data() + sent_a[f], n, pump));
            sent_a[f] += n;
            pump();
        }
        while (sent_b[f] < kBytes) {
            const UInt32 n = static_cast<UInt32>(
                std::min<UInt64>(kChunk, kBytes - sent_b[f]));
            CHECK(SendChunk(sb, conn_b[f], pb[f].data() + sent_b[f], n, pump));
            sent_b[f] += n;
            pump();
        }
    }

    // Wait for the surviving flows to deliver fully.
    for (UInt32 i = 0; i < 1000; ++i) {
        bool done = true;
        {
            std::lock_guard<std::mutex> g(mx);
            for (UInt32 f = 0; f < kConns; f += 2) {
                if (kBytes != bytes_rb[conn_b[f]] || kBytes != bytes_ra[conns[f]]) {
                    done = false;
                    break;
                }
            }
        }
        if (done) {
            break;
        }
        pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Survivors intact (byte count + CRC) in both directions.
    {
        std::lock_guard<std::mutex> g(mx);
        for (UInt32 f = 0; f < kConns; f += 2) {
            CHECK(kBytes == bytes_rb[conn_b[f]]);
            CHECK(crc_a_exp[f] == crc_rb[conn_b[f]]);
            CHECK(kBytes == bytes_ra[conns[f]]);
            CHECK(crc_b_exp[f] == crc_ra[conns[f]]);
        }
    }

    // Close the survivors; drain until everything is reclaimed.
    sa.Close(conns[0]);
    sa.Close(conns[2]);
    for (UInt32 i = 0;
         i < 800 && (0 != sa.ConnectionCount() || 0 != sb.ConnectionCount()); ++i) {
        pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::fprintf(stderr,
                 "[combo-A] conns A=%u B=%u bytes(0,2): a_rx=%llu/%llu b_rx=%llu/%llu\n",
                 (UInt32)sa.ConnectionCount(), (UInt32)sb.ConnectionCount(),
                 (unsigned long long)bytes_ra[conns[0]],
                 (unsigned long long)bytes_ra[conns[2]],
                 (unsigned long long)bytes_rb[conn_b[0]],
                 (unsigned long long)bytes_rb[conn_b[2]]);
    CHECK(0 == sa.ConnectionCount());
    CHECK(0 == sb.ConnectionCount());
}

static void RunScenarioB() {
    constexpr UInt32 kLossyBytes = 192 * 1024;  // 132 segs -> >= 1 drop at /100

    xtcp::ndi::ManualBackend ba, bb;
    xtcp::XtcpStack sa(&ba), sb(&bb);
    sa.SetTwoMsl(20000);
    sb.SetTwoMsl(20000);
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });

    UInt64 recv_b = 0;
    UInt32 crc_b = 0;
    sb.SetRecvHandler([&recv_b, &crc_b](UInt64, const Byte* d, UInt32 len) {
        recv_b += len;
        for (UInt32 j = 0; j < len; ++j) {
            crc_b = (crc_b * 31 + d[j]) & 0x7FFFFFFF;
        }
    });
    sb.SetStateHandler([&sb](UInt64 id, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kCloseWait == st) {
            sb.Close(id);
        }
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 41100;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9201;
    CHECK(sb.Listen(remote));

    const UInt64 c = sa.Connect(local, remote);
    CHECK(0 != c);
    UInt32 seen = 0;
    std::vector<UInt32> drop_seqs;
    for (UInt32 i = 0; i < 300; ++i) {
        PumpDropEvery(ba, bb, 0, seen, drop_seqs);
        PumpDropEvery(bb, ba, 0, seen, drop_seqs);
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (xtcp::core::TcpState::kEstablished == sa.ConnectionState(c)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(xtcp::core::TcpState::kEstablished == sa.ConnectionState(c));

    std::vector<Byte> payload(kLossyBytes);
    UInt32 crc_exp = 0;
    for (UInt32 i = 0; i < kLossyBytes; ++i) {
        payload[i] = static_cast<Byte>((i * 17 + i / 11) & 0xFF);
        crc_exp = (crc_exp * 31 + payload[i]) & 0x7FFFFFFF;
    }

    // Stream through a path that drops every 100th first-seen segment.
    UInt64 sent = 0;
    while (sent < kLossyBytes) {
        const UInt32 n = static_cast<UInt32>(
            std::min<UInt64>(kChunk, kLossyBytes - sent));
        UInt32 g = 0;
        while (!sa.Send(c, payload.data() + sent, n) && 500 > ++g) {
            PumpDropEvery(ba, bb, 100, seen, drop_seqs);
            PumpDropEvery(bb, ba, 0, seen, drop_seqs);
            sa.PollAckTimers();
            sb.PollAckTimers();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(500 > g);
        sent += n;
        PumpDropEvery(ba, bb, 100, seen, drop_seqs);
        PumpDropEvery(bb, ba, 0, seen, drop_seqs);
        sa.PollAckTimers();
        sb.PollAckTimers();
    }
    // Drain: lossy recovery needs RTO/SACK to make progress.
    for (UInt32 i = 0; i < 1500 && recv_b < kLossyBytes; ++i) {
        PumpDropEvery(ba, bb, 100, seen, drop_seqs);
        PumpDropEvery(bb, ba, 0, seen, drop_seqs);
        sa.PollAckTimers();
        sb.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::fprintf(stderr, "[combo-B] recv=%llu expect=%u dropped=%u crc_ok=%d\n",
                 (unsigned long long)recv_b, kLossyBytes,
                 (UInt32)drop_seqs.size(), (crc_b == crc_exp) ? 1 : 0);
    CHECK(kLossyBytes == recv_b);
    CHECK(crc_exp == crc_b);
    CHECK(0 != drop_seqs.size());  // the loss path actually dropped something

    sa.Close(c);
    for (UInt32 i = 0;
         i < 800 && (0 != sa.ConnectionCount() || 0 != sb.ConnectionCount()); ++i) {
        PumpDropEvery(ba, bb, 0, seen, drop_seqs);
        PumpDropEvery(bb, ba, 0, seen, drop_seqs);
        sa.PollAckTimers();
        sb.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(0 == sa.ConnectionCount());
    CHECK(0 == sb.ConnectionCount());
}

int main() {
    xtcp::buf::InitPools();
    {
        RunScenarioA();
        RunScenarioB();
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "COMBO_STRESS: FAILED (%d)\n" : "COMBO_STRESS: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

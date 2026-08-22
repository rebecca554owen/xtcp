/**
 * @file test_bidi_1mb.cpp
 * @brief Bidirectional simultaneous 1 MiB stream transfer with full binary
 *        comparison against independent TMP files.
 *
 * test_1mb_stream is unidirectional (A -> B only). This test drives A -> B
 * and B -> A AT THE SAME TIME over one connection. Each direction uses a
 * DIFFERENT deterministic byte pattern so that cross-direction contamination
 * (A's bytes leaking into B's stream or vice versa) is detectable:
 *   A -> B payload: byte i = (i*31 + i/7) & 0xFF
 *   B -> A payload: byte i = (i*17 + i/11) & 0xFF
 * A reordered/duplicated/lost byte changes the file content, and because the
 * two patterns differ, any stream crosstalk breaks the memcmp comparison.
 *
 * Files (all under TMP):
 *   send_a.bin + recv_b.bin  -> A->B direction (sender A / receiver B)
 *   send_b.bin + recv_a.bin  -> B->A direction (sender B / receiver A)
 * Each direction is compared full binary: size equal (1048576) + every block
 * memcmp-equal.
 *
 * Scenarios:
 *   1. lossless baseline (drop_every = 0)
 *   2. lossy (1/100 first-seen data segments dropped per direction) - SACK /
 *      RTO recovery must still deliver identical files in BOTH directions.
 * Drop bookkeeping is per direction (independent first_seen/dropped vectors)
 * so a drop on A->B can never be confused with a retransmit on B->A.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
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

/** Pumps one direction with an optional 1/N drop policy on first-seen data
 *  segments (retransmits of a previously dropped seq pass). Returns true if
 *  at least one segment was forwarded. */
static bool PumpDir(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                    UInt32 kDropEvery, UInt32& first_seen, std::vector<UInt32>& dropped) {
    bool moved = false;
    Byte out[65536];
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        const UInt32 tcp_off = 20;
        const bool data = (got > tcp_off + 13) && (0 != (out[tcp_off + 13] & 0x08));
        bool drop = false;
        if (data) {
            const UInt32 seq = (static_cast<UInt32>(out[tcp_off + 4]) << 24) |
                               (static_cast<UInt32>(out[tcp_off + 5]) << 16) |
                               (static_cast<UInt32>(out[tcp_off + 6]) << 8) |
                               static_cast<UInt32>(out[tcp_off + 7]);
            const bool is_retransmit =
                std::find(dropped.begin(), dropped.end(), seq) != dropped.end();
            if (!is_retransmit) {
                ++first_seen;
                if (0 != kDropEvery && 0 == (first_seen % kDropEvery)) {
                    drop = true;
                    dropped.push_back(seq);
                }
            }
        }
        if (!drop) {
            to.Inject(out, got, 0x0800);
            moved = true;
        }
    }
    return moved;
}

/** One pump round for both directions with per-direction drop policy. */
static void PumpRound(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb,
                      UInt32 kDropEvery, UInt32& first_seen_ab, std::vector<UInt32>& dropped_ab,
                      UInt32& first_seen_ba, std::vector<UInt32>& dropped_ba) {
    for (UInt32 round = 0; round < 1000; ++round) {
        const bool moved_ab = PumpDir(a, b, kDropEvery, first_seen_ab, dropped_ab);
        const bool moved_ba = PumpDir(b, a, kDropEvery, first_seen_ba, dropped_ba);
        sa.PollAckTimers();
        sb.PollAckTimers();
        if (!moved_ab && !moved_ba) {
            return;
        }
    }
}

/** Writes the full received stream to a file (binary). */
static void WriteFile(const std::string& path, const std::vector<Byte>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    f.close();
}

/** Reads a file fully (binary); returns false on failure. */
static bool ReadFile(const std::string& path, std::vector<Byte>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(sz));
    if (0 < sz) {
        f.read(reinterpret_cast<char*>(out.data()), sz);
    }
    return true;
}

/** Full binary comparison: sizes equal + every block memcmp-equal. */
static void AssertFilesEqual(const char* label, const std::string& send_path,
                             const std::string& recv_path, UInt32 expect_size) {
    std::vector<Byte> sent, recv;
    CHECK(ReadFile(send_path, sent));
    CHECK(ReadFile(recv_path, recv));
    if (sent.empty() || recv.empty()) {
        return;
    }
    CHECK(expect_size == sent.size());
    CHECK(expect_size == recv.size());
    const std::size_t n = (sent.size() < recv.size()) ? sent.size() : recv.size();
    std::size_t first_bad = n;
    for (std::size_t i = 0; i < n; ++i) {
        if (sent[i] != recv[i]) {
            first_bad = i;
            break;
        }
    }
    CHECK(n == first_bad);
    std::fprintf(stderr, "[bidi:%s] compare send=%zu recv=%zu first_bad=%zu %s\n",
                 label, sent.size(), recv.size(), first_bad,
                 (n == first_bad && expect_size == sent.size() && expect_size == recv.size())
                     ? "IDENTICAL" : "MISMATCH");
}

/** Runs one bidirectional 1 MiB transfer. */
static void RunBidi(const char* tag, UInt32 drop_every, const std::string& send_a_path,
                    const std::string& recv_b_path, const std::string& send_b_path,
                    const std::string& recv_a_path) {
    constexpr UInt32 kTotal = 1024 * 1024;
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
    std::vector<Byte> received_b;  // A->B payload arrives at B
    std::vector<Byte> received_a;  // B->A payload arrives at A
    received_b.reserve(kTotal);
    received_a.reserve(kTotal);
    stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kEstablished == st) {
            conn_b = id;
        }
    });
    stack_b.SetRecvHandler([&received_b](UInt64, const Byte* d, UInt32 n) {
        received_b.insert(received_b.end(), d, d + n);
    });
    stack_a.SetRecvHandler([&received_a](UInt64, const Byte* d, UInt32 n) {
        received_a.insert(received_a.end(), d, d + n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40500;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9180;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn_a = stack_a.Connect(local, remote);
    CHECK(0 != conn_a);
    UInt32 fs_ab = 0, fs_ba = 0;
    std::vector<UInt32> dropped_ab, dropped_ba;
    PumpRound(backend_a, backend_b, stack_a, stack_b, 0, fs_ab, dropped_ab, fs_ba, dropped_ba);
    CHECK(0 != conn_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

    // Deterministic payloads, different pattern per direction so crosstalk is
    // detectable: A->B byte i = (i*31 + i/7) & 0xFF, B->A = (i*17 + i/11) & 0xFF.
    std::vector<Byte> payload_ab(kTotal);
    std::vector<Byte> payload_ba(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload_ab[i] = static_cast<Byte>((i * 31 + i / 7) & 0xFF);
        payload_ba[i] = static_cast<Byte>((i * 17 + i / 11) & 0xFF);
    }
    WriteFile(send_a_path, payload_ab);
    WriteFile(send_b_path, payload_ba);

    // Send both directions simultaneously, pumping each direction with its own
    // drop policy (independent counters). Time-based budget: the send loop
    // must advance the wall clock (1ms sleeps) so the 200ms RTO floor fires
    // for dropped segments - an iteration-only budget spins without recovery
    // under loss and stalls the transfer (Linux-tight guard class).
    UInt32 sent_ab = 0, sent_ba = 0;
    const UInt32 guard_max = 600000;
    UInt32 guard = 0;
    const auto send_t0 = std::chrono::steady_clock::now();
    while ((sent_ab < kTotal || sent_ba < kTotal) &&
           60000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - send_t0).count() &&
           guard_max > ++guard) {
        if (sent_ab < kTotal) {
            const UInt32 chunk = (kTotal - sent_ab < 4096) ? (kTotal - sent_ab) : 4096;
            if (stack_a.Send(conn_a, payload_ab.data() + sent_ab, chunk)) {
                sent_ab += chunk;
            }
        }
        if (sent_ba < kTotal) {
            const UInt32 chunk = (kTotal - sent_ba < 4096) ? (kTotal - sent_ba) : 4096;
            if (stack_b.Send(conn_b, payload_ba.data() + sent_ba, chunk)) {
                sent_ba += chunk;
            }
        }
        PumpRound(backend_a, backend_b, stack_a, stack_b, drop_every,
                  fs_ab, dropped_ab, fs_ba, dropped_ba);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // Drain until BOTH receivers have everything (time-based: 6000 x 1ms is
    // 6s on Linux but ~94s on Windows - the recovery tail under 1% loss
    // needs 200ms+ RTO cycles).
    const auto drain_t0 = std::chrono::steady_clock::now();
    for (UInt32 i = 0; i < 600000 && (received_b.size() < kTotal || received_a.size() < kTotal) &&
            60000 > std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - drain_t0).count(); ++i) {
        PumpRound(backend_a, backend_b, stack_a, stack_b, drop_every,
                  fs_ab, dropped_ab, fs_ba, dropped_ba);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(kTotal == sent_ab);
    CHECK(kTotal == sent_ba);
    CHECK(kTotal == received_b.size());
    CHECK(kTotal == received_a.size());
    if (0 != drop_every) {
        CHECK(0 < dropped_ab.size() + dropped_ba.size());  // the policy dropped something
    }
    WriteFile(recv_b_path, received_b);
    WriteFile(recv_a_path, received_a);
    AssertFilesEqual("a->b", send_a_path, recv_b_path, kTotal);
    AssertFilesEqual("b->a", send_b_path, recv_a_path, kTotal);

    stack_a.Close(conn_a);
    stack_b.Close(conn_b);
    for (UInt32 i = 0; i < 200; ++i) {
        PumpRound(backend_a, backend_b, stack_a, stack_b, 0,
                  fs_ab, dropped_ab, fs_ba, dropped_ba);
    }
    std::fprintf(stderr, "[bidi] %s sent_ab=%u sent_ba=%u recv_b=%zu recv_a=%zu "
                 "dropped_ab=%u dropped_ba=%u\n",
                 tag, sent_ab, sent_ba, received_b.size(), received_a.size(),
                 static_cast<UInt32>(dropped_ab.size()),
                 static_cast<UInt32>(dropped_ba.size()));
}

int main() {
    xtcp::buf::InitPools();
    const char* tmp = std::getenv("TMP");
    if (NULLPTR == tmp || 0 == *tmp) {
        tmp = ".";
    }
    const std::string base = std::string(tmp) + "/xtcp_bidi_1mb_test";
    {
        const std::string send_a = base + "_lossless_send_a.bin";
        const std::string recv_b = base + "_lossless_recv_b.bin";
        const std::string send_b = base + "_lossless_send_b.bin";
        const std::string recv_a = base + "_lossless_recv_a.bin";
        RunBidi("lossless", 0, send_a, recv_b, send_b, recv_a);
    }
    {
        const std::string send_a = base + "_lossy_send_a.bin";
        const std::string recv_b = base + "_lossy_recv_b.bin";
        const std::string send_b = base + "_lossy_send_b.bin";
        const std::string recv_a = base + "_lossy_recv_a.bin";
        RunBidi("lossy-1/100", 100, send_a, recv_b, send_b, recv_a);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TEST_BIDI_1MB: FAILED (%d)\n" : "TEST_BIDI_1MB: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

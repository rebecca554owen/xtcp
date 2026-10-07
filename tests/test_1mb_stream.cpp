/**
 * @file test_1mb_stream.cpp
 * @brief 1 MiB single-direction stream transfer with full binary comparison
 *        against a TMP file (detects reordering that echo cannot).
 *
 * Echo round-trips mask stream reordering: both directions are interleaved,
 * so a duplicated/permuted byte may still echo back "correctly" per side. A
 * unidirectional 1 MiB transfer written to disk and compared byte-for-byte
 * against the sender's file proves the delivered stream is EXACTLY the sent
 * stream - same length, same order, no loss, no duplication, no reorder.
 *
 * Scenario:
 *   1. A generates a deterministic 1 MiB payload (unique per position so any
 *      reorder/dup/loss changes the file) and writes it to TMP/send.bin.
 *   2. A -> B transfers the full 1 MiB over a dual-stack ManualBackend.
 *   3. B writes every received byte to TMP/recv.bin.
 *   4. Assert: both files exist, sizes equal (1048576), and every block
 *      memcmp-equal - a full binary comparison, not just a rolling CRC.
 *
 * The transfer runs twice: lossless (baseline) and with 1/1000 segment loss
 * (SACK/RTO recovery must still deliver the identical file).
 */

#define _CRT_SECURE_NO_WARNINGS

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

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

/** Lossy pump: drops every kDropEvery'th first-seen data segment (retx passes). */
static void PumpDrop(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
                     UInt32 kDropEvery, UInt32& first_seen, std::vector<UInt32>& dropped) {
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
static void AssertFilesEqual(const std::string& send_path, const std::string& recv_path,
                             UInt32 expect_size) {
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
    std::fprintf(stderr, "[1mb] compare send=%zu recv=%zu first_bad=%zu %s\n",
                 sent.size(), recv.size(), first_bad,
                 (n == first_bad && expect_size == sent.size() && expect_size == recv.size())
                     ? "IDENTICAL" : "MISMATCH");
}

static void Run1MiB(const char* tag, UInt32 drop_every, const std::string& send_path,
                    const std::string& recv_path) {
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
    std::vector<Byte> received;
    received.reserve(kTotal);
    stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kEstablished == st) {
            conn_b = id;
        }
    });
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.insert(received.end(), d, d + n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40300;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 9180;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(0 != conn_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    // Deterministic payload: byte i = (i*31 + i/7) & 0xFF. Unique-ish per
    // position: any reorder/dup/loss changes the file content.
    std::vector<Byte> payload(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload[i] = static_cast<Byte>((i * 31 + i / 7) & 0xFF);
    }
    WriteFile(send_path, payload);

    // Send the full 1 MiB (chunked), pumping with the drop policy.
    // The hang guard is WALL-CLOCK, not iterations: with burst-driven pacing
    // (patch 0005) a no-progress iteration is nearly free, so an iteration
    // count cannot bound the transfer time - loss recovery is RTO/RACK-paced
    // (hundreds of ms), which a fast-spinning iteration budget can undershoot.
    UInt32 sent = 0, first_seen = 0;
    std::vector<UInt32> dropped;
    const auto send_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (sent < kTotal && std::chrono::steady_clock::now() < send_deadline) {
        const UInt32 chunk = (kTotal - sent < 4096) ? (kTotal - sent) : 4096;
        const UInt32 prev_sent = sent;
        const std::size_t prev_recv = received.size();
        if (stack_a.Send(conn, payload.data() + sent, chunk)) {
            sent += chunk;
        }
        PumpDrop(backend_a, backend_b, drop_every, first_seen, dropped);
        PumpDrop(backend_b, backend_a, drop_every, first_seen, dropped);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        if (prev_sent == sent && prev_recv == received.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    // Drain until the receiver has everything.
    for (UInt32 i = 0; i < 4000 && received.size() < kTotal; ++i) {
        PumpDrop(backend_a, backend_b, drop_every, first_seen, dropped);
        PumpDrop(backend_b, backend_a, drop_every, first_seen, dropped);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(kTotal == sent);
    CHECK(kTotal == received.size());
    if (0 != drop_every) {
        CHECK(0 < dropped.size());  // the policy must have dropped something
    }
    WriteFile(recv_path, received);
    AssertFilesEqual(send_path, recv_path, kTotal);

    stack_a.Close(conn);
    stack_b.Close(conn_b);
    for (UInt32 i = 0; i < 200; ++i) {
        Pump(backend_a, backend_b, stack_a, stack_b);
    }
    std::fprintf(stderr, "[1mb] %s sent=%u recv=%zu dropped=%u\n",
                 tag, sent, received.size(), static_cast<UInt32>(dropped.size()));
}

int main() {
    xtcp::buf::InitPools();
    const char* tmp = std::getenv("TMP");
    if (NULLPTR == tmp || 0 == *tmp) {
        tmp = ".";
    }
    const std::string base = std::string(tmp) + "/xtcp_1mb_stream_test";
    {
        const std::string send_path = base + "_lossless_send.bin";
        const std::string recv_path = base + "_lossless_recv.bin";
        Run1MiB("lossless", 0, send_path, recv_path);
    }
    {
        const std::string send_path = base + "_lossy_send.bin";
        const std::string recv_path = base + "_lossy_recv.bin";
        Run1MiB("lossy-1/100", 100, send_path, recv_path);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TEST_1MB_STREAM: FAILED (%d)\n" : "TEST_1MB_STREAM: ALL PASSED\n",
                 g_failures);
    return g_failures ? 1 : 0;
}

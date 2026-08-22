/**
 * @file test_tcp_retransmit.cpp
 * @brief Retransmission, RTO (RFC 6298), sliding window, fast retransmit.
 */

#include <xtcp/core/tcp.h>

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

typedef std::vector<xtcp::buf::BufRef> TxLog;

static xtcp::core::TxSink MakeSink(TxLog& log) noexcept {
    return [&log](xtcp::buf::BufRef&& packet) { log.push_back(std::move(packet)); };
}

static std::vector<Byte> BuildSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                      UInt16 flags, UInt16 window = 65535,
                                      const Byte* payload = NULLPTR, UInt32 payload_len = 0) noexcept {
    std::vector<Byte> seg(20 + payload_len, 0);
    Byte* t = seg.data();
    t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
    t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                             ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                             ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                             ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                             ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    t[14] = static_cast<Byte>(window >> 8);
    t[15] = static_cast<Byte>(window & 0xFF);
    if (0 < payload_len) {
        std::memcpy(t + 20, payload, payload_len);
    }
    return seg;
}

static xtcp::core::TcpConn MakeConn(TxLog& log, UInt32 iss = 100, UInt32 irs = 200) noexcept {
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    return xtcp::core::TcpConn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
}

static void TestAckClearsQueue() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    const Byte data[] = { 1, 2, 3, 4, 5 };
    CHECK(conn.SendData(data, 5, 1000));
    CHECK(5 == conn.InflightBytes());
    CHECK(0 != conn.NextRetransmitTime());
    CHECK(1 == log.size());

    // Peer ACKs everything.
    const std::vector<Byte> ack = BuildSegment(443, 40000, 201, 106, xtcp::core::kFlagAck);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 5000);
    CHECK(0 == conn.InflightBytes());
    CHECK(0 == conn.NextRetransmitTime());
    CHECK(106 == conn.SndUna());
}

static void TestPartialAck() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    const Byte data[] = { 1, 2, 3, 4, 5 };
    CHECK(conn.SendData(data, 5, 1000));

    // Partial ACK for the first 3 bytes: queue keeps the remainder.
    const std::vector<Byte> ack = BuildSegment(443, 40000, 201, 104, xtcp::core::kFlagAck);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 3000);
    CHECK(2 == conn.InflightBytes());
    CHECK(104 == conn.SndUna());

    // RTO expiry retransmits only the remainder.
    const xtcp::core::TimePoint deadline = conn.NextRetransmitTime();
    conn.OnRetransmitTimer(deadline + 1);
    CHECK(2 == log.size());  // one retransmit
}

static void TestRtoBackoff() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    const Byte data[] = { 1, 2, 3 };
    CHECK(conn.SendData(data, 3, 1000));

    // No ACK ever comes; RTO fires with exponential backoff.
    const xtcp::core::TimePoint d1 = conn.NextRetransmitTime();
    conn.OnRetransmitTimer(d1 + 1);
    const xtcp::core::TimePoint d2 = conn.NextRetransmitTime();
    CHECK(d2 > d1);

    conn.OnRetransmitTimer(d2 + 1);
    const xtcp::core::TimePoint d3 = conn.NextRetransmitTime();
    CHECK(d3 > d2);

    CHECK(3 == log.size());  // original + 2 retransmits
}

static void TestFastRetransmit() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    const Byte data[] = { 1, 2, 3, 4 };
    CHECK(conn.SendData(data, 4, 1000));

    // Three duplicate ACKs trigger fast retransmit.
    for (int i = 0; i < 3; ++i) {
        const std::vector<Byte> dup = BuildSegment(443, 40000, 201, 101, xtcp::core::kFlagAck);
        conn.OnSegment(dup.data(), static_cast<UInt32>(dup.size()), 2000 + i);
    }
    CHECK(2 == log.size());  // original + fast retransmit
}

static void TestWindowFull() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    conn.SetNodelay(true);  // isolate window semantics from Nagle buffering
    // Peer window is 100 bytes; send 60 then 40 (fills), then 10 must fail.
    Byte data[60];
    std::memset(data, 0xAA, sizeof(data));
    CHECK(conn.SendData(data, 60, 1000));

    const std::vector<Byte> ack = BuildSegment(443, 40000, 201, 101, xtcp::core::kFlagAck, 100);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 2000);
    CHECK(60 == conn.InflightBytes());  // window 100, 60 inflight

    // Full send semantics: a window-full send is buffered (Linux style),
    // not rejected, so fire-and-forget apps never drop data.
    CHECK(conn.SendData(data, 40, 3000));
    CHECK(100 == conn.InflightBytes());
    CHECK(conn.SendData(data, 10, 4000));  // buffered inside the send quota
    CHECK(10 == conn.PendingSendBytes());

    // Window opens: peer ACKs 50 bytes (ack=151) and advertises 100 again;
    // the freed window flushes the buffered 10 bytes.
    const std::vector<Byte> ack2 = BuildSegment(443, 40000, 201, 151, xtcp::core::kFlagAck, 100);
    conn.OnSegment(ack2.data(), static_cast<UInt32>(ack2.size()), 5000);
    CHECK(60 == conn.InflightBytes());  // 50 remaining + 10 flushed
    CHECK(0 == conn.PendingSendBytes());
    CHECK(conn.SendData(data, 10, 6000));   // space available again
}

static void TestSendBufQuota() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    conn.SetNodelay(true);  // isolate quota semantics from Nagle buffering
    // Bounded per-connection memory: snd_buf_ caps the retransmission queue.
    conn.SetSndBuf(4096);  // 4 KiB quota
    CHECK(4096 == conn.SndBuf());

    Byte data[2048];
    std::memset(data, 0xBB, sizeof(data));
    // Fill the quota with MSS-sized sends (1460 + 1460 + 1176).
    CHECK(conn.SendData(data, 1460, 1000));
    CHECK(conn.SendData(data, 1460, 1000));
    CHECK(conn.SendData(data, 1176, 1000));
    CHECK(4096 == conn.InflightBytes());

    // At quota the application backs off: pending + inflight would exceed
    // the per-connection memory bound (Linux sndbuf semantics).
    CHECK(!conn.SendData(data, 2048, 2000));
    CHECK(0 == conn.PendingSendBytes());

    // ACK advances snd_una (2048) -> quota frees; MSS-sized sends flow.
    const std::vector<Byte> ack = BuildSegment(443, 40000, 201, 101 + 2048, xtcp::core::kFlagAck, 65535);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 4000);
    CHECK(conn.SendData(data, 1460, 5000));   // 2048 + 1460 <= 4096
    // Worst-case per-connection memory (math): snd_buf + ooo cap + overhead.
    // (ooo cap is 64 KiB in tcp_fsm; assert the accounting invariant here.)
    CHECK(conn.SndInflight() <= conn.SndBuf());
}

static void TestRttSampling() {
    TxLog log;
    xtcp::core::TcpConn conn = MakeConn(log);
    CHECK(1000000 == conn.Rto());  // initial 1s

    const Byte data[] = { 1, 2 };
    CHECK(conn.SendData(data, 2, 10000));
    // ACK 100ms after send: RTO should shrink toward ~100ms + 4*variance.
    const std::vector<Byte> ack = BuildSegment(443, 40000, 201, 103, xtcp::core::kFlagAck);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()), 100000 + 10000);
    CHECK(conn.Rto() < 1000000);
}

int main() {
    xtcp::buf::InitPools();
    std::fprintf(stderr, "T: ackclears\n");
    TestAckClearsQueue();
    std::fprintf(stderr, "T: partialack\n");
    TestPartialAck();
    std::fprintf(stderr, "T: rto\n");
    TestRtoBackoff();
    std::fprintf(stderr, "T: fastretx\n");
    TestFastRetransmit();
    std::fprintf(stderr, "T: window\n");
    TestWindowFull();
    std::fprintf(stderr, "T: rtt\n");
    TestRttSampling();
    TestSendBufQuota();
    std::fprintf(stderr, "T: shutdown\n");
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, "T: shutdown done\n");
    if (0 < g_failures) {
        std::fprintf(stderr, "test_tcp_retransmit: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_tcp_retransmit: all passed\n");
    return 0;
}

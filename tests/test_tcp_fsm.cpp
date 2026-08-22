/**
 * @file test_tcp_fsm.cpp
 * @brief TCP state machine tests: handshake, data, FIN, RFC 5961/1122.
 */

#include <xtcp/core/tcp.h>
#include <xtcp/core/ip.h>

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

/** Builds a raw TCP segment (IP payload form) with valid checksum. */
static std::vector<Byte> BuildSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                      UInt16 flags, const Byte* payload = NULLPTR, UInt32 payload_len = 0) noexcept {
    std::vector<Byte> seg(20 + payload_len, 0);
    Byte* t = seg.data();
    t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
    t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;  // data offset 5
    t[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                             ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                             ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                             ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                             ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    t[14] = 0xFF; t[15] = 0xFF;  // window 65535
    if (0 < payload_len) {
        std::memcpy(t + 20, payload, payload_len);
    }
    return seg;
}

static void TestPassiveHandshake() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 443;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0xC0A80102;
    remote.port = 40000;

    xtcp::core::TcpListener listener(local, 16, MakeSink(log));
    const std::vector<Byte> syn = BuildSegment(remote.port, local.port, 1000, 0, xtcp::core::kFlagSyn);
    CHECK(listener.OnSyn(syn.data(), static_cast<UInt32>(syn.size()), remote));
    CHECK(1 == listener.Pending());
    CHECK(1 == log.size());

    // Response must be SYN+ACK with ack = syn seq + 1.
    const xtcp::buf::BufRef& synack = log[0];
    CHECK(52 == synack.Len());  // 20 (IPv4) + 32 (TCP + MSS + SACK + WSOPT)
    const Byte* ip = synack.Data();
    CHECK(4 == (ip[0] >> 4));
    CHECK(6 == ip[9]);  // TCP
    const Byte* t = ip + 20;
    CHECK(local.port == ((t[0] << 8) | t[1]));   // sport
    CHECK(remote.port == ((t[2] << 8) | t[3]));  // dport
    CHECK(0 != (t[13] & 0x02));  // SYN
    CHECK(0 != (t[13] & 0x10));  // ACK
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(1001 == ack);

    // Complete the handshake with an ACK carrying ack = synack.seq + 1.
    const Byte* st = synack.Data() + 20;
    const UInt32 synack_seq = (static_cast<UInt32>(st[4]) << 24) | (static_cast<UInt32>(st[5]) << 16) |
                              (static_cast<UInt32>(st[6]) << 8) | st[7];
    const std::vector<Byte> ack_seg = BuildSegment(remote.port, local.port, 1001, synack_seq + 1, xtcp::core::kFlagAck);
    listener.OnSynAck(ack_seg.data(), static_cast<UInt32>(ack_seg.size()), remote);
    CHECK(0 == listener.Pending());
}

static void TestListenerRcvBufAdvertised() {
    // the listener's SYN+ACK must advertise the configured receive
    // buffer (scaled by the offered factor) instead of the legacy raw 65535.
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 443;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0xC0A80102;
    remote.port = 40000;

    xtcp::core::TcpListener listener(local, 16, MakeSink(log));
    listener.SetRcvBuf(262144);
    const std::vector<Byte> syn = BuildSegment(remote.port, local.port, 1000, 0, xtcp::core::kFlagSyn);
    CHECK(listener.OnSyn(syn.data(), static_cast<UInt32>(syn.size()), remote));
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    const UInt16 win = (static_cast<UInt16>(t[14]) << 8) | t[15];
    std::fprintf(stderr, "[tcp-fsm] listener SYN+ACK window=%u (expect 2048)\n", win);
    CHECK(2048 == win);  // 262144 >> 7 (the offered scale)

    // The default (no config) advertises 65535 >> 7 = 511 (the scaled
    // protocol default, matching the conn-based SYN+ACK path).
    log.clear();
    xtcp::core::TcpListener legacy(local, 16, MakeSink(log));
    const std::vector<Byte> syn2 = BuildSegment(remote.port, local.port, 1002, 0, xtcp::core::kFlagSyn);
    CHECK(legacy.OnSyn(syn2.data(), static_cast<UInt32>(syn2.size()), remote));
    CHECK(1 == log.size());
    const Byte* t2 = log[0].Data() + 20;
    const UInt16 win2 = (static_cast<UInt16>(t2[14]) << 8) | t2[15];
    CHECK(511 == win2);
}

static void TestListenerDuplicateSynReanswered() {
    // a retransmitted SYN from a client already in the queue must
    // be re-answered with the SAME SYN+ACK (same iss) instead of filling the
    // backlog with a duplicate entry - a lost SYN+ACK otherwise leaves the
    // client retransmitting into a queue that grows to the bound and rejects
    // its eventual ACK.
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 444;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0xC0A80102;
    remote.port = 40001;

    xtcp::core::TcpListener listener(local, 4, MakeSink(log));
    const std::vector<Byte> syn = BuildSegment(remote.port, local.port, 1000, 0, xtcp::core::kFlagSyn);
    CHECK(listener.OnSyn(syn.data(), static_cast<UInt32>(syn.size()), remote));
    CHECK(1 == listener.Pending());
    CHECK(1 == log.size());
    const Byte* t1 = log[0].Data() + 20;
    const UInt32 iss1 = (static_cast<UInt32>(t1[4]) << 24) | (static_cast<UInt32>(t1[5]) << 16) |
                        (static_cast<UInt32>(t1[6]) << 8) | t1[7];

    // Duplicate SYN (retransmission): same SYN+ACK seq, no new queue entry.
    log.clear();
    CHECK(listener.OnSyn(syn.data(), static_cast<UInt32>(syn.size()), remote));
    CHECK(1 == listener.Pending());
    CHECK(1 == log.size());
    const Byte* t2 = log[0].Data() + 20;
    const UInt32 iss2 = (static_cast<UInt32>(t2[4]) << 24) | (static_cast<UInt32>(t2[5]) << 16) |
                        (static_cast<UInt32>(t2[6]) << 8) | t2[7];
    std::fprintf(stderr, "[tcp-fsm] duplicate SYN re-answered: iss1=%u iss2=%u pending=%u\n",
                 iss1, iss2, listener.Pending());
    CHECK(iss1 == iss2);
    CHECK(1 == listener.Pending());
}

static void TestActiveHandshake() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 0x11223344;
    const UInt32 irs = 0x55667788;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, local, remote, iss, irs, MakeSink(log));
    CHECK(xtcp::core::TcpState::kSynSent == conn.State());

    const std::vector<Byte> synack = BuildSegment(remote.port, local.port, irs, iss + 1,
                                                  xtcp::core::kFlagSyn | xtcp::core::kFlagAck);
    conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()));
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    CHECK(0 != (t[13] & 0x10));  // ACK
    const UInt32 seq = (static_cast<UInt32>(t[4]) << 24) | (static_cast<UInt32>(t[5]) << 16) |
                       (static_cast<UInt32>(t[6]) << 8) | t[7];
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(iss + 1 == seq);
    CHECK(irs + 1 == ack);
}

static void TestEstablishedData() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));

    const Byte data[] = { 0x01, 0x02, 0x03, 0x04 };
    // First in-order segment: delivered, delayed ACK (RFC 1122).
    const std::vector<Byte> seg = BuildSegment(remote.port, local.port, irs + 1, iss + 1,
                                               xtcp::core::kFlagAck | xtcp::core::kFlagPsh, data, 4);
    conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()));
    CHECK(irs + 5 == conn.RcvNxt());
    CHECK(0 == log.size());  // delayed ACK: no immediate segment

    // Second in-order segment: triggers the delayed ACK.
    const std::vector<Byte> seg2 = BuildSegment(remote.port, local.port, irs + 5, iss + 1,
                                                xtcp::core::kFlagAck | xtcp::core::kFlagPsh, data, 4);
    conn.OnSegment(seg2.data(), static_cast<UInt32>(seg2.size()));
    CHECK(irs + 9 == conn.RcvNxt());
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(irs + 9 == ack);

    // Old segment: re-ACK (immediate for retransmission), no rcv_nxt advance.
    const std::vector<Byte> old_seg = BuildSegment(remote.port, local.port, irs + 1, iss + 1,
                                                   xtcp::core::kFlagAck, data, 2);
    conn.OnSegment(old_seg.data(), static_cast<UInt32>(old_seg.size()));
    CHECK(irs + 9 == conn.RcvNxt());
    CHECK(2 == log.size());

    // Out-of-order (gap): discarded, re-ACK.
    const std::vector<Byte> gap_seg = BuildSegment(remote.port, local.port, irs + 10, iss + 1,
                                                   xtcp::core::kFlagAck, data, 4);
    conn.OnSegment(gap_seg.data(), static_cast<UInt32>(gap_seg.size()));
    CHECK(irs + 9 == conn.RcvNxt());
    CHECK(3 == log.size());
}

static void TestFinTeardown() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));

    // Peer FIN -> CloseWait + ACK.
    const std::vector<Byte> fin = BuildSegment(remote.port, local.port, irs + 1, iss + 1, xtcp::core::kFlagFin | xtcp::core::kFlagAck);
    conn.OnSegment(fin.data(), static_cast<UInt32>(fin.size()));
    CHECK(xtcp::core::TcpState::kCloseWait == conn.State());
    CHECK(irs + 2 == conn.RcvNxt());

    // Local Close() -> LastAck + FIN.
    conn.Close();
    CHECK(xtcp::core::TcpState::kLastAck == conn.State());

    // Peer ACK of our FIN -> Closed.
    const std::vector<Byte> ack = BuildSegment(remote.port, local.port, irs + 2, iss + 2, xtcp::core::kFlagAck);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()));
    CHECK(xtcp::core::TcpState::kClosed == conn.State());
}

static void TestActiveClose() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
    conn.Close();
    CHECK(xtcp::core::TcpState::kFinWait1 == conn.State());

    const std::vector<Byte> ack = BuildSegment(remote.port, local.port, irs + 1, iss + 2, xtcp::core::kFlagAck);
    conn.OnSegment(ack.data(), static_cast<UInt32>(ack.size()));
    CHECK(xtcp::core::TcpState::kFinWait2 == conn.State());

    const std::vector<Byte> fin = BuildSegment(remote.port, local.port, irs + 1, iss + 2, xtcp::core::kFlagFin | xtcp::core::kFlagAck);
    conn.OnSegment(fin.data(), static_cast<UInt32>(fin.size()));
    CHECK(xtcp::core::TcpState::kTimeWait == conn.State());
}

static void TestIllegalTransitionRejected() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));

    // SYN in Established (RFC 5961): ignored SILENTLY - state unchanged and
    // NO packet emitted (a response to an illegal SYN is itself a reflector
    // vector). Both properties asserted.
    const std::vector<Byte> syn = BuildSegment(remote.port, local.port, irs + 1, iss + 1, xtcp::core::kFlagSyn);
    conn.OnSegment(syn.data(), static_cast<UInt32>(syn.size()));
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
    CHECK(log.empty());  // no RST / ACK / SYN-ACK emitted
}

static void TestRfc5961RstValidation() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;

    // Invalid RST (seq outside window): challenge ACK, connection survives.
    {
        TxLog log2;
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log2));
        const std::vector<Byte> bad_rst = BuildSegment(remote.port, local.port, irs + 900000, iss + 1,
                                                       xtcp::core::kFlagRst | xtcp::core::kFlagAck);
        conn.OnSegment(bad_rst.data(), static_cast<UInt32>(bad_rst.size()));
        CHECK(xtcp::core::TcpState::kEstablished == conn.State());
        CHECK(1 == log2.size());
        const Byte* t = log2[0].Data() + 20;
        CHECK(0 != (t[13] & 0x10));  // challenge ACK
        CHECK(0 == (t[13] & 0x04));  // not RST
    }

    // Valid RST (seq == rcv_nxt): connection closes.
    {
        TxLog log2;
        xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log2));
        const std::vector<Byte> ok_rst = BuildSegment(remote.port, local.port, irs + 1, iss + 1,
                                                      xtcp::core::kFlagRst | xtcp::core::kFlagAck);
        conn.OnSegment(ok_rst.data(), static_cast<UInt32>(ok_rst.size()));
        CHECK(xtcp::core::TcpState::kClosed == conn.State());
    }
}

static void TestKeepaliveProbe() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));

    // RFC 1122 keepalive probe: seq = rcv_nxt - 1, no payload -> ACK reply.
    const std::vector<Byte> probe = BuildSegment(remote.port, local.port, irs, iss + 1, xtcp::core::kFlagAck);
    conn.OnSegment(probe.data(), static_cast<UInt32>(probe.size()));
    CHECK(1 == log.size());
    const Byte* t = log[0].Data() + 20;
    CHECK(0 != (t[13] & 0x10));
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(irs + 1 == ack);
}

static void TestActiveHandshakeIpv6() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 6;
    local.addr[0] = 0x20010DB8;  // 2001:db8::1
    local.addr[1] = 0;
    local.addr[2] = 0;
    local.addr[3] = 1;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 6;
    remote.addr[0] = 0x20010DB8;
    remote.addr[1] = 0;
    remote.addr[2] = 0;
    remote.addr[3] = 2;
    remote.port = 443;

    const UInt32 iss = 0x11112222;
    const UInt32 irs = 0x33334444;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kSynSent, local, remote, iss, irs, MakeSink(log));

    // SYN+ACK from the IPv6 peer (IP payload form).
    const std::vector<Byte> synack = BuildSegment(remote.port, local.port, irs, iss + 1,
                                                  xtcp::core::kFlagSyn | xtcp::core::kFlagAck);
    conn.OnSegment(synack.data(), static_cast<UInt32>(synack.size()));
    CHECK(xtcp::core::TcpState::kEstablished == conn.State());
    CHECK(1 == log.size());

    // Response must be a valid IPv6 packet with a correct TCP checksum.
    const xtcp::buf::BufRef& out = log[0];
    CHECK(60 == out.Len());  // 40 (IPv6) + 20 (TCP)
    const Byte* p = out.Data();
    CHECK(0x60 == p[0]);
    CHECK(6 == p[6]);  // next header: TCP
    // IPv6 addresses.
    CHECK(0x20 == p[8] && 0x01 == p[9] && 0x0D == p[10] && 0xB8 == p[11]);
    CHECK(0x20 == p[24] && 0x01 == p[25] && 0x0D == p[26] && 0xB8 == p[27]);
    // TCP header at offset 40.
    const Byte* t = p + 40;
    CHECK(local.port == ((t[0] << 8) | t[1]));   // sport
    CHECK(remote.port == ((t[2] << 8) | t[3]));  // dport
    CHECK(0 != (t[13] & 0x10));  // ACK
    const UInt32 seq = (static_cast<UInt32>(t[4]) << 24) | (static_cast<UInt32>(t[5]) << 16) |
                       (static_cast<UInt32>(t[6]) << 8) | t[7];
    const UInt32 ack = (static_cast<UInt32>(t[8]) << 24) | (static_cast<UInt32>(t[9]) << 16) |
                       (static_cast<UInt32>(t[10]) << 8) | t[11];
    CHECK(iss + 1 == seq);
    CHECK(irs + 1 == ack);

    // Verify the TCP checksum against an IPv6 pseudo header.
    Byte pseudo[40];
    std::memcpy(pseudo, p + 8, 16);     // src
    std::memcpy(pseudo + 16, p + 24, 16);  // dst
    pseudo[32] = 0; pseudo[33] = 0; pseudo[34] = 0; pseudo[35] = 20;  // 32-bit TCP length
    pseudo[36] = 0; pseudo[37] = 0; pseudo[38] = 0; pseudo[39] = 6;   // next header TCP
    Byte t2[20];
    std::memcpy(t2, t, 20);
    t2[16] = 0; t2[17] = 0;  // zero the checksum field before recomputation
    const UInt16 s1 = xtcp::core::Checksum(pseudo, 40);
    const UInt16 s2 = xtcp::core::Checksum(t2, 20);
    UInt32 sum = (static_cast<UInt32>(~s1) & 0xFFFF) + (static_cast<UInt32>(~s2) & 0xFFFF);
    sum = (sum & 0xFFFF) + (sum >> 16);
    const UInt16 expected = static_cast<UInt16>(~sum & 0xFFFF);
    const UInt16 stored = static_cast<UInt16>((t[16] << 8) | t[17]);
    CHECK(expected == stored);
}

int main() {
    xtcp::buf::InitPools();
    TestPassiveHandshake();
    TestListenerRcvBufAdvertised();
    TestListenerDuplicateSynReanswered();
    TestActiveHandshake();
    TestActiveHandshakeIpv6();
    TestEstablishedData();
    TestFinTeardown();
    TestActiveClose();
    TestIllegalTransitionRejected();
    TestRfc5961RstValidation();
    TestKeepaliveProbe();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_tcp_fsm: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_tcp_fsm: all passed\n");
    return 0;
}

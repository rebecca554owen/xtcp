/**
 * @file test_ecn_cwr.cpp
 * @brief RFC 3168 s6.1.4: the receiver must stop echoing ECE in its ACKs
 *        once the sender responds with CWR. Before the fix, a single
 *        CE-marked packet set ecn_ce_seen_ forever - every subsequent ACK
 *        carried ECE, halving the peer's cwnd once per RTT indefinitely
 *        (throughput collapse after one congestion event).
 *
 *   Phase A: CE-marked data arrives -> the client's ACKs carry ECE.
 *   Phase B: the server responds with CWR (its window cut) -> the echo
 *            state clears.
 *   Phase C: fresh data (no CE) -> the client's ACKs must NOT carry ECE.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt32 Load32BE(const Byte* p) {
    return (static_cast<UInt32>(p[0]) << 24) | (static_cast<UInt32>(p[1]) << 16) |
           (static_cast<UInt32>(p[2]) << 8) | static_cast<UInt32>(p[3]);
}

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

/** Builds a server->client IPv4+TCP segment. ECN bits (0/1/2/3 = Not-ECT /
 *  ECT(1) / ECT(0) / CE) go in the IP TOS low 2 bits; TCP flags in byte 13.
 *  seq/ack are caller-supplied. */
static std::vector<Byte> BuildSeg(UInt32 seq, UInt32 ack, Byte ip_ecn, Byte tcp_flags,
                                  const Byte* payload, UInt32 payload_len) {
    std::vector<Byte> out(40 + payload_len, 0);
    out[0] = 0x45;
    out[1] = static_cast<Byte>(ip_ecn & 0x03);  // ECN field (RFC 3168 IP bits)
    const UInt32 total = 40 + payload_len;
    out[2] = static_cast<Byte>(total >> 8);
    out[3] = static_cast<Byte>(total & 0xFF);
    out[8] = 64;
    out[9] = 6;
    out[12] = 0x0A; out[13] = 0x00; out[14] = 0x00; out[15] = 0x02;  // server
    out[16] = 0x0A; out[17] = 0x00; out[18] = 0x00; out[19] = 0x01;  // client
    Byte* t = out.data() + 20;
    t[0] = 0x1F; t[1] = 0x90;   // sport 8080
    t[2] = 0x9C; t[3] = 0x40;   // dport 40000
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = tcp_flags;
    t[14] = 0xFF; t[15] = 0xFF;
    if (0 < payload_len && NULLPTR != payload) {
        std::memcpy(t + 20, payload, payload_len);
    }
    // Valid checksums: a zero-checksum segment is dropped under the
    // checksum-validate build and the CE/CWR scenario never reaches the
    // connection.
    xtcp::harness::FillIp4Checksum(out.data());
    xtcp::harness::FillTcp4Checksum(out.data(), out.data() + 20, 20 + payload_len);
    return out;
}

/** Drains a backend and counts the client's (A) pending pure-ACK segments:
 *  returns (ece_count, plain_count) - both from the same single drain. */
static void DrainAckCounts(xtcp::ndi::ManualBackend& backend, UInt32& ece, UInt32& plain) {
    Byte out[65536];
    ece = 0;
    plain = 0;
    while (0 != backend.TxPending()) {
        const UInt32 n = backend.PollTx(out);
        if (n < 40) {
            continue;
        }
        const Byte* t = out + 20;  // IPv4 header is 20 bytes (IHL 5)
        if (0 != (t[13] & 0x10) && 0 == (t[13] & 0x08) && 0 == (t[13] & 0x01)) {
            if (0 != (t[13] & 0x40)) {
                ++ece;  // pure ACK with ECE
            } else {
                ++plain;  // pure ACK without ECE
            }
        }
    }
}

int main() {
    xtcp::buf::InitPools();

    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);

    UInt32 iss_b = 0;
    backend_a.SetRxHandler([&stack_a, &iss_b](xtcp::ndi::Packet&& p) {
        // Sniff the server's ISN from the SYN+ACK (client's rcv_nxt anchor).
        if (p.len > 33 && 0 != (p.data[33] & 0x02) && 0 != (p.data[33] & 0x10)) {
            iss_b = Load32BE(p.data + 24);
        }
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
    std::string received_a;
    stack_a.SetRecvHandler([&received_a](UInt64, const Byte* d, UInt32 n) {
        received_a.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;
    remote.port = 8080;
    stack_a.SetDefaultEcn(true);
    stack_b.SetDefaultEcn(true);
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, stack_a, stack_b);
    CHECK(0 != iss_b);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    // The client's send frontier: the server ACKs at this point.
    UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
    UInt64 rto_deadline = 0; UInt32 dup_acks = 0, fast_rec = 0;
    UInt32 front_seq = 0, snd_una = 0; UInt16 lp = 0, rp = 0;
    stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                      rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                      lp, rp);
    const UInt32 client_snd_nxt = snd_una;  // nothing sent: snd_una == snd_nxt
    const UInt32 server_seq = iss_b + 1;    // server's next data seq

    // ---- Phase A: CE-marked data -> the client's ACKs echo ECE. ----
    // Note: drain the client's Tx BEFORE Pump - Pump forwards the client's
    // ACKs into the server, where they are consumed, not queued.
    const Byte data1 = 0x41;
    std::vector<Byte> ce1 = BuildSeg(server_seq, client_snd_nxt, 3, 0x18, &data1, 1);
    backend_a.Inject(ce1.data(), static_cast<UInt32>(ce1.size()), 0x0800);
    const Byte data2 = 0x42;
    std::vector<Byte> ce2 = BuildSeg(server_seq + 1, client_snd_nxt, 3, 0x18, &data2, 1);
    backend_a.Inject(ce2.data(), static_cast<UInt32>(ce2.size()), 0x0800);
    UInt32 ece_acks_a = 0, plain_acks_a = 0;
    DrainAckCounts(backend_a, ece_acks_a, plain_acks_a);
    Pump(backend_a, backend_b, stack_a, stack_b);
    std::fprintf(stderr, "[ecn-cwr] phase A: ECE ACKs=%u plain ACKs=%u (expect >= 1 ECE)\n",
                 ece_acks_a, plain_acks_a);
    CHECK(1 <= ece_acks_a);

    // ---- Phase B: the server responds with CWR (pure ACK + CWR). ----
    std::vector<Byte> cwr = BuildSeg(server_seq + 2, client_snd_nxt, 0, 0x90, NULLPTR, 0);
    backend_a.Inject(cwr.data(), static_cast<UInt32>(cwr.size()), 0x0800);
    UInt32 ece_tmp = 0, plain_tmp = 0;
    DrainAckCounts(backend_a, ece_tmp, plain_tmp);  // drain whatever the CWR round emitted
    Pump(backend_a, backend_b, stack_a, stack_b);

    // ---- Phase C: fresh data (no CE) -> ACKs must NOT carry ECE. ----
    std::vector<Byte> f1 = BuildSeg(server_seq + 2, client_snd_nxt, 0, 0x18, &data1, 1);
    backend_a.Inject(f1.data(), static_cast<UInt32>(f1.size()), 0x0800);
    std::vector<Byte> f2 = BuildSeg(server_seq + 3, client_snd_nxt, 0, 0x18, &data2, 1);
    backend_a.Inject(f2.data(), static_cast<UInt32>(f2.size()), 0x0800);
    UInt32 ece_acks_c = 0, plain_acks_c = 0;
    DrainAckCounts(backend_a, ece_acks_c, plain_acks_c);
    Pump(backend_a, backend_b, stack_a, stack_b);
    std::fprintf(stderr, "[ecn-cwr] phase C: ECE ACKs=%u plain ACKs=%u (expect 0 ECE, >= 1 plain)\n",
                 ece_acks_c, plain_acks_c);
    CHECK(0 == ece_acks_c);
    CHECK(1 <= plain_acks_c);

    // ---- Phase D: CE re-asserted, then an out-of-window RST challenge ->
    // the challenge ACK must echo ECE (RFC 3168 s6.1.3: every ACK while CE
    // is active, including RFC 5961 challenge ACKs). ----
    std::vector<Byte> ce3 = BuildSeg(server_seq + 4, client_snd_nxt, 3, 0x18, &data1, 1);
    backend_a.Inject(ce3.data(), static_cast<UInt32>(ce3.size()), 0x0800);
    std::vector<Byte> ce4 = BuildSeg(server_seq + 5, client_snd_nxt, 3, 0x18, &data2, 1);
    backend_a.Inject(ce4.data(), static_cast<UInt32>(ce4.size()), 0x0800);
    UInt32 ece_tmp2 = 0, plain_tmp2 = 0;
    DrainAckCounts(backend_a, ece_tmp2, plain_tmp2);  // drain the data ACKs
    std::vector<Byte> spoof_rst = BuildSeg(0x99999999, client_snd_nxt, 0, 0x04, NULLPTR, 0);
    backend_a.Inject(spoof_rst.data(), static_cast<UInt32>(spoof_rst.size()), 0x0800);
    UInt32 ece_acks_d = 0, plain_acks_d = 0;
    DrainAckCounts(backend_a, ece_acks_d, plain_acks_d);  // the challenge ACK
    Pump(backend_a, backend_b, stack_a, stack_b);
    std::fprintf(stderr, "[ecn-cwr] phase D: challenge ECE ACKs=%u plain=%u (expect >= 1 ECE)\n",
                 ece_acks_d, plain_acks_d);
    CHECK(1 <= ece_acks_d);
    CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ECN_CWR: FAILED (%d)\n" : "ECN_CWR: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

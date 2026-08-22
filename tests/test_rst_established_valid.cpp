/**
 * @file test_rst_established_valid.cpp
 * @brief RFC 5961 RST validation on an ESTABLISHED connection - the positive
 *        (valid RST) path that test_rst_challenge.cpp does not cover.
 *
 *   test_rst_challenge.cpp only exercises the OUT-of-window side (the stack
 *   must challenge, not close). This test covers both sides on real
 *   dual-stack connections:
 *
 *   (a) A VALID RST (seq == the peer's current send seq == our rcv_nxt,
 *       sniffed from the SYN+ACK on the wire) MUST close the receiver:
 *       A transitions to kClosed and emits no challenge ACK.
 *   (b) An OUT-of-window RST (seq far away from rcv_nxt) MUST NOT close it:
 *       A stays kEstablished, emits exactly one challenge ACK (RFC 5961),
 *       and the connection still carries traffic afterwards.
 *
 * Reference for the injection helper: test_challenge_limit.cpp's
 * InjectRstAtA (RST spoofed as coming from the server toward the client).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include "harness/raw_pkt.h"
#include <cstdio>
#include <cstring>
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

static UInt32 g_iss_b = 0;  // peer (B) ISS, sniffed from the SYN+ACK

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

/** Builds an IPv4 RST from B (src_ip:src_port) toward A (dst_ip:dst_port)
 *  and injects it into A's backend. The seq is caller-supplied. Valid
 *  checksums so the RST path behaves under the checksum-validate build. */
static void InjectRstToA(xtcp::ndi::ManualBackend& backend, UInt32 seq,
                         UInt16 sport, UInt16 dport) {
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, sport, dport, seq, 0, 0x04);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
}

/** Drains a backend's Tx queue and counts TCP packets carrying the ACK flag. */
static UInt32 DrainAckCount(xtcp::ndi::ManualBackend& backend) {
    Byte out[65536];
    UInt32 acks = 0;
    while (0 != backend.TxPending()) {
        const UInt32 n = backend.PollTx(out);
        if (n < 40) {
            continue;
        }
        const UInt32 ip_hlen = static_cast<UInt32>(out[0] & 0x0F) * 4;
        const Byte* tcp = out + ip_hlen;
        if (0 != (tcp[13] & 0x10)) {  // ACK flag
            ++acks;
        }
    }
    return acks;
}

int main() {
    xtcp::buf::InitPools();

    {
        // ---- Scenario (a): a VALID RST closes A (positive path). ----
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        g_iss_b = 0;
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                g_iss_b = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
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

        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
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
        CHECK(0 != conn_b);
        CHECK(0 != g_iss_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // The peer's current send seq == B's ISS + 1 == A's rcv_nxt. Cross-check
        // the wire sniff against ConnStats (snd_una stays iss_B+1 after the
        // handshake with nothing sent).
        const UInt32 valid_seq = g_iss_b + 1;
        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
        UInt64 rto_deadline = 0; UInt32 dup_acks = 0, fast_rec = 0;
        UInt32 front_seq = 0, snd_una = 0; UInt16 lp = 0, rp = 0;
        stack_b.ConnStats(conn_b, inflight, cwnd, ssthresh, snd_wnd, retx,
                          rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                          lp, rp);
        CHECK(valid_seq == snd_una);
        std::fprintf(stderr, "[rst-valid] B send seq=%u (sniffed ISS+1=%u)\n",
                     snd_una, valid_seq);

        // Inject the VALID RST (seq == A's rcv_nxt): A must close, and emit
        // no challenge ACK.
        InjectRstToA(backend_a, valid_seq, 8080, 40000);
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
        CHECK(0 == DrainAckCount(backend_a));  // valid RST: no challenge ACK
        // The peer is untouched: only the RST receiver (A) closes.
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        std::fprintf(stderr, "[rst-valid] valid RST (seq==rcv_nxt) closed A\n");
    }

    {
        // ---- Scenario (b): an OUT-of-window RST is challenged, not honored. ----
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        std::vector<Byte> recv_b;
        g_iss_b = 0;
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                g_iss_b = Load32BE(p.data + 20 + 4);
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
        stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 len) {
            recv_b.insert(recv_b.end(), d, d + len);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40020;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8090;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(0 != g_iss_b);

        // Out-of-window RST (seq far from rcv_nxt): A must survive and emit
        // exactly one challenge ACK (RFC 5961).
        InjectRstToA(backend_a, 0x99999999u, 8090, 40020);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(1 == DrainAckCount(backend_a));
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[rst-valid] out-of-window RST challenged, A alive\n");

        // The connection still carries traffic after the challenge.
        const char* msg = "still-alive";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg),
                           static_cast<UInt32>(std::strlen(msg))));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(recv_b.size() == std::strlen(msg));
        CHECK(0 == std::memcmp(recv_b.data(), msg, std::strlen(msg)));
        std::fprintf(stderr, "[rst-valid] traffic survives the challenge\n");

        // A subsequent VALID RST still closes the challenged connection.
        const UInt32 valid_seq = g_iss_b + 1;
        InjectRstToA(backend_a, valid_seq, 8090, 40020);
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
        std::fprintf(stderr, "[rst-valid] valid RST after challenge still closes A\n");
    }

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_ESTABLISHED_VALID: FAILED (%d)\n" : "RST_ESTABLISHED_VALID: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


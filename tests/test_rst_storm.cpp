/**
 * @file test_rst_storm.cpp
 * @brief RFC 5961 RST-storm resilience on ESTABLISHED connections:
 *
 *   (a) A burst of 1000 out-of-window RSTs (spoofed) must NOT reflect 1:1
 *       into challenge ACKs - the 8/s challenge rate limit (RFC 5961 s5 /
 *       Linux tcp_challenge_ack_limit) caps the reflection, and the
 *       connection must survive and carry traffic afterwards.
 *   (b) After the storm, a VALID in-window RST (seq == rcv_nxt) must STILL
 *       close the receiver - the storm must not poison the acceptance path.
 *   (c) Keepalive-probe answer: an out-of-window RST arriving in response
 *       to a keepalive probe (pure ACK, seq = snd_nxt_-1) must not kill the
 *       connection; probing keeps the flow alive until a valid RST arrives.
 *
 * The positive (valid RST closes) and single-challenge paths are covered in
 * test_rst_established_valid.cpp; this test pins the storm/rate-limit and
 * keepalive-combo boundaries.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <chrono>
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

/** Builds an IPv4 RST from B (src_ip:src_port) toward A (dst_ip:dst_port)
 *  with the given seq and injects it into A's backend. */
static void InjectRstToA(xtcp::ndi::ManualBackend& backend, UInt32 seq,
                         UInt16 sport, UInt16 dport) {
    // Valid checksums: a zero-checksum RST is dropped under the
    // checksum-validate build (storm never challenges, valid RST never
    // closes) and the scenario silently changes.
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
        // ---- Scenario (a): RST storm (1000 out-of-window) is rate-limited. ----
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        UInt32 iss_b = 0;
        backend_a.SetRxHandler([&stack_a, &iss_b](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                iss_b = Load32BE(p.data + 20 + 4);  // SYN+ACK seq = B's ISS
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
        CHECK(0 != iss_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Fire 1000 out-of-window RSTs in one burst (all inside the 1s
        // challenge window). Challenge ACKs must be capped at 8 (RFC 5961
        // tcp_challenge_ack_limit) - NOT 1:1 reflection.
        for (UInt32 i = 0; i < 1000; ++i) {
            InjectRstToA(backend_a, 0x90000000u + i * 977u, 8080, 40000);
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        const UInt32 challenge_acks = DrainAckCount(backend_a);
        std::fprintf(stderr, "[rst-storm] challenge ACKs for 1000 RSTs = %u (cap 8)\n",
                     challenge_acks);
        CHECK(challenge_acks <= 8);

        // The connection still carries traffic after the storm.
        std::vector<Byte> recv_b;
        stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 len) {
            recv_b.insert(recv_b.end(), d, d + len);
        });
        const char* msg = "storm-survived";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg),
                           static_cast<UInt32>(std::strlen(msg))));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(recv_b.size() == std::strlen(msg));
        CHECK(0 == std::memcmp(recv_b.data(), msg, std::strlen(msg)));
        std::fprintf(stderr, "[rst-storm] traffic survives the storm\n");

        // ---- Scenario (b): a VALID RST after the storm still closes A. ----
        const UInt32 valid_seq = iss_b + 1;
        InjectRstToA(backend_a, valid_seq, 8080, 40000);
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kEstablished == stack_b.ConnectionState(conn_b));
        std::fprintf(stderr, "[rst-storm] valid RST after storm closes A\n");
    }

    {
        // ---- Scenario (c): keepalive probe answered by an out-of-window
        //      RST must not kill the connection; a valid RST still does. ----
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        UInt32 iss_b = 0;
        backend_a.SetRxHandler([&stack_a, &iss_b](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && 0x02 == (p.data[20 + 13] & 0x02)) {
                iss_b = Load32BE(p.data + 20 + 4);
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40030;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8090;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != iss_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Arm a very fast keepalive (1 ms idle, 1 ms interval, 3 probes).
        stack_a.SetKeepalive(conn, 1000, 1000, 3);

        // Idle past the keepalive idle: the probe fires (PollAckTimers).
        // The probe is a pure ACK with seq = snd_nxt_-1. Keepalive timers are
        // wall-clock based, so the poll loop must sleep across the 1 ms idle.
        UInt32 probe_acks = 0;
        for (UInt32 i = 0; i < 40 && 0 == probe_acks; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            probe_acks = DrainAckCount(backend_a);
        }
        CHECK(1 <= probe_acks);  // probe (or ack) went out

        // An out-of-window RST "answering" the probe must NOT close A
        // (RFC 5961: spoofed RST protection). A stays established.
        InjectRstToA(backend_a, 0x70000000u, 8090, 40030);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // The flow still carries traffic after the probe+RST exchange.
        std::vector<Byte> recv_b;
        stack_b.SetRecvHandler([&recv_b](UInt64, const Byte* d, UInt32 len) {
            recv_b.insert(recv_b.end(), d, d + len);
        });
        const char* msg = "probe-alive";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg),
                           static_cast<UInt32>(std::strlen(msg))));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(recv_b.size() == std::strlen(msg));
        CHECK(0 == std::memcmp(recv_b.data(), msg, std::strlen(msg)));
        std::fprintf(stderr, "[rst-storm] traffic survives probe-RST combo\n");

        // A valid RST (seq == rcv_nxt) still closes A.
        const UInt32 valid_seq = iss_b + 1;
        InjectRstToA(backend_a, valid_seq, 8090, 40030);
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
        std::fprintf(stderr, "[rst-storm] valid RST after probe closes A\n");
    }

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RST_STORM: FAILED (%d)\n" : "RST_STORM: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

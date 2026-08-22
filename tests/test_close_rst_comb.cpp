/**
 * @file test_close_rst_comb.cpp
 * @brief Closing-state RST + data combination (RFC 793): a FIN-WAIT
 *        connection must keep delivering the peer's half-close data
 *        (ProcessClosingData) while an inbound RST closes it immediately;
 *        LAST-ACK drops stray data without disturbance and still closes on
 *        the final ACK. Core assertion: no anomaly while RST/data interleave
 *        during close, and every side reaches the correct final state.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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

// Inject a raw IPv4/TCP segment (RST or data) straight into a stack. The
// receive path never validates TCP/IP checksums (ParseTcp only reads the
// field), so none is computed here.
static void InjectSegment(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                          UInt16 src_port, UInt16 dst_port, UInt32 seq, UInt32 ack,
                          Byte flags, const Byte* payload, UInt32 payload_len) {
    std::vector<Byte> pkt(40 + payload_len, 0);
    pkt[0] = 0x45;                                   // IPv4, IHL=5
    pkt[2] = static_cast<Byte>((40 + payload_len) >> 8);
    pkt[3] = static_cast<Byte>(40 + payload_len);
    pkt[9] = 6;                                      // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt.data() + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = static_cast<Byte>(seq >> 24); tcp[5] = static_cast<Byte>(seq >> 16);
    tcp[6] = static_cast<Byte>(seq >> 8);  tcp[7] = static_cast<Byte>(seq);
    tcp[8] = static_cast<Byte>(ack >> 24); tcp[9] = static_cast<Byte>(ack >> 16);
    tcp[10] = static_cast<Byte>(ack >> 8); tcp[11] = static_cast<Byte>(ack);
    tcp[12] = 0x50;                                  // data offset 5
    tcp[13] = flags;
    tcp[14] = 0xFF; tcp[15] = 0xFF;                  // window 65535
    if (0 < payload_len) {
        std::memcpy(pkt.data() + 40, payload, payload_len);
    }
    // Valid checksums: the cksum build validates the IPv4 header and TCP
    // checksums; a zero-checksum segment is dropped and the RST/data
    // scenario never reaches the connection.
    xtcp::harness::FillIp4Checksum(pkt.data());
    xtcp::harness::FillTcp4Checksum(pkt.data(), pkt.data() + 20, 20 + payload_len);
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(static_cast<UInt32>(pkt.size()));
    std::memcpy(buf.Data(), pkt.data(), pkt.size());
    buf.SetLen(static_cast<UInt32>(pkt.size()));
    victim.OnPacket(std::move(buf));
}

// Read the TCP sequence number of the client's SYN (first packet in the
// client backend's Tx queue), forwarding it to the peer backend so the
// handshake still completes. IPv4 header is 20 bytes; TCP seq is at +4.
static UInt32 SynSeq(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b) {
    Byte out[256];
    const UInt32 n = a.PollTx(out);
    if (n < 40) {
        return 0;
    }
    b.Inject(out, n, 0x0800);  // deliver A's SYN to the server
    return (static_cast<UInt32>(out[24]) << 24) | (static_cast<UInt32>(out[25]) << 16) |
           (static_cast<UInt32>(out[26]) << 8) | static_cast<UInt32>(out[27]);
}

int main() {
    xtcp::buf::InitPools();
    {
        // --- Scenario 1A: FIN-WAIT delivers half-close data, then RST closes ---
        {
            xtcp::ndi::ManualBackend backend_a, backend_b;
            xtcp::XtcpStack stack_a(&backend_a);
            xtcp::XtcpStack stack_b(&backend_b);
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
            UInt64 recv_a = 0;
            UInt32 crc_a = 0;
            stack_a.SetRecvHandler([&recv_a, &crc_a](UInt64, const Byte* d, UInt32 len) {
                recv_a += len;
                for (UInt32 i = 0; i < len; ++i) {
                    crc_a = (crc_a * 31 + d[i]) & 0x7FFFFFFF;
                }
            });
            UInt64 recv_b = 0;
            stack_b.SetRecvHandler([&recv_b](UInt64, const Byte*, UInt32 len) {
                recv_b += len;
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
            local.port = 40231;
            remote.family = 4;
            remote.addr[0] = 0x0A000002;
            remote.port = 9111;
            CHECK(stack_b.Listen(remote));
            const UInt64 conn = stack_a.Connect(local, remote);
            CHECK(0 != conn);
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(0 != conn_b);
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

            // A closes while 2048 bytes are in flight: Send + Close back to
            // back, so the FIN lands after un-acknowledged data (FIN-WAIT-1).
            static const UInt32 kInFlight = 2048;
            Byte inflight[kInFlight];
            for (UInt32 i = 0; i < kInFlight; ++i) {
                inflight[i] = static_cast<Byte>((i * 17 + 3) & 0xFF);
            }
            CHECK(stack_a.Send(conn, inflight, kInFlight));
            stack_a.Close(conn);
            Pump(backend_a, backend_b, stack_a, stack_b);
            Pump(backend_a, backend_b, stack_a, stack_b);
            const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
            std::fprintf(stderr, "[close-rst] A mid=%d (expect 5/6 FinWait1/2)\n", (int)mid);
            CHECK(xtcp::core::TcpState::kFinWait1 == mid || xtcp::core::TcpState::kFinWait2 == mid);
            CHECK(xtcp::core::TcpState::kCloseWait == stack_b.ConnectionState(conn_b));
            CHECK(kInFlight == recv_b);  // A's in-flight data was genuinely sent

            // B echoes 8192 while in CLOSE-WAIT (RFC 793 half-close); A keeps
            // delivering it via ProcessClosingData.
            const UInt32 kTotal = 8192;
            std::vector<Byte> payload(kTotal);
            for (UInt32 i = 0; i < kTotal; ++i) {
                payload[i] = static_cast<Byte>((i * 23 + i / 5) & 0xFF);
            }
            UInt64 sent = 0;
            while (sent < kTotal) {
                UInt32 n = static_cast<UInt32>(kTotal - sent);
                if (n > 2048) {
                    n = 2048;
                }
                UInt32 g = 0;
                while (!stack_b.Send(conn_b, payload.data() + sent, n) && 500 > ++g) {
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                sent += n;
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            std::fprintf(stderr, "[close-rst] A recv=%llu\n", (unsigned long long)recv_a);
            CHECK(kTotal == recv_a);  // data during close delivered exactly once
            UInt32 crc_expect = 0;
            for (UInt32 i = 0; i < kTotal; ++i) {
                crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
            }
            CHECK(crc_expect == crc_a);

            // RST during FIN-WAIT closes the connection immediately. The valid
            // seq is A's rcv_nxt_ = B's ISS + 1 + the 8192 half-close bytes A
            // already received (RFC 5961: in-window RST is honored).
            InjectSegment(stack_a, 0x0A000002, 0x0A000001, 9111, 40231, g_iss_b + 1 + kTotal, 0, 0x14, NULLPTR, 0);
            CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
            std::fprintf(stderr, "[close-rst] A final=%d\n",
                         (int)stack_a.ConnectionState(conn));
        }

        // --- Scenario 1B: provable FIN-WAIT-1 RST with un-acked data ---
        {
            xtcp::ndi::ManualBackend backend_a, backend_b;
            xtcp::XtcpStack stack_a(&backend_a);
            xtcp::XtcpStack stack_b(&backend_b);
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
            UInt64 recv_b = 0;
            stack_b.SetRecvHandler([&recv_b](UInt64, const Byte*, UInt32 len) {
                recv_b += len;
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
            local.port = 40232;
            remote.family = 4;
            remote.addr[0] = 0x0A000002;
            remote.port = 9112;
            CHECK(stack_b.Listen(remote));
            const UInt64 conn = stack_a.Connect(local, remote);
            CHECK(0 != conn);
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(0 != conn_b);
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

            static const UInt32 kInFlight = 2048;
            Byte inflight[kInFlight];
            for (UInt32 i = 0; i < kInFlight; ++i) {
                inflight[i] = static_cast<Byte>((i * 29 + 7) & 0xFF);
            }
            CHECK(stack_a.Send(conn, inflight, kInFlight));
            stack_a.Close(conn);
            // Nothing has been pumped since Close, so B's ACK cannot have
            // reached A: it is provably FIN-WAIT-1 with data in flight.
            CHECK(xtcp::core::TcpState::kFinWait1 == stack_a.ConnectionState(conn));

            // RST must close immediately - the in-flight data is abandoned.
            // The valid seq is A's rcv_nxt_ = B's ISS + 1 (B has sent no data
            // here; RFC 5961: in-window RST is honored).
            InjectSegment(stack_a, 0x0A000002, 0x0A000001, 9112, 40232, g_iss_b + 1, 0, 0x14, NULLPTR, 0);
            CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));

            // Flush A's already-queued data+FIN: B still receives them (the
            // peer side is unaffected), A stays closed, no anomaly.
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
            CHECK(kInFlight == recv_b);
            std::fprintf(stderr, "[close-rst] FinWait1 RST: A=%d recv_b=%llu\n",
                         (int)stack_a.ConnectionState(conn), (unsigned long long)recv_b);
        }

        // --- Scenario 2: LAST-ACK drops stray data; the final ACK still closes ---
        {
            xtcp::ndi::ManualBackend backend_a, backend_b;
            xtcp::XtcpStack stack_a(&backend_a);
            xtcp::XtcpStack stack_b(&backend_b);
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
            UInt64 recv_b = 0;
            stack_b.SetRecvHandler([&recv_b](UInt64, const Byte*, UInt32 len) {
                recv_b += len;
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
            local.port = 40233;
            remote.family = 4;
            remote.addr[0] = 0x0A000002;
            remote.port = 9114;
            CHECK(stack_b.Listen(remote));
            const UInt64 conn = stack_a.Connect(local, remote);
            CHECK(0 != conn);
            const UInt32 a_iss = SynSeq(backend_a, backend_b);
            CHECK(0 != a_iss);
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(0 != conn_b);
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

            // A sends its FIN; B enters CLOSE-WAIT.
            stack_a.Close(conn);
            Pump(backend_a, backend_b, stack_a, stack_b);
            CHECK(xtcp::core::TcpState::kCloseWait == stack_b.ConnectionState(conn_b));

            // B closes: it sends its own FIN and waits in LAST-ACK.
            stack_b.Close(conn_b);
            CHECK(xtcp::core::TcpState::kLastAck == stack_b.ConnectionState(conn_b));

            // Stray data (e.g. a peer retransmission) arriving in LAST-ACK
            // must be dropped without disturbing the state: LAST-ACK only
            // watches for its FIN's ACK.
            Byte stray[256];
            for (UInt32 i = 0; i < 256; ++i) {
                stray[i] = static_cast<Byte>(i);
            }
            InjectSegment(stack_b, 0x0A000001, 0x0A000002, 40233, 9114, a_iss + 2, 0,
                          0x18, stray, 256);  // PSH|ACK, seq = B's receive frontier
            CHECK(xtcp::core::TcpState::kLastAck == stack_b.ConnectionState(conn_b));
            CHECK(0 == recv_b);  // stray data was not delivered

            // The final ACK of B's FIN still closes LAST-ACK.
            Pump(backend_a, backend_b, stack_a, stack_b);
            const xtcp::core::TcpState endA = stack_a.ConnectionState(conn);
            const xtcp::core::TcpState endB = stack_b.ConnectionState(conn_b);
            std::fprintf(stderr, "[close-rst] lastack final A=%d B=%d\n", (int)endA, (int)endB);
            CHECK(xtcp::core::TcpState::kTimeWait == endA || xtcp::core::TcpState::kClosed == endA);
            CHECK(xtcp::core::TcpState::kClosed == endB);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSE_RST_COMB: FAILED (%d)\n" : "CLOSE_RST_COMB: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

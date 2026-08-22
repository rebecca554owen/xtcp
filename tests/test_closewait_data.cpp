/**
 * @file test_closewait_data.cpp
 * @brief CLOSE-WAIT data+FIN retransmission: after the peer's FIN puts the
 *        local side in CLOSE-WAIT, a retransmitted data+FIN segment whose
 *        seq is EARLIER than rcv_nxt_-1 (the peer lost our ACK and re-sends
 *        the whole merged segment) must be re-ACKed via the SeqLt check -
 *        not silently ignored. The data must not be re-delivered and the
 *        state must stay CLOSE-WAIT.
 *
 * Scenario (dual stack, A client / B server):
 *   1. Handshake; B's conn id captured from the state handler, B's FIN seq
 *      sniffed from the wire.
 *   2. B sends its final payload then closes (test_fin_data style): A
 *      receives the data in full and enters CLOSE-WAIT.
 *   3. Inject a duplicate data+FIN segment with seq = fin_seq - 100 (i.e.
 *      rcv_nxt_-1-100, exactly 100 bytes before the FIN position) carrying
 *      100 bytes + FIN|PSH|ACK - the peer's retransmission of the merged
 *      data+FIN segment.
 *   4. Assert: A re-ACKs (a new ACK is emitted), state stays CLOSE-WAIT,
 *      and the retransmitted 100 bytes are NOT re-delivered (recv count
 *      unchanged) while the original payload remains byte-intact (CRC).
 *
 * Core assertions:
 *   - data+FIN retransmission (seq < rcv_nxt_-1) is re-ACKed
 *   - data integrity: original payload fully delivered, no duplicates
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

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

static UInt32 g_fin_seq = 0;  // B's FIN seq, sniffed from the wire (== rcv_nxt_-1)
static bool g_fin_seen = false;

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

// Injects a data+FIN retransmission into A: seq = fin_seq - kBehind (the
// peer re-sends a merged segment that ends exactly at the FIN), carrying
// kBehind bytes + FIN|PSH|ACK. Returns the number of NEW ACKs A emits in
// response (drains pending Tx first, then counts the delta).
static UInt32 InjectDataFinReTx(xtcp::ndi::ManualBackend& backend_a,
                                xtcp::XtcpStack& stack_a,
                                UInt16 remote_port, UInt16 local_port,
                                UInt32 fin_seq) {
    Byte out[65536];
    UInt32 acks_before = 0;
    while (0 != backend_a.TxPending()) {
        const UInt32 n = backend_a.PollTx(out);
        if (0 < n && 40 <= n && 0 == (out[20 + 13] & 0x01)) {
            ++acks_before;
        }
    }
    const UInt32 kBehind = 100;
    const UInt32 seq = fin_seq - kBehind;
    // Old data + FIN re-send (stale ACK, ignored): payload [0x80..] x100.
    // Valid checksums so the re-ACK path runs under the checksum-validate
    // build (a zero-checksum segment is dropped there, no re-ACK).
    Byte payload[100];
    for (UInt32 i = 0; i < kBehind; ++i) {
        payload[i] = static_cast<Byte>(0x80 + (i & 0x7F));
    }
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, remote_port, local_port, seq, 0, 0x19, payload, kBehind);
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(static_cast<UInt32>(pkt.size()));
    std::memcpy(buf.Data(), pkt.data(), pkt.size());
    buf.SetLen(static_cast<UInt32>(pkt.size()));
    stack_a.OnPacket(std::move(buf));

    UInt32 acks_after = 0;
    while (0 != backend_a.TxPending()) {
        const UInt32 n = backend_a.PollTx(out);
        if (0 < n && 40 <= n && 0 == (out[20 + 13] & 0x01)) {
            ++acks_after;
        }
    }
    return acks_after > acks_before ? (acks_after - acks_before) : 0;
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            if (p.len >= 40 && (p.data[20 + 13] & 0x01) && !(p.data[20 + 13] & 0x02)) {
                g_fin_seq = Load32BE(p.data + 20 + 4);
                g_fin_seen = true;
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
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        const UInt16 kLocalPort = 40205;
        const UInt16 kRemotePort = 9145;
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = kLocalPort;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = kRemotePort;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // B sends its final payload then closes: A receives it fully and
        // enters CLOSE-WAIT (test_fin_data style).
        const UInt32 kTotal = 4096;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 17 + i / 7) & 0xFF);
        }
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        UInt64 sent = 0;
        while (sent < kTotal) {
            UInt32 n = kTotal - static_cast<UInt32>(sent);
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
        stack_b.Close(conn_b);
        // Drain until the FIN is seen (not merely the data: the 4096 bytes
        // may already be delivered by the send loop, so gating on recv_a
        // alone would exit before the FIN is ever pumped out of B's queue).
        for (UInt32 i = 0; i < 2000 && (recv_a < kTotal || !g_fin_seen); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[cw-data] A state=%d recv=%llu fin_seq=%u\n",
                     (int)stack_a.ConnectionState(conn), (unsigned long long)recv_a, g_fin_seq);
        CHECK(xtcp::core::TcpState::kCloseWait == stack_a.ConnectionState(conn));
        CHECK(recv_a == kTotal);
        CHECK(crc_expect == crc_a);
        CHECK(g_fin_seen);

        // Inject a data+FIN retransmission with seq = fin_seq - 100 (i.e.
        // rcv_nxt_-1-100, earlier than the pure-FIN seq). The SeqLt check
        // in the CLOSE-WAIT handler must re-ACK it. The 100 retransmitted
        // bytes must NOT be re-delivered (recv unchanged) and the state
        // must stay CLOSE-WAIT.
        const UInt64 recv_before = recv_a;
        const UInt32 re_acks = InjectDataFinReTx(backend_a, stack_a, kRemotePort, kLocalPort, g_fin_seq);
        std::fprintf(stderr, "[cw-data] re-acks=%u recv=%llu\n", re_acks, (unsigned long long)recv_a);
        CHECK(1 <= re_acks);
        CHECK(xtcp::core::TcpState::kCloseWait == stack_a.ConnectionState(conn));
        CHECK(recv_a == recv_before);
        CHECK(crc_expect == crc_a);

        // Close the loop: A closes back so the shutdown completes cleanly.
        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSEWAIT_DATA: FAILED (%d)\n" : "CLOSEWAIT_DATA: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

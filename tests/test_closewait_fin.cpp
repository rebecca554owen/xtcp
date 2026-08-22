/**
 * @file test_closewait_fin.cpp
 * @brief CLOSE-WAIT duplicate-FIN handling: after the peer's FIN puts the
 *        local side in CLOSE-WAIT, a retransmitted FIN (the peer lost our
 *        ACK) must be re-ACKed so the peer stops burning its retransmission
 *        budget - not silently ignored.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>
#include <thread>

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

static UInt32 g_fin_seq = 0;
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

// Replays a duplicate FIN (the peer's own FIN seq) into A and returns the
// number of re-ACKs A emits in response.
static UInt32 CountReAcks(xtcp::ndi::ManualBackend& backend_a,
                          xtcp::XtcpStack& stack_a) {
    if (!g_fin_seen) {
        return 0;
    }
    Byte out[65536];
    UInt32 acks_before = 0;
    while (0 != backend_a.TxPending()) {
        const UInt32 n = backend_a.PollTx(out);
        if (0 < n && 40 <= n && 0 == (out[20 + 13] & 0x01)) {
            ++acks_before;
        }
    }
    // Duplicate FIN replay with VALID checksums: under the checksum-validate
    // build a zero-checksum FIN is dropped and A never re-ACKs.
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, 8080, 40176, g_fin_seq, 0, 0x01);
    pkt[34] = 0x40; pkt[35] = 0x00;  // window 0x4000 (matches the original)
    xtcp::harness::FillTcp4Checksum(pkt.data(), pkt.data() + 20, 20);
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
            if (p.len >= 40 && 0x01 == (p.data[20 + 13] & 0x01)) {
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

        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40176;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // B closes: A enters CLOSE-WAIT.
        stack_b.Close(conn_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[cw-fin] A state=%d\n", (int)stack_a.ConnectionState(conn));
        CHECK(xtcp::core::TcpState::kCloseWait == stack_a.ConnectionState(conn));

        // Replay a duplicate FIN; A must re-ACK it (>= 1 new ACK emitted).
        const UInt32 re_acks = CountReAcks(backend_a, stack_a);
        std::fprintf(stderr, "[cw-fin] re-acks=%u fin_seq=%u\n", re_acks, g_fin_seq);
        CHECK(1 <= re_acks);
        CHECK(xtcp::core::TcpState::kCloseWait == stack_a.ConnectionState(conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSEWAIT_FIN: FAILED (%d)\n" : "CLOSEWAIT_FIN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

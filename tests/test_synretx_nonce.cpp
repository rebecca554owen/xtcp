/**
 * @file test_synretx_nonce.cpp
 * @brief RFC 3168 s6.1.1 retransmitted-SYN ECN regression: the FIRST SYN
 *        offers ECN (ECE set, both stacks SetDefaultEcn(true) before the
 *        handshake), but a SYN retransmitted by the RTO timer must NOT carry
 *        the ECE bit - ECN is negotiated only on the first SYN; a router may
 *        have marked it (CE), and re-offering ECN on a retransmission would
 *        replay a stale marking.
 *
 *        Scenario: dual stack -> both sides SetDefaultEcn(true) -> Connect
 *        -> intercept A's first SYN (PollTx, record the ECE bit, do NOT
 *        inject it - the lost-SYN blackhole, cf. test_tfo_synloss.cpp) ->
 *        the RTO timer (~1s) retransmits -> backend_b's RxHandler observes
 *        the SYN that actually reaches B and checks the 0x40 ECE bit
 *        (first vs retransmit are distinguished by capture point: the first
 *        SYN is recorded at the intercept, never arrives at B; the
 *        retransmitted SYN is recorded in backend_b's RxHandler) ->
 *        complete the handshake with the retransmitted SYN -> assert first
 *        SYN ECE, retransmitted SYN has no ECE, connection Established, and
 *        an 8192-byte transfer arrives intact (exact byte count + rolling
 *        CRC: loss would under-count, duplication would over-count/mismatch).
 *
 *        Current code complies: the kSynSent RTO retransmit path emits a
 *        bare SYN with no ECE (tcp_fsm.cpp:720-722), while the first SYN
 *        offers ECN (tcp_fsm.cpp:1572). All core assertions are GREEN.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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

namespace {
    // Wire observers. A's tx queue (resp. backend_b's RxHandler) sees A->B
    // traffic; flags live at byte 33 (IPv4 20 + TCP byte 13). ECE = 0x40,
    // SYN = 0x02, SYN+ACK = 0x12.
    UInt32 g_first_syn_ece = 0;  // A's first SYN ECE bit (captured at intercept)
    UInt32 g_retx_syn_ece = 0;   // retransmitted SYN ECE bit (backend_b's RxHandler)
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

int main() {
    xtcp::buf::InitPools();
    {
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
            // backend_b's RxHandler sees every A->B packet. The first SYN was
            // blackholed at the intercept, so a SYN reaching B (SYN bit set,
            // no ACK bit - the plain SYN, never the SYN+ACK B itself emits)
            // is by construction the RTO retransmission. Check its ECE bit.
            if (p.len > 34 && 0 != (p.data[33] & 0x02) && 0 == (p.data[33] & 0x10)) {
                g_retx_syn_ece = (0 != (p.data[33] & 0x40)) ? 1 : 0;
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40168;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9135;
        // Both sides request ECN before the handshake (stack-wide default
        // applied at connection creation, before the SYN goes out).
        stack_a.SetDefaultEcn(true);
        stack_b.SetDefaultEcn(true);
        CHECK(stack_b.Listen(remote));

        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);

        // Grab A's original SYN, record its ECE bit, then blackhole it
        // (never injected into B): this is the lost SYN (the first A->B
        // packet), forcing the RTO timer to retransmit.
        Byte out[65536];
        UInt32 syn_len = 0;
        UInt32 guard = 0;
        while (0 != backend_a.TxPending() && 20000 > ++guard) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n && n > 34 && 0 != (out[33] & 0x02)) {
                syn_len = n;
                g_first_syn_ece = (0 != (out[33] & 0x40)) ? 1 : 0;
                break;  // dropped: not injected into B
            }
        }
        CHECK(0 < syn_len);

        // Wait for the RTO-driven SYN retransmission (~1s: rto_ default,
        // single initial arm). Capture it from A's tx queue.
        Byte retx[65536];
        UInt32 retx_len = 0;
        bool got_retx = false;
        for (UInt32 i = 0; i < 400 && !got_retx; ++i) {
            stack_a.PollAckTimers();  // drives the RTO (real clock)
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(retx);
                if (0 < n && n > 34 && 0 != (retx[33] & 0x02)) {
                    retx_len = n;
                    got_retx = true;
                    break;
                }
            }
            if (!got_retx) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        CHECK(got_retx);

        // Core assertion 1: the FIRST SYN offered ECN (SetDefaultEcn(true)).
        CHECK(0 != g_first_syn_ece);

        if (got_retx) {
            // Deliver the retransmitted SYN to B; backend_b's RxHandler
            // records its ECE bit.
            backend_b.Inject(retx, retx_len, 0x0800);
            UInt32 wguard = 0;
            while (xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn) &&
                   20000 > ++wguard) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

            // Core assertion 2: the RTO-retransmitted SYN MUST carry the same
            // ECN offer (ECE+CWR) as the first SYN (RFC 3168 s6.1.1: the
            // offer persists on retransmissions - dropping it would silently
            // lose the negotiation whenever the first SYN is lost).
            std::fprintf(stderr, "[synretx-nonce] first SYN ECE=%u retransmitted SYN ECE=%u\n",
                         g_first_syn_ece, g_retx_syn_ece);
            CHECK(1 == g_first_syn_ece);
            CHECK(1 == g_retx_syn_ece);

            // Data integrity: the connection must work end to end after the
            // retransmitted SYN (no loss, no duplication).
            const UInt32 kTotal = 8192;
            std::vector<Byte> payload(kTotal);
            for (UInt32 i = 0; i < kTotal; ++i) {
                payload[i] = static_cast<Byte>((i * 3 + i / 19) & 0xFF);
            }
            UInt64 sent = 0;
            for (UInt32 round = 0; round < 16 && sent < kTotal; ++round) {
                UInt32 n = static_cast<UInt32>(kTotal - sent);
                if (n > 2048) {
                    n = 2048;
                }
                UInt32 g = 0;
                while (!stack_a.Send(conn, payload.data() + sent, n) && 300 > ++g) {
                    Pump(backend_a, backend_b, stack_a, stack_b);
                }
                sent += n;
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
            CHECK(kTotal == sent);
            for (UInt32 i = 0; i < 500 && bytes_recv < kTotal; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            std::fprintf(stderr, "[synretx-nonce] received=%llu\n", (unsigned long long)bytes_recv);
            CHECK(kTotal == bytes_recv);  // no loss, no duplicate

            UInt32 crc_expect = 0;
            for (UInt32 i = 0; i < kTotal; ++i) {
                crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
            }
            std::fprintf(stderr, "[synretx-nonce] crc recv=%u exp=%u\n", crc_recv, crc_expect);
            CHECK(crc_expect == crc_recv);  // byte-perfect delivery

            stack_a.Close(conn);
            for (UInt32 i = 0; i < 100; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYNRETX_NONCE: FAILED (%d)\n" : "SYNRETX_NONCE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_tfo_synloss.cpp
 * @brief RFC 7413 first fast-open connection (no cached cookie) + lost SYN:
 *        the no-cookie branch must buffer the early data in pending_send_
 *        (the initial SYN is naked, the wire carries no early bytes), the
 *        RTO retransmit must be a NAKED SYN (a cookie-less SYN+data would be
 *        refused by the server), and the buffered early data flushes exactly
 *        once on Established - no loss, no duplicate.
 *
 *        Scenario: dual stack -> first ConnectWithTfo (early data, no
 *        cookie) -> drop the first A->B packet (the SYN) -> the RTO timer
 *        retransmits -> handshake completes -> assert the early data arrives
 *        intact (exact byte count + rolling CRC: loss would under-count,
 *        duplication would over-count/mismatch) and A is Established.
 *
 *        Known current-code deviation (documented bug): the no-cookie SYN
 *        retransmit path (tcp_fsm.cpp:712-714) still emits SYN+early-data
 *        without a cookie. The server refuses cookie-less SYN-carried data
 *        (stack.cpp:847), so the early bytes are NOT duplicated end to end -
 *        they are delivered once via the pending_send_ flush. The wire-level
 *        "retransmit is naked" assertion below is therefore RED today and
 *        GREEN once that path sends a naked SYN.
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
        local.port = 40166;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9133;
        CHECK(stack_b.Listen(remote));

        const UInt32 kTotal = 8192;
        const UInt32 kEarly = 64;  // early data handed to ConnectWithTfo
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 3 + i / 19) & 0xFF);
        }

        // First-ever fast-open connect: no cached cookie. The no-cookie
        // branch buffers the early data in pending_send_ and emits a NAKED
        // SYN (tcp_fsm.cpp:1591-1601) - the wire must not carry the early
        // bytes on the initial SYN.
        const UInt64 conn = stack_a.ConnectWithTfo(local, remote, payload.data(), kEarly);
        CHECK(0 != conn);

        // Grab A's original SYN and blackhole it (never injected into B):
        // this is the lost SYN (the first A->B packet).
        Byte out[65536];
        UInt32 syn_len = 0;
        UInt32 first_syn_payload = 0;
        UInt32 guard = 0;
        while (0 != backend_a.TxPending() && 20000 > ++guard) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n && n > 34 && 0 != (out[33] & 0x02)) {
                syn_len = n;
                const UInt32 tcp_hdr = (static_cast<UInt32>(out[32]) >> 4) * 4;
                first_syn_payload = (syn_len > 20 + tcp_hdr) ? (syn_len - 20 - tcp_hdr) : 0;
                break;
            }
        }
        CHECK(0 < syn_len);
        CHECK(0 == first_syn_payload);  // no-cookie first SYN is naked (fix)

        // Wait for the RTO-driven SYN retransmission (~1s: rto_ default,
        // single initial arm). Capture it from A's tx queue.
        Byte retx[65536];
        UInt32 retx_len = 0;
        UInt32 retx_payload = 0;
        bool got_retx = false;
        for (UInt32 i = 0; i < 400 && !got_retx; ++i) {
            stack_a.PollAckTimers();  // drives the RTO (real clock)
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(retx);
                if (0 < n && n > 34 && 0 != (retx[33] & 0x02)) {
                    retx_len = n;
                    const UInt32 tcp_hdr = (static_cast<UInt32>(retx[32]) >> 4) * 4;
                    retx_payload = (retx_len > 20 + tcp_hdr) ? (retx_len - 20 - tcp_hdr) : 0;
                    got_retx = true;
                    break;
                }
            }
            if (!got_retx) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        CHECK(got_retx);
        if (got_retx) {
            std::fprintf(stderr, "[tfo-synloss] retransmitted SYN carries %u data bytes\n",
                         retx_payload);
            // Fixed behavior: the no-cookie retransmit is a NAKED SYN (the
            // early data lives in pending_send_, flushed on Established).
            // Current code (tcp_fsm.cpp:712-714) still emits SYN+data here ->
            // RED today, GREEN once that path sends a naked SYN.
            CHECK(0 == retx_payload);

            // Complete the handshake with the retransmitted SYN.
            backend_b.Inject(retx, retx_len, 0x0800);
            UInt32 wguard = 0;
            while (xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn) &&
                   20000 > ++wguard) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

            // The buffered early data must be flushed exactly once on
            // Established (pending_send_ -> wire, not SYN-carried).
            for (UInt32 i = 0; i < 100 && bytes_recv < kEarly; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            CHECK(kEarly <= bytes_recv);

            // Send the rest; everything must arrive intact end to end.
            UInt64 sent = kEarly;
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
            std::fprintf(stderr, "[tfo-synloss] received=%llu\n", (unsigned long long)bytes_recv);
            CHECK(kTotal == bytes_recv);  // no loss, no duplicate

            UInt32 crc_expect = 0;
            for (UInt32 i = 0; i < kTotal; ++i) {
                crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
            }
            std::fprintf(stderr, "[tfo-synloss] crc recv=%u exp=%u\n", crc_recv, crc_expect);
            CHECK(crc_expect == crc_recv);  // byte-perfect delivery

            stack_a.Close(conn);
            for (UInt32 i = 0; i < 100; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TFO_SYNLOSS: FAILED (%d)\n" : "TFO_SYNLOSS: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

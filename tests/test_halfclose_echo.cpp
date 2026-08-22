/**
 * @file test_halfclose_echo.cpp
 * @brief Half-close echo server (real echo mode): A sends data + Close (data
 *        in flight, FIN-WAIT-1), B - the peer on the half-close receive side -
 *        echoes every byte it receives back (a genuine echo server), then
 *        closes. A must receive the complete echo intact and both sides must
 *        reach their RFC 793 final states.
 *
 * Scenario
 * --------
 *   - Dual-stack A<->B over two ManualBackends (back-to-back).
 *   - A's connection uses a custom CC ("bigwin", snd_cwnd = 10 MSS) so the
 *     whole 8 KiB payload is in flight BEFORE the FIN. The default RFC 5681
 *     initial window (3 MSS, tcp_fsm.cpp:532) would put only 4380 B ahead of
 *     the FIN; the remaining data would reach B only after B had already
 *     entered CLOSE-WAIT, and the CloseWait case (tcp_fsm.cpp:2033) delivers
 *     no payload - those bytes would be dropped and the echo would be broken.
 *   - A sends 8192 bytes + Close() back to back: A enters FIN-WAIT-1 with all
 *     8192 bytes unacknowledged.
 *   - B echoes every received chunk back from its recv handler (real echo),
 *     i.e. it returns exactly what it got - so A's own payload is the echo.
 *   - Once A holds the full echo, B Close()s: B -> LAST-ACK -> CLOSED.
 *   - A (FIN-WAIT-1/2) receives B's echo data + FIN -> TIME-WAIT.
 *
 * Core assertions
 * --------------
 *   CHECK(kFinWait1 == A state right after Send+Close)  - data in flight, FIN sent
 *   CHECK(kTotal == recv_b && crc_expect == crc_b)      - B received A's payload intact
 *   CHECK(kTotal == recv_a && crc_expect == crc_a)      - A received the complete echo intact
 *   CHECK(kCloseWait == B state while echoing)          - B sits on the half-close receive side
 *   CHECK(0 == echo_fail)                               - the real-echo Send never backed off
 *   CHECK(kTimeWait == A final || kClosed == A final)   - A's close completes
 *   CHECK(kClosed == B final)                           - B's close completes
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/cc/cc.h>

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

// Big initial window so the whole 8 KiB test payload is in flight at Close
// (the default RFC 5681 initial window of 3 MSS caps the burst at 4380 B,
// which would let B enter CLOSE-WAIT before the tail data arrived).
void BigWinInit(xtcp::cc::XtcpConnCc* sk) noexcept {
    sk->snd_cwnd = 10;
}
const xtcp::cc::XtcpCongestionOps kBigWin = {
    "bigwin",   // name
    BigWinInit, // init
    NULLPTR,    // release
    NULLPTR,    // ssthresh
    NULLPTR,    // cong_avoid
    NULLPTR,    // set_state
    NULLPTR,    // cwnd_event
    NULLPTR,    // pkts_acked
    NULLPTR,    // undo_cwnd
    NULLPTR,    // cong_control
    NULLPTR,    // reinit_ssthresh
    0,          // flags
};

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
    CHECK(xtcp::cc::RegisterCongestionControl(kBigWin));
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

        // A counts/digests what it receives: this is the echo A must get back
        // byte-for-byte, exactly once (fewer = lost, more = duplicated).
        UInt64 recv_a = 0;
        UInt32 crc_a = 0;
        stack_a.SetRecvHandler([&recv_a, &crc_a](UInt64, const Byte* d, UInt32 len) {
            recv_a += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_a = (crc_a * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        // Real echo server on B: echo back exactly what arrived, and keep
        // bookkeeping (bytes + CRC) so the echo's correctness is verifiable.
        UInt64 recv_b = 0;
        UInt32 crc_b = 0;
        UInt32 echo_fail = 0;
        stack_b.SetRecvHandler([&stack_b, &recv_b, &crc_b, &echo_fail](
                                   UInt64 id, const Byte* d, UInt32 len) {
            recv_b += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_b = (crc_b * 31 + d[i]) & 0x7FFFFFFF;
            }
            if (!stack_b.Send(id, d, len)) {
                ++echo_fail;  // the echo must never back off at 8 KiB
            }
        });

        // B's passive conn id MUST be captured from SetStateHandler - each
        // stack generates its own ids, never assume conn_b == conn_a + 1.
        UInt64 conn_b = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40261;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9163;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(0 != conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Widen both windows: A must put the whole payload ahead of its FIN,
        // B must burst the echo back without the ACK clock.
        CHECK(stack_a.SetCongestionControl(conn, "bigwin"));
        CHECK(stack_b.SetCongestionControl(conn_b, "bigwin"));

        // A sends 8192 bytes (6 segments) and closes immediately: FIN-WAIT-1
        // with all 8192 bytes unacknowledged and the echo still owed by B.
        const UInt32 kTotal = 8192;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 23 + i / 5) & 0xFF);
        }
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(stack_a.Send(conn, payload.data(), kTotal));
        stack_a.Close(conn);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[halfclose-echo] A state after Send+Close=%d (expect 5=FinWait1)\n",
                     static_cast<int>(mid));
        CHECK(xtcp::core::TcpState::kFinWait1 == mid);

        // B receives A's data + FIN (-> CLOSE-WAIT), echoing every chunk back;
        // A delivers the echo through ProcessClosingData while in FIN-WAIT-1/2.
        for (UInt32 i = 0; i < 500 && (recv_a < kTotal || recv_b < kTotal); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr,
                     "[halfclose-echo] A_recv=%llu B_recv=%llu crc_a=%u crc_b=%u echo_fail=%u\n",
                     (unsigned long long)recv_a, (unsigned long long)recv_b, crc_a, crc_b, echo_fail);

        // B got A's payload intact (the data the echo is built from) ...
        CHECK(kTotal == recv_b);
        CHECK(crc_expect == crc_b);
        // ... and A got the complete echo back, byte-for-byte, exactly once.
        CHECK(kTotal == recv_a);
        CHECK(crc_expect == crc_a);
        CHECK(0 == echo_fail);

        // B sits on the half-close receive side (A's FIN consumed) while A is
        // still closing (FIN-WAIT-1/2) - the RFC 793 half-close configuration.
        const xtcp::core::TcpState b_state = stack_b.ConnectionState(conn_b);
        const xtcp::core::TcpState a_state = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[halfclose-echo] B state=%d (expect 7=CloseWait) A state=%d\n",
                     static_cast<int>(b_state), static_cast<int>(a_state));
        CHECK(xtcp::core::TcpState::kCloseWait == b_state);
        CHECK(xtcp::core::TcpState::kFinWait1 == a_state ||
              xtcp::core::TcpState::kFinWait2 == a_state);

        // B closes its half: B -> LAST-ACK -> CLOSED; A gets B's FIN and the
        // exchange reaches TIME-WAIT.
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 300; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn);
        const xtcp::core::TcpState b_end = stack_b.ConnectionState(conn_b);
        std::fprintf(stderr, "[halfclose-echo] A final=%d (expect 10=TimeWait or 0=Closed) B final=%d\n",
                     static_cast<int>(end), static_cast<int>(b_end));
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
        CHECK(xtcp::core::TcpState::kClosed == b_end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "HALFCLOSE_ECHO: FAILED (%d)\n" : "HALFCLOSE_ECHO: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

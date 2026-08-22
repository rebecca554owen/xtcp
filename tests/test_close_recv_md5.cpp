/**
 * @file test_close_recv_md5.cpp
 * @brief RFC 793 half-close receive path under RFC 2385 TCP-MD5: A closes
 *        first (its FIN goes out; A waits in FIN-WAIT-1/2), then B - now in
 *        CLOSE-WAIT - replies with a large payload before closing. Every
 *        segment B emits in that half-close reply MUST carry a valid TCP-MD5
 *        signature (kind 19, len 18, non-zero digest): the signature chain
 *        (SendSegment -> Md5Key/Md5KeyLen, cf. test_synretx_md5.cpp) has to
 *        stay intact on the post-close data path, and A's MD5-validating
 *        receive path must accept the signed reply. The connection is set up
 *        with ConnectWithMd5 + SetMd5KeyForListener (key armed before SYN,
 *        Linux TCP_MD5SIG semantics), so the handshake itself is MD5-gated.
 *
 *        Scenario (mirrors test_close_recv.cpp): dual stack MD5 -> A Close
 *        (FinWait1/2, MD5-signed FIN) -> B, in CloseWait, sends 8192 bytes
 *        back -> A's ProcessClosingData delivers the reply while it waits
 *        -> B Close (signed FIN) -> A terminal state TimeWait/Closed.
 *
 *        Core assertion: the half-close echo is byte-perfect (recv count +
 *        rolling CRC), A reaches its terminal state, and - the MD5-specific
 *        half of the test - EVERY B->A segment carrying payload during the
 *        CloseWait reply is wire-level signed with a non-zero digest.
 *        Because A drops unsigned/incorrectly-signed segments before the
 *        data path (VerifyMd5Segment, tcp_fsm.cpp:1718), a complete echo
 *        independently proves the half-close path's MD5 validation.
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

// Scans a captured IPv4+TCP packet's TCP options for an RFC 2385 TCP-MD5
// option (kind 19, length 18). Returns true when present AND the 16-byte
// digest is non-zero (a real computed signature, not the zeroed build-time
// placeholder). Options are walked generically (kind/len), so the layout is
// not assumed.
static bool HasMd5Signature(const Byte* p, UInt32 n, bool& nonzero_digest) {
    nonzero_digest = false;
    if (NULLPTR == p || n < 40) {
        return false;
    }
    const UInt32 tcp_off = (static_cast<UInt32>(p[32] >> 4)) * 4;
    if (tcp_off < 24 || tcp_off > n - 20) {
        return false;
    }
    const Byte* t = p + 20;  // TCP header (IPv4)
    UInt32 pos = 20;         // first option byte
    const UInt32 end = tcp_off;
    while (pos + 1 < end) {
        const Byte kind = t[pos];
        if (1 == kind) {
            ++pos;  // NOP
            continue;
        }
        const Byte len = t[pos + 1];
        if (2 > len || pos + len > end) {
            break;
        }
        if (19 == kind && 18 == len) {
            for (UInt32 i = 0; i < 16; ++i) {
                if (0 != t[pos + 2 + i]) {
                    nonzero_digest = true;
                }
            }
            return true;
        }
        pos += len;
    }
    return false;
}

// B->A data segments counted on the wire (payload-carrying segments only)
// and, of those, how many carry a valid non-zero TCP-MD5 signature.
static UInt32 g_b2a_data_total = 0;
static UInt32 g_b2a_data_signed = 0;

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
                // Probe the B->A half-close reply: any segment carrying
                // payload past the TCP header is a data segment, and must be
                // MD5-signed (kind 19, len 18, non-zero digest).
                const UInt32 tcp_off = (static_cast<UInt32>(out[32] >> 4)) * 4;
                if (n > 20 + tcp_off) {
                    ++g_b2a_data_total;
                    bool nz = false;
                    if (HasMd5Signature(out, n, nz) && nz) {
                        ++g_b2a_data_signed;
                    }
                }
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

        UInt64 recv_a = 0;
        UInt32 crc_a = 0;
        stack_a.SetRecvHandler([&recv_a, &crc_a](UInt64, const Byte* d, UInt32 len) {
            recv_a += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_a = (crc_a * 31 + d[i]) & 0x7FFFFFFF;
            }
        });
        UInt64 conn_b = 0;  // B's established connection id (acceptance proof)
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });

        const Byte key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40183;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9149;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));

        // MD5 key armed before the SYN goes out (ConnectWithMd5 ->
        // SetMd5Key -> SendSyn, stack.cpp:491/502). The listener validates
        // the signed SYN; the handshake completing is the acceptance proof.
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[close-recv-md5] handshake A state=%d B_conn_id=%llu\n",
                     (int)stack_a.ConnectionState(conn), (unsigned long long)conn_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(0 != conn_b);
        CHECK(1 == stack_b.ConnectionCount());

        // A closes first (its MD5-signed FIN goes out); B, now in
        // CLOSE-WAIT, still replies with a large payload before closing
        // (RFC 793 half-close). Reset the wire probe for the echo phase.
        g_b2a_data_total = 0;
        g_b2a_data_signed = 0;
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        const xtcp::core::TcpState mid = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[close-recv-md5] A mid-close state=%d\n", (int)mid);
        CHECK(xtcp::core::TcpState::kFinWait1 == mid || xtcp::core::TcpState::kFinWait2 == mid);

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
        stack_b.Close(conn_b);
        for (UInt32 i = 0; i < 500 && recv_a < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[close-recv-md5] A_recv=%llu b2a_data=%u b2a_signed=%u\n",
                     (unsigned long long)recv_a, g_b2a_data_total, g_b2a_data_signed);

        // Core assertion: the half-close echo is complete and byte-perfect.
        CHECK(kTotal == recv_a);
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_a);

        // MD5-specific assertion: every B->A data segment on the half-close
        // reply path carries a real TCP-MD5 signature. (A would drop any
        // unsigned/corrupt segment at VerifyMd5Segment before the data path,
        // so the complete echo above already proves acceptance - this is the
        // direct wire-level confirmation.)
        CHECK(0 < g_b2a_data_total);
        CHECK(g_b2a_data_total == g_b2a_data_signed);

        // Let B's MD5-signed FIN (sent after its data) reach A.
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const xtcp::core::TcpState end = stack_a.ConnectionState(conn);
        std::fprintf(stderr, "[close-recv-md5] A final state=%d\n", (int)end);
        CHECK(xtcp::core::TcpState::kTimeWait == end || xtcp::core::TcpState::kClosed == end);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CLOSE_RECV_MD5: FAILED (%d)\n" : "CLOSE_RECV_MD5: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

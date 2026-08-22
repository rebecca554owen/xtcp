/**
 * @file test_synretx_md5.cpp
 * @brief RFC 2385 TCP-MD5 over a lost SYN: the FIRST A->B SYN is blackholed
 *        (never injected); the RTO timer retransmits it. The retransmitted
 *        SYN MUST carry a valid TCP-MD5 signature (kind 19, len 18, non-zero
 *        digest) - the key is armed before connect() (Linux TCP_MD5SIG
 *        semantics), so every SYN this connection emits is signed. The
 *        MD5-validating listener ACCEPTS the signed retransmit (a
 *        signatureless/invalid SYN is dropped, cf. test_syncookie_md5.cpp),
 *        the handshake completes, and a 16 KiB transfer arrives byte-perfect.
 *
 *        Scenario (mirrors test_synretx_nonce.cpp): dual stack -> stack_b
 *        Listens + SetMd5KeyForListener -> stack_a ConnectWithMd5 -> intercept
 *        A's first SYN (PollTx, record its MD5 signature, do NOT inject - the
 *        lost-SYN blackhole) -> the RTO timer (~1s) retransmits -> capture the
 *        retransmitted SYN, verify its signature -> deliver it to B -> the
 *        handshake completes with the retransmitted SYN -> transfer.
 *
 *        Wire-level assertion: the MD5 option (kind 19, length 18, 16-byte
 *        digest) is present with a non-zero digest on BOTH the first SYN and
 *        the RTO retransmission - tcp_fsm.cpp:720-722 routes the SynSent RTO
 *        retransmit through SendSegment, which signs via Md5Key()/Md5KeyLen().
 *        The B-side state handler observes kEstablished, proving B's listener
 *        accepted the signed retransmit. The 8192-byte... 16384-byte transfer
 *        is verified by exact byte count + rolling CRC (loss would
 *        under-count, duplication would over-count/mismatch).
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

        UInt64 conn_b = 0;  // B's established connection id (acceptance proof)
        UInt64 bytes_recv = 0;
        UInt32 crc_recv = 0;
        stack_b.SetStateHandler([&conn_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                conn_b = id;
            }
        });
        stack_b.SetRecvHandler([&bytes_recv, &crc_recv](UInt64, const Byte* d, UInt32 len) {
            bytes_recv += len;
            for (UInt32 i = 0; i < len; ++i) {
                crc_recv = (crc_recv * 31 + d[i]) & 0x7FFFFFFF;
            }
        });

        const Byte key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40182;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9148;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));

        // A arms the MD5 key before the SYN goes out (ConnectWithMd5 ->
        // SetMd5Key -> SendSyn, stack.cpp:491/502).
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);

        // Grab A's original SYN, record its MD5 signature, then blackhole it
        // (never injected into B): the lost SYN, forcing the RTO to retransmit.
        Byte out[65536];
        UInt32 syn_len = 0;
        bool first_syn_signed = false;
        bool first_syn_digest = false;
        UInt32 guard = 0;
        while (0 != backend_a.TxPending() && 20000 > ++guard) {
            const UInt32 n = backend_a.PollTx(out);
            if (0 < n && n > 34 && 0 != (out[33] & 0x02)) {
                syn_len = n;
                first_syn_signed = HasMd5Signature(out, n, first_syn_digest);
                break;  // dropped: not injected into B
            }
        }
        CHECK(0 < syn_len);
        std::fprintf(stderr, "[synretx-md5] first SYN len=%u signed=%d digest_nonzero=%d\n",
                     syn_len, first_syn_signed ? 1 : 0, first_syn_digest ? 1 : 0);
        // The key was armed before connect(): the first SYN is signed too.
        CHECK(first_syn_signed);
        CHECK(first_syn_digest);

        // Wait for the RTO-driven SYN retransmission (~1s: rto_ default,
        // single initial arm). Capture it from A's tx queue.
        Byte retx[65536];
        UInt32 retx_len = 0;
        bool retx_signed = false;
        bool retx_digest = false;
        bool got_retx = false;
        for (UInt32 i = 0; i < 400 && !got_retx; ++i) {
            stack_a.PollAckTimers();  // drives the RTO (real clock)
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(retx);
                if (0 < n && n > 34 && 0 != (retx[33] & 0x02)) {
                    retx_len = n;
                    retx_signed = HasMd5Signature(retx, n, retx_digest);
                    got_retx = true;
                    break;
                }
            }
            if (!got_retx) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        CHECK(got_retx);
        std::fprintf(stderr, "[synretx-md5] retransmitted SYN len=%u signed=%d digest_nonzero=%d\n",
                     retx_len, retx_signed ? 1 : 0, retx_digest ? 1 : 0);

        // Core assertion 1: the RTO retransmitted SYN is still MD5-signed
        // (tcp_fsm.cpp:720-722 -> SendSegment -> Md5Key/Md5KeyLen) with a
        // non-zero digest. A bare/unsigned retransmit would be rejected by
        // the MD5-validating listener and the handshake could never finish.
        CHECK(retx_signed);
        CHECK(retx_digest);

        if (got_retx) {
            // Deliver the retransmitted SYN to B. B's listener verifies the
            // signature; only a valid signed SYN is accepted.
            backend_b.Inject(retx, retx_len, 0x0800);
            UInt32 wguard = 0;
            while (xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn) &&
                   20000 > ++wguard) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            std::fprintf(stderr, "[synretx-md5] A state=%d B_conns=%u B_conn_id=%llu\n",
                         (int)stack_a.ConnectionState(conn), (UInt32)stack_b.ConnectionCount(),
                         (unsigned long long)conn_b);

            // Core assertion 2: the handshake completes through the
            // retransmitted SYN - B accepted its signature. (An unsigned or
            // wrongly-signed SYN is dropped by the MD5-keyed listener, so
            // kEstablished is the acceptance proof.)
            CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
            CHECK(0 != conn_b);
            CHECK(1 == stack_b.ConnectionCount());

            // Data integrity: the connection must work end to end after the
            // retransmitted SYN (no loss, no duplication).
            const UInt32 kTotal = 16384;
            std::vector<Byte> payload(kTotal);
            for (UInt32 i = 0; i < kTotal; ++i) {
                payload[i] = static_cast<Byte>((i * 3 + i / 19) & 0xFF);
            }
            UInt64 sent = 0;
            for (UInt32 round = 0; round < 32 && sent < kTotal; ++round) {
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
            std::fprintf(stderr, "[synretx-md5] received=%llu\n", (unsigned long long)bytes_recv);

            // Core assertion 3: the full payload arrives exactly once.
            CHECK(kTotal == bytes_recv);  // no loss, no duplicate

            UInt32 crc_expect = 0;
            for (UInt32 i = 0; i < kTotal; ++i) {
                crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
            }
            std::fprintf(stderr, "[synretx-md5] crc recv=%u exp=%u\n", crc_recv, crc_expect);
            CHECK(crc_expect == crc_recv);  // byte-perfect delivery

            stack_a.Close(conn);
            for (UInt32 i = 0; i < 100; ++i) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "SYNRETX_MD5: FAILED (%d)\n" : "SYNRETX_MD5: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

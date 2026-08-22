/**
 * @file test_md5_large.cpp
 * @brief RFC 2385 TCP-MD5 over a 1 MiB large transfer: a connection signing
 *        every segment (ConnectWithMd5 + SetMd5KeyForListener) must carry a
 *        1 MiB payload across the wire losslessly. The scenario stresses the
 *        per-segment signature path (every data segment is signed - kind 19,
 *        len 18, non-zero digest - as the connection is armed before the SYN,
 *        Linux TCP_MD5SIG semantics) while the transfer itself exercises the
 *        throughput end to end.
 *
 *        Scenario (mirrors test_wscale_transfer.cpp): dual stack -> stack_b
 *        Listens + SetMd5KeyForListener -> stack_a ConnectWithMd5 -> handshake
 *        completes (B's MD5-validating listener accepts the signed SYN) ->
 *        1 MiB send, chunked 4096 bytes at a time with a pump/retry loop
 *        (large-buffer chunking, cf. test_wscale_transfer.cpp) -> the B-side
 *        recv handler accumulates byte count + rolling CRC.
 *
 *        Assertions:
 *          1. Handshake: A kEstablished, B connection captured via
 *             SetStateHandler(kEstablished), stack_b.ConnectionCount()==1.
 *          2. No segment loss: exact 1 MiB received (loss would under-count,
 *             duplication would over-count).
 *          3. Content integrity: rolling CRC over the received bytes equals
 *             the CRC over the source payload (any reordered/duplicated/lost
 *             byte breaks the match).
 *          4. Per-segment signature: every A->B packet that carries TCP
 *             payload is MD5-signed with a non-zero digest (tcp_fsm.cpp:71
 *             include_md5 fires on every segment of a keyed connection) - the
 *             per-segment signing path survives a full megabyte of segments.
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

// Wire-level counts for the per-segment signature assertion.
static UInt64 g_data_segs = 0;    // A->B packets carrying TCP payload
static UInt64 g_signed_segs = 0;  // ...that carry a valid MD5 signature

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

// Counts a captured A->B packet as a "data segment" and checks its MD5
// signature, when it actually carries TCP payload (beyond IPv4+TCP headers).
static void AuditDataSegment(const Byte* p, UInt32 n) {
    if (NULLPTR == p || n < 40) {
        return;
    }
    if (4 != (p[0] >> 4)) {
        return;  // IPv4 only in this test
    }
    const UInt32 ip_hdr = (static_cast<UInt32>(p[0] & 0x0F)) * 4;
    const UInt32 tcp_off = (static_cast<UInt32>(p[32] >> 4)) * 4;
    if (ip_hdr < 20 || tcp_off < 20 || n < ip_hdr + tcp_off) {
        return;
    }
    const UInt32 payload_len = n - ip_hdr - tcp_off;
    if (0 == payload_len) {
        return;  // pure ACK / SYN / FIN: no data
    }
    ++g_data_segs;
    bool digest = false;
    if (HasMd5Signature(p, n, digest) && digest) {
        ++g_signed_segs;
    }
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                AuditDataSegment(out, n);
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
        local.port = 40335;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9185;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));

        // A arms the MD5 key before the SYN goes out (ConnectWithMd5 ->
        // SetMd5Key -> SendSyn, stack.cpp:491/502).
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 &&
                xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[md5-large] A state=%d B_conns=%u B_conn_id=%llu\n",
                     (int)stack_a.ConnectionState(conn), (UInt32)stack_b.ConnectionCount(),
                     (unsigned long long)conn_b);

        // Core assertion 1: the MD5 handshake completes - B's listener
        // accepted A's signed SYN (a signatureless SYN is dropped).
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(0 != conn_b);
        CHECK(1 == stack_b.ConnectionCount());

        // 1 MiB transfer, chunked 4096 bytes at a time with pump/retry
        // (large-buffer chunking, cf. test_wscale_transfer.cpp).
        const UInt32 kTotal = 1024 * 1024;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 9 + i / 41) & 0xFF);
        }
        UInt64 accepted = 0;
        UInt32 guard = 0;
        while (accepted < kTotal && 400000 > ++guard) {
            UInt32 n = static_cast<UInt32>(kTotal - accepted);
            if (n > 4096) {
                n = 4096;
            }
            UInt32 tries = 0;
            while (!stack_a.Send(conn, payload.data() + accepted, n) && 500 > ++tries) {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            accepted += n;
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal == accepted);
        for (UInt32 i = 0; i < 5000 && bytes_recv < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[md5-large] sent=%llu received=%llu\n",
                     (unsigned long long)accepted, (unsigned long long)bytes_recv);

        // Core assertion 2: no segment loss - the full 1 MiB arrives exactly
        // once (loss under-counts, duplication over-counts).
        CHECK(kTotal == bytes_recv);

        // Core assertion 3: content integrity - rolling CRC over what B
        // received matches the CRC over the source payload.
        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        std::fprintf(stderr, "[md5-large] crc recv=%u exp=%u\n", crc_recv, crc_expect);
        CHECK(crc_expect == crc_recv);

        // Core assertion 4: per-segment signature throughput - every A->B
        // data segment that crossed the wire is MD5-signed with a non-zero
        // digest (RFC 2385 per-segment signing held for the whole megabyte).
        std::fprintf(stderr, "[md5-large] data_segs=%llu signed_segs=%llu\n",
                     (unsigned long long)g_data_segs, (unsigned long long)g_signed_segs);
        CHECK(0 < g_data_segs);
        CHECK(g_data_segs == g_signed_segs);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_LARGE: FAILED (%d)\n" : "MD5_LARGE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

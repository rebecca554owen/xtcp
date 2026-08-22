/**
 * @file test_md5_rst.cpp
 * @brief RFC 2385 RST safety semantics on an MD5 connection: (a) an unsigned
 *        RST cannot kill the connection - OnSegment verifies the signature
 *        FIRST and drops the segment (verification-first), and (b) a signed
 *        RST (peer Abort: the stack signs every segment including RST) does
 *        terminate the connection.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>

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

// A 40-byte IPv4/TCP segment with the RST flag and a plain 20-byte TCP header
// (data offset 5): NO TCP-MD5 option. An attacker without the key would send
// exactly this - and RFC 2385 requires the peer to drop it.
static void InjectUnsignedRst(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                              UInt16 src_port, UInt16 dst_port) {
    Byte pkt[40];
    std::memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;                 // total length
    pkt[9] = 6;                              // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = 0x00; tcp[5] = 0x00; tcp[6] = 0x00; tcp[7] = 0x01;  // seq = 1
    tcp[13] = 0x04;                          // RST
    tcp[12] = 0x50;                          // data offset 5 (no options)
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(sizeof(pkt));
    std::memcpy(buf.Data(), pkt, sizeof(pkt));
    buf.SetLen(sizeof(pkt));
    victim.OnPacket(std::move(buf));
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

        // A (client) counts kClosed transitions; B records its accepted conn id.
        std::atomic<UInt32> a_closed{0};
        stack_a.SetStateHandler([&a_closed](UInt64, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kClosed == st) {
                a_closed.fetch_add(1, std::memory_order_relaxed);
            }
        });
        std::atomic<UInt64> b_conn{0};
        stack_b.SetAcceptHandler([&b_conn](UInt64 id, const xtcp::core::Endpoint&,
                                           const xtcp::core::Endpoint&) {
            b_conn.store(id, std::memory_order_relaxed);
            return true;
        });

        const Byte key[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9094;
        CHECK(stack_b.Listen(remote));
        stack_b.SetMd5KeyForListener(remote, key, sizeof(key));
        const UInt64 conn = stack_a.ConnectWithMd5(local, remote, key, sizeof(key));
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(0 != b_conn.load(std::memory_order_relaxed));

        // (a) Unsigned RST (no MD5 option) must be dropped: the MD5 signature
        // is verified before the RST is processed (RFC 2385 verification-first).
        InjectUnsignedRst(stack_a, 0x0A000002, 0x0A000001, 9094, 40061);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[md5-rst] after unsigned RST: A=%d closed=%u\n",
                     (int)stack_a.ConnectionState(conn), a_closed.load());
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        CHECK(0 == a_closed.load(std::memory_order_relaxed));

        // (b) Signed RST (peer Abort: the stack signs RST too) terminates the
        // connection - the genuine peer's RST is accepted and honored.
        stack_b.Abort(b_conn.load(std::memory_order_relaxed));
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[md5-rst] after signed RST: A=%d closed=%u\n",
                     (int)stack_a.ConnectionState(conn), a_closed.load());
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn));
        CHECK(1 <= a_closed.load(std::memory_order_relaxed));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_RST: FAILED (%d)\n" : "MD5_RST: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_md5_wildcard.cpp
 * @brief RFC 2385 + wildcard listener: an MD5-armed wildcard (0.0.0.0)
 *        listener must enforce signing for SYNs to ANY specific destination.
 *        Pre-fix: the MD5 lookup keyed on the exact EndpointKey(dst), so a
 *        wildcard listener's key silently enforced nothing (unsigned SYNs
 *        accepted - a security bypass).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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
    for (UInt32 round = 0; round < 500; ++round) {
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
        const Byte key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
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

        // B listens on the WILDCARD address and arms MD5 for it.
        xtcp::core::Endpoint wild;
        wild.family = 4;
        wild.addr[0] = 0;
        wild.port = 9090;
        CHECK(stack_b.Listen(wild));
        stack_b.SetMd5KeyForListener(wild, key, sizeof(key));

        // A connects to a SPECIFIC dst with the key: the SYN is signed and
        // must be accepted (the wildcard fallback finds the key).
        xtcp::core::Endpoint local, specific;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        specific.family = 4;
        specific.addr[0] = 0x0A000002;
        specific.port = 9090;
        const UInt64 conn_ok = stack_a.ConnectWithMd5(local, specific, key, sizeof(key));
        CHECK(0 != conn_ok);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_ok));
        std::fprintf(stderr, "[md5-wildcard] signed SYN accepted via wildcard key\n");

        // A SECOND connect WITHOUT the key: the SYN is unsigned and must be
        // REFUSED (RST) - the wildcard listener's MD5 enforcement applies.
        xtcp::core::Endpoint local2;
        local2.family = 4;
        local2.addr[0] = 0x0A000001;
        local2.port = 40062;
        const UInt64 conn_bad = stack_a.Connect(local2, specific);
        CHECK(0 != conn_bad);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        std::fprintf(stderr, "[md5-wildcard] unsigned SYN state=%d (expect %d closed)\n",
                     static_cast<int>(stack_a.ConnectionState(conn_bad)),
                     static_cast<int>(xtcp::core::TcpState::kClosed));
        CHECK(xtcp::core::TcpState::kClosed == stack_a.ConnectionState(conn_bad));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MD5_WILDCARD: FAILED (%d)\n" : "MD5_WILDCARD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

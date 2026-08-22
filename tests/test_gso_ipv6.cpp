/**
 * @file test_gso_ipv6.cpp
 * @brief Software GSO must segment IPv6 super-segments too: a large IPv6
 *        send must hit the wire as MSS-sized packets (not one oversized
 *        datagram the peer's MSS negotiation would reject).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    std::atomic<UInt32> g_max_v6_pkt{0};
}

static void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 500; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                b.Inject(out, n, 0x86DD);
                moved = true;
            }
        }
        while (0 != b.TxPending()) {
            const UInt32 n = b.PollTx(out);
            if (0 < n) {
                a.Inject(out, n, 0x86DD);
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
            if (0x86DD == p.eth_type && p.len > g_max_v6_pkt.load(std::memory_order_relaxed)) {
                g_max_v6_pkt.store(p.len, std::memory_order_relaxed);
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 6;
        local.addr[0] = 0xFD000001;  // fd00::1
        local.port = 40000;
        remote.family = 6;
        remote.addr[0] = 0xFD000002;  // fd00::2
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // 32 KB in super-segment sends: the tx boundary must segment into
        // MSS-sized IPv6 packets (1460 payload + 40 IPv6 + 20 TCP = 1520).
        constexpr UInt32 kTotal = 32 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 3 + 1) & 0xFF));
        }
        UInt32 sent = 0;
        while (sent < kTotal) {
            const UInt32 chunk = (kTotal - sent < 8192) ? (kTotal - sent) : 8192;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 200 && received.size() < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }

        CHECK(kTotal == received.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
        const UInt32 max_pkt = g_max_v6_pkt.load(std::memory_order_relaxed);
        std::fprintf(stderr, "[gso-v6] sent=%u recv=%zu max_pkt=%u (cap 1520)\n",
                     sent, received.size(), max_pkt);
        CHECK(1520 >= max_pkt);  // MSS 1460 + IPv6 40 + TCP 20
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "GSO_IPV6: FAILED (%d)\n" : "GSO_IPV6: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

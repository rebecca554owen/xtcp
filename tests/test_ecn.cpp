/**
 * @file test_ecn.cpp
 * @brief RFC 3168 ECN end-to-end: both sides request ECN; the handshake
 *        negotiates it (SYN/SYN+ACK ECE), data segments are marked with
 *        ECT(0) in the IP header (never ECE - congestion reporting lives
 *        only on ACKs), and pure ACKs carry ECE while ECN is active.
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
    std::atomic<UInt32> g_ect_data{0};  // A->B data segments with ECT(0) in IP header
    std::atomic<UInt32> g_ece_data{0};  // A->B data segments wrongly carrying ECE
    std::atomic<UInt32> g_ack_ece{0};   // pure ACK segments with ECE (congestion report)
    std::atomic<bool> g_syn_ece{false};
    std::atomic<bool> g_synack_ece{false};
}

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
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            // B->A traffic (server's sends): SYN+ACK echoes the ECE offer.
            if (p.len > 33) {
                const Byte flags = p.data[33];
                if (0 != (flags & 0x12) && 0 != (flags & 0x40)) {
                    g_synack_ece.store(true, std::memory_order_relaxed);
                }
            }
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            // A->B traffic (client's sends): SYN offers ECN; data segments
            // carry ECT(0) in the IP header (byte 1 low 2 bits = 0b10) and
            // must NOT carry ECE; the handshake-completion ACK carries ECE.
            if (p.len > 33) {
                const Byte flags = p.data[33];
                if (0 != (flags & 0x02) && 0 == (flags & 0x10) && 0 != (flags & 0x40)) {
                    g_syn_ece.store(true, std::memory_order_relaxed);
                }
                if (0 != (flags & 0x08)) {  // data segment (PSH)
                    if (0x02 == (p.data[1] & 0x03)) {  // ECT(0) in IP header
                        g_ect_data.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (0 != (flags & 0x40)) {  // ECE on a data segment = bug
                        g_ece_data.fetch_add(1, std::memory_order_relaxed);
                    }
                } else if (0 == (flags & 0x02) && 0 == (flags & 0x08) && 0 == (flags & 0x01) &&
                           0 != (flags & 0x10) && 0 != (flags & 0x40)) {
                    g_ack_ece.fetch_add(1, std::memory_order_relaxed);  // pure ACK with ECE
                }
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
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        // Both sides request ECN before the handshake (stack-wide default
        // applied at connection creation, before the SYN goes out).
        stack_a.SetDefaultEcn(true);
        stack_b.SetDefaultEcn(true);
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Handshake ECE negotiation happened.
        std::fprintf(stderr, "[ecn] SYN-ECE=%s SYNACK-ECE=%s\n",
                     g_syn_ece.load() ? "yes" : "no", g_synack_ece.load() ? "yes" : "no");
        CHECK(g_syn_ece.load());
        CHECK(g_synack_ece.load());

        // Data flows; ECN-active data segments are marked with ECT(0) in the
        // IP header (RFC 3168) - never ECE (congestion reporting is ACK-only).
        std::string payload(16384, 'E');
        UInt32 sent = 0;
        while (sent < payload.size()) {
            const UInt32 chunk = static_cast<UInt32>(payload.size()) - sent;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        for (UInt32 i = 0; i < 200 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "[ecn] data ECT segments=%u data ECE violations=%u ACK ECE segments=%u\n",
                     g_ect_data.load(std::memory_order_relaxed),
                     g_ece_data.load(std::memory_order_relaxed),
                     g_ack_ece.load(std::memory_order_relaxed));
        CHECK(0 < g_ect_data.load(std::memory_order_relaxed));
        CHECK(0 == g_ece_data.load(std::memory_order_relaxed));
        CHECK(0 < g_ack_ece.load(std::memory_order_relaxed));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ECN: FAILED (%d)\n" : "ECN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

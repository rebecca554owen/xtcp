/**
 * @file test_ooo_flood.cpp
 * @brief Out-of-order flood resilience: an attacker injects a large volume
 *        of out-of-sequence data segments (beyond the bounded reassembly
 *        buffer); the receive window and ooo-buffer limits contain the
 *        attack, and a normal in-order transfer still delivers intact.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>

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

// Injects an out-of-order data segment directly into the victim stack.
static void InjectOoo(xtcp::XtcpStack& victim, UInt32 src_ip, UInt32 dst_ip,
                      UInt16 src_port, UInt16 dst_port, UInt32 seq, UInt32 payload_len) {
    const UInt32 total = 20 + 20 + payload_len;
    std::vector<Byte> pkt(total);
    std::memset(pkt.data(), 0xCC, total);
    pkt[0] = 0x45;
    pkt[2] = static_cast<Byte>(total >> 8); pkt[3] = static_cast<Byte>(total);
    pkt[9] = 6;                              // TCP
    pkt[12] = static_cast<Byte>(src_ip >> 24); pkt[13] = static_cast<Byte>(src_ip >> 16);
    pkt[14] = static_cast<Byte>(src_ip >> 8);  pkt[15] = static_cast<Byte>(src_ip);
    pkt[16] = static_cast<Byte>(dst_ip >> 24); pkt[17] = static_cast<Byte>(dst_ip >> 16);
    pkt[18] = static_cast<Byte>(dst_ip >> 8);  pkt[19] = static_cast<Byte>(dst_ip);
    Byte* tcp = pkt.data() + 20;
    tcp[0] = static_cast<Byte>(src_port >> 8); tcp[1] = static_cast<Byte>(src_port);
    tcp[2] = static_cast<Byte>(dst_port >> 8); tcp[3] = static_cast<Byte>(dst_port);
    tcp[4] = static_cast<Byte>(seq >> 24); tcp[5] = static_cast<Byte>(seq >> 16);
    tcp[6] = static_cast<Byte>(seq >> 8);  tcp[7] = static_cast<Byte>(seq);
    tcp[12] = 0x50;                          // data offset 5
    tcp[13] = 0x18;                          // PSH + ACK
    tcp[14] = 0x40; tcp[15] = 0x00;          // window 16384
    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(total);
    std::memcpy(buf.Data(), pkt.data(), total);
    buf.SetLen(total);
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
        local.port = 40071;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9095;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Flood: 5000 out-of-order segments (each 1024 B, gaps between them)
        // with sequences far ahead of the receive frontier.
        const UInt32 base = 0x20000000;
        for (UInt32 i = 0; i < 5000; ++i) {
            InjectOoo(stack_b, 0x0A000001, 0x0A000002, 40071, 9095, base + i * 2048, 1024);
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Normal in-order transfer: must still deliver intact.
        const UInt32 kTotal = 16384;
        std::vector<Byte> payload(kTotal);
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload[i] = static_cast<Byte>((i * 13 + i / 31) & 0xFF);
        }
        UInt32 accepted = 0;
        UInt32 guard = 0;
        while (accepted < kTotal && 100000 > ++guard) {
            UInt32 n = kTotal - accepted;
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
        for (UInt32 i = 0; i < 2000 && bytes_recv < kTotal; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[ooo-flood] received=%llu\n", (unsigned long long)bytes_recv);
        CHECK(kTotal == bytes_recv);

        UInt32 crc_expect = 0;
        for (UInt32 i = 0; i < kTotal; ++i) {
            crc_expect = (crc_expect * 31 + payload[i]) & 0x7FFFFFFF;
        }
        CHECK(crc_expect == crc_recv);
        std::fprintf(stderr, "[ooo-flood] crc recv=%u expect=%u\n", crc_recv, crc_expect);

        stack_a.Close(conn);
        for (UInt32 i = 0; i < 100; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "OOO_FLOOD: FAILED (%d)\n" : "OOO_FLOOD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

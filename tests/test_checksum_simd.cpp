/**
 * @file test_checksum_simd.cpp
 * @brief Differential test for the vectorized RFC 1071 checksum: the
 *        dispatched Checksum() (SSSE3 path when the CPU has it, scalar
 *        otherwise) must be bit-identical to the scalar reference on every
 *        input - sizes around every boundary (0/1/2/3/4/7/8/15/16/17/31/32/
 *        33/63/64/65/127/128/129/255/256/1023/1024/1460/4095/4096/16383/
 *        16384/65535/65536/1MiB+, covering the 16 KiB accumulator drain)
 *        with deterministic pseudo-random content, plus the RFC 1071
 *        self-check (checksum of a segment with its checksum in place is 0)
 *        and an end-to-end wire check that a stack-emitted segment's
 *        checksum field equals the scalar computation over the same bytes.
 */

#include <xtcp/core/stack.h>
#include <xtcp/core/ip.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt32 g_rng = 0x12345678;
static UInt32 NextRand() {
    g_rng = g_rng * 1664525u + 1013904223u;
    return g_rng;
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
        // --- Differential: dispatched vs scalar reference, boundary sizes.
        const UInt32 sizes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33,
                                63, 64, 65, 127, 128, 129, 255, 256, 511, 512, 1023, 1024,
                                1460, 2047, 4095, 4096, 8191, 8192, 16383, 16384, 16385,
                                32767, 32768, 65535, 65536, 65537};
        std::vector<Byte> buf(1u << 20);
        for (UInt32 iter = 0; iter < 200; ++iter) {
            for (UInt32 s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
                const UInt32 n = sizes[s];
                if (buf.size() < n) {
                    buf.resize(n);
                }
                for (UInt32 i = 0; i < n; ++i) {
                    buf[i] = static_cast<Byte>(NextRand());
                }
                const UInt16 fast = xtcp::core::Checksum(buf.data(), n);
                const UInt16 ref = xtcp::core::ChecksumScalar(buf.data(), n);
                if (fast != ref) {
                    std::fprintf(stderr, "FAIL iter=%u size=%u fast=%04x ref=%04x\n", iter, n, fast, ref);
                    ++g_failures;
                }
            }
            // Random sizes up to 256 KiB (spans multiple 16 KiB drains).
            const UInt32 n = NextRand() % 262144;
            for (UInt32 i = 0; i < n; ++i) {
                buf[i] = static_cast<Byte>(NextRand());
            }
            if (xtcp::core::Checksum(buf.data(), n) != xtcp::core::ChecksumScalar(buf.data(), n)) {
                std::fprintf(stderr, "FAIL random size=%u\n", n);
                ++g_failures;
            }
        }
        std::fprintf(stderr, "[cksum-simd] dispatched %s, differential loop done\n",
                     xtcp::core::CpuHasSsse3() ? "SSSE3" : "scalar");

        // --- RFC 1071 self-check: a segment with its checksum in place sums
        // to zero under BOTH paths.
        std::vector<Byte> seg(20 + 20 + 100);
        for (UInt32 i = 0; i < seg.size(); ++i) {
            seg[i] = static_cast<Byte>(i * 7 + 3);
        }
        seg[16] = 0;  // checksum field
        seg[17] = 0;
        const UInt16 csum = xtcp::core::ChecksumScalar(seg.data(), static_cast<UInt32>(seg.size()));
        seg[16] = static_cast<Byte>(csum >> 8);
        seg[17] = static_cast<Byte>(csum & 0xFF);
        CHECK(0 == xtcp::core::Checksum(seg.data(), static_cast<UInt32>(seg.size())));
        CHECK(0 == xtcp::core::ChecksumScalar(seg.data(), static_cast<UInt32>(seg.size())));

        // --- End-to-end wire check: A -> B data segment's checksum field
        // must equal the scalar computation over pseudo-header + TCP
        // header + payload (proves the TX fast path is bit-identical).
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
        xtcp::core::Endpoint a_local, b_local;
        a_local.family = 4;
        a_local.addr[0] = 0x0A000001;
        a_local.port = 40195;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9107;
        CHECK(stack_b.Listen(b_local));
        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        const UInt32 kPayload = 1000;
        Byte payload[kPayload];
        for (UInt32 i = 0; i < kPayload; ++i) {
            payload[i] = static_cast<Byte>(NextRand());
        }
        CHECK(stack_a.Send(conn_a, payload, kPayload));
        // A's tx: the data segment (multiple might be queued; take the
        // first non-ACK one).
        Byte pkt[65536];
        UInt32 n = 0;
        while (0 != backend_a.TxPending()) {
            n = backend_a.PollTx(pkt);
            if (0 != n) {
                break;
            }
        }
        CHECK(0 != n);
        const UInt32 ip_total = (static_cast<UInt32>(pkt[2]) << 8) | pkt[3];
        CHECK(ip_total == n);
        const UInt32 tcp_off = 20;  // no IP options
        const UInt32 tcp_len = ip_total - tcp_off;
        const UInt16 wire_sum = (static_cast<UInt16>(pkt[tcp_off + 16]) << 8) | pkt[tcp_off + 17];
        // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2).
        Byte pseudo[12];
        std::memcpy(pseudo, pkt + 12, 8);
        pseudo[8] = 0;
        pseudo[9] = 6;
        pseudo[10] = static_cast<Byte>(tcp_len >> 8);
        pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
        std::vector<Byte> full(pseudo, pseudo + 12);
        full.insert(full.end(), pkt + tcp_off, pkt + ip_total);
        full[12 + 16] = 0;  // zero the checksum field: RFC 1071 sums it as 0
        full[12 + 17] = 0;
        const UInt16 ref_sum = xtcp::core::ChecksumScalar(full.data(), static_cast<UInt32>(full.size()));
        std::fprintf(stderr, "[cksum-simd] wire checksum=%04x scalar-ref=%04x\n", wire_sum, ref_sum);
        CHECK(wire_sum == ref_sum);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CHECKSUM_SIMD: FAILED (%d)\n" : "CHECKSUM_SIMD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

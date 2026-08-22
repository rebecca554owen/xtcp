/**
 * @file test_accept_reject.cpp
 * @brief Server-mode acceptance: SetAcceptHandler(true) accepts and the
 *        SYN+ACK flows; SetAcceptHandler(false) refuses and an RST flows
 *        back (RFC 793), leaving no connection state.
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

namespace {
    constexpr UInt32 kServerV4 = 0x0A000002;  // 10.0.0.2
    constexpr UInt32 kClientV4 = 0x0A000001;  // 10.0.0.1
    constexpr UInt16 kPort     = 9000;
}

/** Builds a raw SYN for the client flow. */
static UInt32 BuildSyn(Byte* out, UInt16 sport, UInt16 dport, UInt32 seq) {
    UInt32 off = 0;
    out[off++] = 0x45; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 0x28;
    out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 64;   out[off++] = 6;
    out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = static_cast<Byte>(kClientV4 >> 24); out[off++] = static_cast<Byte>(kClientV4 >> 16);
    out[off++] = static_cast<Byte>(kClientV4 >> 8);  out[off++] = static_cast<Byte>(kClientV4 & 0xFF);
    out[off++] = static_cast<Byte>(kServerV4 >> 24); out[off++] = static_cast<Byte>(kServerV4 >> 16);
    out[off++] = static_cast<Byte>(kServerV4 >> 8);  out[off++] = static_cast<Byte>(kServerV4 & 0xFF);
    out[off++] = static_cast<Byte>(sport >> 8); out[off++] = static_cast<Byte>(sport & 0xFF);
    out[off++] = static_cast<Byte>(dport >> 8); out[off++] = static_cast<Byte>(dport & 0xFF);
    out[off++] = static_cast<Byte>(seq >> 24); out[off++] = static_cast<Byte>(seq >> 16);
    out[off++] = static_cast<Byte>(seq >> 8);  out[off++] = static_cast<Byte>(seq & 0xFF);
    out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x50; out[off++] = 0x02;  // SYN
    out[off++] = 0xFF; out[off++] = 0xFF;
    out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 2; out[off++] = 4; out[off++] = 0x05; out[off++] = 0xB4;  // MSS 1460
    // Valid IPv4 + TCP checksums (RFC 791/793) so the test also passes under
    // the checksum-validate build - a zero-checksum SYN is dropped there.
    {
        UInt32 sum = 0;
        for (UInt32 i = 0; i < 20; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(out[i]) << 8) | out[i + 1]);
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        out[10] = static_cast<Byte>(~(sum & 0xFFFF) >> 8);
        out[11] = static_cast<Byte>(~sum & 0xFF);
    }
    {
        UInt32 sum = 0;
        const Byte* t = out + 20;
        const Byte pseudo[12] = {
            out[12], out[13], out[14], out[15],
            out[16], out[17], out[18], out[19],
            0, 6, 0x00, 0x14,
        };
        for (UInt32 i = 0; i < 12; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(pseudo[i]) << 8) | pseudo[i + 1]);
        }
        for (UInt32 i = 0; i < 20; i += 2) {
            sum += static_cast<UInt32>((static_cast<UInt32>(t[i]) << 8) | t[i + 1]);
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        out[36] = static_cast<Byte>(~(sum & 0xFFFF) >> 8);
        out[37] = static_cast<Byte>(~sum & 0xFF);
    }
    return off;
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend;
        xtcp::XtcpStack stack(&backend);
        backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack.OnPacket(std::move(buf));
        });

        xtcp::core::Endpoint server;
        server.family = 4;
        server.addr[0] = kServerV4;
        server.port = kPort;
        CHECK(stack.Listen(server));

        // Drains backend output, classifying SYN+ACK vs RST responses.
        auto drain = [&backend](UInt32& synacks, UInt32& rsts) {
            Byte out[65536];
            synacks = rsts = 0;
            while (0 != backend.TxPending()) {
                const UInt32 got = backend.PollTx(out);
                if (got < 40) {
                    continue;
                }
                const Byte flags = out[33];
                if (0 != (flags & 0x04)) {
                    ++rsts;
                } else if (0 != (flags & 0x12) && 0 == (flags & 0x01)) {
                    ++synacks;
                }
            }
        };

        // 1) Accept path: SYN is answered with SYN+ACK, connection lives.
        {
            UInt32 accepted = 0;
            stack.SetAcceptHandler([&accepted](UInt64, const xtcp::core::Endpoint&,
                                               const xtcp::core::Endpoint&) {
                ++accepted;
                return true;
            });
            Byte syn[256];
            const UInt32 syn_len = BuildSyn(syn, 40001, kPort, 0x10000000);
            backend.Inject(syn, syn_len, 0x0800);
            UInt32 synacks = 0, rsts = 0;
            drain(synacks, rsts);
            CHECK(1 == accepted);
            CHECK(1 == synacks);
            CHECK(0 == rsts);
            CHECK(1 == stack.ConnectionCount());
            std::fprintf(stderr, "[accept] accepted=%u synacks=%u conns=%u\n",
                         accepted, synacks, (UInt32)stack.ConnectionCount());
        }

        // 3) Abort (RST) end-to-end: the server aborts an accepted connection
        //    and the RST goes out on the wire (Linux SO_LINGER=0 semantics).
        {
            UInt64 server_conn = 0;
            std::atomic<bool> aborted{false};
            stack.SetAcceptHandler([&](UInt64 id, const xtcp::core::Endpoint&,
                                       const xtcp::core::Endpoint&) {
                server_conn = id;
                return true;
            });
            Byte syn[256];
            const UInt32 syn_len = BuildSyn(syn, 40003, kPort, 0x30000000);
            backend.Inject(syn, syn_len, 0x0800);
            UInt32 synacks = 0, rsts = 0;
            drain(synacks, rsts);
            CHECK(1 == synacks);
            CHECK(0 != server_conn);

            stack.Abort(server_conn);
            stack.PollAckTimers();  // reclaim the aborted (CLOSED) connection
            drain(synacks, rsts);
            CHECK(1 == rsts);  // RST emitted
            aborted.store(true, std::memory_order_relaxed);
            std::fprintf(stderr, "[accept] abort path: RST emitted OK\n");
        }
        {
            UInt32 rejected = 0;
            stack.SetAcceptHandler([&rejected](UInt64, const xtcp::core::Endpoint&,
                                               const xtcp::core::Endpoint&) {
                ++rejected;
                return false;
            });
            Byte syn[256];
            const UInt32 syn_len = BuildSyn(syn, 40002, kPort, 0x20000000);
            backend.Inject(syn, syn_len, 0x0800);
            UInt32 synacks = 0, rsts = 0;
            drain(synacks, rsts);
            CHECK(1 == rejected);
            CHECK(0 == synacks);
            CHECK(1 == rsts);
            CHECK(1 == stack.ConnectionCount());  // unchanged (first conn still open)
            std::fprintf(stderr, "[accept] rejected=%u rsts=%u conns=%u\n",
                         rejected, rsts, (UInt32)stack.ConnectionCount());
        }
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ACCEPT_REJECT: FAILED (%d)\n" : "ACCEPT_REJECT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

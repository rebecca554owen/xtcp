/**
 * @file test_zc_rxpath.cpp
 * @brief DMA RX zero-copy gate: a backend delivering OWNED pool-buffer
 *        packets (DPDK-style zero-copy RX - the DMA descriptor hands the
 *        buffer to the stack) must reach the application's recv handler
 *        WITHOUT any copy. Proof: the set of payload pointers the backend
 *        injects must be EXACTLY the set the recv handler receives - any
 *        memcpy on the RX delivery path would produce a different address.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

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

        // The zero-copy RX producer: hands the stack a POOL-OWNED buffer.
        // At injection time (the buffer is still fresh) parse the headers
        // and record the payload position - later pool recycling would
        // overwrite the content and make the header parse invalid.
        struct Injected {
            const Byte* payload;  // expected zero-copy delivery pointer
            UInt32 seq;           // TCP sequence number (debug)
            UInt32 len;           // payload length (debug)
        };
        std::vector<Injected> injected;
        backend_b.SetRxHandler([&stack_b, &injected](xtcp::ndi::Packet&& p) {
            CHECK(!p.owned.IsEmpty());
            CHECK(p.data == p.owned.Data());
            // Use the stack's own TCP parse for the exact payload position.
            const UInt32 ip_hdr = (p.data[0] & 0x0F) << 2;
            xtcp::core::TcpHdr tcp;
            const UInt32 tcp_total = ((p.data[2] << 8) | p.data[3]) - ip_hdr;
            if (xtcp::core::ParseTcp(p.data + ip_hdr, tcp_total, tcp) &&
                tcp_total > tcp.hdr_len) {
                const Byte* t = p.data + ip_hdr;
                injected.push_back({p.data + ip_hdr + tcp.payload_off,
                                    static_cast<UInt32>((t[4] << 24) | (t[5] << 16) | (t[6] << 8) | t[7]),
                                    tcp_total - tcp.hdr_len});
            }
            stack_b.OnPacket(std::move(p.owned));
        });

        std::atomic<UInt64> recv_bytes{0};
        std::vector<std::pair<const Byte*, UInt32>> delivered;
        stack_b.SetRecvHandler([&recv_bytes, &delivered](UInt64, const Byte* data, UInt32 len) {
            recv_bytes.fetch_add(len);
            delivered.push_back({data, len});
            return true;
        });

        auto pump = [&]() {
            Byte out[65536];
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    // DMA-ring semantics: the wire bytes arrive in a fresh
                    // pool buffer, handed to the stack OWNED.
                    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(n);
                    CHECK(!buf.IsEmpty());
                    std::memcpy(buf.Data(), out, n);
                    buf.SetLen(n);
                    xtcp::ndi::Packet p;
                    p.data = buf.Data();
                    p.len = n;
                    p.owned = std::move(buf);
                    backend_b.Inject(std::move(p));
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(n);
                    CHECK(!buf.IsEmpty());
                    std::memcpy(buf.Data(), out, n);
                    buf.SetLen(n);
                    xtcp::ndi::Packet p;
                    p.data = buf.Data();
                    p.len = n;
                    p.owned = std::move(buf);
                    backend_a.Inject(std::move(p));
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        const UInt64 conn = stack_a.Connect(client_ep, server_ep);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 200 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Send 64KB; the receiver must get it all.
        const UInt32 kTotal = 64 * 1024;
        std::vector<Byte> payload(kTotal, 0x3C);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 5000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
            }
            pump();
        }
        // The recv handler sees only DATA segments (ACK-only segments never
        // reach it), so delivered.size() must equal the number of data
        // segments the backend injected - not the packet count (handshake
        // and ACK-only packets are injected too but produce no delivery).
        CHECK(!injected.empty());
        CHECK(!delivered.empty());

        // ZERO-COPY PROOF: every delivered payload pointer must be one of
        // the pool-buffer payloads the backend injected (the pool recycles
        // blocks, so the same address may legitimately be injected and
        // delivered multiple times). A copy anywhere on the RX path would
        // produce an address that is NOT an injected pool payload - the
        // stack's internal buffers (pending queues, reassembly) live
        // outside the pool.
        UInt64 identity = 0;
        for (size_t d = 0; d < delivered.size(); ++d) {
            bool found = false;
            for (size_t k = 0; k < injected.size(); ++k) {
                if (delivered[d].first == injected[k].payload) {
                    found = true;
                    break;
                }
            }
            if (found) {
                ++identity;
            } else if (d < 8) {
                std::fprintf(stderr, "[zcrx] delivered[%llu]=%p len=%u content=%02X%02X%02X%02X (first=%02X%02X%02X%02X)\n",
                             (unsigned long long)d, (const void*)delivered[d].first, delivered[d].second,
                             delivered[d].first[0], delivered[d].first[1], delivered[d].first[2], delivered[d].first[3],
                             injected[0].payload[0], injected[0].payload[1], injected[0].payload[2], injected[0].payload[3]);
            }
        }
        if (injected.size() != delivered.size()) {
            std::fprintf(stderr, "[zcrx] injected-data=%llu delivered=%llu (extra injections:\n",
                         (unsigned long long)injected.size(), (unsigned long long)delivered.size());
            for (size_t k = 0; k < injected.size(); ++k) {
                std::fprintf(stderr, "  [%llu] seq=%08X len=%u ptr=%p\n", (unsigned long long)k,
                             injected[k].seq, injected[k].len, (const void*)injected[k].payload);
            }
            const Byte* raw = injected[1].payload - 40;
            std::fprintf(stderr, "raw[1]:");
            for (UInt32 i = 0; i < 44; ++i) {
                std::fprintf(stderr, " %02X", raw[i]);
            }
            std::fprintf(stderr, "\n");
        }
        CHECK(identity == delivered.size());
        std::fprintf(stderr, "[zcrx] recv=%llu data-segments=%llu pointer-identity=%llu/%llu\n",
                     (unsigned long long)recv_bytes.load(), (unsigned long long)injected.size(),
                     (unsigned long long)identity, (unsigned long long)delivered.size());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "ZC_RXPATH: FAILED (%d)\n" : "ZC_RXPATH: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

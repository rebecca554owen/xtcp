/**
 * @file test_gro_rx.cpp
 * @brief GRO RX offload (Generic Receive Offload): a NIC/DPDK backend
 *        coalesces consecutive in-order segments into super-segments (up to
 *        ~64KB each, one IP+TCP header rebuilt, PSH stripped) before the
 *        stack sees them. The stack must deliver the coalesced payloads
 *        byte-exact, ACK the whole covered range, and never stall flow
 *        control. The app must observe SUPER-SEGMENT-sized deliveries (the
 *        coalescing is effective), not one delivery per MSS segment.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/ip.h>
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

// One's-complement combine (RFC 1071), mirror of the FSM's ChecksumCombine.
static UInt16 CombineSum(UInt32 sum) noexcept {
    while (0x10000 <= sum) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<UInt16>(~sum & 0xFFFF);
}

// TCP checksum over the pseudo header + TCP header + payload, with the
// checksum field zeroed. Matches the FSM's send-side semantics exactly.
static UInt16 TcpChecksum(const Byte* ip, UInt32 ip_hdr_len, UInt32 tcp_len) noexcept {
    Byte pseudo[12];
    std::memcpy(pseudo, ip + 12, 8);  // src + dst
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10] = static_cast<Byte>(tcp_len >> 8);
    pseudo[11] = static_cast<Byte>(tcp_len & 0xFF);
    UInt32 sum = 0;
    for (UInt32 i = 0; i < 12; i += 2) {
        sum += (static_cast<UInt32>(pseudo[i]) << 8) | pseudo[i + 1];
    }
    for (UInt32 i = 0; i < tcp_len; i += 2) {
        const Byte* p = ip + ip_hdr_len + i;
        sum += (static_cast<UInt32>(p[0]) << 8) |
               ((i + 1 < tcp_len) ? p[1] : 0);
    }
    return CombineSum(sum);
}

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        // The test drives a steady 32 KB stream on a manual clock; pin Reno
        // (ACK-clock) so the rate-based KCC default does not pace the drain.
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            stack_b.OnPacket(std::move(p.owned));
        });

        std::atomic<UInt64> recv_bytes{0};
        std::atomic<UInt64> recv_calls{0};
        stack_b.SetRecvHandler([&recv_bytes, &recv_calls](UInt64, const Byte*, UInt32 len) {
            recv_bytes.fetch_add(len, std::memory_order_relaxed);
            recv_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        });

        UInt32 debug_flushes = 0;
        UInt32 debug_singles = 0;
        UInt32 debug_fallback = 0;
        UInt32 debug_inject_fail = 0;
        // GRO-emulating pump: polls A's tx, coalesces the consecutive
        // in-order segments into super-segments (GRO cap ~60KB payload),
        // rebuilds one IP+TCP header per super-segment with a valid
        // checksum, and injects it into B as one owned packet. When the
        // pool is transiently exhausted, the run falls back to segment-level
        // injection (never loses bytes).
        auto pump = [&]() {
            Byte out[65536];
            Byte gro[65536];
            UInt32 gro_off = 0;  // payload bytes accumulated in gro+40
            UInt32 gro_seq = 0;
            bool gro_active = false;
            UInt32 gro_seq_end = 0;
            UInt32 gro_lens[64] = {0};  // per-segment payload lengths (fallback)
            UInt32 gro_nsegs = 0;
            Byte hold[65536] = {};  // a segment the pool blocked from coalescing
            UInt32 hold_len = 0;
            UInt32 hold_seq = 0;
            bool hold_active = false;
            auto inject = [&](const Byte* buf, UInt32 total) {
                xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(total);
                if (b.IsEmpty()) {
                    ++debug_inject_fail;
                    return false;
                }
                std::memcpy(b.Data(), buf, total);
                b.SetLen(total);
                xtcp::ndi::Packet p;
                p.data = b.Data();
                p.len = total;
                p.owned = std::move(b);
                backend_b.Inject(std::move(p));
                return true;
            };
            auto rebuild = [&](Byte* buf, UInt32 total) {
                buf[2] = static_cast<Byte>(total >> 8);
                buf[3] = static_cast<Byte>(total & 0xFF);
                buf[10] = 0;  // RFC 791: the checksum field is zeroed before summing
                buf[11] = 0;
                const UInt16 ip_sum = xtcp::core::Checksum(buf, 20);
                buf[10] = static_cast<Byte>(ip_sum >> 8);
                buf[11] = static_cast<Byte>(ip_sum & 0xFF);
                buf[20 + 13] = static_cast<Byte>(buf[20 + 13] & ~0x08);  // clear PSH (GRO)
                const UInt32 tcp_len = 20 + total - 40;
                buf[20 + 16] = 0;
                buf[20 + 17] = 0;
                const UInt16 tcp_sum = TcpChecksum(buf, 20, tcp_len);
                buf[20 + 16] = static_cast<Byte>(tcp_sum >> 8);
                buf[20 + 17] = static_cast<Byte>(tcp_sum & 0xFF);
            };
            // Flushes the accumulated run. Returns false when the pool is
            // blocked - the run is RETAINED (gro buffer untouched) for the
            // next pump, and the caller must hold the current segment.
            auto flush = [&]() -> bool {
                if (!gro_active) {
                    return true;
                }
                ++debug_flushes;
                if (0 == gro_off) {
                    ++debug_singles;
                } else if (1 == gro_off / 1024) {
                    ++debug_singles;
                }
                // Rebuild: total_len, TCP seq stays the first segment's,
                // flags = ACK (PSH stripped by GRO), valid checksums.
                const UInt32 total = 40 + gro_off;
                rebuild(gro, total);
                if (inject(gro, total)) {
                    gro_active = false;
                    return true;
                }
                // Pool transiently exhausted: fall back to segment-level
                // injection (the run's bytes are preserved in gro + gro_lens).
                ++debug_fallback;
                UInt32 prefix = 0;
                for (UInt32 s = 0; s < gro_nsegs; ++s) {
                    const UInt32 seg_total = 40 + gro_lens[s];
                    Byte seg[65536];
                    std::memcpy(seg, gro, 40);
                    const UInt32 seg_seq = gro_seq + prefix;
                    seg[20 + 4] = static_cast<Byte>(seg_seq >> 24);
                    seg[20 + 5] = static_cast<Byte>(seg_seq >> 16);
                    seg[20 + 6] = static_cast<Byte>(seg_seq >> 8);
                    seg[20 + 7] = static_cast<Byte>(seg_seq & 0xFF);
                    std::memcpy(seg + 40, gro + 40 + prefix, gro_lens[s]);
                    rebuild(seg, seg_total);
                    if (!inject(seg, seg_total)) {
                        return false;  // still blocked: retain the run
                    }
                    prefix += gro_lens[s];
                }
                gro_active = false;
                return true;
            };
            // The retained run or the held segment from a previous pump:
            // retry the flush first (the pool has had time to free blocks).
            if (hold_active) {
                if (!flush()) {
                    return;  // still blocked: keep everything
                }
                std::memcpy(gro, hold, 40);
                gro_off = hold_len;
                gro_seq = hold_seq;
                gro_seq_end = hold_seq + hold_len;
                gro_nsegs = 1;
                gro_lens[0] = hold_len;
                gro_active = true;
                hold_active = false;
            } else if (gro_active && !flush()) {
                return;  // still blocked: keep the run
            }
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 == n) {
                    continue;
                }
                const Byte* t = out + 20;
                const UInt32 seq = (t[4] << 24) | (t[5] << 16) | (t[6] << 8) | t[7];
                const UInt32 payload = n - 40;
                if (!gro_active) {
                    // Start a new GRO run from this segment (its headers
                    // become the super-segment's).
                    std::memcpy(gro, out, 40);
                    gro_off = 0;
                    gro_seq = seq;
                    gro_seq_end = seq + payload;
                    gro_nsegs = 0;
                    gro_active = true;
                } else if (seq == gro_seq_end && gro_off + payload <= 60000) {
                    // Consecutive: coalesce (the run is in-order, no gaps).
                } else {
                    if (!flush()) {
                        // The pool blocked the previous run: hold THIS
                        // segment for the next pump (the run is retained).
                        std::memcpy(hold, out, n);
                        hold_len = n;
                        hold_seq = seq;
                        hold_active = true;
                        break;
                    }
                    std::memcpy(gro, out, 40);
                    gro_off = 0;
                    gro_seq = seq;
                    gro_seq_end = seq + payload;
                    gro_nsegs = 0;
                    gro_active = true;
                }
                if (gro_active) {
                    std::memcpy(gro + 40 + gro_off, out + 40, payload);
                    gro_off += payload;
                    gro_seq_end = seq + payload;
                    if (gro_nsegs < 64) {
                        gro_lens[gro_nsegs++] = payload;
                    }
                    if (60000 <= gro_off && !flush()) {
                        // Run hit the cap but the pool blocked the flush:
                        // hold the next polled segment (the run is retained).
                        break;
                    }
                }
            }
            flush();  // best effort: retained on failure (retried next pump)
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
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
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));

        // Send 256KB; the GRO pump coalesces the sender's BURSTS (the cwnd
        // lets ~14 segments out before the window blocks - the pump then
        // drains them as GRO super-segments).
        const UInt32 kTotal = 256 * 1024;
        std::vector<Byte> payload(kTotal, 0x5A);
        UInt32 sent = 0;
        for (UInt32 i = 0; i < 20000 && sent < kTotal; ++i) {
            if (stack_a.Send(conn, payload.data() + sent, 1024)) {
                sent += 1024;
                continue;  // keep bursting until the cwnd/window blocks
            }
            pump();  // drain the burst through the GRO pump
        }
        // Final drain: the retained runs (a pool-blocked flush) and the
        // peer's last segments only make it out when the pump runs again.
        for (UInt32 i = 0; i < 500 && recv_bytes.load() < kTotal; ++i) {
            pump();
        }
        CHECK(kTotal == recv_bytes.load());

        // GRO effectiveness: the app must have received COALESCED deliveries.
        // The robust proof: at least 8 flushes coalesced 2+ segments (the
        // stream's 256KB must produce multi-segment runs; an uncoalesced
        // stream produces none), and the delivery count must be far below
        // the 256-segment baseline.
        const UInt64 calls = recv_calls.load();
        std::fprintf(stderr, "[gro] recv=%llu deliveries=%llu avg=%.1fKB multiseg-runs=%u\n",
                     (unsigned long long)recv_bytes.load(), (unsigned long long)calls,
                     (double)(recv_bytes.load() / (calls ? calls : 1)) / 1024.0,
                     debug_flushes - debug_singles);
        CHECK(8 <= (debug_flushes - debug_singles));
        CHECK(calls < kTotal / 1500);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "GRO_RX: FAILED (%d)\n" : "GRO_RX: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

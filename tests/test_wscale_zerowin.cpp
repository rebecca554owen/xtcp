/**
 * @file test_wscale_zerowin.cpp
 * @brief Zero-window persist under RFC 7323 window scaling: a dual-stack
 *        connection negotiates WSOPT=7 (patched into the real server SYN+ACK
 *        so the client's send window is scaled by 128), then a window=0 ACK
 *        shrinks the scaled window to 0, the RFC 1122 persist probe goes out
 *        on the wire, and a scaled window-update restores the window and
 *        flushes the buffered payload intact.
 *
 * Observed behavior (current stack): the SND.WL guard (tcp_fsm.cpp:1834)
 * requires window updates to arrive on a segment newer than the last update,
 * so the injected ACKs carry the connection's real snd_una plus an advancing
 * seq. The window field itself is scaled on the receive path
 * (snd_wnd_ = window << snd_wscale_, tcp_fsm.cpp:1836): window=0 stays 0,
 * a recovery field of 64 becomes 8192 (64<<7). Data integrity is proven by
 * byte count + memcmp, and the probe byte(s) are delivered as legal data
 * before the payload (mirror of test_persist_stack.cpp).
 */

#include <xtcp/core/stack.h>
#include "harness/raw_pkt.h"
#include <xtcp/ndi/manual.h>
#include <atomic>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <thread>
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
    std::atomic<UInt32> g_probes{0};  // 41-byte PSH (1 payload byte) persist probes at B
    UInt32 g_b_iss = 0;               // server ISS captured from the (patched) SYN+ACK
    bool   g_synack_patched = false;
}

// Patch the WSOPT value in an IPv4 SYN+ACK's TCP options to `value` (kind 3).
// Scans the option area so the byte offset is never hardcoded. The TCP
// checksum is recomputed after the patch: the default build does not
// validate inbound checksums, but the checksum-validate build drops a
// segment whose checksum no longer matches its bytes.
static bool PatchSynWscale(Byte* pkt, UInt32 len, Byte value) {
    if (nullptr == pkt || 40 > len || 4 != (pkt[0] >> 4)) {
        return false;
    }
    const UInt32 tcp_off = static_cast<UInt32>(pkt[0] & 0x0F) * 4;
    if (len < tcp_off + 20) {
        return false;
    }
    const UInt32 tcp_hdr_len = static_cast<UInt32>(pkt[tcp_off + 12] >> 4) * 4;
    if (len < tcp_off + tcp_hdr_len) {
        return false;
    }
    for (UInt32 off = tcp_off + 20; off + 1 < tcp_off + tcp_hdr_len;) {
        const Byte kind = pkt[off];
        if (0 == kind) {
            return false;  // EOL before any WSOPT
        }
        if (1 == kind) {  // NOP
            ++off;
            continue;
        }
        const Byte olen = pkt[off + 1];
        if (olen < 2 || tcp_off + tcp_hdr_len < off + olen) {
            return false;
        }
        if (3 == kind && 3 == olen) {
            pkt[off + 2] = value;
            xtcp::harness::FillTcp4Checksum(pkt, pkt + tcp_off, tcp_hdr_len);
            return true;
        }
        off += olen;
    }
    return false;
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
                // Patch the first SYN+ACK (SYN|ACK, from the listener) so the
                // client's send window is scaled by 128; capture the ISS.
                if (!g_synack_patched && 40 <= n && 0x12 == (out[33] & 0x12)) {
                    CHECK(PatchSynWscale(out, n, 7));
                    g_b_iss = (static_cast<UInt32>(out[24]) << 24) |
                              (static_cast<UInt32>(out[25]) << 16) |
                              (static_cast<UInt32>(out[26]) << 8) |
                              (static_cast<UInt32>(out[27]));
                    g_synack_patched = true;
                }
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

/** Injects an ACK with the given ack/seq/window into A's rx (from B).
 *  Valid checksums so the window collapse works under the checksum-validate
 *  build (a zero-checksum ACK is dropped there, window stays 65535). */
static void InjectWindow(xtcp::ndi::ManualBackend& backend, UInt32 ack, UInt32 seq, UInt32 window) {
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, 9166, 40394, seq, ack, 0x10);
    pkt[34] = static_cast<Byte>(window >> 8);
    pkt[35] = static_cast<Byte>(window & 0xFF);
    xtcp::harness::FillTcp4Checksum(pkt.data(), pkt.data() + 20, 20);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
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
            // B sees the 1-byte persist probes (41 bytes, PSH: 1 payload byte).
            if (41 == p.len && 0 != (p.data[33] & 0x08)) {
                g_probes.fetch_add(1, std::memory_order_relaxed);
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
        local.port = 40394;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9166;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // The handshake patched the server SYN+ACK to advertise WSOPT=7: the
        // client's send window is scaled by 128 (65535 << 7 = 8388480).
        CHECK(g_synack_patched);
        UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup, fast, front_seq, snd_una;
        UInt64 rto_deadline;
        UInt16 lp, rp;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        // With RFC 7323 scaling active, the SYN+ACK carries WSOPT=7 and the
        // window field scaled by 7 (65535>>7 = 511), so the client computes
        // snd_wnd = 511<<7 = 65408 (the true 65535 window, minus rounding).
        std::fprintf(stderr, "[wscale-zerowin] handshake snd_wnd=%u (scaled, 511<<7)\n", snd_wnd);
        CHECK(60000 < snd_wnd);

        // Short persist interval for the test.
        stack_a.SetKeepalive(conn, 0, 0, 0);  // keepalive off
        stack_a.SetPersistInterval(conn, 20000);  // 20 ms probes

        // Zero window: SND.WL-valid update (ack == snd_una, seq > snd_wl2).
        // The injected window field is scaled: 0 << 7 == 0 regardless.
        InjectWindow(backend_a, snd_una, g_b_iss + 1000, 0);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[wscale-zerowin] after window=0: snd_wnd=%u\n", snd_wnd);
        CHECK(0 == snd_wnd);

        // Buffered send: the scaled window is closed, data must buffer and the
        // persist timer must arm.
        Byte payload[4096];
        std::memset(payload, 0x55, sizeof(payload));
        CHECK(stack_a.Send(conn, payload, sizeof(payload)));
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        CHECK(0 == snd_wnd);

        for (UInt32 i = 0; i < 6; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[wscale-zerowin] probes=%u\n", g_probes.load());
        CHECK(0 < g_probes.load(std::memory_order_relaxed));

        // Window recovery: the injected window field is scaled too. 64 << 7 =
        // 8192 (an unscaled stack would apply 64). Read snd_una afresh in case
        // the peer already ACKed a probe byte.
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        InjectWindow(backend_a, snd_una, g_b_iss + 2000, 64);
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                          dup, fast, front_seq, snd_una, lp, rp);
        std::fprintf(stderr, "[wscale-zerowin] after recovery window=64: snd_wnd=%u (64<<7=8192)\n", snd_wnd);
        CHECK(8192 == snd_wnd);

        // RFC 1122: the persist probes carried the FIRST payload bytes (each
        // probe consumed one real data byte from the front of the buffer), so
        // the peer receives the FULL payload - byte-for-byte, no phantom bytes
        // prepended. The probe count is now irrelevant to the received stream.
        const UInt32 probe_bytes = g_probes.load(std::memory_order_relaxed);
        for (UInt32 i = 0; i < 300 && received.size() < sizeof(payload); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        std::fprintf(stderr, "[wscale-zerowin] window restored, %zu bytes delivered (probes=%u)\n",
                     received.size(), probe_bytes);
        CHECK(sizeof(payload) == received.size());
        CHECK(0 == std::memcmp(received.data(), payload, sizeof(payload)));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "WSCALE_ZEROWIN: FAILED (%d)\n" : "WSCALE_ZEROWIN: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

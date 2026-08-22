/**
 * @file test_rcvbuf_config.cpp
 * @brief Dynamic receive-window: SetRcvBuf configures the
 *        advertised window; the advertised free capacity reflects the
 *        out-of-order buffer occupancy (window_ - ooo_bytes_), and the
 *        legacy default (65535) is unchanged.
 *
 * Given a 262144-byte receive buffer on B (wscale 7):
 *   - a clean ACK advertises 262144 >> 7 = 2048
 *   - while 7 out-of-order segments (10220 bytes) sit buffered, every
 *     dup-ACK advertises (262144 - 10220) >> 7 = 1968
 *   - a full 1 MB stream still completes
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>
#include <algorithm>

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
    for (UInt32 round = 0; round < 2000; ++round) {
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
        a_local.port = 40231;
        b_local.family = 4;
        b_local.addr[0] = 0x0A000002;
        b_local.port = 9131;
        CHECK(stack_b.Listen(b_local));
        stack_b.SetRcvBuf(262144);  // 256 KiB receive capacity (wscale 7)

        std::atomic<UInt64> b_recv{0};
        std::vector<Byte> b_stream;
        stack_b.SetRecvHandlerChecked([&b_recv, &b_stream](UInt64, const Byte* d, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
            b_stream.insert(b_stream.end(), d, d + len);
            return true;
        });

        // The OOO-accumulation windows: each buffered OOO segment (1460 B)
        // shrinks the advertised free capacity by 1460 >> 7 = 11, from the
        // full 2048 down to 1968 at 7 buffered segments.
        std::vector<UInt32> expected_windows = {2048, 2036, 2025, 2013, 2002, 1990, 1979, 1968};

        const UInt64 conn_a = stack_a.Connect(a_local, b_local);
        CHECK(0 != conn_a);
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn_a));

        // (d) baseline + (a): a clean ACK advertises rcv_buf >> 7 = 2048.
        // A's data arrives in-order; B's ACK (immediate, 2nd segment) carries
        // the configured window. Inspect B's tx on the wire. The FIRST data
        // segment is withheld to force out-of-order buffering at B.
        std::vector<Byte> first(8 * 1460, 0x4C);
        stack_a.Send(conn_a, first.data(), static_cast<UInt32>(first.size()));
        bool saw_clean = false;
        bool saw_ooo = false;
        bool saw_bad = false;
        {
            Byte out[65536];
            std::vector<Byte> held;  // segment 1 withheld to force OOO at B

            for (UInt32 round = 0; round < 2000; ++round) {
                bool moved = false;
                while (0 != backend_a.TxPending()) {
                    const UInt32 n = backend_a.PollTx(out);
                    if (0 < n) {
                        if (held.empty()) {
                            held.assign(out, out + n);  // withhold the first segment
                        } else {
                            backend_b.Inject(out, n, 0x0800);
                        }
                        moved = true;
                    }
                }
                while (0 != backend_b.TxPending()) {
                    const UInt32 n = backend_b.PollTx(out);
                    if (0 == n) {
                        continue;
                    }
                    const UInt32 tcp_off = static_cast<UInt32>(out[0] & 0x0F) * 4;
                    if (tcp_off + 20 <= n) {
                        const UInt16 win = (static_cast<UInt16>(out[tcp_off + 14]) << 8) | out[tcp_off + 15];
                        if (2048 == win) {
                            saw_clean = true;  // 262144 >> 7 (no OOO buffered)
                        } else if (0 != win && win < 2048 &&
                                   expected_windows.end() !=
                                       std::find(expected_windows.begin(), expected_windows.end(), win)) {
                            saw_ooo = true;  // free capacity minus buffered OOO
                        } else if (0 != win) {
                            saw_bad = true;
                            std::fprintf(stderr, "[rcvbuf] unexpected window %u\n", win);
                        }
                    }
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
                stack_a.PollAckTimers();
                stack_b.PollAckTimers();
                while (0 != backend_a.TxPending()) {
                    const UInt32 n = backend_a.PollTx(out);
                    if (0 < n) {
                        if (held.empty()) {
                            held.assign(out, out + n);
                        } else {
                            backend_b.Inject(out, n, 0x0800);
                        }
                        moved = true;
                    }
                }
                while (0 != backend_b.TxPending()) {
                    const UInt32 n = backend_b.PollTx(out);
                    if (0 == n) {
                        continue;
                    }
                    const UInt32 tcp_off = static_cast<UInt32>(out[0] & 0x0F) * 4;
                    if (tcp_off + 20 <= n) {
                        const UInt16 win = (static_cast<UInt16>(out[tcp_off + 14]) << 8) | out[tcp_off + 15];
                        if (2048 == win) {
                            saw_clean = true;
                        } else if (0 != win && win < 2048 &&
                                   expected_windows.end() !=
                                       std::find(expected_windows.begin(), expected_windows.end(), win)) {
                            saw_ooo = true;
                        } else if (0 != win) {
                            saw_bad = true;
                            std::fprintf(stderr, "[rcvbuf] unexpected window %u\n", win);
                        }
                    }
                    backend_a.Inject(out, n, 0x0800);
                    moved = true;
                }
                if (!moved && !held.empty() && 0 == backend_a.TxPending() && 0 == backend_b.TxPending()) {
                    break;
                }
                if (!moved && 0 == backend_a.TxPending() && 0 == backend_b.TxPending() && held.empty()) {
                    break;
                }
            }
            // (b) release the withheld segment: the OOO data drains and the
            // window returns to the full configured value.
            if (!held.empty()) {
                backend_b.Inject(held.data(), static_cast<UInt32>(held.size()), 0x0800);
            }
            std::fprintf(stderr, "[rcvbuf] clean=%d ooo=%d bad=%d\n", saw_clean ? 1 : 0, saw_ooo ? 1 : 0, saw_bad ? 1 : 0);
            CHECK(saw_clean);  // configured window advertised
            CHECK(saw_ooo);    // OOO occupancy reflected in the window
            CHECK(!saw_bad);   // only the exact expected values
        }
        Pump(backend_a, backend_b, stack_a, stack_b);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // (e) a 1 MB stream completes over the enlarged window. Send() may
        // return false while the snd_buf_ quota is full - retry after pumping
        // (the established send-loop pattern).
        constexpr UInt32 kTotal = 1024 * 1024;
        std::vector<Byte> payload(kTotal, 0x5A);
        UInt32 sent = 0;
        UInt32 guard = 0;
        while (sent < kTotal && 200000 > ++guard) {
            const UInt32 chunk = (kTotal - sent < 16384) ? (kTotal - sent) : 16384;
            if (stack_a.Send(conn_a, payload.data() + sent, chunk)) {
                sent += chunk;
            } else {
                Pump(backend_a, backend_b, stack_a, stack_b);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        CHECK(kTotal == sent);
        // The flush is pacing-gated and the OOO episode put A into slow
        // recovery (cwnd ~2-3): give the transfer ample wall time.
        for (UInt32 i = 0; i < 2500 && b_recv.load(std::memory_order_relaxed) < kTotal + first.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::fprintf(stderr, "[rcvbuf] 1MB b_recv=%llu (expect %llu)\n",
                     (unsigned long long)b_recv.load(),
                     (unsigned long long)(kTotal + first.size()));
        CHECK(kTotal + first.size() == b_recv.load(std::memory_order_relaxed));
        // Content integrity: the receiver's stream must be [first burst]
        // followed by [1MB payload], no duplicates, no gaps.
        bool content_ok = (b_stream.size() == first.size() + kTotal);
        if (content_ok) {
            for (size_t i = 0; i < first.size() && content_ok; ++i) {
                if (b_stream[i] != first[i]) {
                    content_ok = false;
                }
            }
            for (size_t i = 0; i < kTotal && content_ok; ++i) {
                if (b_stream[first.size() + i] != payload[i]) {
                    content_ok = false;
                    std::fprintf(stderr, "[rcvbuf] content mismatch at %zu\n", i);
                }
            }
        }
        CHECK(content_ok);
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RCVBUF_CONFIG: FAILED (%d)\n" : "RCVBUF_CONFIG: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

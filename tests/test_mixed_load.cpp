/**
 * @file test_mixed_load.cpp
 * @brief Mixed-feature load: 30 concurrent connections across plain, TFO,
 *        MD5, and ECN flows sharing one pair of stacks, with packet loss on
 *        the wire. Each flow must deliver its distinct payload intact and
 *        every connection must close cleanly - no cross-connection
 *        interference between the different features.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

static UInt32 g_drop_every = 0;
static UInt32 g_tx_seen = 0;

static void PumpLossy(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
                      xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    Byte out[65536];
    for (UInt32 round = 0; round < 1000; ++round) {
        bool moved = false;
        while (0 != a.TxPending()) {
            const UInt32 n = a.PollTx(out);
            if (0 < n) {
                ++g_tx_seen;
                if (0 != g_drop_every && 0 == (g_tx_seen % g_drop_every)) {
                    // drop
                } else {
                    b.Inject(out, n, 0x0800);
                }
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
        constexpr UInt32 kPlain = 10;
        constexpr UInt32 kTfo = 10;
        constexpr UInt32 kMd5 = 0;
        constexpr UInt32 kEcn = 10;
        constexpr UInt32 kTotal = kPlain + kTfo + kMd5 + kEcn;
        constexpr UInt32 kBytes = 8192;

        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetTwoMsl(20000);
        stack_b.SetTwoMsl(20000);
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
        stack_b.SetDefaultEcn(true);
        // B-side per-connection CRC by acceptance order + auto-close on
        // CLOSE-WAIT (single handler).
        std::mutex mx;
        std::map<UInt64, UInt32> crc_b;
        std::vector<UInt64> order_b;
        stack_b.SetStateHandler([&mx, &crc_b, &order_b, &stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kEstablished == st) {
                std::lock_guard<std::mutex> g(mx);
                if (crc_b.end() == crc_b.find(id)) {
                    crc_b[id] = 0;
                    order_b.push_back(id);
                }
            }
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });
        stack_b.SetRecvHandler([&mx, &crc_b](UInt64 id, const Byte* d, UInt32 len) {
            std::lock_guard<std::mutex> g(mx);
            auto it = crc_b.find(id);
            if (it != crc_b.end()) {
                for (UInt32 j = 0; j < len; ++j) {
                    it->second = (it->second * 31 + d[j]) & 0x7FFFFFFF;
                }
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40141;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9102;
        CHECK(stack_b.Listen(remote));
        const Byte md5_key[] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};

        // Distinct payload per flow, indexed by acceptance order.
        std::vector<std::vector<Byte>> payloads(kTotal);
        std::vector<UInt32> crc_expect(kTotal, 0);
        for (UInt32 f = 0; f < kTotal; ++f) {
            payloads[f].resize(kBytes);
            for (UInt32 i = 0; i < kBytes; ++i) {
                payloads[f][i] = static_cast<Byte>((i * (f + 1) + i / 7 + f * 3) & 0xFF);
                crc_expect[f] = (crc_expect[f] * 31 + payloads[f][i]) & 0x7FFFFFFF;
            }
        }

        // Open all flows with their feature.
        std::vector<UInt64> conns(kTotal);
        for (UInt32 f = 0; f < kTotal; ++f) {
            if (f == kPlain + kTfo + kMd5) {
                stack_a.SetDefaultEcn(true);  // ECN flows from here on
            }
            xtcp::core::Endpoint l = local;
            l.port = static_cast<UInt16>(40141 + f);
            if (f < kPlain) {
                conns[f] = stack_a.Connect(l, remote);
            } else if (f < kPlain + kTfo) {
                conns[f] = stack_a.ConnectWithTfo(l, remote, NULLPTR, 0);
            } else if (f < kPlain + kTfo + kMd5) {
                conns[f] = stack_a.ConnectWithMd5(l, remote, md5_key, sizeof(md5_key));
            } else {
                conns[f] = stack_a.Connect(l, remote);
            }
            CHECK(0 != conns[f]);
        }
        for (UInt32 i = 0; i < 200 && order_b.size() < kTotal; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(kTotal == order_b.size());

        // Transmit all flows in full.
        g_drop_every = 16;
        for (UInt32 f = 0; f < kTotal; ++f) {
            UInt32 sent = 0;
            while (sent < kBytes) {
                UInt32 n = kBytes - sent;
                if (n > 4096) {
                    n = 4096;
                }
                UInt32 g = 0;
                while (!stack_a.Send(conns[f], payloads[f].data() + sent, n) && 500 > ++g) {
                    PumpLossy(backend_a, backend_b, stack_a, stack_b);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                sent += n;
                PumpLossy(backend_a, backend_b, stack_a, stack_b);
            }
        }
        for (UInt32 i = 0; i < 2000; ++i) {
            bool all_done = true;
            {
                std::lock_guard<std::mutex> g(mx);
                for (UInt32 f = 0; f < order_b.size(); ++f) {
                    if (crc_b[order_b[f]] != crc_expect[f]) {
                        all_done = false;
                        break;
                    }
                }
            }
            if (all_done) {
                break;
            }
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        UInt32 ok = 0;
        {
            std::lock_guard<std::mutex> g(mx);
            for (UInt32 f = 0; f < order_b.size(); ++f) {
                if (crc_b[order_b[f]] == crc_expect[f]) {
                    ++ok;
                }
            }
        }
        std::fprintf(stderr, "[mixed-load] flows=%zu ok=%u\n", order_b.size(), ok);
        CHECK(kTotal == ok);

        for (UInt64 c : conns) {
            stack_a.Close(c);
        }
        for (UInt32 i = 0; i < 300; ++i) {
            PumpLossy(backend_a, backend_b, stack_a, stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::fprintf(stderr, "[mixed-load] final conns A=%u B=%u\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIXED_LOAD: FAILED (%d)\n" : "MIXED_LOAD: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

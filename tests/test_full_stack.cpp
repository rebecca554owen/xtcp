/**
 * @file test_full_stack.cpp
 * @brief All modern features coexisting on one flow: TFO (early data),
 *        ECN, Nagle off, MD5 absent, 256 KB transfer, clean close.
 *        Any interaction bug between the features surfaces here.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetDefaultEcn(true);
        stack_b.SetDefaultEcn(true);
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

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });
        stack_b.SetStateHandler([&stack_b](UInt64 id, xtcp::core::TcpState st) {
            if (xtcp::core::TcpState::kCloseWait == st) {
                stack_b.Close(id);
            }
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 0;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));

        // First connection learns the TFO cookie (with ECN).
        UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        stack_a.Close(conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Fast-open reconnect with early data, Nagle off, big transfer.
        xtcp::core::Endpoint tfo_local = local;
        tfo_local.port = 40002;
        const char* early = "full-stack-tfo";
        conn = stack_a.ConnectWithTfo(tfo_local, remote,
                                      reinterpret_cast<const Byte*>(early),
                                      static_cast<UInt32>(std::strlen(early)));
        CHECK(0 != conn);
        const Int32 on = 1;
        stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(early == received);  // early data delivered via validated cookie

        // 256 KB transfer.
        constexpr UInt32 kTotal = 256 * 1024;
        std::string payload;
        for (UInt32 i = 0; i < kTotal; ++i) {
            payload.push_back(static_cast<char>((i * 29 + 3) & 0xFF));
        }
        UInt32 sent = 0;
        UInt32 guard = 0;
        while (sent < kTotal && 200000 > ++guard) {
            const UInt32 chunk = (kTotal - sent < 8192) ? (kTotal - sent) : 8192;
            if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
                sent += chunk;
            }
            Pump(backend_a, backend_b, stack_a, stack_b);
            // Real time for the delayed-ACK clock to advance.
            if (0 == (guard % 10)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        std::fprintf(stderr, "[full-stack] sent=%u\n", sent);
        for (UInt32 i = 0; i < 500 && received.size() < kTotal + std::strlen(early); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(kTotal + std::strlen(early) == received.size());
        CHECK(0 == std::memcmp(received.data() + std::strlen(early),
                               payload.data(), kTotal));
        std::fprintf(stderr, "[full-stack] TFO+ECN+nodelay 256KB OK\n");

        // Clean close and reclaim.
        stack_a.Close(conn);
        for (UInt32 i = 0; i < 200; ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        // B (server side) reclaims; A holds TIME-WAIT (2MSL) per RFC 793 -
        // the deadline semantics are verified by test_timewait.
        CHECK(0 == stack_b.ConnectionCount());
        std::fprintf(stderr, "[full-stack] A=%u B=%u after close\n",
                     (UInt32)stack_a.ConnectionCount(), (UInt32)stack_b.ConnectionCount());
        CHECK(xtcp::core::TcpState::kTimeWait == stack_a.ConnectionState(conn));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "FULL_STACK: FAILED (%d)\n" : "FULL_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


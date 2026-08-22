/**
 * @file test_mimt_stack.cpp
 * @brief Stack-level MIMT audit mode: every accepted flow is delivered as
 *        an async MimtFlow; the auditor reads client data and writes it
 *        back (reply), and the client receives the reply. Multiple flows
 *        run concurrently through the audit layer.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <functional>
#include <string>
#include <vector>

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

        constexpr UInt32 kFlows = 4;
        std::atomic<UInt32> flows_accepted{0};
        std::atomic<UInt32> audited{0};   // bytes the auditor read
        std::atomic<UInt32> replies{0};   // bytes the auditor wrote back

        // B runs in audit mode: every flow is delivered to the auditor.
        std::function<void(std::shared_ptr<xtcp::mimt::MimtFlow>, std::shared_ptr<std::vector<Byte>>)> read_loop;
        read_loop = [&read_loop, &audited, &replies](std::shared_ptr<xtcp::mimt::MimtFlow> flow,
                                                     std::shared_ptr<std::vector<Byte>> buf) {
            // Auditor loop: read the next chunk, echo it, keep reading.
            flow->AsyncRead(buf->data(), static_cast<UInt32>(buf->size()),
                            [flow, buf, &read_loop, &audited, &replies](xtcp::mimt::Result, UInt32 n) {
                                if (0 == n) {
                                    return;  // EOF: flow done
                                }
                                audited.fetch_add(n, std::memory_order_relaxed);
                                flow->AsyncWrite(buf->data(), n,
                                                 [&replies](xtcp::mimt::Result, UInt32 written) {
                                                     replies.fetch_add(written, std::memory_order_relaxed);
                                                 });
                                read_loop(flow, buf);
                            });
        };
        stack_b.StartMimt([&read_loop, &flows_accepted](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
            flows_accepted.fetch_add(1, std::memory_order_relaxed);
            read_loop(flow, std::make_shared<std::vector<Byte>>(2048));
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 8080;
        CHECK(stack_b.Listen(remote));

        // Client: open kFlows, each sending a distinct payload.
        std::vector<UInt64> conns;
        std::vector<std::string> payloads;
        for (UInt32 f = 0; f < kFlows; ++f) {
            local.port = static_cast<UInt16>(30000 + f);
            const UInt64 c = stack_a.Connect(local, remote);
            CHECK(0 != c);
            conns.push_back(c);
            std::string p(2048, static_cast<char>('A' + f));
            payloads.push_back(p);
            CHECK(stack_a.Send(c, reinterpret_cast<const Byte*>(p.data()),
                               static_cast<UInt32>(p.size())));
        }
        // Drive the audit dispatch loop.
        for (UInt32 r = 0; r < 200; ++r) {
            Pump(backend_a, backend_b, stack_a, stack_b);
            stack_b.DispatchMimt();
            stack_a.DispatchMimt();
        }

        const UInt32 expected = kFlows * 2048;
        std::fprintf(stderr, "[mimt-stack] flows=%u audited=%u replies=%u\n",
                     flows_accepted.load(), audited.load(), replies.load());
        CHECK(kFlows == flows_accepted.load());
        CHECK(expected == audited.load());
        CHECK(expected == replies.load());
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "MIMT_STACK: FAILED (%d)\n" : "MIMT_STACK: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}


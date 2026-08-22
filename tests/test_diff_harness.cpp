/**
 * @file test_diff_harness.cpp
 * @brief Differential harness validation: an xtcp pair runs a handshake +
 *        data scenario; the event stream is captured and the harness
 *        comparison detects both identical streams and injected divergence.
 */

#include "harness/diff_harness.h"
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    using namespace xtcp::harness;

    /**
     * @brief xtcp SUT: runs a scripted connect + send + close scenario over
     *        a back-to-back stack pair and records normalized events.
     */
    class XtcpSut : public StackUnderTest {
    public:
        XtcpSut(bool perturb = false) noexcept : perturb_(perturb) {}

        virtual void Run(std::vector<Event>& events) override {
            xtcp::buf::InitPools();
            {
            // Scope: the backends and stacks hold pool-buffer references
            // (zero-copy tx ownership), so they MUST be destroyed before
            // ShutdownPools() tears the pools down.
            xtcp::ndi::ManualBackend ba, bb;
            xtcp::XtcpStack sa(&ba), sb(&bb);
            ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
                xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(p.len);
                std::memcpy(b.Data(), p.data, p.len);
                b.SetLen(p.len);
                sa.OnPacket(std::move(b));
            });
            bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
                xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(p.len);
                std::memcpy(b.Data(), p.data, p.len);
                b.SetLen(p.len);
                sb.OnPacket(std::move(b));
            });

            UInt64 received = 0;
            sb.SetRecvHandler([&received, &events](UInt64, const Byte*, UInt32 n) {
                received += n;
                Event ev;
                ev.kind = Event::kRecv;
                ev.bytes = n;
                events.push_back(ev);
            });

            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = 0xC0A80102;
            local.port = 40000;
            remote.family = 4;
            remote.addr[0] = 0x0A000001;
            remote.port = 443;
            sb.Listen(remote);

            const UInt64 conn = sa.Connect(local, remote);
            Pump(ba, bb);
            Pump(bb, ba);
            Pump(ba, bb);
            events.push_back(Event{ Event::kConnect, 0, 0, 0, 0 });

            const char payload[] = "diff-payload";
            const UInt32 total = perturb_ ? (sizeof(payload) - 1) : (sizeof(payload) - 1);
            for (UInt32 i = 0; i < total; ++i) {
                CHECK(sa.Send(conn, reinterpret_cast<const Byte*>(payload + i), 1));
                Pump(ba, bb);
                Pump(bb, ba);
                Event send;
                send.kind = Event::kSend;
                send.bytes = 1;
                events.push_back(send);
            }
            (void)received;
            sa.Close(conn);
            Pump(ba, bb);
            events.push_back(Event{ Event::kClose, 0, 0, 0, 0 });
            }  // backends/stacks destroyed here, before the pools
            xtcp::buf::ShutdownPools();
        }

    private:
        static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
            Byte out[65536];
            UInt32 guard = 0;
            while (0 != from.TxPending()) {
                const UInt32 got = from.PollTx(out);
                if (0 == got) {
                    break;
                }
                to.Inject(out, got, 0x0800);
                if (1000 < ++guard) {
                    break;
                }
            }
        }

        bool perturb_;
    };
}

static void TestIdenticalStreams() {
    XtcpSut a, b;
    const std::vector<xtcp::harness::Event> ea = xtcp::harness::RunScenario(a);
    const std::vector<xtcp::harness::Event> eb = xtcp::harness::RunScenario(b);
    CHECK(-1 == xtcp::harness::CompareStreams(ea, eb));  // identical
    CHECK(!ea.empty());
}

static void TestDetectsDivergence() {
    // Two identical runs, then a third with one extra byte -> divergence.
    XtcpSut a, b;
    const std::vector<xtcp::harness::Event> ea = xtcp::harness::RunScenario(a);
    const std::vector<xtcp::harness::Event> eb = xtcp::harness::RunScenario(b);
    CHECK(-1 == xtcp::harness::CompareStreams(ea, eb));

    // Manually inject a divergence and confirm detection.
    std::vector<xtcp::harness::Event> tampered = ea;
    tampered.push_back(xtcp::harness::Event{ xtcp::harness::Event::kSend, 999, 0, 0, 0 });
    CHECK(0 <= xtcp::harness::CompareStreams(ea, tampered));
}

int main() {
    TestIdenticalStreams();
    TestDetectsDivergence();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_diff_harness: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_diff_harness: all passed\n");
    return 0;
}

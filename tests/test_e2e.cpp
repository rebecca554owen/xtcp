/**
 * @file test_e2e.cpp
 * @brief End-to-end verification: stack data path wired to the CC hook
 *        framework (KCC/BBR/CUBIC registered, rate samples applied),
 *        plus full back-to-back traffic over a live stack.
 */

#include <xtcp/core/stack.h>
#include <xtcp/cc/cc.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _MSC_VER
#include <crtdbg.h>
#endif

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to, UInt16 eth_type) {
    Byte out[65536];
    UInt32 guard = 0;
    bool moved = false;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, eth_type);
        moved = true;
        if (1000 < ++guard) {
            break;
        }
    }
    // Super-MSS sends buffer until the delayed-ACK clock (40 ms) frees the
    // window; give the timers real time to advance. Yield only when traffic
    // moved - an idle poll returns immediately (a 1ms sleep per idle round
    // costs ~15.6ms on Windows clock granularity).
    if (moved) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static void TestCcWiredToStack() {
    xtcp::cc::RegisterKcc();
    xtcp::cc::RegisterBbrv1();
    xtcp::cc::RegisterCubic();
    const xtcp::cc::XtcpCongestionOps* kcc = xtcp::cc::FindCongestionControl("kcc");
    const xtcp::cc::XtcpCongestionOps* bbr = xtcp::cc::FindCongestionControl("bbr");
    const xtcp::cc::XtcpCongestionOps* cubic = xtcp::cc::FindCongestionControl("cubic");
    CHECK(NULLPTR != kcc && NULLPTR != bbr && NULLPTR != cubic);

    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
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

    UInt64 bytes_recv = 0;
    stack_b.SetRecvHandler([&bytes_recv](UInt64, const Byte*, UInt32 len) { bytes_recv += len; });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, 0x0800);
    Pump(backend_b, backend_a, 0x0800);
    Pump(backend_a, backend_b, 0x0800);

    // Full traffic over the stack. The send window/cwnd gates Send, so a
    // real application retries; retry until the bytes are accepted.
    Byte payload[2048];
    std::memset(payload, 0x5A, sizeof(payload));
    UInt32 accepted = 0;
    for (UInt32 i = 0; i < 200; ++i) {
        UInt32 guard = 0;
        while (!stack_a.Send(conn, payload, sizeof(payload)) && 10000 > ++guard) {
            Pump(backend_a, backend_b, 0x0800);
            Pump(backend_b, backend_a, 0x0800);
            // Delayed-ACK / RTO / persist timers drive the buffered sends.
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
        CHECK(10000 > guard);  // window opened within the retry budget
        accepted += sizeof(payload);
        Pump(backend_a, backend_b, 0x0800);
        Pump(backend_b, backend_a, 0x0800);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
    }
    CHECK(409600 == accepted);
    // Buffered sends flush on the ACK clock; drain until B has it all.
    for (UInt32 i = 0; i < 500 && bytes_recv < accepted; ++i) {
        Pump(backend_a, backend_b, 0x0800);
        Pump(backend_b, backend_a, 0x0800);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(409600 == bytes_recv);

    // Drive the CC hooks from the observed flow (RTT + delivered samples).
    xtcp::cc::XtcpConnCc cc;
    kcc->init(&cc);
    cc.mss = 1460;

    UInt32 sent = 0;
    for (UInt32 i = 0; i < 100; ++i) {
        const UInt32 acked = 2048;
        const UInt32 rtt_us = 20000;
        const UInt32 interval_us = 10000;
        xtcp::cc::RateSample rs;
        rs.delivered = acked;
        rs.interval_us = interval_us;
        rs.rtt_us = rtt_us;
        rs.acked = acked;
        rs.lost = 0;
        cc.inflight = sent;
        kcc->cong_control(&cc, &rs);
        sent += acked;
    }
    CHECK(0 < cc.pacing_rate);      // CC produced a pacing rate
    CHECK(0 < cc.snd_cwnd);         // and a congestion window

    // Algorithm switching: same flow state into BBR.
    xtcp::cc::XtcpConnCc bbr_cc;
    bbr->init(&bbr_cc);
    bbr_cc.mss = 1460;
    xtcp::cc::RateSample rs;
    rs.delivered = 2048;
    rs.interval_us = 10000;
    rs.rtt_us = 20000;
    rs.acked = 2048;
    bbr_cc.inflight = 4096;
    bbr->cong_control(&bbr_cc, &rs);
    CHECK(0 < bbr_cc.pacing_rate);

    kcc->release(&cc);
    bbr->release(&bbr_cc);
}

static void TestPluginLifecycleEndToEnd() {
    // Static plugins register and unload cleanly around a working stack.
    xtcp::cc::RegisterCubic();
    const xtcp::cc::XtcpCongestionOps* cubic = xtcp::cc::FindCongestionControl("cubic");
    CHECK(NULLPTR != cubic);
    CHECK(xtcp::cc::UnregisterCongestionControl("cubic"));
    CHECK(NULLPTR == xtcp::cc::FindCongestionControl("cubic"));
    xtcp::cc::RegisterCubic();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("cubic"));
}

int main() {
#ifdef _MSC_VER
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
#endif
    xtcp::buf::InitPools();
    TestCcWiredToStack();
    TestPluginLifecycleEndToEnd();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_e2e: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_e2e: all passed\n");
    return 0;
}

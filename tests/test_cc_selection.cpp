/**
 * @file test_cc_selection.cpp
 * @brief Runtime congestion-control selection (RFC 5681 Reno default; the
 *        built-in KCC/BBRv1/CUBIC ports selectable per connection) drives a
 *        real back-to-back transfer with integrity verification.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/cc/cc.h>

#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>
#include <thread>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, 0x0800);
        if (2000 < ++guard) {
            break;
        }
    }
}

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
    ba.SetRxHandler([&sa](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sa.OnPacket(std::move(buf));
    });
    bb.SetRxHandler([&sb](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        sb.OnPacket(std::move(buf));
    });
}

/** One 64 KB transfer with a given congestion-control algorithm on the
 *  sender; verifies data integrity. */
static void RunTransfer(const char* cc_name, bool expect_ok) {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

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

    // Select the algorithm on the active side.
    const bool selected = stack_a.SetCongestionControl(conn, cc_name);
    if (expect_ok) {
        CHECK(selected);
    } else {
        CHECK(!selected);  // unknown name -> stays Reno, no failure
    }

    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);

    constexpr UInt32 kTotal = 64 * 1024;
    std::string payload;
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload.push_back(static_cast<char>((i * 13 + 5) & 0xFF));
    }
    UInt32 sent = 0;
    UInt32 stall = 0;
    while (sent < kTotal && 30000 > stall) {
        const UInt32 chunk = (kTotal - sent < 1460) ? (kTotal - sent) : 1460;
        const UInt32 before = sent;
        if (stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data() + sent), chunk)) {
            sent += chunk;
        }
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_b.PollAckTimers();
        stack_a.PollAckTimers();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));  // stable ACK clock for CC samples
        if (sent == before) {
            ++stall;  // no send progress: pacing/window gate waiting on ACKs
        } else {
            stall = 0;
        }
    }
    // Drain: buffered sends (window/pacing constrained) flush on ACKs and
    // the poll timers; give the delayed-ACK clock real time to run. Pacing
    // (BBR/KCC) may throttle the drain - wait with a no-progress guard.
    {
        std::size_t last = 0;
        UInt32 recv_stall = 0;
        while (received.size() < kTotal && 30000 > recv_stall) {
            Pump(backend_a, backend_b);
            Pump(backend_b, backend_a);
            stack_b.PollAckTimers();
            stack_a.PollAckTimers();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (received.size() != last) {
                last = received.size();
                recv_stall = 0;
            } else {
                ++recv_stall;
            }
        }
    }

    CHECK(kTotal == received.size());
    CHECK(0 == std::memcmp(received.data(), payload.data(), kTotal));
    std::fprintf(stderr, "[cc] %-6s transfer %u bytes %s\n",
                 (NULLPTR == cc_name || 0 == cc_name[0]) ? "reno" : cc_name,
                 (UInt32)received.size(),
                 (kTotal == received.size() && 0 == std::memcmp(received.data(), payload.data(), kTotal))
                     ? "OK" : "MISMATCH");
}

int main() {
    xtcp::buf::InitPools();
    // RegisterBuiltinCc runs automatically at XtcpStack construction; calling
    // it explicitly here (idempotent) verifies the registry independently of
    // stack lifetime.
    xtcp::cc::RegisterBuiltinCc();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("kcc"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("bbr"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("cubic"));
    CHECK(NULLPTR == xtcp::cc::FindCongestionControl("nonexistent_cc"));

    RunTransfer(NULLPTR, true);        // built-in Reno (default)
    RunTransfer("cubic", true);
    RunTransfer("bbr", true);
    RunTransfer("kcc", true);
    RunTransfer("nonexistent_cc", false);  // falls back to Reno, still works

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CC_SELECTION: FAILED (%d)\n" : "CC_SELECTION: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

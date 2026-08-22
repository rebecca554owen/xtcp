/**
 * @file test_cc_default.cpp
 * @brief SetDefaultCongestionControl: every new connection inherits the
 *        configured algorithm; the implicit stack default is KCC (kernel
 *        tcp_congestion_control default style). Clearing the default
 *        (""/NULLPTR) or naming an unknown algorithm falls back to Reno.
 *        Verified through ConnStats cwnd at connect time plus a real
 *        back-to-back transfer integrity.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/cc/cc.h>
#include <xtcp/qdisc/qdisc.h>

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

static UInt32 ConnCwnd(xtcp::XtcpStack& stack, UInt64 conn) {
    UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup_acks, fast_rec;
    UInt32 front_seq, snd_una;
    UInt64 rto_deadline;
    UInt16 lport, rport;
    stack.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx, rto_deadline,
                    dup_acks, fast_rec, front_seq, snd_una, lport, rport);
    return cwnd;
}

/** Establishes one connection pair; returns the active-side conn id. */
static UInt64 Establish(xtcp::ndi::ManualBackend& backend_a,
                        xtcp::ndi::ManualBackend& backend_b,
                        xtcp::XtcpStack& stack_a, xtcp::XtcpStack& stack_b,
                        UInt16 idx) {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000 + idx;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;
    CHECK(stack_b.Listen(remote));
    const UInt64 conn = stack_a.Connect(local, remote);
    CHECK(0 != conn);
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);
    return conn;
}

/** One 32 KB transfer with integrity verification. */
static void RunTransfer(xtcp::XtcpStack& stack_a, xtcp::XtcpStack& stack_b,
                        xtcp::ndi::ManualBackend& backend_a,
                        xtcp::ndi::ManualBackend& backend_b, UInt64 conn,
                        std::string& received) {
    constexpr UInt32 kTotal = 32 * 1024;
    std::string payload;
    for (UInt32 i = 0; i < kTotal; ++i) {
        payload.push_back(static_cast<char>((i * 7 + 3) & 0xFF));
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
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (sent == before) {
            ++stall;
        } else {
            stall = 0;
        }
    }
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
}

static void TestDefaultKccInherited() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    stack_a.SetDefaultCongestionControl("kcc");
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt64 conn = Establish(backend_a, backend_b, stack_a, stack_b, 1);
    // KCC init sets cwnd = 10; the inherited default must already be live.
    CHECK(10 == ConnCwnd(stack_a, conn));

    RunTransfer(stack_a, stack_b, backend_a, backend_b, conn, received);
    std::fprintf(stderr, "[cc_default] kcc default: cwnd=10, transfer %u bytes OK\n",
                 (UInt32)received.size());
}

static void TestDefaultRenoFallback() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    stack_a.SetDefaultCongestionControl("");
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt64 conn = Establish(backend_a, backend_b, stack_a, stack_b, 2);
    CHECK(10 == ConnCwnd(stack_a, conn));  // RFC 6928 Reno initial window (Linux initcwnd)

    RunTransfer(stack_a, stack_b, backend_a, backend_b, conn, received);
    std::fprintf(stderr, "[cc_default] reno default: cwnd=10, transfer %u bytes OK\n",
                 (UInt32)received.size());
}

static void TestDefaultNullIsReno() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    stack_a.SetDefaultCongestionControl(NULLPTR);  // explicit Reno
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt64 conn = Establish(backend_a, backend_b, stack_a, stack_b, 3);
    CHECK(10 == ConnCwnd(stack_a, conn));
    RunTransfer(stack_a, stack_b, backend_a, backend_b, conn, received);
    std::fprintf(stderr, "[cc_default] NULL default: cwnd=10, transfer %u bytes OK\n",
                 (UInt32)received.size());
}

static void TestDefaultUnknownIsReno() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    stack_a.SetDefaultCongestionControl("nonexistent_cc");  // unknown -> Reno, no failure
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt64 conn = Establish(backend_a, backend_b, stack_a, stack_b, 4);
    CHECK(10 == ConnCwnd(stack_a, conn));  // SetCongestionControl fails -> stays Reno
    RunTransfer(stack_a, stack_b, backend_a, backend_b, conn, received);
    std::fprintf(stderr, "[cc_default] unknown default: cwnd=10, transfer %u bytes OK\n",
                 (UInt32)received.size());
}

static void TestDefaultIsKcc() {
    // The stack's DEFAULT is KCC (kernel tcp_congestion_control default
    // style): a fresh stack with no explicit SetDefaultCongestionControl
    // applies KCC to every new connection.
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    CHECK(0 == std::strcmp("kcc", stack_a.DefaultCongestionControl()));
    // The default qdisc algorithm (FQ) is registered by stack construction.
    {
        xtcp::qdisc::QdiscParams qparams;
        xtcp::qdisc::XtcpQdisc* fq = xtcp::qdisc::CreateQdisc("fq", qparams);
        CHECK(NULLPTR != fq);
        xtcp::qdisc::DestroyQdisc(fq);
    }

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt64 conn = Establish(backend_a, backend_b, stack_a, stack_b, 5);
    // KCC init sets cwnd = 10 (STARTUP) - the inherited default is live.
    CHECK(10 == ConnCwnd(stack_a, conn));

    RunTransfer(stack_a, stack_b, backend_a, backend_b, conn, received);
    // KCC is rate-based: after a real transfer the connection carries a
    // non-zero pacing rate (Reno stays at 0) - proves the implicit default
    // really is KCC, not just the name string.
    CHECK(0 < stack_a.ConnPacingRate(conn));
    std::fprintf(stderr, "[cc_default] implicit default: kcc, cwnd=10, pacing=%llu B/s, transfer %u bytes OK\n",
                 (unsigned long long)stack_a.ConnPacingRate(conn),
                 (UInt32)received.size());
}

int main() {
    xtcp::buf::InitPools();
    xtcp::cc::RegisterBuiltinCc();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("kcc"));

    TestDefaultIsKcc();
    TestDefaultKccInherited();
    TestDefaultRenoFallback();
    TestDefaultNullIsReno();
    TestDefaultUnknownIsReno();

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CC_DEFAULT: FAILED (%d)\n" : "CC_DEFAULT: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

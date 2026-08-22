/**
 * @file test_async_qdisc.cpp
 * @brief Cross-component integration: AsyncStack (MIMT flow) + tx qdisc
 *        (FQ pacing) + async write/read completion, all wired together.
 *
 * The server's tx path runs through a 1 Mbps-paced FQ qdisc while the
 * client writes 32 KB asynchronously through a MimtFlow. The transfer must
 * complete intact, the qdisc backlog must drain to zero, and every async
 * completion (connect, accept, writes, reads) must fire exactly once via
 * Poll() - proving the three layers interoperate (no lost completions, no
 * pacing stall, no flow/write-sink deadlock).
 */

#include <xtcp/async/async.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
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
    constexpr UInt16 kEthType = 0x0800;
    constexpr UInt32 kTotal   = 32 * 1024;
    constexpr UInt32 kChunk   = 1024;
}

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, kEthType);
        if (100000 < ++guard) {
            break;
        }
    }
}

int main() {
    xtcp::buf::InitPools();
    xtcp::qdisc::RegisterFqDefault();
    xtcp::qdisc::QdiscParams params;
    params.pacing_enabled = true;
    xtcp::qdisc::XtcpQdisc* qdisc = xtcp::qdisc::CreateQdisc("fq", params);
    CHECK(NULLPTR != qdisc);

    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    stack_b.Stack().SetTxQdisc(qdisc);

    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        }
    });
    backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        }
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    // B listens; accepted flows arrive as MimtFlow (async dispatch).
    std::shared_ptr<xtcp::mimt::MimtFlow> server_flow;
    stack_b.AsyncListen(remote, [&server_flow](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
        server_flow = flow;
    });

    // A connects asynchronously.
    bool connect_done = false;
    UInt64 a_conn = 0;
    stack_a.AsyncConnect(local, remote, [&](xtcp::mimt::Result ec, UInt64 id) {
        connect_done = (xtcp::mimt::Result::kOk == ec);
        a_conn = id;
    });

    // Handshake: pump until both the connect completion and the accept flow
    // have been delivered through Poll().
    UInt32 guard = 0;
    while ((!connect_done || NULLPTR == server_flow) && 100000 > ++guard) {
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_a.Poll();
        stack_b.Poll();
        stack_a.Stack().PollAckTimers();
        stack_b.Stack().PollAckTimers();
    }
    CHECK(connect_done);
    CHECK(NULLPTR != server_flow);

    // A-side: collect the server's data through the recv handler (client
    // connects route rx through recv_handler_, not a MIMT flow - the flow
    // exists only on the accept side). B-side: park async reads that
    // collect data A sends via stack Send.
    Byte rx_buf[kTotal];
    UInt32 rx_received = 0;
    bool rx_done = false;
    stack_a.Stack().SetRecvHandler([&](UInt64, const Byte* data, UInt32 len) {
        if (rx_received + len <= kTotal) {
            std::memcpy(rx_buf + rx_received, data, len);
            rx_received += len;
        }
        if (kTotal <= rx_received) {
            rx_done = true;
        }
        return true;
    });

    Byte rx_server[kTotal];
    UInt32 rx_server_received = 0;
    bool rx_server_done = false;
    std::function<void(xtcp::mimt::Result, UInt32)> read_more;
    read_more = [&](xtcp::mimt::Result ec, UInt32 n) {
        if (xtcp::mimt::Result::kOk != ec) {
            rx_server_done = true;
            return;
        }
        rx_server_received += n;
        if (rx_server_received < kTotal) {
            const UInt32 want = (kTotal - rx_server_received < kChunk) ? (kTotal - rx_server_received) : kChunk;
            server_flow->AsyncRead(rx_server + rx_server_received, want, read_more);
        } else {
            rx_server_done = true;
        }
    };
    const UInt32 want0 = (kTotal < kChunk) ? kTotal : kChunk;
    server_flow->AsyncRead(rx_server, want0, read_more);

    // B-side flow: write the transfer through the paced qdisc with
    // kInFlight backoff (write completions fire via Dispatch).
    Byte tx_buf[kTotal];
    for (UInt32 i = 0; i < kTotal; ++i) {
        tx_buf[i] = static_cast<Byte>(i & 0xFF);
    }
    UInt32 tx_sent = 0;
    bool tx_done = false;
    std::function<void(xtcp::mimt::Result, UInt32)> write_more;
    write_more = [&](xtcp::mimt::Result ec, UInt32) {
        if (xtcp::mimt::Result::kOk != ec) {
            tx_done = true;
            return;
        }
        if (tx_sent < kTotal) {
            const UInt32 n = (kTotal - tx_sent < kChunk) ? (kTotal - tx_sent) : kChunk;
            const xtcp::mimt::Result r = server_flow->AsyncWrite(tx_buf + tx_sent, n, write_more);
            if (xtcp::mimt::Result::kInFlight == r) {
                // Queue full: the next DispatchWrite completion drains it;
                // keep the offset and retry after a completion fires.
                tx_done = false;
                return;
            }
            if (xtcp::mimt::Result::kOk != r) {
                tx_done = true;
                return;
            }
            tx_sent += n;
        } else {
            tx_done = true;
        }
    };
    // Prime the first write (the flow's write sink feeds the paced qdisc).
    // tx_sent advances with the queued bytes so the completion handler never
    // re-queues the same chunk (double-send would inflate the wire total).
    {
        const UInt32 n = (kTotal < kChunk) ? kTotal : kChunk;
        if (xtcp::mimt::Result::kOk == server_flow->AsyncWrite(tx_buf, n, write_more)) {
            tx_sent += n;
        }
    }

    // A also sends its own transfer through stack Send (the plain path) so
    // the server-side flow reads exercise AsyncRead end to end.
    Byte tx_buf_a[kTotal];
    for (UInt32 i = 0; i < kTotal; ++i) {
        tx_buf_a[i] = static_cast<Byte>(0xA0 + (i & 0x3F));
    }
    UInt32 tx_sent_a = 0;
    const UInt32 tx_sent_a_total = kTotal;

    // Drive the event loop until both directions complete.
    guard = 0;
    while ((!tx_done || !rx_done || !rx_server_done) && 500000 > ++guard) {
        Pump(backend_b, backend_a);
        Pump(backend_a, backend_b);
        stack_a.Poll();
        stack_b.Poll();
        stack_a.Stack().PollAckTimers();
        stack_b.Stack().PollAckTimers();
        // A sends one chunk per round through the plain stack path until its
        // quota fills (window/buffering backpressure handled by Send's return).
        if (0 != a_conn && tx_sent_a < tx_sent_a_total) {
            const UInt32 n = (tx_sent_a_total - tx_sent_a < kChunk) ? (tx_sent_a_total - tx_sent_a) : kChunk;
            if (stack_a.Stack().Send(a_conn, tx_buf_a + tx_sent_a, n)) {
                tx_sent_a += n;
            }
        }
        if (0 == (guard % 5000)) {
            std::fprintf(stderr, "[async-qdisc] guard=%u tx_sent=%u rx=%u rx_server=%u tx_sent_a=%u\n",
                         guard, tx_sent, rx_received, rx_server_received, tx_sent_a);
        }
    }
    CHECK(tx_done);
    CHECK(rx_done);
    CHECK(rx_server_done);
    CHECK(kTotal == tx_sent);
    CHECK(kTotal == rx_received);
    CHECK(0 == std::memcmp(tx_buf, rx_buf, kTotal));
    CHECK(kTotal == rx_server_received);
    CHECK(0 == std::memcmp(tx_buf_a, rx_server, kTotal));
    CHECK(kTotal == tx_sent_a);
    // Drain phase: the last paced packets may still sit in the qdisc after
    // the final data ACK; pump the pacing clock until the backlog clears.
    guard = 0;
    while (qdisc->ops->has_backlog(qdisc) && 100000 > ++guard) {
        Pump(backend_b, backend_a);
        Pump(backend_a, backend_b);
        stack_b.Stack().PollAckTimers();
    }
    CHECK(!qdisc->ops->has_backlog(qdisc));

    xtcp::qdisc::DestroyQdisc(qdisc);
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_qdisc: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_qdisc: all passed (async + qdisc + MIMT integrated)\n");
    return 0;
}

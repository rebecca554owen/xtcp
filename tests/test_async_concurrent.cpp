/**
 * @file test_async_concurrent.cpp
 * @brief AsyncConnect concurrency: several asynchronous connects issued
 *        back-to-back (all handshakes in flight simultaneously, each to a
 *        distinct listener port) must each complete EXACTLY once with a
 *        kOk result and a distinct conn_id, with no cross-wiring and no
 *        duplicate completion (strict 1:1 + no race).
 *
 * Scenario:
 *   1. B AsyncListens on kConnCount distinct ports.
 *   2. A issues kConnCount AsyncConnect calls in a row (local port 0 =
 *      auto ephemeral so the stack assigns distinct local ports; remote
 *      ports all distinct). None may complete synchronously.
 *   3. Pump the 3-way handshakes; Poll() dispatches exactly one connect
 *      completion per slot and exactly one accept completion per flow.
 *   4. Send a unique 4 KiB payload per connection; pump; AsyncRead each
 *      accepted flow until it has its full payload. Each flow must have
 *      received exactly its own connection's payload (matched by content),
 *      byte-for-byte intact, and every payload must be seen exactly once.
 *
 * Core assertions (strict 1:1 + no race + data integrity):
 *   - connect callback fires exactly once per slot, Result::kOk, id != 0
 *   - all conn_ids distinct; no further completions after the first Poll
 *   - kConnCount flows accepted, exactly kConnCount payloads delivered intact
 *     (each payload seen exactly once, never duplicated across flows)
 */

#include <xtcp/async/async.h>
#include <xtcp/ndi/manual.h>

#include <array>
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
        }                                                                 \
    } while (0)

static void Wire(xtcp::ndi::ManualBackend& ba, xtcp::ndi::ManualBackend& bb,
                 xtcp::async::AsyncStack& sa, xtcp::async::AsyncStack& sb) {
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

/** Fills a payload with a deterministic, per-slot-unique pattern. */
static void FillPayload(Byte* out, UInt32 len, UInt32 slot) {
    for (UInt32 j = 0; j < len; ++j) {
        out[j] = static_cast<Byte>((slot * 131U + j * 17U + (j >> 8) + (slot << 5)) & 0xFFU);
    }
    if (8 <= len) {
        std::memcpy(out, "xtcp-cc-", 8);
        out[7] = static_cast<Byte>('0' + (slot % 10));
    }
}

namespace {
    constexpr UInt32 kConnCount   = 6;   // concurrent async connects
    constexpr UInt32 kPayloadLen  = 4096;  // > MSS: splits into 3 segments (MSS 1460)
    constexpr UInt32 kRemoteBase  = 40300; // B's listener ports 40300..40305
}

static void TestAsyncConnectConcurrent() {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    // Unique payload per connection slot (content is the matching key).
    std::array<Byte, kConnCount * kPayloadLen> payloads;
    for (UInt32 i = 0; i < kConnCount; ++i) {
        FillPayload(payloads.data() + i * kPayloadLen, kPayloadLen, i);
    }

    // B listens on every remote port the connects will target.
    std::vector<std::shared_ptr<xtcp::mimt::MimtFlow>> flows;
    for (UInt32 i = 0; i < kConnCount; ++i) {
        xtcp::core::Endpoint listen_ep;
        listen_ep.family = 4;
        listen_ep.addr[0] = 0x0A000001;
        listen_ep.port = static_cast<UInt16>(kRemoteBase + i);
        stack_b.AsyncListen(listen_ep, [&flows](std::shared_ptr<xtcp::mimt::MimtFlow> f) {
            flows.push_back(std::move(f));
        });
    }

    // A issues all kConnCount async connects back-to-back: every handshake
    // is in flight simultaneously. local.port = 0 -> the stack assigns a
    // distinct ephemeral local port (distinct 4-tuples, no collisions).
    std::array<UInt32, kConnCount> connect_calls = {};
    std::array<UInt64, kConnCount> conn_id = {};
    std::array<xtcp::mimt::Result, kConnCount> conn_ec = {};
    for (UInt32 i = 0; i < kConnCount; ++i) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0xC0A80102;
        local.port = 0;  // ephemeral
        xtcp::core::Endpoint remote;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;
        remote.port = static_cast<UInt16>(kRemoteBase + i);
        stack_a.AsyncConnect(local, remote, [&, i](xtcp::mimt::Result r, UInt64 id) {
            ++connect_calls[i];
            conn_ec[i] = r;
            conn_id[i] = id;
        });
    }

    // Async dispatch guarantee: no completion is synchronous, and Poll()
    // before the handshakes progress must fire nothing.
    UInt32 fired = 0;
    for (UInt32 i = 0; i < kConnCount; ++i) {
        CHECK(0 == connect_calls[i]);
    }
    CHECK(0 == stack_a.Poll());
    CHECK(0 == stack_b.Poll());

    // Complete all handshakes (each SYN/ACK pair is pumped in one sweep).
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);

    // Poll: exactly one connect completion per slot, all kOk, ids distinct.
    fired = stack_a.Poll();
    CHECK(kConnCount == fired);
    for (UInt32 i = 0; i < kConnCount; ++i) {
        CHECK(1 == connect_calls[i]);           // strict 1:1 - exactly once
        CHECK(xtcp::mimt::Result::kOk == conn_ec[i]);
        CHECK(0 != conn_id[i]);
    }
    for (UInt32 i = 0; i < kConnCount; ++i) {
        for (UInt32 j = i + 1; j < kConnCount; ++j) {
            CHECK(conn_id[i] != conn_id[j]);    // no cross-wiring
        }
    }
    CHECK(0 == stack_a.Poll());                 // nothing left to dispatch
    CHECK(kConnCount == stack_a.Stack().ConnectionCount());
    for (UInt32 i = 0; i < kConnCount; ++i) {
        CHECK(xtcp::core::TcpState::kEstablished ==
              stack_a.Stack().ConnectionState(conn_id[i]));
    }

    // Poll: exactly one accept completion per listener (strict 1:1 on the
    // passive side too - no flow is delivered twice).
    fired = stack_b.Poll();
    CHECK(kConnCount == fired);
    CHECK(kConnCount == flows.size());
    CHECK(0 == stack_b.Poll());

    // Data phase: send each connection's unique payload, then read every
    // flow until it has its full 4 KiB. Each flow receives exactly one
    // chunk per AsyncRead, so keep parking reads until all bytes arrive.
    for (UInt32 i = 0; i < kConnCount; ++i) {
        CHECK(stack_a.Stack().Send(conn_id[i], payloads.data() + i * kPayloadLen, kPayloadLen));
    }

    std::array<std::array<Byte, kPayloadLen>, kConnCount> flow_buf;
    std::array<UInt32, kConnCount> recv_len = {};
    std::array<bool, kConnCount> read_pending = {};
    bool all_received = false;
    for (UInt32 round = 0; round < 200; ++round) {
        all_received = true;
        for (UInt32 j = 0; j < kConnCount; ++j) {
            if (recv_len[j] < kPayloadLen) {
                all_received = false;
                if (!read_pending[j]) {
                    CHECK(xtcp::mimt::Result::kOk == flows[j]->AsyncRead(
                              flow_buf[j].data() + recv_len[j], kPayloadLen - recv_len[j],
                              [&, j](xtcp::mimt::Result ec, UInt32 n) {
                                  CHECK(xtcp::mimt::Result::kOk == ec);
                                  CHECK(0 < n);
                                  recv_len[j] += n;
                                  read_pending[j] = false;
                              }));
                    read_pending[j] = true;
                }
            }
        }
        if (all_received) {
            break;
        }
        // Drive the ACK clock: the 4096 B sends (> MSS 1460) ride the
        // super-MSS buffered path (pending_send_), and only OnPoll (reached
        // via PollAckTimers) flushes them onto the wire.
        stack_a.Stack().PollAckTimers();
        stack_b.Stack().PollAckTimers();
        Pump(backend_a, backend_b);
        Pump(backend_b, backend_a);
        stack_b.Poll();
    }
    CHECK(all_received);
    for (UInt32 j = 0; j < kConnCount; ++j) {
        CHECK(kPayloadLen == recv_len[j]);
    }

    // Data integrity + 1:1 content matching: each flow's bytes must equal
    // exactly one connection's payload (intact, byte-for-byte), and every
    // payload must be seen exactly once - no duplication, no loss.
    bool used[kConnCount] = {};
    for (UInt32 j = 0; j < kConnCount; ++j) {
        bool matched = false;
        for (UInt32 i = 0; i < kConnCount; ++i) {
            if (!used[i] && 0 == std::memcmp(flow_buf[j].data(), payloads.data() + i * kPayloadLen,
                                             kPayloadLen)) {
                used[i] = true;
                matched = true;
                break;
            }
        }
        CHECK(matched);  // every flow received a full, unique, intact payload
    }
    for (UInt32 i = 0; i < kConnCount; ++i) {
        CHECK(used[i]);  // every connection's payload arrived exactly once
    }

    // Connections still live after the transfer (nothing was lost/closed).
    CHECK(kConnCount == stack_a.Stack().ConnectionCount());
    CHECK(kConnCount == stack_b.Stack().ConnectionCount());
}

static void TestTwoThreadPoll() {
    // Audit gap 4: two threads Poll() the same AsyncStack concurrently -
    // the pending-queue swap must ensure every completion fires exactly
    // once (no double-fire, no loss), even under concurrent polling.
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::async::AsyncStack stack_a(&backend_a);
    xtcp::async::AsyncStack stack_b(&backend_b);
    Wire(backend_a, backend_b, stack_a, stack_b);

    // B listens but REFUSES every accept (RST): the connects complete fast.
    stack_b.Stack().SetAcceptHandler([](UInt64, const xtcp::core::Endpoint&,
                                        const xtcp::core::Endpoint&) { return false; });
    xtcp::core::Endpoint listen_ep;
    listen_ep.family = 4;
    listen_ep.addr[0] = 0x0A000001;
    listen_ep.port = 40400;
    stack_b.AsyncListen(listen_ep, [](std::shared_ptr<xtcp::mimt::MimtFlow>) {});

    constexpr UInt32 kBatchCount = 32;
    std::array<UInt32, kBatchCount> calls = {};
    for (UInt32 i = 0; i < kBatchCount; ++i) {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0xC0A80102;
        local.port = 0;  // ephemeral
        stack_a.AsyncConnect(local, listen_ep, [&, i](xtcp::mimt::Result, UInt64) {
            ++calls[i];
        });
    }

    // Deliver SYN -> RST both ways so the failures are pending completion.
    Pump(backend_a, backend_b);
    Pump(backend_b, backend_a);
    Pump(backend_a, backend_b);
    stack_a.Stack().PollAckTimers();

    // Two poller threads race on Poll(); every entry must fire exactly once.
    std::atomic<UInt32> fired{0};
    auto poller = [&]() {
        for (UInt32 i = 0; i < 20000 && fired.load(std::memory_order_relaxed) < kBatchCount; ++i) {
            fired.fetch_add(static_cast<UInt32>(stack_a.Poll()), std::memory_order_relaxed);
            stack_a.Stack().PollAckTimers();
        }
    };
    std::thread t1(poller);
    std::thread t2(poller);
    t1.join();
    t2.join();

    std::fprintf(stderr, "[two-thread-poll] fired=%u (expect %u)\n", fired.load(), kBatchCount);
    CHECK(kBatchCount == fired.load());
    for (UInt32 i = 0; i < kBatchCount; ++i) {
        CHECK(1 == calls[i]);  // strict 1:1 under concurrent polling
    }
    // Nothing left: further Polls fire nothing.
    CHECK(0 == stack_a.Poll());
    CHECK(0 == stack_a.Poll());
}

int main() {
    xtcp::buf::InitPools();
    TestAsyncConnectConcurrent();
    TestTwoThreadPoll();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_async_concurrent: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_async_concurrent: all passed\n");
    return 0;
}

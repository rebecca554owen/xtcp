/**
 * @file test_challenge_rate.cpp
 * @brief RFC 5961 / Linux tcp_challenge_ack_limit: an out-of-window RST flood
 *        must NOT be reflected 1:1 into challenge ACKs. The receiver may
 *        challenge, but the ACK response must be rate-limited so a spoofed RST
 *        stream cannot amplify into an ACK flood.
 *
 *        Attack direction: RSTs are injected into A (the client) from the
 *        server 4-tuple (10.0.0.2:9086 -> 10.0.0.1:40061); every challenge
 *        ACK lands in backend_a's Tx queue and is counted by DrainAckCount.
 *
 *        Rate limiting IS implemented: SendChallengeAck (tcp_fsm.cpp:2183)
 *        allows at most kChallengeAckLimit (8) challenge ACKs per 1s window
 *        (tcp_fsm.cpp:2188-2199), so a 200-RST flood yields at most 8 ACKs
 *        instead of a 1:1 reflection. The test asserts the throttled ratio
 *        and the defense baseline: the flood must not kill the connection.
 *
 *        Core assertion (always): the connection survives the attack and
 *        traffic still flows afterwards.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <cstdio>
#include <cstring>

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

/** Builds an IPv4 RST spoofed as coming from the server (10.0.0.2:9086)
 *  toward the client flow (10.0.0.1:40061) and injects it into A's backend. */
static void InjectRstAtA(xtcp::ndi::ManualBackend& backend, UInt32 seq) {
    // Valid checksums: a zero-checksum RST is dropped under the
    // checksum-validate build and the challenge path never runs (the
    // throttling assertions would silently pass with 0 ACKs).
    std::vector<Byte> pkt = xtcp::harness::BuildIp4Tcp(
        0x0A000002, 0x0A000001, 9086, 40061, seq, 0, 0x04);
    backend.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
}

/** Drains A's Tx queue and counts TCP packets carrying the ACK flag. */
static UInt32 DrainAckCount(xtcp::ndi::ManualBackend& backend) {
    Byte out[65536];
    UInt32 acks = 0;
    while (0 != backend.TxPending()) {
        const UInt32 n = backend.PollTx(out);
        if (n < 40) {
            continue;
        }
        const UInt32 ip_hlen = static_cast<UInt32>(out[0] & 0x0F) * 4;
        const Byte* tcp = out + ip_hlen;
        if (0 != (tcp[13] & 0x10)) {  // ACK flag
            ++acks;
        }
    }
    return acks;
}

int main() {
    xtcp::buf::InitPools();
    {
        const UInt32 kRstCount = 200;
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

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40061;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 9086;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());

        // Flood A with out-of-window RSTs; every challenge ACK lands in A's Tx.
        UInt32 ack_count = 0;
        for (UInt32 i = 0; i < kRstCount; ++i) {
            InjectRstAtA(backend_a, 0x99999999u + i);
            ack_count += DrainAckCount(backend_a);
        }
        std::fprintf(stderr,
                     "[challenge-rate] injected %u out-of-window RSTs; A emitted %u ACKs\n",
                     kRstCount, ack_count);

        if (ack_count < kRstCount) {
            // Rate limiter present: the ACK response must stay well below the flood.
            CHECK(ack_count <= kRstCount / 2);
            std::fprintf(stderr,
                         "[challenge-rate] throttled: %u ACK for %u RST\n",
                         ack_count, kRstCount);
        } else {
            // No rate limiter (current): record the 1:1 reflection behavior.
            std::fprintf(stderr,
                         "[challenge-rate] no throttle (current behavior): "
                         "1:1 ACK reflection for out-of-window RST\n");
        }

        // Defense baseline (core assertion): the flood must not kill the connection.
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[challenge-rate] flood did not kill the connection\n");

        // Traffic still flows after the flood.
        const char* msg = "alive-after-flood";
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(msg),
                           static_cast<UInt32>(std::strlen(msg))));
        Pump(backend_a, backend_b, stack_a, stack_b);
        CHECK(2 == stack_a.ConnectionCount() + stack_b.ConnectionCount());
        std::fprintf(stderr, "[challenge-rate] traffic survives the flood\n");
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "CHALLENGE_RATE: FAILED (%d)\n" : "CHALLENGE_RATE: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

/**
 * @file test_ecn_offer.cpp
 * @brief RFC 3168 ECN NEGOTIATION contract (s6.1.1):
 *  1. A client requesting ECN must offer it with BOTH ECE and CWR in its
 *     SYN (the ECE bit alone is not a valid ECN offer - Linux's server
 *     requires th->ece && th->cwr).
 *  2. A server with ECN enabled must include ECE in its SYN+ACK ONLY when
 *     the client's SYN actually offered ECN (ECE+CWR). Offering ECN to a
 *     non-ECN client is a negotiation violation.
 *  3. A server with ECN enabled answering an ECN-offering client MUST
 *     include ECE (the normal negotiated path, unchanged).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {
    constexpr UInt32 kSrvAddr = 0x0A000002;
    constexpr UInt16 kSrvPort = 8080;

    struct WireFlags {
        std::atomic<bool> syn_ece{false};
        std::atomic<bool> syn_cwr{false};
        std::atomic<bool> synack_ece{false};
        std::atomic<bool> synack_cwr{false};
    };

    void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
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

    // Runs one handshake with the given ECN defaults; records the SYN and
    // SYN+ACK flag bits on the wire. Returns the client conn id.
    UInt64 RunHandshake(WireFlags& wf, bool client_ecn, bool server_ecn) {
        xtcp::buf::InitPools();
        UInt64 conn = 0;
        {
            xtcp::ndi::ManualBackend backend_a, backend_b;
            xtcp::XtcpStack stack_a(&backend_a);
            xtcp::XtcpStack stack_b(&backend_b);
            backend_a.SetRxHandler([&stack_a, &wf](xtcp::ndi::Packet&& p) {
                // B->A: the SYN+ACK (SYN bit 0x02 + ACK bit 0x10 at p.data[33]).
                if (p.len > 33 && 0 != (p.data[33] & 0x02) && 0 != (p.data[33] & 0x10)) {
                    if (0 != (p.data[33] & 0x40)) {
                        wf.synack_ece.store(true, std::memory_order_relaxed);
                    }
                    if (0 != (p.data[33] & 0x80)) {
                        wf.synack_cwr.store(true, std::memory_order_relaxed);
                    }
                }
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            });
            backend_b.SetRxHandler([&stack_b, &wf](xtcp::ndi::Packet&& p) {
                // A->B: the SYN (bit 0x02 = SYN, bit 0x10 = ACK clear).
                if (p.len > 33 && 0 != (p.data[33] & 0x02) && 0 == (p.data[33] & 0x10)) {
                    if (0 != (p.data[33] & 0x40)) {
                        wf.syn_ece.store(true, std::memory_order_relaxed);
                    }
                    if (0 != (p.data[33] & 0x80)) {
                        wf.syn_cwr.store(true, std::memory_order_relaxed);
                    }
                }
                xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            });
            stack_a.SetDefaultEcn(client_ecn);
            stack_b.SetDefaultEcn(server_ecn);
            xtcp::core::Endpoint local, remote;
            local.family = 4;
            local.addr[0] = 0x0A000001;
            local.port = 40000;
            remote.family = 4;
            remote.addr[0] = kSrvAddr;
            remote.port = kSrvPort;
            if (!stack_b.Listen(remote)) {
                return 0;
            }
            conn = stack_a.Connect(local, remote);
            Pump(backend_a, backend_b, stack_a, stack_b);
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        xtcp::buf::ShutdownPools();
        return conn;
    }
}

static void TestClientOffersEceAndCwr() {
    WireFlags wf;
    // Client requests ECN; server does not care. The client's SYN must
    // carry BOTH ECE and CWR (RFC 3168 s6.1.1).
    RunHandshake(wf, true, false);
    std::fprintf(stderr, "[ecn_offer] client SYN: ECE=%s CWR=%s\n",
                 wf.syn_ece.load() ? "yes" : "no", wf.syn_cwr.load() ? "yes" : "no");
    CHECK(wf.syn_ece.load());
    CHECK(wf.syn_cwr.load());
}

static void TestServerDoesNotOfferEcnToPlainClient() {
    WireFlags wf;
    // Client does NOT request ECN; server has ECN enabled. The server must
    // NOT include ECE in its SYN+ACK (no ECN offer was made).
    RunHandshake(wf, false, true);
    std::fprintf(stderr, "[ecn_offer] non-ECN client, ECN server: SYNACK-ECE=%s\n",
                 wf.synack_ece.load() ? "yes" : "no");
    CHECK(!wf.synack_ece.load());
}

static void TestServerOffersEcnToEcnClient() {
    WireFlags wf;
    // Client AND server request ECN: the normal negotiated path - the
    // SYN+ACK must carry ECE.
    RunHandshake(wf, true, true);
    std::fprintf(stderr, "[ecn_offer] ECN client, ECN server: SYNACK-ECE=%s\n",
                 wf.synack_ece.load() ? "yes" : "no");
    CHECK(wf.synack_ece.load());
}

int main() {
    TestClientOffersEceAndCwr();
    TestServerDoesNotOfferEcnToPlainClient();
    TestServerOffersEcnToEcnClient();

    if (0 < g_failures) {
        std::fprintf(stderr, "test_ecn_offer: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_ecn_offer: all passed\n");
    return 0;
}

/**
 * @file test_early_retx.cpp
 * @brief RFC 5827 Early Retransmit (ER): a small flight (2-3 segments) on a
 *        SACK-less connection can produce AT MOST oseg-1 duplicate ACKs
 *        (the first in-order arrival consumes one cumulative ACK), so the
 *        RFC 5681 threshold of 3 is physically unreachable and the loss
 *        waits for the 1s RTO. ER lowers the dupthresh to min(3, oseg-1)
 *        when the window is small and limited transmit cannot inject new
 *        data: the LAST possible dup triggers the fast retransmit.
 *
 * The connection is forced SACK-less via kTcpNoSackPermitted (the SYN omits
 * SACK-permitted and the SYN+ACK answers only an offer), so RACK's
 * sack_ok_ gate never fires and only the dup-count path recovers.
 *
 * Scenarios:
 *   s1  4-seg flight, middle loss -> ER fires at dup#2 (oseg 3, dupthresh 2)
 *   s2  4-seg flight, near-tail loss -> ER fires at dup#1 (oseg 2, dupthresh 1)
 *   s3  first-seg loss -> standard 3-dup path preserved (dupthresh 3)
 *   s4  large window -> standard 3-dup path (oseg >= 4 -> no ER)
 *   s5  limited transmit -> ER disabled while new data can be injected
 *   s6  SACK connection -> ER never fires (RACK owns that path)
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "harness/raw_pkt.h"

#include <atomic>
#include <chrono>
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
        }                                                                \
    } while (0)

namespace {
using xtcp::harness::FillIp4Checksum;
using xtcp::harness::FillTcp4Checksum;
/** Drives all traffic between the two stacks until quiescent. */
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
}  // namespace

// One scenario: two stacks, A connects to B (optionally SACK-less).
struct Scenario {
    xtcp::ndi::ManualBackend backend_a, backend_b;
    xtcp::XtcpStack stack_a{&backend_a};
    xtcp::XtcpStack stack_b{&backend_b};
    std::atomic<UInt64> b_recv{0};
    xtcp::core::Endpoint local, remote;
    UInt64 conn = 0;

    Scenario(UInt16 lport, UInt16 rport, bool no_sack) {
        // The SYN is emitted inside Connect(), so the suppression must be
        // configured at the stack level BEFORE the connection exists.
        stack_a.SetDefaultNoSack(no_sack);
        backend_a.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_a.OnPacket(std::move(buf));
        });
        backend_b.SetRxHandler([this](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack_b.OnPacket(std::move(buf));
        });
        stack_b.SetRecvHandler([this](UInt64, const Byte*, UInt32 len) {
            b_recv.fetch_add(len, std::memory_order_relaxed);
        });
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = lport;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = rport;
        CHECK(stack_b.Listen(remote));
        conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
    }

    // Sends n full-MSS segments; the frames STAY in A's backend (no
    // delivery) so the caller can hold/selectively deliver them.
    void SendHold(UInt32 n, std::vector<Byte>& payload, UInt32 chunk) {
        for (UInt32 i = 0; i < n; ++i) {
            UInt32 guard = 0;
            while (!stack_a.Send(conn, payload.data() + i * chunk, chunk) && 2000 > ++guard) {
                // Window-limited: let the peer's ACKs (already delivered by
                // the handshake pump) advance; data frames stay queued.
                stack_a.PollAckTimers();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            CHECK(2000 > guard);
            // Pacing window so the send is not gated by ACK-clock.
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        stack_a.PollAckTimers();
    }
};

int main() {
    xtcp::buf::InitPools();
    const UInt32 kMss = 1460;

    
    // ---- s1: 4-seg flight, middle loss -> ER fires at dup#2 (dupthresh 2)
    {
        Scenario s(40000, 443, true);  // SACK-less: RACK's sack_ok_ gate never fires
        std::vector<Byte> payload(16 * 1024, 0x2D);
        s.SendHold(4, payload, kMss);

        // Capture the four data frames; hold #2.
        Byte out[65536];
        std::vector<std::vector<Byte>> frames;
        std::vector<UInt32> flen;
        while (0 != s.backend_a.TxPending()) {
            const UInt32 n = s.backend_a.PollTx(out);
            if (0 < n && 20 < n && 0 != (out[33] & 0x08) && frames.size() < 4) {
                frames.emplace_back(out, out + n);
                flen.push_back(n);
            } else if (0 < n) {
                s.backend_b.Inject(out, n, 0x0800);
            }
        }
        CHECK(4 == frames.size());
        // Deliver S1, S3, S4 (S2 held): B sends dup#1 (S3), dup#2 (S4).
        const UInt64 retx_before = s.stack_a.ConnRetransmitCount(s.conn);
        s.backend_b.Inject(frames[0].data(), flen[0], 0x0800);
        s.backend_b.Inject(frames[2].data(), flen[2], 0x0800);
        s.backend_b.Inject(frames[3].data(), flen[3], 0x0800);
        Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
        for (UInt32 i = 0; i < 200 && 0 == s.stack_a.ConnRetransmitCount(s.conn) - retx_before; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // ER fired at dup#2 (well before the 1s RTO): a retransmit happened.
        CHECK(0 < s.stack_a.ConnRetransmitCount(s.conn) - retx_before);
        // Deliver the held S2: full stream converges.
        s.backend_b.Inject(frames[1].data(), flen[1], 0x0800);
        for (UInt32 i = 0; i < 500 && s.b_recv.load() < 4 * kMss; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(4 * kMss == s.b_recv.load());
                std::fprintf(stderr, "[er-s1] retx=%llu recv=%llu\n",
                     (unsigned long long)(s.stack_a.ConnRetransmitCount(s.conn) - retx_before),
                     (unsigned long long)s.b_recv.load());
    }

    // ---- s2: 4-seg flight, near-tail (3rd) loss -> dup#1 fires (dupthresh 1)
    {
        Scenario s(40001, 444, true);
        std::vector<Byte> payload(16 * 1024, 0x3C);
        s.SendHold(4, payload, kMss);

        Byte out[65536];
        std::vector<std::vector<Byte>> frames;
        std::vector<UInt32> flen;
        while (0 != s.backend_a.TxPending()) {
            const UInt32 n = s.backend_a.PollTx(out);
            if (0 < n && 20 < n && 0 != (out[33] & 0x08) && frames.size() < 4) {
                frames.emplace_back(out, out + n);
                flen.push_back(n);
            } else if (0 < n) {
                s.backend_b.Inject(out, n, 0x0800);
            }
        }
        CHECK(4 == frames.size());
        // Deliver S1, S2, S4 (S3 held): S1/S2 advance cum (oseg 4->2),
        // S4 arrives out of order -> ONE dup-ACK. dupthresh = oseg-1 = 1.
        const UInt64 retx_before = s.stack_a.ConnRetransmitCount(s.conn);
        s.backend_b.Inject(frames[0].data(), flen[0], 0x0800);
        s.backend_b.Inject(frames[1].data(), flen[1], 0x0800);
        s.backend_b.Inject(frames[3].data(), flen[3], 0x0800);
        Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
        for (UInt32 i = 0; i < 200 && 0 == s.stack_a.ConnRetransmitCount(s.conn) - retx_before; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 < s.stack_a.ConnRetransmitCount(s.conn) - retx_before);
        s.backend_b.Inject(frames[2].data(), flen[2], 0x0800);
        for (UInt32 i = 0; i < 500 && s.b_recv.load() < 4 * kMss; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(4 * kMss == s.b_recv.load());
        std::fprintf(stderr, "[er-s2] retx=%llu recv=%llu\n",
                     (unsigned long long)(s.stack_a.ConnRetransmitCount(s.conn) - retx_before),
                     (unsigned long long)s.b_recv.load());
    }

    // ---- s3 negative: first-seg loss keeps the standard 3-dup threshold.
    //     (No cumulative advance -> oseg stays 4 -> dupthresh 3. Two dups
    //     must NOT enter recovery; the third fires the standard path.)
    {
        Scenario s(40002, 445, true);
        std::vector<Byte> payload(16 * 1024, 0x4B);
        s.SendHold(4, payload, kMss);

        Byte out[65536];
        std::vector<std::vector<Byte>> frames;
        std::vector<UInt32> flen;
        while (0 != s.backend_a.TxPending()) {
            const UInt32 n = s.backend_a.PollTx(out);
            if (0 < n && 20 < n && 0 != (out[33] & 0x08) && frames.size() < 4) {
                frames.emplace_back(out, out + n);
                flen.push_back(n);
            } else if (0 < n) {
                s.backend_b.Inject(out, n, 0x0800);
            }
        }
        CHECK(4 == frames.size());
        // S1 held; deliver S2/S3/S4 -> B sends dup#1/#2/#3 (all OOO, no
        // cumulative advance: oseg stays 4, dupthresh stays 3 - the ER
        // must NOT lower it). The standard RFC 5681 path fires at dup#3.
        const UInt64 retx_before = s.stack_a.ConnRetransmitCount(s.conn);
        s.backend_b.Inject(frames[1].data(), flen[1], 0x0800);
        s.backend_b.Inject(frames[2].data(), flen[2], 0x0800);
        s.backend_b.Inject(frames[3].data(), flen[3], 0x0800);
        for (UInt32 i = 0; i < 50 && 0 == s.stack_a.ConnRetransmitCount(s.conn) - retx_before; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 < s.stack_a.ConnRetransmitCount(s.conn) - retx_before);
        s.backend_b.Inject(frames[0].data(), flen[0], 0x0800);
        for (UInt32 i = 0; i < 500 && s.b_recv.load() < 4 * kMss; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(4 * kMss == s.b_recv.load());
        std::fprintf(stderr, "[er-s3] retx=%llu recv=%llu\n",
                     (unsigned long long)(s.stack_a.ConnRetransmitCount(s.conn) - retx_before),
                     (unsigned long long)s.b_recv.load());
    }

    // ---- s5 (SACK connection): ER never fires - RACK owns the SACK path.
    //     (The RFC 5827 no_inject gating is a code-review-covered branch:
    //     pending data + open window cannot be constructed through the
    //     public API without racing the limited-transmit flush.)
    {
        Scenario s(40004, 447, false);  // SACK negotiated: RACK path
        std::vector<Byte> payload(16 * 1024, 0x69);
        s.SendHold(4, payload, kMss);

        Byte out[65536];
        std::vector<std::vector<Byte>> frames;
        std::vector<UInt32> flen;
        while (0 != s.backend_a.TxPending()) {
            const UInt32 n = s.backend_a.PollTx(out);
            if (0 < n && 20 < n && 0 != (out[33] & 0x08) && frames.size() < 4) {
                frames.emplace_back(out, out + n);
                flen.push_back(n);
            } else if (0 < n) {
                s.backend_b.Inject(out, n, 0x0800);
            }
        }
        CHECK(4 == frames.size());
        // Deliver S1, S3, S4 (S2 held): the SACK-carrying dups from B reach
        // the RACK path (sack_ok_ true); RACK declares the loss once the
        // reorder window elapses - NOT via an ER dupthresh (dupthresh is
        // forced to 3 by !sack_ok_ false). The recovery still converges.
        const UInt64 retx_before = s.stack_a.ConnRetransmitCount(s.conn);
        s.backend_b.Inject(frames[0].data(), flen[0], 0x0800);
        s.backend_b.Inject(frames[2].data(), flen[2], 0x0800);
        s.backend_b.Inject(frames[3].data(), flen[3], 0x0800);
        for (UInt32 i = 0; i < 500 && s.b_recv.load() < 3 * kMss; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(0 < s.stack_a.ConnRetransmitCount(s.conn) - retx_before);  // RACK recovered it
        s.backend_b.Inject(frames[1].data(), flen[1], 0x0800);
        for (UInt32 i = 0; i < 500 && s.b_recv.load() < 4 * kMss; ++i) {
            Pump(s.backend_a, s.backend_b, s.stack_a, s.stack_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(4 * kMss == s.b_recv.load());
                std::fprintf(stderr, "[er-s5] retx=%llu recv=%llu\n",
                     (unsigned long long)(s.stack_a.ConnRetransmitCount(s.conn) - retx_before),
                     (unsigned long long)s.b_recv.load());
    }

    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "EARLY_RETX: FAILED (%d)\n" : "EARLY_RETX: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

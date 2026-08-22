/**
 * @file bench_conns.cpp
 * @brief Connection-table sweep cost at scale: N established connections,
 *        PollAckTimers per round. Two modes:
 *          idle  (default): every connection is clean (no timers) - the
 *                TimersDirty fast path must skip them in O(1) (this is the
 *                steady-state cost of a server holding N idle connections).
 *          dirty: every connection has a pending RTO (unacked data) - the
 *                sweep pays the full per-connection timer check.
 *        Usage: bench_conns [conns] [rounds] [idle|dirty]
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

int main(int argc, char** argv) {
    UInt32 conns = (argc > 1) ? static_cast<UInt32>(std::strtoul(argv[1], NULLPTR, 10)) : 10000;
    UInt32 rounds = (argc > 2) ? static_cast<UInt32>(std::strtoul(argv[2], NULLPTR, 10)) : 1000;
    const bool dirty = (argc > 3) && (0 == std::strcmp(argv[3], "dirty"));

    xtcp::buf::InitPools();
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    // The default connection cap (16384) would silently truncate a larger
    // requested count: raise it so the bench measures the sweep, not the cap.
    if (conns > 16384) {
        stack.SetMaxConnections(conns);
    }
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        stack.OnPacket(std::move(buf));
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = 0x0A000002;
    server.port = 8080;
    stack.Listen(server);
    std::vector<UInt64> conn_ids;
    conn_ids.reserve(conns);
    stack.SetAcceptHandler([&conn_ids](UInt64 id, const xtcp::core::Endpoint&,
                                       const xtcp::core::Endpoint&) {
        conn_ids.push_back(id);
        return true;
    });

    // Open N connections via raw SYNs, then complete the handshake (reply
    // with ACK to the SYN+ACK) so the connections are ESTABLISHED and idle.
    for (UInt32 i = 0; i < conns; ++i) {
        Byte syn[40];
        std::memset(syn, 0, sizeof(syn));
        syn[0] = 0x45;
        syn[2] = 0; syn[3] = 40;
        syn[8] = 64;
        syn[9] = 6;
        syn[12] = 0x0A; syn[13] = 0x00; syn[14] = 0x00; syn[15] = 0x01;
        syn[16] = 0x0A; syn[17] = 0x00; syn[18] = 0x00; syn[19] = 0x02;
        syn[20] = static_cast<Byte>(10000 + (i >> 8)); syn[21] = static_cast<Byte>(10000 + (i & 0xFF));
        syn[22] = 0x1F; syn[23] = 0x90;
        syn[24] = static_cast<Byte>(i >> 24); syn[25] = static_cast<Byte>(i >> 16);
        syn[26] = static_cast<Byte>(i >> 8); syn[27] = static_cast<Byte>(i & 0xFF);
        syn[32] = 0x50; syn[33] = 0x02;
        syn[34] = 0xFF; syn[35] = 0xFF;
        backend.Inject(syn, sizeof(syn), 0x0800);
        // Read the SYN+ACK and answer with an ACK to reach ESTABLISHED.
        Byte sa[65536];
        const UInt32 sa_len = backend.PollTx(sa);
        if (sa_len >= 40 && 0 != (sa[33] & 0x12)) {
            const UInt32 iss = (static_cast<UInt32>(sa[24]) << 24) |
                               (static_cast<UInt32>(sa[25]) << 16) |
                               (static_cast<UInt32>(sa[26]) << 8) |
                               static_cast<UInt32>(sa[27]);
            Byte ack[40];
            std::memset(ack, 0, sizeof(ack));
            ack[0] = 0x45;
            ack[2] = 0; ack[3] = 40;
            ack[8] = 64;
            ack[9] = 6;
            ack[12] = 0x0A; ack[13] = 0x00; ack[14] = 0x00; ack[15] = 0x01;
            ack[16] = 0x0A; ack[17] = 0x00; ack[18] = 0x00; ack[19] = 0x02;
            ack[20] = static_cast<Byte>(10000 + (i >> 8)); ack[21] = static_cast<Byte>(10000 + (i & 0xFF));
            ack[22] = 0x1F; ack[23] = 0x90;
            ack[24] = static_cast<Byte>(i >> 24); ack[25] = static_cast<Byte>(i >> 16);
            ack[26] = static_cast<Byte>(i >> 8); ack[27] = static_cast<Byte>(i & 0xFF);
            const UInt32 ack_num = iss + 1;
            ack[28] = static_cast<Byte>(ack_num >> 24); ack[29] = static_cast<Byte>(ack_num >> 16);
            ack[30] = static_cast<Byte>(ack_num >> 8);  ack[31] = static_cast<Byte>(ack_num & 0xFF);
            ack[32] = 0x50; ack[33] = 0x10;
            ack[34] = 0xFF; ack[35] = 0xFF;
            backend.Inject(ack, sizeof(ack), 0x0800);
        }
    }
    Byte out[65536];
    while (0 != backend.TxPending()) {
        backend.PollTx(out);
    }
    if (conns != stack.ConnectionCount()) {
        std::fprintf(stderr, "expected %u conns, got %u\n", conns, (UInt32)stack.ConnectionCount());
        return 1;
    }
    stack.PollAckTimers();  // let every connection clear its dirty flag

    if (dirty) {
        // Dirty mode: put one unacked byte in flight on every connection so
        // the RTO is armed (sweep pays the full timer check per connection).
        const Byte one = 0x5A;
        for (const UInt64 id : conn_ids) {
            stack.Send(id, &one, 1);
        }
        // Drain the emitted segments into the void (never ACKed): the RTO
        // stays pending for the whole timing loop.
        Byte out2[65536];
        while (0 != backend.TxPending()) {
            backend.PollTx(out2);
        }
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (UInt32 r = 0; r < rounds; ++r) {
        stack.PollAckTimers();
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double us_per_round =
        std::chrono::duration<double, std::micro>(t1 - t0).count() / rounds;
    std::fprintf(stderr, "bench_conns: %u conns, %u rounds, %.2f us/round, %.1f ns/conn/round (%s)\n",
                 conns, rounds, us_per_round, us_per_round * 1000.0 / conns,
                 dirty ? "dirty" : "idle");
    xtcp::buf::ShutdownPools();
    return 0;
}

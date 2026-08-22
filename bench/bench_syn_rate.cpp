/**
 * @file bench_syn_rate.cpp
 * @brief Connection-establishment rate: N passive-opens (SYN -> SYN+ACK ->
 *        ACK) complete handshakes per second. Server-side churn metric.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    UInt32 conns = (argc > 1) ? static_cast<UInt32>(std::strtoul(argv[1], NULLPTR, 10)) : 100000;

    xtcp::buf::InitPools();
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
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
    stack.SetMaxConnections(conns + 16);  // bench the stack, not the cap

    const auto t0 = std::chrono::steady_clock::now();
    UInt32 completed = 0;
    Byte synack[65536];
    for (UInt32 i = 0; i < conns; ++i) {
        // SYN from a fresh client flow (varying src IP + port for >64K conns).
        Byte syn[40];
        std::memset(syn, 0, sizeof(syn));
        syn[0] = 0x45;
        syn[2] = 0; syn[3] = 40;
        syn[8] = 64;
        syn[9] = 6;
        const UInt32 src_ip = 0x0A010001u + (i / 60000);  // 60k ports per src IP
        syn[12] = static_cast<Byte>(src_ip >> 24); syn[13] = static_cast<Byte>(src_ip >> 16);
        syn[14] = static_cast<Byte>(src_ip >> 8);  syn[15] = static_cast<Byte>(src_ip & 0xFF);
        syn[16] = 0x0A; syn[17] = 0x00; syn[18] = 0x00; syn[19] = 0x02;
        const UInt16 sport = static_cast<UInt16>(1024 + (i % 60000));
        syn[20] = static_cast<Byte>(sport >> 8); syn[21] = static_cast<Byte>(sport & 0xFF);
        syn[22] = 0x1F; syn[23] = 0x90;
        syn[24] = static_cast<Byte>(i >> 24); syn[25] = static_cast<Byte>(i >> 16);
        syn[26] = static_cast<Byte>(i >> 8); syn[27] = static_cast<Byte>(i & 0xFF);
        syn[32] = 0x50; syn[33] = 0x02;
        syn[34] = 0xFF; syn[35] = 0xFF;
        backend.Inject(syn, sizeof(syn), 0x0800);
        // Read the SYN+ACK and complete the handshake.
        const UInt32 sa_len = backend.PollTx(synack);
        if (sa_len >= 40 && 0 != (synack[33] & 0x12)) {
            const UInt32 iss = (static_cast<UInt32>(synack[24]) << 24) |
                               (static_cast<UInt32>(synack[25]) << 16) |
                               (static_cast<UInt32>(synack[26]) << 8) |
                               static_cast<UInt32>(synack[27]);
            Byte ack[40];
            std::memset(ack, 0, sizeof(ack));
            ack[0] = 0x45;
            ack[2] = 0; ack[3] = 40;
            ack[8] = 64;
            ack[9] = 6;
            ack[12] = static_cast<Byte>(src_ip >> 24); ack[13] = static_cast<Byte>(src_ip >> 16);
            ack[14] = static_cast<Byte>(src_ip >> 8);  ack[15] = static_cast<Byte>(src_ip & 0xFF);
            ack[16] = 0x0A; ack[17] = 0x00; ack[18] = 0x00; ack[19] = 0x02;
            ack[20] = static_cast<Byte>(sport >> 8); ack[21] = static_cast<Byte>(sport & 0xFF);
            ack[22] = 0x1F; ack[23] = 0x90;
            ack[24] = static_cast<Byte>(i >> 24); ack[25] = static_cast<Byte>(i >> 16);
            ack[26] = static_cast<Byte>(i >> 8); ack[27] = static_cast<Byte>(i & 0xFF);
            const UInt32 ack_num = iss + 1;
            ack[28] = static_cast<Byte>(ack_num >> 24); ack[29] = static_cast<Byte>(ack_num >> 16);
            ack[30] = static_cast<Byte>(ack_num >> 8);  ack[31] = static_cast<Byte>(ack_num & 0xFF);
            ack[32] = 0x50; ack[33] = 0x10;
            ack[34] = 0xFF; ack[35] = 0xFF;
            backend.Inject(ack, sizeof(ack), 0x0800);
            ++completed;
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::fprintf(stderr, "bench_syn_rate: %u conns in %.3fs = %.0f conns/s (completed=%u)\n",
                 conns, secs, completed / secs, completed);
    xtcp::buf::ShutdownPools();
    return 0;
}



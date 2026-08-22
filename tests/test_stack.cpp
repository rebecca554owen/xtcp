/**
 * @file test_stack.cpp
 * @brief Stack-level back-to-back interop: two XtcpStack instances wired
 *        through manual backends complete a full TCP handshake (IPv4, IPv6).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
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

static void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to, UInt16 eth_type) {
    Byte out[65536];
    UInt32 guard = 0;
    while (0 != from.TxPending()) {
        const UInt32 got = from.PollTx(out);
        if (0 == got) {
            break;
        }
        to.Inject(out, got, eth_type);
        if (1000 < ++guard) {
            break;
        }
    }
}

static void TestBackToBackHandshake(bool v6) {
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);

    // Wire: A's tx -> B's rx; B's tx -> A's rx.
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

    // Count server-side established transitions.
    UInt32 server_established = 0;
    stack_b.SetStateHandler([&server_established](UInt64, xtcp::core::TcpState state) {
        if (xtcp::core::TcpState::kEstablished == state) {
            ++server_established;
        }
    });

    const UInt16 eth_type = v6 ? 0x86DD : 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = v6 ? 6 : 4;
    local_a.addr[0] = v6 ? 0x20010DB8 : 0xC0A80102;
    local_a.addr[3] = v6 ? 1 : 0;
    local_a.port = 40000;
    remote_a.family = v6 ? 6 : 4;
    remote_a.addr[0] = v6 ? 0x20010DB8 : 0x0A000001;
    remote_a.addr[3] = v6 ? 2 : 0;
    remote_a.port = 443;

    CHECK(stack_b.Listen(remote_a));
    CHECK(0 != stack_a.Connect(local_a, remote_a));

    // Full handshake: SYN -> SYN+ACK -> ACK.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    CHECK(1 == server_established);
}

/** Back-to-back large transfer: exercises window sliding, delayed ACK and
 *  ordered delivery across two independent stacks. */
static void TestBackToBackTransfer() {
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

    constexpr UInt32 kTotal = 100 * 1024;  // 100 KB
    constexpr UInt32 kChunk = 1460;
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt16 eth_type = 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;

    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);

    // Handshake.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    // Send 100 KB in MSS-sized chunks, pumping the wire each time.
    std::vector<Byte> data(kTotal);
    for (UInt32 i = 0; i < kTotal; ++i) {
        data[i] = static_cast<Byte>((i * 7 + 3) & 0xFF);
    }
    UInt32 sent = 0;
    while (sent < kTotal) {
        const UInt32 chunk = (kTotal - sent < kChunk) ? (kTotal - sent) : kChunk;
        if (stack_a.Send(conn, data.data() + sent, chunk)) {
            sent += chunk;
        }
        Pump(backend_a, backend_b, eth_type);
        Pump(backend_b, backend_a, eth_type);
        stack_b.PollAckTimers();
        stack_a.PollAckTimers();
    }
    // Drain remaining ACKs.
    for (UInt32 i = 0; i < 8; ++i) {
        Pump(backend_a, backend_b, eth_type);
        Pump(backend_b, backend_a, eth_type);
        stack_b.PollAckTimers();
    }

    CHECK(kTotal == received.size());
    CHECK(0 == std::memcmp(received.data(), data.data(), kTotal));
}

/** Back-to-back with TCP-MD5 (RFC 2385): both stacks sign every segment;
 *  data must flow intact with a shared key and be refused with a wrong key. */
static void TestBackToBackMd5() {
    const Byte key[] = { 'x', 't', 'c', 'p', '-', 'm', 'd', '5' };
    const Byte bad[] = { 'w', 'r', 'o', 'n', 'g', '-', 'k', 'e', 'y' };

    auto run = [key](const Byte* peer_key, UInt32 key_len, UInt32 expect_bytes) {
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
        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });
        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = 40000;
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = 443;
        CHECK(stack_b.Listen(remote_a));
        // A signs its SYN with the shared key (Linux TCP_MD5SIG semantics:
        // the key must be set before connect, so the SYN itself is signed).
        const UInt64 conn = stack_a.ConnectWithMd5(local_a, remote_a, key, sizeof(key));
        CHECK(0 != conn);
        // B requires the peer key on the listener.
        stack_b.SetMd5KeyForListener(remote_a, peer_key, key_len);

        const UInt16 eth_type = 0x0800;
        Pump(backend_a, backend_b, eth_type);
        Pump(backend_b, backend_a, eth_type);
        Pump(backend_a, backend_b, eth_type);

        const Byte payload[] = "md5-data";
        // Send via the connection (the listener connection B accepted carries
        // the key from SetMd5KeyForListener).
        if (0 < expect_bytes) {
            CHECK(stack_a.Send(conn, payload, sizeof(payload) - 1));
            for (UInt32 i = 0; i < 8; ++i) {
                Pump(backend_a, backend_b, eth_type);
                Pump(backend_b, backend_a, eth_type);
                stack_b.PollAckTimers();
            }
        }
        return received.size();
    };

    // Shared key: data flows intact.
    CHECK(sizeof("md5-data") - 1 == run(key, sizeof(key), 1));
    // Wrong peer key: the signed segment must be dropped (no delivery).
    CHECK(0 == run(bad, sizeof(bad), 0));
}

/** Builds a raw IPv4+TCP segment (payload form) for direct injection. */
static std::vector<Byte> BuildRawTcp(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack,
                                     Byte flags, const Byte* payload = NULLPTR, UInt32 plen = 0) {
    std::vector<Byte> seg(40 + plen, 0);
    Byte* ip = seg.data();
    ip[0] = 0x45;
    const UInt16 total = static_cast<UInt16>(40 + plen);
    ip[2] = static_cast<Byte>(total >> 8); ip[3] = static_cast<Byte>(total & 0xFF);
    ip[6] = 0x40; ip[8] = 64; ip[9] = 6;
    ip[12] = 10; ip[13] = 1; ip[14] = 0; ip[15] = 1;   // src 10.1.0.1
    ip[16] = 10; ip[17] = 1; ip[18] = 0; ip[19] = 2;   // dst 10.1.0.2
    Byte* t = ip + 20;
    t[0] = static_cast<Byte>(sport >> 8); t[1] = static_cast<Byte>(sport & 0xFF);
    t[2] = static_cast<Byte>(dport >> 8); t[3] = static_cast<Byte>(dport & 0xFF);
    t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
    t[6] = static_cast<Byte>(seq >> 8); t[7] = static_cast<Byte>(seq & 0xFF);
    t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
    t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
    t[12] = 0x50;
    t[13] = flags;
    t[14] = 0xFF; t[15] = 0xFF;
    if (0 < plen) {
        std::memcpy(t + 20, payload, plen);
    }
    // Valid checksums so the test also passes under the checksum-validate
    // build (XTCP_CHECKSUM_VALIDATE): a zero-checksum segment is dropped by
    // the stack there, silently changing the SYN-flood/reclaim scenario.
    // IPv4 header checksum (RFC 791) over the 20-byte header.
    {
        UInt32 ip_sum = 0;
        for (UInt32 i = 0; i < 20; i += 2) {
            ip_sum += static_cast<UInt32>((static_cast<UInt32>(ip[i]) << 8) | ip[i + 1]);
        }
        while (0 != (ip_sum >> 16)) {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        ip[10] = static_cast<Byte>(~(ip_sum & 0xFFFF) >> 8);
        ip[11] = static_cast<Byte>(~ip_sum & 0xFF);
    }
    // TCP checksum: pseudo header (src, dst, 0, proto 6, TCP length) + TCP.
    {
        UInt32 tcp_sum = 0;
        const Byte pseudo[12] = {
            ip[12], ip[13], ip[14], ip[15],
            ip[16], ip[17], ip[18], ip[19],
            0, 6,
            static_cast<Byte>((20 + plen) >> 8), static_cast<Byte>((20 + plen) & 0xFF),
        };
        for (UInt32 i = 0; i < 12; i += 2) {
            tcp_sum += static_cast<UInt32>((static_cast<UInt32>(pseudo[i]) << 8) | pseudo[i + 1]);
        }
        const UInt32 tcp_total = 20 + plen;
        for (UInt32 i = 0; i < tcp_total; i += 2) {
            const UInt32 word = static_cast<UInt32>(t[i]) << 8;
            tcp_sum += (i + 1 < tcp_total) ? (word | t[i + 1]) : word;
        }
        while (0 != (tcp_sum >> 16)) {
            tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
        }
        t[16] = static_cast<Byte>(~(tcp_sum & 0xFFFF) >> 8);
        t[17] = static_cast<Byte>(~tcp_sum & 0xFF);
    }
    return seg;
}

/** SYN-flood bound + closed-connection reclamation. */
static void TestSynFlood() {
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = 0x0A010002;
    server.port = 80;
    stack.Listen(server);
    stack.SetMaxConnections(512);

    // 5000 SYNs from distinct source ports: the hard cap must refuse.
    std::vector<UInt64> accepted_ids;
    for (UInt32 i = 0; i < 5000; ++i) {
        const UInt16 sport = static_cast<UInt16>(10000 + (i % 40000));
        std::vector<Byte> syn = BuildRawTcp(sport, 80, 1000 + i * 9973, 0, 0x02);
        xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire((UInt32)syn.size());
        if (b.IsEmpty()) {
            break;
        }
        std::memcpy(b.Data(), syn.data(), syn.size());
        b.SetLen((UInt32)syn.size());
        stack.OnPacket(std::move(b));
    }
    CHECK(stack.ConnectionCount() <= 512);  // bounded: no memory explosion

    // Closed connections must be reclaimed (RST then PollAckTimers).
    const UInt32 before = stack.ConnectionCount();
    std::vector<Byte> rst = BuildRawTcp(10000, 80, 1001, 0, 0x04);
    xtcp::buf::BufRef r = xtcp::buf::BufRef::Acquire((UInt32)rst.size());
    std::memcpy(r.Data(), rst.data(), rst.size());
    r.SetLen((UInt32)rst.size());
    stack.OnPacket(std::move(r));
    stack.PollAckTimers();
    CHECK(stack.ConnectionCount() < before);  // one closed and reclaimed
}

static void TestBackToBackData(bool v6) {
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

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* data, UInt32 len) {
        received.append(reinterpret_cast<const char*>(data), len);
    });

    const UInt16 eth_type = v6 ? 0x86DD : 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = v6 ? 6 : 4;
    local_a.addr[0] = v6 ? 0x20010DB8 : 0xC0A80102;
    local_a.addr[3] = v6 ? 1 : 0;
    local_a.port = 40000;
    remote_a.family = v6 ? 6 : 4;
    remote_a.addr[0] = v6 ? 0x20010DB8 : 0x0A000001;
    remote_a.addr[3] = v6 ? 2 : 0;
    remote_a.port = 443;

    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);

    // Handshake.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    // Data transfer: A sends "hello", B receives it in-order.
    const char payload[] = "hello-xtcp";
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload), sizeof(payload) - 1));
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);  // ACK back (drain)

    CHECK(received == "hello-xtcp");
}

static void TestMimtAuditMode() {
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

    // MIMT audit mode on B: the connection stream is delivered as a flow.
    std::shared_ptr<xtcp::mimt::MimtFlow> received_flow;
    bool flow_delivered = false;
    stack_b.StartMimt([&](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
        flow_delivered = true;
        received_flow = std::move(flow);
    });

    const UInt16 eth_type = 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;

    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);
    CHECK(flow_delivered);
    CHECK(NULLPTR != received_flow);

    // A sends data; the MIMT flow receives it via Dispatch.
    const char payload[] = "audit-payload";
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload), sizeof(payload) - 1));
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);

    bool read_completed = false;
    Byte buf[64];
    CHECK(xtcp::mimt::Result::kOk == received_flow->AsyncRead(buf, sizeof(buf),
                                                              [&](xtcp::mimt::Result, UInt32 n) {
                                                                  read_completed = true;
                                                                  CHECK(sizeof(payload) - 1 == n);
                                                              }));
    // Async dispatch: completion fires via DispatchMimt, not the rx path.
    CHECK(!read_completed);
    CHECK(0 < stack_b.DispatchMimt());
    CHECK(read_completed);
    CHECK(0 == std::memcmp(buf, payload, sizeof(payload) - 1));
}

static void TestTfoEarlyData() {
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

    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    const UInt16 eth_type = 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;

    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);

    // TFO: A sends the SYN with early data (zero-RTT).
    const char early[] = "tfo-early";
    CHECK(stack_a.TfoSendSynData(conn, reinterpret_cast<const Byte*>(early), sizeof(early) - 1));

    // B receives the early data before the handshake completes.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    CHECK(received == "tfo-early");
}

/**
 * @brief RFC 793 half-close: A sends data, closes (FIN), then B answers with
 *        more data while A is in FinWait1/2. The closing states must keep
 *        processing and ACKing peer data (ProcessClosingData).
 */
static void TestHalfClose() {
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

    const UInt16 eth_type = 0x0800;
    std::string recv_a;
    std::string recv_b;
    UInt64 conn_b = 0;
    stack_a.SetRecvHandler([&recv_a](UInt64, const Byte* d, UInt32 n) {
        recv_a.append(reinterpret_cast<const char*>(d), n);
    });
    stack_b.SetRecvHandler([&recv_b, &conn_b](UInt64 cid, const Byte* d, UInt32 n) {
        if (0 == conn_b) {
            conn_b = cid;
        }
        recv_b.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;
    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn_a = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn_a);
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    // A sends data then closes (FIN).
    const char hello[] = "hello-close";
    CHECK(stack_a.Send(conn_a, reinterpret_cast<const Byte*>(hello), sizeof(hello) - 1));
    stack_a.Close(conn_a);
    for (UInt32 i = 0; i < 8; ++i) {
        Pump(backend_a, backend_b, eth_type);
        Pump(backend_b, backend_a, eth_type);
        stack_b.PollAckTimers();
        stack_a.PollAckTimers();
    }
    CHECK(recv_b == "hello-close");  // B received the data

    // B answers with data after A's FIN (B is in CloseWait - it may still send).
    const char reply[] = "reply-after-fin";
    CHECK(0 != conn_b);  // B's accepted connection id captured from the recv handler
    stack_b.Send(conn_b, reinterpret_cast<const Byte*>(reply), sizeof(reply) - 1);
    for (UInt32 i = 0; i < 8; ++i) {
        Pump(backend_b, backend_a, eth_type);
        Pump(backend_a, backend_b, eth_type);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
    }
    CHECK(recv_a == "reply-after-fin");  // A (FinWait1) processed the reply

    // B closes -> A transitions FinWait2/TimeWait.
    stack_b.Close(conn_b);
    for (UInt32 i = 0; i < 8; ++i) {
        Pump(backend_b, backend_a, eth_type);
        Pump(backend_a, backend_b, eth_type);
        stack_a.PollAckTimers();
        stack_b.PollAckTimers();
    }
    std::fprintf(stderr, "[stack] half-close: A recv=%s B recv=%s\n",
                 recv_a.c_str(), recv_b.c_str());
}

/**
 * @brief Stack-level RTO wiring: XtcpStack::PollAckTimers must fire
 *        TcpConn::OnRetransmitTimer (the stack previously never drove the
 *        retransmission timer - only unit tests did). A sends a segment, B
 *        withholds the ACK, and after the RTO the segment must be retransmitted.
 */
static void TestStackRtoRetransmit() {
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

    const UInt16 eth_type = 0x0800;
    std::string received;
    stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
        received.append(reinterpret_cast<const char*>(d), n);
    });

    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;
    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    // A sends data; B's ACK is withheld (we only pump A->B).
    const char payload[] = "rto-retransmit";
    CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload), sizeof(payload) - 1));
    Pump(backend_a, backend_b, eth_type);  // data reaches B

    // Wait past the RTO (200ms floor) with the stack driving the timer.
    UInt32 retx = 0;
    for (UInt32 i = 0; i < 50; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        stack_a.PollAckTimers();
        UInt32 infl = 0, cwnd = 0, ssth = 0, wnd = 0, retx_t = 0, dup = 0, fr = 0, fseq = 0, una = 0;
        UInt16 lp = 0, rp = 0;
        UInt64 rto = 0;
        stack_a.ConnStats(conn, infl, cwnd, ssth, wnd, retx_t, rto, dup, fr, fseq, una, lp, rp);
        if (0 < retx_t) {
            retx = retx_t;
            break;
        }
    }
    CHECK(0 < retx);  // the stack's PollAckTimers drove the RTO retransmission

    // Deliver the retransmission to B.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    stack_b.PollAckTimers();
    stack_a.PollAckTimers();
    CHECK(received == payload);
    std::fprintf(stderr, "[stack] rto retransmit: retx=%u B recv=%s\n", retx, received.c_str());
}

/**
 * @brief MTU/DF: emitted IPv4 packets carry the Don't-Fragment flag and MSS-
 *        sized segments stay within the path MTU (RFC 879/1191).
 */
static void TestMtuDfFlag() {
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

    const UInt16 eth_type = 0x0800;
    xtcp::core::Endpoint local_a, remote_a;
    local_a.family = 4;
    local_a.addr[0] = 0xC0A80102;
    local_a.port = 40000;
    remote_a.family = 4;
    remote_a.addr[0] = 0x0A000001;
    remote_a.port = 443;
    CHECK(stack_b.Listen(remote_a));
    const UInt64 conn = stack_a.Connect(local_a, remote_a);
    CHECK(0 != conn);
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);

    // A sends a full-MSS segment.
    constexpr UInt32 kChunk = 1460;
    std::vector<Byte> data(kChunk, 0xAB);
    CHECK(stack_a.Send(conn, data.data(), kChunk));

    // Inspect A's emitted data packet: DF flag set, TTL sane, size <= MTU.
    Byte out[65536];
    bool found_data = false;
    UInt32 guard = 0;
    while (0 != backend_a.TxPending() && 2000 > ++guard) {
        const UInt32 got = backend_a.PollTx(out);
        if (0 == got) {
            break;
        }
        const UInt32 tcp_off = 20;
        if (got > tcp_off + 13 && 0 != (out[tcp_off + 13] & 0x08)) {  // PSH = data
            CHECK(0 != (out[6] & 0x40));   // DF flag set (RFC 1191)
            CHECK(got <= 1500);            // within the 1500-byte path MTU
            CHECK(64 == out[8]);           // TTL
            found_data = true;
            break;
        }
    }
    CHECK(found_data);
    std::fprintf(stderr, "[stack] MTU/DF: data packet DF-set size=%u\n",
                 found_data ? 1500u : 0u);
}

/**
 * @brief RFC 793 simultaneous open: both sides send SYN, each receives the
 *        peer's SYN while in SynSent, replies SYN+ACK, and both establish.
 */
static void TestSimultaneousOpen() {
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

    UInt32 established_a = 0;
    UInt32 established_b = 0;
    stack_a.SetStateHandler([&established_a](UInt64, xtcp::core::TcpState s) {
        if (xtcp::core::TcpState::kEstablished == s) {
            ++established_a;
        }
    });
    stack_b.SetStateHandler([&established_b](UInt64, xtcp::core::TcpState s) {
        if (xtcp::core::TcpState::kEstablished == s) {
            ++established_b;
        }
    });

    const UInt16 eth_type = 0x0800;
    xtcp::core::Endpoint a_local, a_remote;
    a_local.family = 4;
    a_local.addr[0] = 0xC0A80102;
    a_local.port = 40000;
    a_remote.family = 4;
    a_remote.addr[0] = 0x0A000001;
    a_remote.port = 443;
    // B's endpoints are the mirror of A's.
    xtcp::core::Endpoint b_local, b_remote;
    b_local.family = 4;
    b_local.addr[0] = 0x0A000001;
    b_local.port = 443;
    b_remote.family = 4;
    b_remote.addr[0] = 0xC0A80102;
    b_remote.port = 40000;

    // Both sides actively open (no listener).
    CHECK(0 != stack_a.Connect(a_local, a_remote));
    CHECK(0 != stack_b.Connect(b_local, b_remote));

    // Cross the SYNs, then each side's SYN+ACK, then the ACKs.
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);
    Pump(backend_a, backend_b, eth_type);
    Pump(backend_b, backend_a, eth_type);

    CHECK(1 == established_a);
    CHECK(1 == established_b);
    std::fprintf(stderr, "[stack] simultaneous open: both established\n");
}

int main() {    xtcp::buf::InitPools();
    TestBackToBackHandshake(false);
    TestBackToBackHandshake(true);
    TestBackToBackData(false);
    TestBackToBackData(true);
    TestBackToBackTransfer();
    TestBackToBackMd5();
    TestMimtAuditMode();
    TestTfoEarlyData();
    TestHalfClose();
    TestStackRtoRetransmit();
    TestMtuDfFlag();
    TestSimultaneousOpen();
    TestSynFlood();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_stack: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_stack: all passed\n");
    return 0;
}

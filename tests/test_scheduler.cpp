/**
 * @file test_scheduler.cpp
 * @brief Scheduler tests: placement, routing, MPSC queue, migration.
 */

#include <xtcp/core/scheduler.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

static xtcp::core::FlowKey MakeKey(UInt32 src, UInt16 sport) noexcept {
    xtcp::core::FlowKey key;
    key.addr_family = 4;
    key.saddr[0] = src;
    key.daddr[0] = 0x0A000001;
    key.sport = sport;
    key.dport = 443;
    return key;
}

static void TestPlacement() {
    xtcp::core::Scheduler sched(4, 1024, 64);
    // Seed shard 2 with flows so it becomes the busiest.
    for (UInt32 i = 0; i < 100; ++i) {
        CHECK(sched.GetShard(2).AddFlow(MakeKey(i, static_cast<UInt16>(1000 + i)), i + 1));
    }
    const UInt32 picked = sched.PlaceNewFlow();
    CHECK(2 != picked);  // least-loaded shard is NOT the seeded one
}

static void TestRouting() {
    xtcp::core::Scheduler sched(4, 1024, 64);
    const xtcp::core::FlowKey key = MakeKey(0xC0A80101, 50000);
    CHECK(0xFFFFFFFF == sched.Route(key));  // unknown
    sched.RegisterFlow(key, 3);
    CHECK(3 == sched.Route(key));
    sched.UnregisterFlow(key);
    CHECK(0xFFFFFFFF == sched.Route(key));
}

static void TestMpscQueue() {
    xtcp::core::MpscQueue q(4096);
    CHECK(q.IsEmpty());

    // Single producer, ordered pop.
    for (UInt32 i = 0; i < 100; ++i) {
        xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(64);
        CHECK(!p.IsEmpty());
        p.SetLen(4);
        std::memcpy(p.Data(), &i, 4);
        CHECK(q.Push(std::move(p)));
    }
    CHECK(100 == q.Size());
    for (UInt32 i = 0; i < 100; ++i) {
        xtcp::buf::BufRef p = q.Pop();
        CHECK(!p.IsEmpty());
        UInt32 v = 0;
        std::memcpy(&v, p.Data(), 4);
        CHECK(i == v);
    }
    CHECK(q.IsEmpty());
    CHECK(q.Pop().IsEmpty());
}

static void TestMpscMultiProducer() {
    xtcp::core::MpscQueue q(65536);
    std::thread t1([&]() {
        for (UInt32 i = 0; i < 500; ++i) {
            xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(16);
            p.SetLen(1);
            p.Data()[0] = 1;
            while (!q.Push(std::move(p))) {
                std::this_thread::yield();
            }
        }
    });
    std::thread t2([&]() {
        for (UInt32 i = 0; i < 500; ++i) {
            xtcp::buf::BufRef p = xtcp::buf::BufRef::Acquire(16);
            p.SetLen(1);
            p.Data()[0] = 2;
            while (!q.Push(std::move(p))) {
                std::this_thread::yield();
            }
        }
    });
    t1.join();
    t2.join();
    UInt32 total = 0;
    while (!q.IsEmpty()) {
        CHECK(!q.Pop().IsEmpty());
        ++total;
    }
    CHECK(1000 == total);
}

static void TestMigration() {
    xtcp::core::Scheduler sched(2, 1024, 64);
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    std::vector<xtcp::buf::BufRef> sink1, sink2;
    xtcp::core::TcpConn conn1(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                              [&sink1](xtcp::buf::BufRef&& p) { sink1.push_back(std::move(p)); });
    const Byte data[] = { 1, 2, 3, 4 };
    CHECK(conn1.SendData(data, 4, 1000));
    CHECK(105 == conn1.SndNxt());  // iss(100)+1 SYN + 4 bytes

    // A configured receive window must survive the migration: without rcv_wnd_
    // the restored connection drops RX data beyond the 65535 default while
    // its advertised window still promises the configured capacity.
    conn1.SetRcvBuf(262144);
    const xtcp::core::TcpConn::ConnCheckpoint ckpt = sched.Checkpoint(conn1);
    xtcp::core::TcpConn conn2(xtcp::core::TcpState::kClosed, local, remote, 100, 200,
                              [&sink2](xtcp::buf::BufRef&& p) { sink2.push_back(std::move(p)); });
    sched.Restore(conn2, ckpt);

    CHECK(xtcp::core::TcpState::kEstablished == conn2.State());
    CHECK(101 == conn2.SndUna());
    CHECK(105 == conn2.SndNxt());
    CHECK(201 == conn2.RcvNxt());
    CHECK(4 == conn2.InflightBytes());
    CHECK(262144 == conn2.Window());  // the configured receive window survived

    // The in-flight segment survived the migration: an RTO on the restored
    // connection retransmits it (the checkpoint must carry the retransmission
    // queue - without it the RTO path no-ops on an empty queue and the data
    // is unrecoverable). The deadline is wall-clock based, so use a distant
    // future timestamp.
    conn2.OnRetransmitTimer(static_cast<xtcp::core::TimePoint>(1ull << 62));
    CHECK(1 == sink2.size());
    CHECK(44 == sink2[0].Len());  // 20 (IPv4) + 20 (TCP) + 4 payload

    // Post-migration traffic continues: peer ACKs the outstanding data.
    // (Segment builder: sport=443 dport=40000 seq=201 ack=105 ACK only)
    Byte seg[20];
    std::memset(seg, 0, sizeof(seg));
    seg[0] = 0x01; seg[1] = 0xBB;
    seg[2] = 0x9C; seg[3] = 0x40;
    seg[8] = 0x00; seg[9] = 0x00; seg[10] = 0x00; seg[11] = 105;
    seg[12] = 0x50;
    seg[13] = 0x10;  // ACK
    seg[14] = 0xFF; seg[15] = 0xFF;
    conn2.OnSegment(seg, sizeof(seg), 4000);
    CHECK(105 == conn2.SndUna());
    CHECK(0 == conn2.InflightBytes());
}

int main() {
    std::fprintf(stderr, "S: initpools\n");
    xtcp::buf::InitPools();
    std::fprintf(stderr, "S: placement\n");
    TestPlacement();
    std::fprintf(stderr, "S: routing\n");
    TestRouting();
    std::fprintf(stderr, "S: mpsc\n");
    TestMpscQueue();
    std::fprintf(stderr, "S: mpsc-multi\n");
    TestMpscMultiProducer();
    std::fprintf(stderr, "S: migration\n");
    TestMigration();
    std::fprintf(stderr, "S: shutdown\n");
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_scheduler: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_scheduler: all passed\n");
    return 0;
}

/**
 * @file test_ooo_capacity.cpp
 * @brief : the out-of-order buffer capacity follows the configured
 *        receive window. With SetRcvBuf(262144), a 130 KB out-of-order burst
 *        must be fully buffered (no eviction at the legacy 64 KB mark), and
 *        the advertised window must reflect the FULL occupancy down to
 *        (262144 - 129940) >> 7 = 1032 - below the 1536 floor the legacy
 *        eviction cap would produce.
 */

#include <xtcp/core/tcp.h>

#include <cstdio>
#include <cstring>
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

typedef std::vector<xtcp::buf::BufRef> TxLog;

xtcp::core::TxSink MakeSink(TxLog& log) {
    return [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); };
}

std::vector<Byte> BuildSegment(UInt16 sport, UInt16 dport, UInt32 seq, UInt32 ack, UInt16 flags,
                               const Byte* payload = NULLPTR, UInt32 payload_len = 0) {
    std::vector<Byte> seg(20 + payload_len, 0);
    seg[0] = static_cast<Byte>(sport >> 8);
    seg[1] = static_cast<Byte>(sport & 0xFF);
    seg[2] = static_cast<Byte>(dport >> 8);
    seg[3] = static_cast<Byte>(dport & 0xFF);
    seg[4] = static_cast<Byte>(seq >> 24);
    seg[5] = static_cast<Byte>(seq >> 16);
    seg[6] = static_cast<Byte>(seq >> 8);
    seg[7] = static_cast<Byte>(seq & 0xFF);
    seg[8] = static_cast<Byte>(ack >> 24);
    seg[9] = static_cast<Byte>(ack >> 16);
    seg[10] = static_cast<Byte>(ack >> 8);
    seg[11] = static_cast<Byte>(ack & 0xFF);
    seg[12] = 0x50;
    seg[13] = static_cast<Byte>(((flags & xtcp::core::kFlagFin) ? 0x01 : 0x00) |
                                ((flags & xtcp::core::kFlagSyn) ? 0x02 : 0x00) |
                                ((flags & xtcp::core::kFlagRst) ? 0x04 : 0x00) |
                                ((flags & xtcp::core::kFlagPsh) ? 0x08 : 0x00) |
                                ((flags & xtcp::core::kFlagAck) ? 0x10 : 0x00));
    seg[14] = 0xFF;
    seg[15] = 0xFF;  // window 65535 (injected; irrelevant to the rx path)
    if (0 < payload_len) {
        std::memcpy(seg.data() + 20, payload, payload_len);
    }
    return seg;
}

}  // namespace

static void TestOooCapacityFollowsRcvBuf() {
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
    conn.SetRcvBuf(262144);
    conn.SetRcvWscale(7);

    UInt64 delivered = 0;
    conn.SetRecvHandler([&delivered](const Byte*, UInt32 len) {
        delivered += len;
        return true;
    });

    // 89 out-of-order segments (the first, in-order byte is the gap). All
    // must be buffered: 89 * 1460 = 129940 <= 262144 (the configured window,
    // NOT the legacy 64 KB cap). Each arrival emits a dup-ACK advertising the
    // free capacity (262144 - ooo_bytes_) >> 7.
    std::vector<Byte> payload(1460, 0x6E);
    bool saw_deep = false;
    bool saw_floor = false;
    for (UInt32 i = 1; i <= 89; ++i) {
        const UInt32 seq = irs + 1 + i * 1460;
        const std::vector<Byte> seg = BuildSegment(remote.port, local.port, seq, iss + 1,
                                                   xtcp::core::kFlagAck | xtcp::core::kFlagPsh,
                                                   payload.data(), 1460);
        log.clear();
        conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()));
        for (const auto& p : log) {
            const Byte* t = p.Data() + 20;
            const UInt16 win = (static_cast<UInt16>(t[14]) << 8) | t[15];
            if (1032 == win) {
                saw_deep = true;  // full 129940 B occupancy (new cap)
            } else if (1536 == win) {
                saw_floor = true;  // legacy 64 KB eviction floor
            }
        }
    }
    std::fprintf(stderr, "[ooo-cap] deep=%d legacy_floor=%d\n", saw_deep ? 1 : 0, saw_floor ? 1 : 0);
    CHECK(saw_deep);    // the full OOO occupancy is advertised (no 64KB cap)
    CHECK(!saw_floor);  // the legacy eviction floor must not appear

    // The gap fills: the in-order segment delivers everything (no eviction =
    // no retransmit needed), content-identical.
    const std::vector<Byte> gap = BuildSegment(remote.port, local.port, irs + 1, iss + 1,
                                               xtcp::core::kFlagAck | xtcp::core::kFlagPsh,
                                               payload.data(), 1460);
    conn.OnSegment(gap.data(), static_cast<UInt32>(gap.size()));
    std::fprintf(stderr, "[ooo-cap] delivered=%llu rcv_nxt_adv=%u\n",
                 (unsigned long long)delivered, conn.RcvNxt() - (irs + 1));
    CHECK(90 * 1460 == conn.RcvNxt() - (irs + 1));  // all 90 segments consumed
    CHECK(90 * 1460 == delivered);
}

static void TestDefaultKeepsLegacyCap() {
    // The default window (65535) keeps the legacy 64 KB behavior: the 46th
    // OOO segment is evicted (ooo_bytes_ stays <= 65536), so the advertised
    // window never drops below (65535 - 65536) -> 0... actually below the
    // floor the legacy cap imposes: the window shrinks to (65535-ooo)>>0.
    TxLog log;
    xtcp::core::Endpoint local;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40001;
    xtcp::core::Endpoint remote;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    const UInt32 iss = 100, irs = 200;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, iss, irs, MakeSink(log));
    // default window: 65535 (legacy)

    std::vector<Byte> payload(1460, 0x6E);
    UInt32 min_ooo_win = 65535;
    for (UInt32 i = 1; i <= 50; ++i) {
        const UInt32 seq = irs + 1 + i * 1460;
        const std::vector<Byte> seg = BuildSegment(remote.port, local.port, seq, iss + 1,
                                                   xtcp::core::kFlagAck | xtcp::core::kFlagPsh,
                                                   payload.data(), 1460);
        log.clear();
        conn.OnSegment(seg.data(), static_cast<UInt32>(seg.size()));
        for (const auto& p : log) {
            const Byte* t = p.Data() + 20;
            const UInt16 win = (static_cast<UInt16>(t[14]) << 8) | t[15];
            if (win < min_ooo_win) {
                min_ooo_win = win;
            }
        }
    }
    std::fprintf(stderr, "[ooo-cap] default min window=%u\n", min_ooo_win);
    // 44 * 1460 = 64240 <= 65535 buffered; the 45th+ are evicted, so the
    // window floor is (65535 - 64240) = 1295 (no wscale: raw window field).
    CHECK(1295 == min_ooo_win);
}

int main() {
    xtcp::buf::InitPools();
    TestOooCapacityFollowsRcvBuf();
    TestDefaultKeepsLegacyCap();
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "OOO_CAPACITY: FAILED (%d)\n" : "OOO_CAPACITY: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

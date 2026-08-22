/**
 * @file test_options.cpp
 * @brief Kernel-compat option layer tests (TCP_NODELAY semantics, params).
 */

#include <xtcp/options/options.h>

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

static void TestNodelay() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80102;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 443;

    std::vector<xtcp::buf::BufRef> log;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    // Default: off.
    CHECK(!conn.Nodelay());

    // Set ON via the kernel-compat option.
    Int32 enable = 1;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, &enable, sizeof(enable)));
    CHECK(conn.Nodelay());

    // TCP_MAXSEG: peer MSS is configurable via the option (Linux semantics:
    // a CEILING on the send MSS, applied immediately when it lowers).
    Int32 mss = 1200;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss, sizeof(mss)));
    CHECK(1200 == conn.PeerMss());
    CHECK(1200u == conn.UserMss());

    // A RAISE above the current peer MSS is stored as the ceiling but must
    // NOT inflate the send MSS beyond the peer's advertised value (RFC 1122
    // §4.2.2.6: never send larger than the peer announced).
    Int32 mss_raise = 9000;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss_raise, sizeof(mss_raise)));
    CHECK(1200 == conn.PeerMss());  // unchanged: the ceiling does not raise
    CHECK(9000u == conn.UserMss());
    // The handshake applying the peer's 1460 stays 1460 (ceiling 9000 does
    // not bind); a fresh lower ceiling then caps it.
    conn.SetPeerMss(1460);
    CHECK(1460 == conn.PeerMss());
    Int32 mss_low = 512;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss_low, sizeof(mss_low)));
    CHECK(512 == conn.PeerMss());  // immediate reduction
    conn.SetPeerMss(1460);  // handshake value capped by the 512 ceiling
    CHECK(512 == conn.PeerMss());

    // TCP_QUICKACK: accepted and applied.
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpQuickack, &enable, sizeof(enable)));

    // TCP_KEEPIDLE/INTVL/CNT: keepalive becomes active.
    Int32 idle = 10;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &idle, sizeof(idle)));
    CHECK(0 < conn.KeepaliveIdle());

    // Set OFF.
    Int32 disable = 0;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, &disable, sizeof(disable)));
    CHECK(!conn.Nodelay());

    // Get returns the current value.
    Int32 out = -1;
    UInt32 len = sizeof(out);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpNodelay, &out, len));
    CHECK(0 == out);
    CHECK(sizeof(Int32) == len);

    // Wrong value size is rejected.
    Int16 bad = 1;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, &bad, sizeof(bad)));
}

static void TestUnsupported() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 1;
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 2;
    remote.port = 443;
    std::vector<xtcp::buf::BufRef> log;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    // TCP_FASTOPEN is now wired (server offers the TFO cookie; the client
    // uses ConnectWithTfo) - the option is accepted. Other unsupported
    // options are still rejected cleanly.
    Int32 v = 1;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpFastopen, &v, sizeof(v)));
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpFastopenConnect, &v, sizeof(v)));
    UInt32 len = sizeof(v);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpFastopen, &v, len));
}

static void TestKeepaliveRoundtrip() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80103;
    local.port = 40001;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 444;
    std::vector<xtcp::buf::BufRef> log;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    // Keepalive tri-parameter round-trip (kernel-compat second semantics).
    Int32 idle = 12, intvl = 5, cnt = 3;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &idle, sizeof(idle)));
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &intvl, sizeof(intvl)));
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepcnt, &cnt, sizeof(cnt)));
    CHECK(12000000u == conn.KeepaliveIdle());
    CHECK(5000000u == conn.KeepaliveInterval());
    CHECK(3u == conn.KeepaliveCount());
    Int32 out = -1;
    UInt32 len = sizeof(out);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpKeepidle, &out, len));
    CHECK(12 == out);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpKeepintvl, &out, len));
    CHECK(5 == out);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpKeepcnt, &out, len));
    CHECK(3 == out);

    // Zero values are accepted by the option layer; the keepalive clamps
    // (0 -> default) live in TcpConn::SetKeepalive, verified below.
    Int32 micro = 0;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &micro, sizeof(micro)));
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &micro, sizeof(micro)));
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepcnt, &micro, sizeof(micro)));

    // RFC 1122 s4.2.3.6: values beyond the old UInt32-us cap (~4294 s,
    // below the 2-hour default!) are now representable (UInt64 us storage,
    // Linux parity: up to INT_MAX seconds). The pre-fix rejection pinned
    // the old UInt32 representation (audit M2).
    Int32 huge = 7200;  // 2 h: the RFC 1122 keepalive default
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &huge, sizeof(huge)));
    CHECK(7200ull * 1000000ull == conn.KeepaliveIdle());
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &huge, sizeof(huge)));
    CHECK(7200ull * 1000000ull == conn.KeepaliveInterval());
    Int32 max_s = 2147483647;  // INT_MAX seconds: still representable
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &max_s, sizeof(max_s)));
    CHECK(2147483647ull * 1000000ull == conn.KeepaliveIdle());
    // Round-trip: the GET must clamp at INT32_MAX, not wrap negative
    // (the UInt32->Int32 cast of the rounded 2147483648 would overflow).
    Int32 get_idle = 0;
    UInt32 glen = sizeof(get_idle);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpKeepidle, &get_idle, glen));
    CHECK(2147483647 == get_idle);  // CORE: clamped, not negative

    // Keepalive semantics: idle 0 = keepalive off, intvl 0 -> 1 s, cnt 0 -> 8.
    Int32 zero = 0;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &zero, sizeof(zero)));
    CHECK(0u == conn.KeepaliveIdle());
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &zero, sizeof(zero)));
    CHECK(1000000u == conn.KeepaliveInterval());
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpKeepcnt, &zero, sizeof(zero)));
    CHECK(8u == conn.KeepaliveCount());
}

static void TestSynCntEcnCork() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80104;
    local.port = 40002;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 445;
    std::vector<xtcp::buf::BufRef> log;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    // SYN retries round-trip; 0 is accepted (kernel-compat: 0 retries).
    Int32 retries = 4;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpSynCnt, &retries, sizeof(retries)));
    CHECK(4u == conn.SynRetries());
    Int32 out = -1;
    UInt32 len = sizeof(out);
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpSynCnt, &out, len));
    CHECK(4 == out);

    // ECN round-trip both ways.
    Int32 ecn = 1;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpEcn, &ecn, sizeof(ecn)));
    CHECK(conn.EcnRequested());
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpEcn, &out, len));
    CHECK(1 == out);
    ecn = 0;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpEcn, &ecn, sizeof(ecn)));
    CHECK(!conn.EcnRequested());
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpEcn, &out, len));
    CHECK(0 == out);

    // Cork: accepted for compatibility, no send aggregation in v1 - reads 0.
    Int32 cork = 1;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpCork, &cork, sizeof(cork)));
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpCork, &out, len));
    CHECK(0 == out);
    cork = 0;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpCork, &cork, sizeof(cork)));
    CHECK(xtcp::options::GetOption(conn, xtcp::options::kTcpCork, &out, len));
    CHECK(0 == out);
}

static void TestRejections() {
    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0xC0A80105;
    local.port = 40003;
    remote.family = 4;
    remote.addr[0] = 0x0A000001;
    remote.port = 446;
    std::vector<xtcp::buf::BufRef> log;
    xtcp::core::TcpConn conn(xtcp::core::TcpState::kEstablished, local, remote, 100, 200,
                             [&log](xtcp::buf::BufRef&& p) { log.push_back(std::move(p)); });

    // Negative values are rejected everywhere (never stored).
    Int32 neg = -1;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpKeepidle, &neg, sizeof(neg)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &neg, sizeof(neg)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpKeepcnt, &neg, sizeof(neg)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpSynCnt, &neg, sizeof(neg)));

    // MSS outside [1, 65535] is rejected (RFC 879).
    Int32 mss0 = 0;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss0, sizeof(mss0)));
    Int32 mss_neg = -100;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss_neg, sizeof(mss_neg)));
    Int32 mss_huge = 65536;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &mss_huge, sizeof(mss_huge)));

    // Wrong value sizes are rejected; stored state is untouched by failures.
    Int32 v = 1;
    CHECK(xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, &v, sizeof(v)));
    CHECK(conn.Nodelay());
    Int16 bad = 1;
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, &bad, sizeof(bad)));
    CHECK(conn.Nodelay());
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpKeepintvl, &bad, sizeof(bad)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpSynCnt, &bad, sizeof(bad)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpEcn, &bad, sizeof(bad)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpMaxseg, &bad, sizeof(bad)));
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpCork, &bad, sizeof(bad)));

    // NULL value / NULL out are rejected.
    CHECK(!xtcp::options::SetOption(conn, xtcp::options::kTcpNodelay, NULLPTR, sizeof(v)));
    Int32 out = -1;
    UInt32 len = sizeof(out);
    CHECK(!xtcp::options::GetOption(conn, xtcp::options::kTcpNodelay, NULLPTR, len));

    // GetOption with a short buffer is rejected without touching len.
    len = 1;
    CHECK(!xtcp::options::GetOption(conn, xtcp::options::kTcpNodelay, &out, len));
    CHECK(1 == len);
}

int main() {
    xtcp::buf::InitPools();
    TestNodelay();
    TestUnsupported();
    TestKeepaliveRoundtrip();
    TestSynCntEcnCork();
    TestRejections();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_options: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_options: all passed\n");
    return 0;
}

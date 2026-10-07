#include <xtcp/core/tcp.h>
#include <algorithm>
#include <cstdio>
#include <vector>

static int failures = 0;
#define CHECK(value) do { if (!(value)) { ++failures; std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #value); } } while (0)

static void Put32(Byte* p, UInt32 n) {
    p[0] = Byte(n >> 24); p[1] = Byte(n >> 16); p[2] = Byte(n >> 8); p[3] = Byte(n);
}

static void CheckOverlap(UInt32 irs, xtcp::core::TcpState state, int scenario) {
    using namespace xtcp::core;
    Endpoint local, remote;
    local.family = remote.family = 4;
    local.addr[0] = 0x0a000001; remote.addr[0] = 0x0a000002;
    local.port = 40002; remote.port = 443;
    constexpr UInt32 iss = 100;
    TcpConn conn(state, local, remote, iss, irs, [](xtcp::buf::BufRef&&) {});
    std::vector<Byte> bytes(64000), received;
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = Byte(i * 37 + i / 251);
    unsigned calls = 0;
    bool reject_tail = scenario == 6;
    conn.SetRecvHandler([&](const Byte* p, UInt32 n) {
        CHECK(n != 0);
        ++calls;
        if (reject_tail && calls == 2) return false;
        received.insert(received.end(), p, p + n);
        return true;
    });
    const auto inject = [&](UInt32 offset, UInt32 length, bool fin = false) {
        std::vector<Byte> packet(20 + length, 0);
        packet[0] = Byte(remote.port >> 8); packet[1] = Byte(remote.port);
        packet[2] = Byte(local.port >> 8); packet[3] = Byte(local.port);
        Put32(packet.data() + 4, irs + 1 + offset);
        Put32(packet.data() + 8, iss + 1);
        packet[12] = 0x50; packet[13] = Byte(kFlagAck | (fin ? kFlagFin : 0));
        packet[14] = packet[15] = 0xff;
        std::copy(bytes.begin() + offset, bytes.begin() + offset + length, packet.begin() + 20);
        conn.OnSegment(packet.data(), static_cast<UInt32>(packet.size()));
    };
    UInt32 expected = 0;
    bool expected_fin = false;
    switch (scenario) {
    case 0:
        inject(1000, 31000); inject(32000, 31207); inject(0, 64000);
        expected = 64000;
        break;
    case 1:
        inject(1000, 31000); inject(32000, 31207); inject(0, 2000);
        expected = 63207;
        break;
    case 2:
        inject(0, 500); inject(1000, 2000); inject(0, 2000);
        expected = 3000;
        break;
    case 3:
        inject(1000, 3000); inject(2000, 5000); inject(0, 2000);
        expected = 7000;
        break;
    case 4:
        inject(1000, 6000); inject(2000, 2000); inject(0, 2000);
        expected = 7000;
        break;
    case 5:
        inject(1000, 2000, true); inject(0, 3000);
        expected = 3000; expected_fin = true;
        break;
    case 6:
        inject(1000, 3000); inject(0, 2000);
        CHECK(conn.RcvNxt() == irs + 1 + 2000);
        CHECK(conn.ReceiveState().rcv_blocked);
        CHECK(conn.ReceiveState().ooo_bytes == 2000);
        reject_tail = false;
        CHECK(conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
        inject(2000, 2000);
        expected = 4000;
        break;
    case 7:
        // Every drain advances into the next range, without an exact key.
        // This exercises a deep overlap chain and both numeric map ranges.
        for (UInt32 i = 1; i <= 2048; ++i) inject(2 * i, 3);
        inject(0, 2);
        expected = 4099;
        break;
    }
    const auto snapshot = conn.ReceiveState();
    CHECK(snapshot.ooo_bytes == 0);
    CHECK(snapshot.advertised_window == 65535);
    CHECK(received.size() == expected);
    CHECK(received.size() <= bytes.size() && std::equal(received.begin(), received.end(), bytes.begin()));
    CHECK(conn.RcvNxt() == irs + 1 + expected + (expected_fin ? 1 : 0));
    if (expected_fin) {
        CHECK(conn.State() == (state == TcpState::kEstablished ? TcpState::kCloseWait : TcpState::kTimeWait));
    }
}

int main() {
    xtcp::buf::InitPools();
    for (UInt32 irs : {200U, 0xfffff000U}) {
        for (auto state : {xtcp::core::TcpState::kEstablished, xtcp::core::TcpState::kFinWait2}) {
            for (int scenario = 0; scenario < 8; ++scenario) CheckOverlap(irs, state, scenario);
        }
    }
    xtcp::buf::ShutdownPools();
    std::printf("OOO frontier: 32 scenarios, %d failures\n", failures);
    return failures ? 1 : 0;
}

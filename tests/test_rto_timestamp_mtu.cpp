/**
 * @file test_rto_timestamp_mtu.cpp
 * @brief Regression proof: a fresh-TS RTO retransmission must remain IPv4 MTU-sized.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            ++g_failures;                                                       \
        }                                                                       \
    } while (0)

struct IPv4Frame final {
    bool valid = false;
    bool timestamps = false;
    UInt32 wire_bytes = 0;
    UInt16 total_length = 0;
    Byte ihl = 0;
    Byte tcp_data_offset = 0;
    Byte tcp_flags = 0;
    UInt32 sequence = 0;
    UInt16 payload_length = 0;
};

UInt16 ReadBigEndian16(const Byte* bytes) {
    return static_cast<UInt16>((static_cast<UInt16>(bytes[0]) << 8) | bytes[1]);
}

UInt32 ReadBigEndian32(const Byte* bytes) {
    return (static_cast<UInt32>(bytes[0]) << 24) |
        (static_cast<UInt32>(bytes[1]) << 16) |
        (static_cast<UInt32>(bytes[2]) << 8) | bytes[3];
}

IPv4Frame ParseIPv4Frame(const Byte* bytes, UInt32 length) {
    IPv4Frame frame;
    frame.wire_bytes = length;
    if (bytes == NULLPTR || length < 40 || (bytes[0] >> 4) != 4) {
        return frame;
    }

    const UInt32 ihl = static_cast<UInt32>(bytes[0] & 0x0f) * 4;
    const UInt16 total_length = ReadBigEndian16(bytes + 2);
    if (ihl < 20 || total_length < ihl + 20 || total_length > length) {
        return frame;
    }
    const Byte* tcp = bytes + ihl;
    const UInt32 tcp_data_offset = static_cast<UInt32>(tcp[12] >> 4) * 4;
    if (tcp_data_offset < 20 || ihl + tcp_data_offset > total_length) {
        return frame;
    }

    frame.valid = true;
    frame.total_length = total_length;
    frame.ihl = static_cast<Byte>(ihl);
    frame.tcp_data_offset = static_cast<Byte>(tcp_data_offset);
    frame.tcp_flags = tcp[13];
    frame.sequence = ReadBigEndian32(tcp + 4);
    frame.payload_length = static_cast<UInt16>(total_length - ihl - tcp_data_offset);
    for (UInt32 option = 20; option < tcp_data_offset;) {
        const Byte kind = tcp[option];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            ++option;
            continue;
        }
        if (option + 1 >= tcp_data_offset) {
            break;
        }
        const UInt32 option_length = tcp[option + 1];
        if (option_length < 2 || option + option_length > tcp_data_offset) {
            break;
        }
        if (kind == 8 && option_length == 10) {
            frame.timestamps = true;
        }
        option += option_length;
    }
    return frame;
}

bool IsData(const IPv4Frame& frame) {
    return frame.valid && frame.payload_length != 0 &&
        (frame.tcp_flags & xtcp::core::kFlagAck) != 0;
}

void Wire(xtcp::ndi::ManualBackend& backend_a, xtcp::ndi::ManualBackend& backend_b,
    xtcp::XtcpStack& stack_a, xtcp::XtcpStack& stack_b) {
    backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& packet) {
        xtcp::buf::BufRef copy = xtcp::buf::BufRef::Acquire(packet.len);
        if (copy.IsEmpty()) {
            return;
        }
        std::memcpy(copy.Data(), packet.data, packet.len);
        copy.SetLen(packet.len);
        stack_a.OnPacket(std::move(copy));
    });
    backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& packet) {
        xtcp::buf::BufRef copy = xtcp::buf::BufRef::Acquire(packet.len);
        if (copy.IsEmpty()) {
            return;
        }
        std::memcpy(copy.Data(), packet.data, packet.len);
        copy.SetLen(packet.len);
        stack_b.OnPacket(std::move(copy));
    });
}

void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to,
    bool drop_first_data, bool& first_data_dropped, IPv4Frame& first_data,
    bool& retransmission_captured, IPv4Frame& retransmission,
    UInt32& timestamped_syns, std::vector<IPv4Frame>& outputs) {
    Byte packet[65536];
    while (from.TxPending() != 0) {
        const UInt32 length = from.PollTx(packet);
        if (length == 0) {
            break;
        }
        const IPv4Frame frame = ParseIPv4Frame(packet, length);
        if (frame.valid) {
            outputs.push_back(frame);
            if ((frame.tcp_flags & xtcp::core::kFlagSyn) != 0 && frame.timestamps) {
                ++timestamped_syns;
            }
        }
        if (drop_first_data && !first_data_dropped && IsData(frame)) {
            first_data_dropped = true;
            first_data = frame;
            continue;
        }
        if (first_data_dropped && !retransmission_captured && IsData(frame) &&
            frame.sequence == first_data.sequence) {
            retransmission_captured = true;
            retransmission = frame;
        }
        to.Inject(packet, length, 0x0800);
    }
}

} // namespace

int main() {
    xtcp::buf::InitPools();
    {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        stack_a.SetDefaultCongestionControl("");
        stack_b.SetDefaultCongestionControl("");
        Wire(backend_a, backend_b, stack_a, stack_b);
        std::vector<Byte> received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* data, UInt32 len) {
            received.insert(received.end(), data, data + len);
            return true;
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0xC0A80102;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000001;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));

        bool first_data_dropped = false;
        bool retransmission_captured = false;
        IPv4Frame first_data;
        IPv4Frame retransmission;
        UInt32 timestamped_syns = 0;
        std::vector<IPv4Frame> outputs;
        const auto pump_a_to_b = [&](bool drop_first_data) {
            Pump(backend_a, backend_b, drop_first_data, first_data_dropped, first_data,
                retransmission_captured, retransmission, timestamped_syns, outputs);
        };
        const auto pump_b_to_a = [&]() {
            Pump(backend_b, backend_a, false, first_data_dropped, first_data,
                retransmission_captured, retransmission, timestamped_syns, outputs);
        };

        const UInt64 connection = stack_a.Connect(local, remote);
        CHECK(connection != 0);
        for (UInt32 i = 0; i < 100 &&
             stack_a.ConnectionState(connection) != xtcp::core::TcpState::kEstablished; ++i) {
            pump_a_to_b(false);
            pump_b_to_a();
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
        CHECK(stack_a.ConnectionState(connection) == xtcp::core::TcpState::kEstablished);
        CHECK(timestamped_syns >= 2);  // Normal connect negotiated RFC 7323 timestamps.

        std::vector<Byte> payload(1460, 0x5a);
        CHECK(stack_a.Send(connection, payload.data(), static_cast<UInt32>(payload.size())));
        // The send is buffered because 1460 exceeds the timestamp-safe data
        // cap. Drive the flush, then deliberately lose its full first piece.
        stack_a.PollAckTimers();
        pump_a_to_b(true);
        pump_b_to_a();
        CHECK(first_data_dropped);
        CHECK(first_data.payload_length == 1448);
        CHECK(first_data.total_length == 1488);

        for (UInt32 i = 0; i < 3000 && !retransmission_captured; ++i) {
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            pump_a_to_b(false);
            pump_b_to_a();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(retransmission_captured);
        CHECK(retransmission.timestamps);
        CHECK(retransmission.payload_length == first_data.payload_length);
        CHECK(retransmission.total_length == 1500);
        CHECK(retransmission.wire_bytes == 1500);
        std::fprintf(stderr,
            "[rto-timestamp-mtu] fresh-ts retransmission: wire=%u ipv4_total=%u ihl=%u tcp=%u payload=%u\n",
            retransmission.wire_bytes, retransmission.total_length, retransmission.ihl,
            retransmission.tcp_data_offset, retransmission.payload_length);

        bool saw_tail = false;
        for (const IPv4Frame& frame : outputs) {
            CHECK(frame.wire_bytes <= 1500);
            CHECK(frame.total_length <= 1500);
            if (IsData(frame) && frame.sequence == first_data.sequence + 1448 &&
                frame.payload_length == 12) {
                saw_tail = true;
            }
        }
        CHECK(saw_tail);
        CHECK(received.size() == payload.size());
        CHECK(0 == std::memcmp(received.data(), payload.data(), payload.size()));
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "RTO_TIMESTAMP_MTU: FAILED (%d)\n"
                                    : "RTO_TIMESTAMP_MTU: ALL PASSED\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

/**
 * @file test_pcap.cpp
 * @brief pcap reader tests: container parsing, record extraction, replay
 *        into a live stack (no crash), malformed input rejection.
 */

#include <xtcp/pcap/pcap_reader.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

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

namespace {
    inline void Store32(Byte* p, UInt32 v) noexcept {
        p[0] = static_cast<Byte>(v >> 24);
        p[1] = static_cast<Byte>(v >> 16);
        p[2] = static_cast<Byte>(v >> 8);
        p[3] = static_cast<Byte>(v & 0xFF);
    }

    inline void Store32LE(Byte* p, UInt32 v) noexcept {
        p[0] = static_cast<Byte>(v & 0xFF);
        p[1] = static_cast<Byte>(v >> 8);
        p[2] = static_cast<Byte>(v >> 16);
        p[3] = static_cast<Byte>(v >> 24);
    }

    inline void StoreField(bool store_le, Byte* p, UInt32 v) noexcept {
        if (store_le) Store32LE(p, v); else Store32(p, v);
    }

    /**
     * @brief Builds a pcap file with two raw-IP records (network=101).
     */
    std::vector<Byte> BuildPcap(UInt32 frame_len) noexcept {
        std::vector<Byte> pcap;
        // Global header.
        Byte gh[24];
        std::memset(gh, 0, sizeof(gh));
        Store32(gh, 0xA1B2C3D4);  // microsecond magic
        gh[4] = 0x00; gh[5] = 0x02; gh[6] = 0x00; gh[7] = 0x04;  // version 2.4
        Store32(gh + 20, 101);       // LINKTYPE_RAW (raw IP)
        pcap.insert(pcap.end(), gh, gh + 24);

        // Two records.
        for (UInt32 r = 0; r < 2; ++r) {
            Byte rh[16];
            std::memset(rh, 0, sizeof(rh));
            Store32(rh, 1000 + r);       // ts_sec
            Store32(rh + 4, r * 1000);   // ts_frac
            Store32(rh + 8, frame_len);  // incl_len
            Store32(rh + 12, frame_len); // orig_len
            pcap.insert(pcap.end(), rh, rh + 16);
            pcap.insert(pcap.end(), frame_len, static_cast<Byte>(0xAA + r));
        }
        return pcap;
    }

    /**
     * @brief Same container as BuildPcap but the global magic and every
     *        record field may be stored little-endian (store_le == true,
     *        the parser's BSwap32 path) or big-endian.
     */
    std::vector<Byte> BuildPcapOrdered(UInt32 magic, bool store_le, UInt32 frame_len) noexcept {
        std::vector<Byte> pcap;
        Byte gh[24];
        std::memset(gh, 0, sizeof(gh));
        StoreField(store_le, gh, magic);
        // Version 2.4 (major at offset 4, minor at offset 6), written in the
        // FILE's byte order - the parser's version gate (major == 2) reads
        // it through the same swap-aware Field() as every other field.
        gh[4] = store_le ? 0x02 : 0x00;
        gh[5] = store_le ? 0x00 : 0x02;
        gh[6] = store_le ? 0x04 : 0x00;
        gh[7] = store_le ? 0x00 : 0x04;
        StoreField(store_le, gh + 20, 101);
        pcap.insert(pcap.end(), gh, gh + 24);
        for (UInt32 r = 0; r < 2; ++r) {
            Byte rh[16];
            std::memset(rh, 0, sizeof(rh));
            StoreField(store_le, rh, 1000 + r);       // ts_sec
            StoreField(store_le, rh + 4, r * 1000);   // ts_frac
            StoreField(store_le, rh + 8, frame_len);  // incl_len
            StoreField(store_le, rh + 12, frame_len); // orig_len
            pcap.insert(pcap.end(), rh, rh + 16);
            pcap.insert(pcap.end(), frame_len, static_cast<Byte>(0xAA + r));
        }
        return pcap;
    }

    // RFC 1071 one's-complement checksum (network byte order).
    UInt16 NetChecksum(const Byte* p, UInt32 len) noexcept {
        UInt32 sum = 0;
        for (UInt32 i = 0; i + 1 < len; i += 2) {
            sum += (static_cast<UInt32>(p[i]) << 8) | p[i + 1];
        }
        if (len & 1) {
            sum += static_cast<UInt32>(p[len - 1]) << 8;
        }
        while (0 != (sum >> 16)) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<UInt16>(~sum & 0xFFFF);
    }

    /**
     * @brief Builds a real IPv4/TCP packet (no options) with correct IP and
     *        TCP checksums. src 10.0.0.1, dst 10.0.0.2.
     */
    UInt32 BuildTcpPacket(Byte* out, UInt16 sport, UInt16 dport,
                          UInt32 seq, UInt32 ack, Byte flags, UInt16 win) noexcept {
        const UInt32 tcp_len = 20;
        const UInt32 total = 20 + tcp_len;
        UInt32 off = 0;
        out[off++] = 0x45; out[off++] = 0x00;
        out[off++] = static_cast<Byte>(total >> 8); out[off++] = static_cast<Byte>(total & 0xFF);
        out[off++] = 0x00; out[off++] = 0x00;
        out[off++] = 0x40; out[off++] = 0x00;
        out[off++] = 64;   out[off++] = 6;
        out[off++] = 0x00; out[off++] = 0x00;  // IP checksum (filled below)
        out[off++] = 0x0A; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x01;  // src 10.0.0.1
        out[off++] = 0x0A; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x02;  // dst 10.0.0.2
        out[off++] = static_cast<Byte>(sport >> 8); out[off++] = static_cast<Byte>(sport & 0xFF);
        out[off++] = static_cast<Byte>(dport >> 8); out[off++] = static_cast<Byte>(dport & 0xFF);
        out[off++] = static_cast<Byte>(seq >> 24); out[off++] = static_cast<Byte>(seq >> 16);
        out[off++] = static_cast<Byte>(seq >> 8);  out[off++] = static_cast<Byte>(seq & 0xFF);
        out[off++] = static_cast<Byte>(ack >> 24); out[off++] = static_cast<Byte>(ack >> 16);
        out[off++] = static_cast<Byte>(ack >> 8);  out[off++] = static_cast<Byte>(ack & 0xFF);
        out[off++] = 0x50; out[off++] = flags;  // hlen 5 (20B), flags
        out[off++] = static_cast<Byte>(win >> 8); out[off++] = static_cast<Byte>(win & 0xFF);
        out[off++] = 0x00; out[off++] = 0x00;   // TCP checksum (filled below)
        out[off++] = 0x00; out[off++] = 0x00;   // urgent
        const UInt16 ip_sum = static_cast<UInt16>(NetChecksum(out, 20));
        out[10] = static_cast<Byte>(ip_sum >> 8); out[11] = static_cast<Byte>(ip_sum & 0xFF);
        Byte pseudo[32];
        std::memset(pseudo, 0, sizeof(pseudo));
        std::memcpy(pseudo, out + 12, 8);   // src + dst IP
        pseudo[8] = 0; pseudo[9] = 6;       // TCP
        pseudo[10] = 0; pseudo[11] = static_cast<Byte>(tcp_len);
        std::memcpy(pseudo + 12, out + 20, tcp_len);
        const UInt16 tcp_sum = static_cast<UInt16>(NetChecksum(pseudo, 12 + tcp_len));
        out[36] = static_cast<Byte>(tcp_sum >> 8); out[37] = static_cast<Byte>(tcp_sum & 0xFF);
        return off;
    }
}

static void TestParse() {
    const std::vector<Byte> pcap = BuildPcap(40);
    std::vector<xtcp::pcap::Record> records;
    CHECK(xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
    CHECK(2 == records.size());
    CHECK(101 == records[0].network);
    CHECK(40 == records[0].data.size());
    CHECK(0xAA == records[0].data[0]);
    CHECK(0xAB == records[1].data[0]);
    CHECK(1000 == records[0].ts_sec);
    CHECK(1001 == records[1].ts_sec);
}

static void TestMalformed() {
    // Too short.
    Byte tiny[4] = { 0, 0, 0, 0 };
    std::vector<xtcp::pcap::Record> records;
    CHECK(!xtcp::pcap::ParsePcap(tiny, sizeof(tiny), records));

    // Wrong magic.
    std::vector<Byte> bad = BuildPcap(16);
    bad[0] = 0xDE;
    CHECK(!xtcp::pcap::ParsePcap(bad.data(), static_cast<UInt32>(bad.size()), records));

    // Truncated record body.
    std::vector<Byte> trunc = BuildPcap(64);
    trunc.resize(trunc.size() - 10);
    CHECK(!xtcp::pcap::ParsePcap(trunc.data(), static_cast<UInt32>(trunc.size()), records));
}

static void TestReplayNoCrash() {
    // Replay pcap records into a live stack: must never crash.
    const std::vector<Byte> pcap = BuildPcap(40);
    std::vector<xtcp::pcap::Record> records;
    CHECK(xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));

    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(p.len);
        if (!b.IsEmpty()) {
            std::memcpy(b.Data(), p.data, p.len);
            b.SetLen(p.len);
            stack.OnPacket(std::move(b));
        }
    });
    for (const auto& rec : records) {
        backend.Inject(rec.data.data(), static_cast<UInt32>(rec.data.size()), 0x0800);
    }
    Byte out[65536];
    while (0 != backend.TxPending()) {
        if (0 == backend.PollTx(out)) {
            break;
        }
    }
}

static void TestLittleEndianMagic() {
    // 0xA1B2C3D4 stored little-endian: on-disk bytes D4 C3 B2 A1 drive the
    // parser's BSwap32 path. Parsed records must be identical to the
    // big-endian file.
    const std::vector<Byte> pcap = BuildPcapOrdered(0xA1B2C3D4, true, 40);
    std::vector<xtcp::pcap::Record> records;
    CHECK(xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
    CHECK(2 == records.size());
    CHECK(101 == records[0].network);
    CHECK(40 == records[0].data.size());
    CHECK(0xAA == records[0].data[0]);
    CHECK(0xAB == records[1].data[0]);
    CHECK(1000 == records[0].ts_sec);
    CHECK(0 == records[0].ts_frac);
    CHECK(1001 == records[1].ts_sec);
    CHECK(1000 == records[1].ts_frac);
    CHECK(!records[0].nanos);
}

static void TestNanosecondMagic() {
    // Big-endian nanosecond magic 0xA1B23C4D: nanos flag must be set and
    // ts_frac parsed at native resolution.
    const std::vector<Byte> pcap = BuildPcapOrdered(0xA1B23C4D, false, 40);
    std::vector<xtcp::pcap::Record> records;
    CHECK(xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
    CHECK(2 == records.size());
    CHECK(records[0].nanos);
    CHECK(records[1].nanos);
    CHECK(1000 == records[0].ts_sec);
    CHECK(1000 == records[1].ts_frac);
    CHECK(1001 == records[1].ts_sec);
    CHECK(101 == records[0].network);

    // Little-endian nanosecond magic: the on-disk bytes are 4D 3C 2B A1
    // (the byte-reversed big-endian nanosecond magic 0xA1B23C4D). Storing
    // 0xA12B3C4D little-endian yields exactly those bytes.
    const std::vector<Byte> le = BuildPcapOrdered(0xA12B3C4D, true, 40);
    std::vector<xtcp::pcap::Record> records_le;
    CHECK(xtcp::pcap::ParsePcap(le.data(), static_cast<UInt32>(le.size()), records_le));
    if (2 != records_le.size()) {
        return;  // parse failed: avoid OOB on the empty vector below
    }
    CHECK(records_le[0].nanos);
    CHECK(1000 == records_le[0].ts_sec);
    CHECK(1000 == records_le[1].ts_frac);
}

static void TestOrigLenLessThanInclLen() {
    // Malformed: orig_len < incl_len (captured more than the original) must
    // be rejected.
    std::vector<Byte> pcap = BuildPcapOrdered(0xA1B2C3D4, false, 40);
    Store32(pcap.data() + 24 + 12, 8);  // record 0 orig_len 40 -> 8 < incl 40
    std::vector<xtcp::pcap::Record> records;
    CHECK(!xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
}

static void TestTrailingPartialHeader() {
    // A 1-15 byte tail after complete records is a partial record header and
    // must be rejected for every possible residual size.
    for (UInt32 tail = 1; tail < 16; ++tail) {
        std::vector<Byte> pcap = BuildPcapOrdered(0xA1B2C3D4, false, 8);
        pcap.resize(pcap.size() + tail);
        std::vector<xtcp::pcap::Record> records;
        CHECK(!xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
    }
}

static void TestRecordCountCap() {
    // The reader's OOM guard caps records at kMaxRecordCount = 1,000,000.
    // Exactly the cap parses; one beyond is rejected.
    constexpr UInt32 kCap = 1000000;
    const UInt32 cap_bytes = 24 + kCap * 16;
    std::vector<Byte> at_cap(cap_bytes, 0);
    Store32(at_cap.data(), 0xA1B2C3D4);
    at_cap[4] = 0x00; at_cap[5] = 0x02;  // version 2 (major) at offset 4
    Store32(at_cap.data() + 20, 101);
    std::vector<xtcp::pcap::Record> records;
    records.reserve(kCap);
    CHECK(xtcp::pcap::ParsePcap(at_cap.data(), static_cast<UInt32>(at_cap.size()), records));
    CHECK(kCap == records.size());

    std::vector<xtcp::pcap::Record> overflow;
    std::vector<Byte> over(cap_bytes + 16, 0);  // one extra zero-length record
    std::memcpy(over.data(), at_cap.data(), cap_bytes);
    CHECK(!xtcp::pcap::ParsePcap(over.data(), static_cast<UInt32>(over.size()), overflow));
}

static void TestReplaySynHandshake() {
    // A real IPv4/TCP SYN (correct checksums) wrapped in a pcap record and
    // replayed into a live stack with a listener must complete a full
    // handshake: SYN -> SYN+ACK -> ACK, leaving a connection in the stack.
    const UInt32 kSynSeq = 0x10000000;
    Byte pkt[128];
    const UInt32 syn_len = BuildTcpPacket(pkt, 40001, 9090, kSynSeq, 0, 0x02, 0x1000);

    std::vector<Byte> pcap;
    {
        Byte gh[24];
        std::memset(gh, 0, sizeof(gh));
        Store32(gh, 0xA1B2C3D4);
        gh[4] = 0x00; gh[5] = 0x02; gh[6] = 0x00; gh[7] = 0x04;
        Store32(gh + 20, 101);
        pcap.insert(pcap.end(), gh, gh + 24);
        Byte rh[16];
        std::memset(rh, 0, sizeof(rh));
        Store32(rh, 1000);
        Store32(rh + 8, syn_len);
        Store32(rh + 12, syn_len);
        pcap.insert(pcap.end(), rh, rh + 16);
        pcap.insert(pcap.end(), pkt, pkt + syn_len);
    }
    std::vector<xtcp::pcap::Record> records;
    CHECK(xtcp::pcap::ParsePcap(pcap.data(), static_cast<UInt32>(pcap.size()), records));
    CHECK(1 == records.size());

    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef b = xtcp::buf::BufRef::Acquire(p.len);
        if (!b.IsEmpty()) {
            std::memcpy(b.Data(), p.data, p.len);
            b.SetLen(p.len);
            stack.OnPacket(std::move(b));
        }
    });
    xtcp::core::Endpoint local;
    local.addr[0] = 0x0A000002;  // 10.0.0.2
    local.port = 9090;
    CHECK(stack.Listen(local));

    backend.Inject(records[0].data.data(), static_cast<UInt32>(records[0].data.size()), 0x0800);

    // Drain: expect exactly one SYN+ACK reply; capture the server ISN.
    Byte out[65536];
    UInt32 synack_seq = 0;
    bool got_synack = false;
    while (0 != backend.TxPending()) {
        const UInt32 got = backend.PollTx(out);
        if (got < 40) {
            continue;
        }
        const Byte flags = out[33];
        if (0 != (flags & 0x02) && 0 != (flags & 0x10)) {  // SYN+ACK
            got_synack = true;
            synack_seq = (static_cast<UInt32>(out[24]) << 24) |
                         (static_cast<UInt32>(out[25]) << 16) |
                         (static_cast<UInt32>(out[26]) << 8)  |
                         static_cast<UInt32>(out[27]);
        }
    }
    CHECK(got_synack);

    // Final ACK completes the handshake.
    const UInt32 ack_len = BuildTcpPacket(pkt, 40001, 9090, kSynSeq + 1, synack_seq + 1, 0x10, 0x1000);
    backend.Inject(pkt, ack_len, 0x0800);
    while (0 != backend.TxPending()) {
        backend.PollTx(out);
    }
    CHECK(1 == stack.ConnectionCount());
}

int main() {
    xtcp::buf::InitPools();
    TestParse();
    TestMalformed();
    TestReplayNoCrash();
    TestLittleEndianMagic();
    TestNanosecondMagic();
    TestOrigLenLessThanInclLen();
    TestTrailingPartialHeader();
    TestRecordCountCap();
    TestReplaySynHandshake();
    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_pcap: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_pcap: all passed\n");
    return 0;
}

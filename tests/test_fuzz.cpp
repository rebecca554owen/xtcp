/**
 * @file test_fuzz.cpp
 * @brief Deterministic packet fuzzing: malformed IPv4/IPv6+TCP segments are
 *        injected into a live XtcpStack; the stack must never crash and
 *        never leave corrupted state. Zero tolerance (G4).
 */

#define _CRT_SECURE_NO_WARNINGS

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    /**
     * @brief Deterministic PRNG (xorshift64).
     */
    struct Prng {
        UInt64 s;
        explicit Prng(UInt64 seed) noexcept : s(seed) {}
        UInt32 Next() noexcept {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            return static_cast<UInt32>(s);
        }
    };

    /**
     * @brief Builds a random malformed IPv4+TCP packet.
     */
    void BuildMalformedV4(Prng& rng, std::vector<Byte>& out) noexcept {
        out.clear();
        // Random total length: often truncated, sometimes huge.
        const UInt32 len = rng.Next() % 96;
        out.resize(len, 0);
        if (len < 20) {
            return;  // truncated IP header
        }
        Byte* p = out.data();
        p[0] = 0x40 | (rng.Next() & 0x0F);           // version/ihl (may be wrong)
        const UInt32 ihl = (p[0] & 0x0F) * 4;
        if (ihl > len) {
            return;  // header beyond packet -> rejected by parser
        }
        p[2] = static_cast<Byte>(len >> 8);
        p[3] = static_cast<Byte>(len & 0xFF);        // total length (may mismatch)
        p[8] = static_cast<Byte>(rng.Next());
        p[9] = (0 == (rng.Next() % 3)) ? 6 : static_cast<Byte>(rng.Next() & 0xFF);  // proto
        // src/dst random.
        for (UInt32 i = 12; i < 20 && i < len; ++i) {
            p[i] = static_cast<Byte>(rng.Next());
        }
        if (len < 40 || 6 != p[9]) {
            return;
        }
        // TCP header at 20..39 with random fields.
        Byte* t = p + 20;
        const UInt32 tcp_len = (len < 40) ? 0 : (len - 20);
        if (tcp_len < 20) {
            return;
        }
        t[0] = static_cast<Byte>(rng.Next());
        t[1] = static_cast<Byte>(rng.Next());
        t[2] = static_cast<Byte>(rng.Next());
        t[3] = static_cast<Byte>(rng.Next());
        for (UInt32 i = 4; i < 12; ++i) {
            t[i] = static_cast<Byte>(rng.Next());
        }
        // data offset: 0..15, often wrong vs tcp_len.
        const Byte off_field = static_cast<Byte>(rng.Next() & 0x0F);
        t[12] = static_cast<Byte>(off_field << 4);
        t[13] = static_cast<Byte>(rng.Next());       // random flags (may be SYN+FIN etc.)
        t[14] = static_cast<Byte>(rng.Next());       // window (random, may be tiny)
        t[15] = static_cast<Byte>(rng.Next());
        // Random option bytes to exercise ParseTcpOpts malformed handling.
        if (off_field >= 5 && tcp_len > 20) {
            const UInt32 opt_area = (static_cast<UInt32>(off_field) * 4 > tcp_len)
                                        ? (tcp_len - 20)
                                        : (static_cast<UInt32>(off_field) * 4 - 20);
            for (UInt32 i = 0; i < opt_area; ++i) {
                t[20 + i] = static_cast<Byte>(rng.Next());
            }
        }
    }

    /**
     * @brief Builds a random malformed IPv6+TCP packet.
     */
    void BuildMalformedV6(Prng& rng, std::vector<Byte>& out) noexcept {
        out.clear();
        const UInt32 len = rng.Next() % 96;
        out.resize(len, 0);
        if (len < 40) {
            return;
        }
        Byte* p = out.data();
        p[0] = 0x60 | (rng.Next() & 0x0F);
        const UInt16 payload_len = static_cast<UInt16>(rng.Next() & 0xFFFF);
        p[4] = static_cast<Byte>(payload_len >> 8);
        p[5] = static_cast<Byte>(payload_len & 0xFF);
        p[6] = static_cast<Byte>(rng.Next());  // next header (random, incl. ext)
        p[7] = static_cast<Byte>(rng.Next());
        for (UInt32 i = 8; i < 40 && i < len; ++i) {
            p[i] = static_cast<Byte>(rng.Next());
        }
        if (len < 60) {
            return;
        }
        Byte* t = p + 40;
        for (UInt32 i = 0; i < 20; ++i) {
            t[i] = static_cast<Byte>(rng.Next());
        }
        t[12] = static_cast<Byte>((rng.Next() & 0x0F) << 4);
        t[13] = static_cast<Byte>(rng.Next());
    }

    /**
     * @brief Builds a targeted hostile segment (specific malformations).
     */
    void BuildHostile(Prng& rng, std::vector<Byte>& out) noexcept {
        out.clear();
        const UInt32 kind = rng.Next() % 6;
        // A minimal valid IPv4+TCP frame then corruption.
        out.assign(40, 0);
        Byte* p = out.data();
        p[0] = 0x45;
        p[2] = 0; p[3] = 40;
        p[8] = 64;
        p[9] = 6;
        p[12] = 0xC0; p[13] = 0xA8; p[14] = 0x01; p[15] = 0x02;
        p[16] = 0x0A; p[17] = 0x00; p[18] = 0x00; p[19] = 0x01;
        Byte* t = p + 20;
        t[0] = 0x00; t[1] = 0x50;   // sport 80
        t[2] = 0x01; t[3] = 0xBB;   // dport 443
        t[12] = 0x50;
        t[13] = 0x02;               // SYN
        t[14] = 0xFF; t[15] = 0xFF;
        switch (kind) {
        case 0:  // data offset claims options beyond packet
            t[12] = 0xF0;
            break;
        case 1:  // huge seq with SYN+FIN+RST
            for (UInt32 i = 4; i < 12; ++i) t[i] = 0xFF;
            t[13] = 0x07;
            break;
        case 2:  // zero window
            t[14] = 0; t[15] = 0;
            break;
        case 3:  // truncated TCP header (len 20 but data offset 12)
            t[12] = 0xC0;
            break;
        case 4: {  // malformed option run (WSOPT len 3 truncated)
            out.assign(44, 0);
            out[0] = 0x45; out[2] = 0; out[3] = 44;
            out[8] = 64; out[9] = 6;
            out[12] = 0xC0; out[13] = 0xA8; out[14] = 0x01; out[15] = 0x02;
            out[16] = 0x0A; out[17] = 0x00; out[18] = 0x00; out[19] = 0x01;
            Byte* t2 = out.data() + 20;
            t2[0] = 0; t2[1] = 80;
            t2[2] = 1; t2[3] = 0xBB;
            t2[12] = 0x60;
            t2[13] = 0x02;
            t2[20] = 3; t2[21] = 3; t2[22] = 7; t2[23] = 0xFF;  // WSOPT + garbage
            break;
        }
        case 5:  // out-of-order seq on an active flow
            for (UInt32 i = 4; i < 8; ++i) t[i] = 0xFF;  // huge seq
            t[13] = 0x18;  // PSH|ACK
            break;
        }
    }

    /**
     * @brief Builds a hostile segment aimed at an ESTABLISHED flow:
     *        window-edge sequences (incl. wraparound), flag combos, zero /
     *        huge windows, malformed option runs, truncated headers.
     */
    void BuildConnHostile(Prng& rng, std::vector<Byte>& out, UInt32 base_seq) noexcept {
        out.clear();
        const UInt32 kind = rng.Next() % 8;
        const UInt32 len = (6 == kind) ? 20 : (40 + (rng.Next() % 24));  // 6 = truncated
        out.resize(len, 0);
        Byte* p = out.data();
        p[0] = 0x45;
        p[2] = static_cast<Byte>(len >> 8); p[3] = static_cast<Byte>(len & 0xFF);
        p[8] = 64;
        p[9] = 6;
        // The established flow: client 10.0.0.1:40000 -> server 10.0.0.2:443.
        p[12] = 0x0A; p[13] = 0x00; p[14] = 0x00; p[15] = 0x01;
        p[16] = 0x0A; p[17] = 0x00; p[18] = 0x00; p[19] = 0x02;
        if (len < 40) {
            return;  // truncated TCP header
        }
        Byte* t = p + 20;
        t[0] = 0x9C; t[1] = 0x40;   // sport 40000
        t[2] = 0x01; t[3] = 0xBB;   // dport 443
        UInt32 seq = base_seq;
        switch (kind) {
        case 0: seq = base_seq + rng.Next() % 131072; break;              // in window
        case 1: seq = base_seq + 1000000 + rng.Next() % 1000000; break;   // far ahead
        case 2: seq = base_seq - 1000 - (rng.Next() % 1000); break;       // old
        case 3: seq = base_seq + 0xFFFFFFF0u; break;                      // near wraparound
        case 4: seq = 0xFFFFFFFFu - (rng.Next() % 64); break;             // wraparound edge
        case 5: seq = base_seq + rng.Next() % 4096; break;                // ooo small
        case 6: seq = base_seq; break;                                    // exact
        default: seq = rng.Next(); break;                                 // random
        }
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(rng.Next()); t[9] = static_cast<Byte>(rng.Next());
        t[10] = static_cast<Byte>(rng.Next()); t[11] = static_cast<Byte>(rng.Next());
        const Byte flags = static_cast<Byte>(rng.Next() & 0x3F);
        t[12] = static_cast<Byte>(0x50 | ((rng.Next() % 4) << 4));  // hdr len 20-32
        t[13] = flags;
        t[14] = static_cast<Byte>(rng.Next()); t[15] = static_cast<Byte>(rng.Next());
        // Option area when the data offset claims one (TCP space = len-20).
        const UInt32 hdr_len = static_cast<UInt32>(t[12] >> 4) * 4;
        const UInt32 tcp_space = len - 20;
        if (hdr_len > 20 && hdr_len <= tcp_space) {
            for (UInt32 i = 20; i < hdr_len; ++i) {
                t[i] = static_cast<Byte>(rng.Next());  // malformed options
            }
        }
        // Some payload bytes when space allows.
        if (hdr_len < tcp_space) {
            for (UInt32 i = hdr_len; i < tcp_space; ++i) {
                t[i] = static_cast<Byte>(rng.Next());
            }
        }
    }

    /**
     * @brief Builds a valid IPv6 base header plus a random extension-header
     *        chain (next header 0 / 43 / 44 / 60, non-first-fragment garbage).
     *        payload_len is always consistent with the buffer. Exercises every
     *        ParseIp6 extension-header branch (ip.cpp) including the truncated
     *        "header past the end" rejections.
     */
    void BuildIpv6ExtChain(Prng& rng, std::vector<Byte>& out) noexcept {
        out.clear();
        // Truncated ext header: 1-2 bytes only, so the parser's "ext header
        // runs past the payload" guards fire (ip.cpp: off+1 >= end / off+len).
        if (0 == (rng.Next() % 6)) {
            const UInt32 stub = (0 == (rng.Next() % 2)) ? 1u : 2u;
            out.resize(40 + stub, 0);
            Byte* s = out.data();
            s[0] = 0x60;
            s[6] = 0x00;  // hop-by-hop
            s[7] = 64;
            for (UInt32 i = 8; i < 40; ++i) {
                s[i] = static_cast<Byte>(rng.Next());
            }
            out[40] = static_cast<Byte>(rng.Next());
            if (2 <= stub) {
                out[41] = 1;  // claims a 16-byte header over a 2-byte payload
            }
            s[4] = static_cast<Byte>(stub >> 8);
            s[5] = static_cast<Byte>(stub & 0xFF);
            return;
        }

        // Layered chain from the transport outward; each (type, bytes) block's
        // byte 0 names the next header. The byte stream must be outermost-first.
        Byte nh = 6;  // innermost: the transport protocol
        std::vector<std::pair<Byte, std::vector<Byte>>> headers;
        std::vector<Byte> garbage;  // trailing bytes after a non-first fragment
        bool fragment_seen = false;
        const UInt32 max_ext = 1 + (rng.Next() % 3);
        for (UInt32 e = 0; e < max_ext && !fragment_seen; ++e) {
            if (0 == (rng.Next() % 3)) {
                break;  // chain ends here
            }
            const UInt32 choice = rng.Next() % 4;
            if (2 == choice) {
                // Fragment header (44): fixed 8 bytes.
                std::vector<Byte> h(8, 0);
                h[0] = nh;
                UInt16 off_units = 0;
                if (0 == (rng.Next() % 4)) {
                    off_units = static_cast<UInt16>(rng.Next() & 0x1FFF);
                }
                const UInt16 more = static_cast<UInt16>(rng.Next() % 2);
                const UInt16 field = static_cast<UInt16>((off_units << 3) | more);
                h[2] = static_cast<Byte>(field >> 8);
                h[3] = static_cast<Byte>(field & 0xFF);
                for (UInt32 i = 4; i < 8; ++i) {
                    h[i] = static_cast<Byte>(rng.Next());  // fragment id
                }
                headers.push_back(std::make_pair(static_cast<Byte>(44), std::move(h)));
                fragment_seen = true;
                nh = 6;  // a fragment header ends the chain at the transport
                if (0 < off_units) {
                    // RFC 8200: a non-first fragment carries only payload;
                    // trailing garbage bytes must be tolerated.
                    const UInt32 g = 1 + (rng.Next() % 32);
                    for (UInt32 i = 0; i < g; ++i) {
                        garbage.push_back(static_cast<Byte>(rng.Next()));
                    }
                }
            } else {
                // Hop-by-Hop (0) / Routing (43) / Destination Options (60):
                // next byte + Hdr Ext Len byte + (len+1)*8 - 2 padding bytes.
                const Byte ext = (0 == choice) ? static_cast<Byte>(0)
                                 : ((1 == choice) ? static_cast<Byte>(43) : static_cast<Byte>(60));
                Byte ext_len = static_cast<Byte>(rng.Next() % 8);
                if (0 == (rng.Next() % 5)) {
                    ext_len = static_cast<Byte>(30);  // oversized block
                }
                const UInt32 hdr_len = (static_cast<UInt32>(ext_len) + 1) * 8;
                std::vector<Byte> h(hdr_len, 0);
                h[0] = nh;
                h[1] = ext_len;
                for (UInt32 i = 2; i < hdr_len; ++i) {
                    h[i] = static_cast<Byte>(rng.Next());
                }
                headers.push_back(std::make_pair(ext, std::move(h)));
                nh = ext;
            }
        }
        if (0 == (rng.Next() % 4)) {
            nh = static_cast<Byte>(rng.Next() & 0xFF);  // random end (default branch)
        }
        const Byte first_nh = nh;

        // Emit the chain outermost-first, then garbage, then a plausible TCP
        // payload so proto-6 packets can progress to ParseTcp.
        std::vector<Byte> body;
        for (auto it = headers.rbegin(); it != headers.rend(); ++it) {
            body.insert(body.end(), it->second.begin(), it->second.end());
        }
        body.insert(body.end(), garbage.begin(), garbage.end());
        if (6 == first_nh) {
            for (UInt32 i = 0; i < 40; ++i) {
                body.push_back(static_cast<Byte>(rng.Next()));
            }
        } else if (0 == (rng.Next() % 2)) {
            for (UInt32 i = 0; i < 16; ++i) {
                body.push_back(static_cast<Byte>(rng.Next()));
            }
        }
        const UInt32 total = 40 + static_cast<UInt32>(body.size());
        if (total > 65535) {
            out.resize(40, 0);
            return;
        }
        out.resize(40, 0);
        Byte* p = out.data();
        p[0] = 0x60;
        p[4] = static_cast<Byte>(body.size() >> 8);
        p[5] = static_cast<Byte>(body.size() & 0xFF);
        p[6] = first_nh;
        p[7] = 64;  // hop limit
        for (UInt32 i = 8; i < 40; ++i) {
            p[i] = static_cast<Byte>(rng.Next());
        }
        out.insert(out.end(), body.begin(), body.end());
    }

    /**
     * @brief Builds a hostile ACK segment aimed at an ESTABLISHED flow with a
     *        structured SACK/option flood: 4-block SACK (opt_len 34 - beyond
     *        BuildConnHostile's 12-byte option ceiling), most-recent-first
     *        ordering, wraparound blocks, NOP floods, truncated SACK lengths,
     *        zero-block SACK, timestamps + TFO cookie combos. Exercises the
     *        ParseTcpOpts SACK normalization (tcp_fsm.cpp:519-530) and the
     *        SACK recovery walk with hostile block layouts.
     */
    void BuildSackFlood(Prng& rng, std::vector<Byte>& out, UInt32 base_ack,
                        UInt32 base_seq) noexcept {
        out.clear();
        const UInt32 kind = rng.Next() % 8;
        Byte opts[60];
        UInt32 opt_len = 0;
        switch (kind) {
        case 0: {  // 4-block SACK (opt_len 34), random blocks
            opts[opt_len++] = 5;
            opts[opt_len++] = 34;
            for (UInt32 b = 0; b < 4; ++b) {
                UInt32 left = base_ack + 1 + (rng.Next() % 30000);
                UInt32 right = left + 1 + (rng.Next() % 1000);
                opts[opt_len++] = static_cast<Byte>(left >> 24);
                opts[opt_len++] = static_cast<Byte>(left >> 16);
                opts[opt_len++] = static_cast<Byte>(left >> 8);
                opts[opt_len++] = static_cast<Byte>(left & 0xFF);
                opts[opt_len++] = static_cast<Byte>(right >> 24);
                opts[opt_len++] = static_cast<Byte>(right >> 16);
                opts[opt_len++] = static_cast<Byte>(right >> 8);
                opts[opt_len++] = static_cast<Byte>(right & 0xFF);
            }
            break;
        }
        case 1: {  // 4-block SACK, most-recent-first (RFC 2018 s3 order)
            UInt32 blocks[4][2];
            for (UInt32 b = 0; b < 4; ++b) {
                UInt32 left = base_ack + 1 + (rng.Next() % 30000);
                blocks[b][0] = left;
                blocks[b][1] = left + 1 + (rng.Next() % 1000);
            }
            opts[opt_len++] = 5;
            opts[opt_len++] = 34;
            for (UInt32 b = 4; 0 < b; --b) {  // newest first
                for (UInt32 i = 0; i < 2; ++i) {
                    UInt32 v = blocks[b - 1][i];
                    opts[opt_len++] = static_cast<Byte>(v >> 24);
                    opts[opt_len++] = static_cast<Byte>(v >> 16);
                    opts[opt_len++] = static_cast<Byte>(v >> 8);
                    opts[opt_len++] = static_cast<Byte>(v & 0xFF);
                }
            }
            break;
        }
        case 2: {  // wraparound SACK blocks (left raw > right raw)
            opts[opt_len++] = 5;
            opts[opt_len++] = 18;  // 2 blocks
            for (UInt32 b = 0; b < 2; ++b) {
                UInt32 left = 0xFFFFFFF0u - (rng.Next() % 64);   // near 2^32
                UInt32 right = 0x00000010u + (rng.Next() % 64);  // past wrap
                opts[opt_len++] = static_cast<Byte>(left >> 24);
                opts[opt_len++] = static_cast<Byte>(left >> 16);
                opts[opt_len++] = static_cast<Byte>(left >> 8);
                opts[opt_len++] = static_cast<Byte>(left & 0xFF);
                opts[opt_len++] = static_cast<Byte>(right >> 24);
                opts[opt_len++] = static_cast<Byte>(right >> 16);
                opts[opt_len++] = static_cast<Byte>(right >> 8);
                opts[opt_len++] = static_cast<Byte>(right & 0xFF);
            }
            break;
        }
        case 3: {  // NOP flood: 40 NOPs (hdr_len 60)
            for (UInt32 i = 0; i < 40; ++i) {
                opts[opt_len++] = 1;
            }
            break;
        }
        case 4: {  // truncated SACK length 3..9 (malformed)
            opts[opt_len++] = 5;
            opts[opt_len++] = static_cast<Byte>(3 + (rng.Next() % 7));
            opts[opt_len++] = static_cast<Byte>(rng.Next());
            break;
        }
        case 5: {  // zero-block SACK (opt_len 2) + 1 NOP
            opts[opt_len++] = 5;
            opts[opt_len++] = 2;
            opts[opt_len++] = 1;
            break;
        }
        case 6: {  // timestamps + 2-block SACK + TFO cookie combo
            opts[opt_len++] = 8;
            opts[opt_len++] = 10;
            for (UInt32 i = 0; i < 8; ++i) {
                opts[opt_len++] = static_cast<Byte>(rng.Next());
            }
            opts[opt_len++] = 5;
            opts[opt_len++] = 18;
            for (UInt32 b = 0; b < 2; ++b) {
                UInt32 left = base_ack + 1 + (rng.Next() % 30000);
                UInt32 right = left + 1 + (rng.Next() % 1000);
                opts[opt_len++] = static_cast<Byte>(left >> 24);
                opts[opt_len++] = static_cast<Byte>(left >> 16);
                opts[opt_len++] = static_cast<Byte>(left >> 8);
                opts[opt_len++] = static_cast<Byte>(left & 0xFF);
                opts[opt_len++] = static_cast<Byte>(right >> 24);
                opts[opt_len++] = static_cast<Byte>(right >> 16);
                opts[opt_len++] = static_cast<Byte>(right >> 8);
                opts[opt_len++] = static_cast<Byte>(right & 0xFF);
            }
            opts[opt_len++] = 34;
            opts[opt_len++] = static_cast<Byte>(10 + (rng.Next() % 8));  // 6..18
            const UInt32 cookie_len = opts[opt_len - 1] - 2;
            for (UInt32 i = 0; i < cookie_len && opt_len < 60; ++i) {
                opts[opt_len++] = static_cast<Byte>(rng.Next());
            }
            break;
        }
        default: {  // unknown option kinds with bogus lengths
            opts[opt_len++] = static_cast<Byte>(200 + (rng.Next() % 40));
            opts[opt_len++] = static_cast<Byte>(3 + (rng.Next() % 40));
            for (UInt32 i = 0; i < 8; ++i) {
                opts[opt_len++] = static_cast<Byte>(rng.Next());
            }
            opts[opt_len++] = 7;  // kind 7 (unknown, valid short length)
            opts[opt_len++] = 2;
            break;
        }
        }
        // Round the header length to a multiple of 4 (RFC 793 padding).
        const UInt32 hdr_len = 20 + ((opt_len + 3) / 4) * 4;
        if (hdr_len > 60) {
            out.clear();
            return;
        }
        // ~1/8 hostile segments carry payload with a random URG/PSH - the
        // RFC 7323 PAWS drop path (payload-gated) and the recv/urgent
        // delivery paths must survive garbage timestamps and URG marks.
        const bool with_data = (0 == (rng.Next() % 8));
        const UInt32 data_len = with_data ? (1 + (rng.Next() % 64)) : 0;
        const UInt32 urg_flag = (0 == (rng.Next() % 16)) ? 0x20 : 0;
        const UInt32 psh_flag = with_data ? 0x08 : 0;
        out.resize(20 + hdr_len + data_len, 0);
        Byte* p = out.data();
        p[0] = 0x45;
        p[2] = static_cast<Byte>((20 + hdr_len + data_len) >> 8);
        p[3] = static_cast<Byte>((20 + hdr_len + data_len) & 0xFF);
        p[8] = 64;
        p[9] = 6;
        p[12] = 0x0A; p[13] = 0x00; p[14] = 0x00; p[15] = 0x01;  // client
        p[16] = 0x0A; p[17] = 0x00; p[18] = 0x00; p[19] = 0x02;  // server
        Byte* t = p + 20;
        t[0] = 0x9C; t[1] = 0x40;   // sport 40000
        t[2] = 0x01; t[3] = 0xBB;   // dport 443
        const UInt32 ack = (0 == (rng.Next() % 4)) ? base_ack
                                                   : (base_ack + (rng.Next() % 4096) - 2048);
        const UInt32 seq = base_seq + (rng.Next() % 256);
        t[4] = static_cast<Byte>(seq >> 24); t[5] = static_cast<Byte>(seq >> 16);
        t[6] = static_cast<Byte>(seq >> 8);  t[7] = static_cast<Byte>(seq & 0xFF);
        t[8] = static_cast<Byte>(ack >> 24); t[9] = static_cast<Byte>(ack >> 16);
        t[10] = static_cast<Byte>(ack >> 8); t[11] = static_cast<Byte>(ack & 0xFF);
        t[12] = static_cast<Byte>((hdr_len / 4) << 4);
        t[13] = static_cast<Byte>(0x10 | urg_flag | psh_flag);
        t[14] = 0xFF; t[15] = 0xFF;
        std::memcpy(t + 20, opts, opt_len);
        if (0 < data_len) {
            for (UInt32 i = 0; i < data_len; ++i) {
                t[20 + opt_len + i] = static_cast<Byte>(rng.Next());
            }
        }
    }

    /**
     * @brief Builds one IPv4 TCP fragment (20-byte header, proto 6).
     */
    void BuildIpv4Frag(std::vector<Byte>& out, UInt16 id, UInt32 src, UInt32 dst,
                       UInt16 off_units, bool more, const Byte* payload,
                       UInt32 payload_len) noexcept {
        const UInt32 total = 20 + payload_len;
        out.resize(total, 0);
        Byte* p = out.data();
        p[0] = 0x45;
        p[2] = static_cast<Byte>(total >> 8);
        p[3] = static_cast<Byte>(total & 0xFF);
        p[4] = static_cast<Byte>(id >> 8);
        p[5] = static_cast<Byte>(id & 0xFF);
        const UInt16 field = static_cast<UInt16>((more ? 0x2000 : 0) | (off_units & 0x1FFF));
        p[6] = static_cast<Byte>(field >> 8);
        p[7] = static_cast<Byte>(field & 0xFF);
        p[8] = 64;  // TTL
        p[9] = 6;   // TCP
        p[12] = static_cast<Byte>(src >> 24);
        p[13] = static_cast<Byte>(src >> 16);
        p[14] = static_cast<Byte>(src >> 8);
        p[15] = static_cast<Byte>(src & 0xFF);
        p[16] = static_cast<Byte>(dst >> 24);
        p[17] = static_cast<Byte>(dst >> 16);
        p[18] = static_cast<Byte>(dst >> 8);
        p[19] = static_cast<Byte>(dst & 0xFF);
        if (NULLPTR != payload && 0 < payload_len) {
            std::memcpy(p + 20, payload, payload_len);
        }
    }

    void Pump(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
              xtcp::XtcpStack& sa, xtcp::XtcpStack& sb) {
        Byte out[65536];
        for (UInt32 round = 0; round < 200; ++round) {
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

    void FuzzActiveConnection() {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Hostile segments aimed at the live flow (client -> server).
        Prng rng2(0xF00D2u);
        const UInt32 base_seq = 0x40000000;  // server's rcv_nxt region
        for (UInt32 i = 0; i < 24000; ++i) {
            std::vector<Byte> seg;
            BuildConnHostile(rng2, seg, base_seq);
            backend_a.Inject(seg.data(), static_cast<UInt32>(seg.size()), 0x0800);
            if (0 == (i % 500)) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        // The connection must still carry legitimate traffic intact.
        std::string payload(8192, 'Z');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()),
                           static_cast<UInt32>(payload.size())));
        for (UInt32 i = 0; i < 500 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "test_fuzz: active-connection hostile injection survived (%u)\n", 24000u);
    }

    /**
     * @brief Fuzzes IPv6 extension-header parsing: random ext chains injected
     *        into a live stack must never crash it, and the established
     *        connection must still carry legitimate traffic afterwards.
     */
    void FuzzIpv6ExtHeaders() {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        Prng rng(0xF0070u);
        for (UInt32 i = 0; i < 6000; ++i) {
            std::vector<Byte> pkt;
            BuildIpv6ExtChain(rng, pkt);
            if (40 > pkt.size()) {
                continue;
            }
            backend_a.Inject(pkt.data(), static_cast<UInt32>(pkt.size()), 0x0800);
            if (0 == (i % 500)) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        std::string payload(8192, 'I');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()),
                           static_cast<UInt32>(payload.size())));
        for (UInt32 i = 0; i < 500 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "test_fuzz: ipv6 ext-header fuzz survived (%u)\n", 6000u);
    }

    /**
     * @brief Fuzzes IPv4 fragment reassembly (IpFragTable::Add): 2-3 TCP
     *        fragments per iteration covering overlap / huge offset /
     *        bitmap-grow / first-fragment-missing / per-source cap /
     *        complete-datagram delivery. The stack must never crash and the
     *        established connection must survive.
     */
    void FuzzIpv4Fragments() {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        Prng rng(0xF4472u);
        std::vector<Byte> f0, f1;
        for (UInt32 i = 0; i < 6000; ++i) {
            const UInt32 mode = i % 6;
            // Randomize the 4-tuple so the per-source cap (below) cannot starve
            // the other boundary modes after the first few iterations.
            const UInt32 src = 0x0A000001u ^ (rng.Next() & 0x00FFFFFFu);
            const UInt32 dst = 0x0A000002u ^ (rng.Next() & 0x00FFFFFFu);
            const UInt16 id = static_cast<UInt16>(rng.Next());
            Byte tcp[64];
            for (UInt32 j = 0; j < 64; ++j) {
                tcp[j] = static_cast<Byte>(rng.Next());
            }
            switch (mode) {
            case 0: {  // complete datagram: offset-0 TCP frag + final frag
                BuildIpv4Frag(f0, id, src, dst, 0, true, tcp, 40);
                BuildIpv4Frag(f1, id, src, dst, 5, false, tcp + 40, 24);
                backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                backend_a.Inject(f1.data(), static_cast<UInt32>(f1.size()), 0x0800);
                break;
            }
            case 1: {  // overlap: second fragment overlaps the first
                BuildIpv4Frag(f0, id, src, dst, 0, true, tcp, 32);
                BuildIpv4Frag(f1, id, src, dst, 2, false, tcp + 32, 32);
                backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                backend_a.Inject(f1.data(), static_cast<UInt32>(f1.size()), 0x0800);
                break;
            }
            case 2: {  // huge offset: beyond the kMaxPayload byte cap
                BuildIpv4Frag(f0, id, src, dst, static_cast<UInt16>(5000 + (rng.Next() % 4000)),
                              false, tcp, 32);
                backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                break;
            }
            case 3: {  // bitmap grow: small first frag, then a far-offset one
                BuildIpv4Frag(f0, id, src, dst, 0, true, tcp, 8);
                BuildIpv4Frag(f1, id, src, dst, static_cast<UInt16>(2000 + (rng.Next() % 1000)),
                              false, tcp + 8, 16);
                backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                backend_a.Inject(f1.data(), static_cast<UInt32>(f1.size()), 0x0800);
                break;
            }
            case 4: {  // first fragment missing: only non-zero offsets
                BuildIpv4Frag(f0, id, src, dst, static_cast<UInt16>(1 + (rng.Next() % 100)),
                              true, tcp, 16);
                BuildIpv4Frag(f1, id, src, dst, static_cast<UInt16>(20 + (rng.Next() % 50)),
                              false, tcp + 16, 8);
                backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                backend_a.Inject(f1.data(), static_cast<UInt32>(f1.size()), 0x0800);
                break;
            }
            default: {  // per-source cap: 9 partial sets from one source
                const UInt32 cap_src = 0x0A000001u;
                for (UInt32 k = 0; k < 9; ++k) {
                    const UInt16 sid = static_cast<UInt16>(rng.Next());
                    const UInt32 cap_dst = 0x0A000002u ^ (static_cast<UInt32>(k) << 16);
                    BuildIpv4Frag(f0, sid, cap_src, cap_dst, 0, true, tcp, 16);
                    backend_a.Inject(f0.data(), static_cast<UInt32>(f0.size()), 0x0800);
                }
                break;
            }
            }
            if (0 == (i % 250)) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        std::string payload(8192, 'F');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()),
                           static_cast<UInt32>(payload.size())));
        for (UInt32 i = 0; i < 500 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "test_fuzz: ipv4 fragment fuzz survived (%u)\n", 6000u);
    }
    /**
     * @brief Fuzzes the SACK option parser + sender recovery walk with a
     *        structured SACK/option flood (4-block SACKs, most-recent-first,
     *        wraparound blocks, NOP floods, truncated SACK lengths, zero-block
     *        SACKs, timestamp+TFO combos). Aimed at the live flow's send
     *        window (base_ack = the client's snd_una) so the ACK/dup-ACK and
     *        SACK normalization paths actually run. The connection must still
     *        carry legitimate traffic afterwards.
     */
    void FuzzSackFlood() {
        xtcp::ndi::ManualBackend backend_a, backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_a.OnPacket(std::move(buf));
            }
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& p) {
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), p.data, p.len);
                buf.SetLen(p.len);
                stack_b.OnPacket(std::move(buf));
            }
        });

        std::string received;
        stack_b.SetRecvHandler([&received](UInt64, const Byte* d, UInt32 n) {
            received.append(reinterpret_cast<const char*>(d), n);
        });

        xtcp::core::Endpoint local, remote;
        local.family = 4;
        local.addr[0] = 0x0A000001;
        local.port = 40000;
        remote.family = 4;
        remote.addr[0] = 0x0A000002;
        remote.port = 443;
        CHECK(stack_b.Listen(remote));
        const UInt64 conn = stack_a.Connect(local, remote);
        CHECK(0 != conn);
        Pump(backend_a, backend_b, stack_a, stack_b);

        // Prime the connection: deliver one full payload so the server's
        // sequence space is settled.
        std::string prime(4096, 'P');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(prime.data()),
                           static_cast<UInt32>(prime.size())));
        for (UInt32 i = 0; i < 500 && received.size() < prime.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(prime == received);
        received.clear();

        // Put a fresh payload in flight WITHOUT pumping: the client now has
        // unACKed segments, so dup-ACKs + SACK blocks land in a live
        // [snd_una_, snd_nxt_] window and drive the recovery walk.
        std::string inflight_payload(8192, 'I');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(inflight_payload.data()),
                           static_cast<UInt32>(inflight_payload.size())));

        UInt32 inflight = 0, cwnd = 0, ssthresh = 0, snd_wnd = 0, retx = 0;
        UInt64 rto_deadline = 0;
        UInt32 dup_acks = 0, fast_rec = 0, front_seq = 0, snd_una = 0;
        UInt16 lport = 0, rport = 0;
        stack_a.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                          rto_deadline, dup_acks, fast_rec, front_seq, snd_una,
                          lport, rport);
        CHECK(0 != snd_una);

        Prng rng(0x5AC5u);
        for (UInt32 i = 0; i < 20000; ++i) {
            std::vector<Byte> seg;
            BuildSackFlood(rng, seg, snd_una, 0x40000000);
            if (seg.empty()) {
                continue;
            }
            backend_a.Inject(seg.data(), static_cast<UInt32>(seg.size()), 0x0800);
            if (0 == (i % 500)) {
                Pump(backend_a, backend_b, stack_a, stack_b);
            }
        }
        Pump(backend_a, backend_b, stack_a, stack_b);

        // The in-flight 'I' payload must still arrive intact after the flood.
        for (UInt32 i = 0; i < 500 && received.size() < inflight_payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(inflight_payload == received);
        received.clear();

        // The connection must still carry fresh legitimate traffic intact.
        std::string payload(8192, 'S');
        CHECK(stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()),
                           static_cast<UInt32>(payload.size())));
        for (UInt32 i = 0; i < 500 && received.size() < payload.size(); ++i) {
            Pump(backend_a, backend_b, stack_a, stack_b);
        }
        CHECK(payload == received);
        std::fprintf(stderr, "test_fuzz: SACK/option flood survived (%u)\n", 20000u);
    }
}

int main() {
    xtcp::buf::InitPools();

    // Live stack with a listener and an active connection.
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);
    backend.SetRxHandler([&stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (!buf.IsEmpty()) {
            std::memcpy(buf.Data(), p.data, p.len);
            buf.SetLen(p.len);
            stack.OnPacket(std::move(buf));
        }
    });
    xtcp::core::Endpoint server;
    server.family = 4;
    server.addr[0] = 0x0A000001;
    server.port = 443;
    CHECK(stack.Listen(server));

    UInt64 seed = 0xC0FFEE1u;
    if (const char* env = std::getenv("XTCP_FUZZ_SEED")) {
        seed = std::strtoull(env, NULLPTR, 10);
    }
    Prng rng(seed);
    const UInt32 kIterations = 50000;
    for (UInt32 i = 0; i < kIterations; ++i) {
        std::vector<Byte> packet;
        switch (rng.Next() % 3) {
        case 0:
            BuildMalformedV4(rng, packet);
            break;
        case 1:
            BuildMalformedV6(rng, packet);
            break;
        default:
            BuildHostile(rng, packet);
            break;
        }
        if (packet.empty()) {
            continue;
        }
        // Inject. The stack must accept any input without crashing.
        backend.Inject(packet.data(), static_cast<UInt32>(packet.size()), 0x0800);
    }

    // Drain any emitted traffic.
    Byte out[65536];
    while (0 != backend.TxPending()) {
        if (0 == backend.PollTx(out)) {
            break;
        }
    }

    // Fuzz an ESTABLISHED connection: hostile segments must not corrupt
    // the state machine (legitimate traffic still flows afterwards).
    FuzzActiveConnection();

    // IPv6 extension-header chain fuzz: random ext headers / fragments
    // must not crash the parser (ParseIp6 full branch coverage).
    FuzzIpv6ExtHeaders();

    // IPv4 fragment reassembly fuzz: overlap / huge offset / bitmap-grow /
    // first-missing / per-source cap boundaries in IpFragTable::Add.
    FuzzIpv4Fragments();

    // SACK/option structured flood: 4-block / most-recent-first / wraparound
    // SACKs, NOP floods, truncated lengths - ParseTcpOpts normalization +
    // sender recovery walk must survive and the flow stays intact.
    FuzzSackFlood();

    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_fuzz: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_fuzz: all passed (%u injections)\n", kIterations);
    return 0;
}

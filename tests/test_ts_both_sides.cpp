/**
 * @file test_ts_both_sides.cpp
 * @brief RFC 7323 both-sides rule: timestamps activate only when BOTH SYNs
 *        carried the TSopt. A TFO fast-open SYN deliberately omits the
 *        option (option space / RFC 7413), so even though the server's
 *        SYN+ACK answers with the TSopt, the client must NOT activate
 *        timestamps - otherwise its ACKs would carry a TSopt it never
 *        offered.
 *
 * The observation is the client's ACK option layout: a timestamps_ok_
 * connection puts kind-8 TSopt (12 bytes) on ACK segments; a suppressed
 * one sends bare 20-byte headers.
 */

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

namespace {

    // Returns true when a drained A->B packet's TCP header carries a
    // kind-8 TSopt. Scans every pending Tx packet; drains them all.
    bool AckHasTsOpt(xtcp::ndi::ManualBackend& backend_a, Byte* out) {
        bool found = false;
        while (0 != backend_a.TxPending()) {
            const UInt32 n = backend_a.PollTx(out);
            if (n < 40) {
                continue;
            }
            const Byte* t = out + 20;  // IPv4 header is 20 bytes
            const UInt32 data_off = (t[12] >> 4) * 4;
            if (data_off <= 20) {
                continue;  // no options
            }
            UInt32 off = 20;
            while (off + 1 < data_off) {
                const Byte kind = t[off];
                if (0 == kind) {
                    break;  // EOL
                }
                if (1 == kind) {
                    ++off;  // NOP
                    continue;
                }
                const UInt32 len = t[off + 1];
                if (len < 2 || off + len > data_off) {
                    break;  // malformed: stop
                }
                if (8 == kind) {
                    found = true;  // TSopt present
                    break;
                }
                off += len;
            }
        }
        return found;
    }

}  // namespace

int main() {
    xtcp::buf::InitPools();
    {
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

        // Per-connection receive tracking. The server (stack_b) receives;
        // the handler routes by the SERVER-side conn ids captured by the
        // accept handler (the client's Connect id differs from the server's).
        UInt64 tfo_conn = 0, normal_conn = 0;
        std::vector<Byte> rx_tfo, rx_normal;
        stack_b.SetAcceptHandler([&](UInt64 id, const xtcp::core::Endpoint&,
                                     const xtcp::core::Endpoint&) {
            if (0 == tfo_conn) {
                tfo_conn = id;
            } else {
                normal_conn = id;
            }
            return true;
        });
        stack_b.SetRecvHandler([&](UInt64 id, const Byte* data, UInt32 len) {
            if (id == tfo_conn) {
                rx_tfo.insert(rx_tfo.end(), data, data + len);
            } else if (id == normal_conn) {
                rx_normal.insert(rx_normal.end(), data, data + len);
            }
            return true;
        });

        auto pump = [&]() {
            Byte out[65536];
            while (0 != backend_a.TxPending()) {
                const UInt32 n = backend_a.PollTx(out);
                if (0 < n) {
                    backend_b.Inject(out, n, 0x0800);
                }
            }
            while (0 != backend_b.TxPending()) {
                const UInt32 n = backend_b.PollTx(out);
                if (0 < n) {
                    backend_a.Inject(out, n, 0x0800);
                }
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        };

        xtcp::core::Endpoint server_ep, client_ep;
        server_ep.family = 4;
        server_ep.addr[0] = 0x0A000001;
        server_ep.port = 443;
        client_ep.family = 4;
        client_ep.addr[0] = 0xC0A80102;
        client_ep.port = 40000;
        CHECK(stack_b.Listen(server_ep));

        // RFC 7413 fast-open connect WITH early data and no cached cookie:
        // the SYN goes out WITHOUT the TSopt (the fast-open SYN never
        // carries it - the option space is the RFC 7413 rationale) and the
        // early data is buffered until the handshake completes.
        const Byte early[64] = {0x7A};
        const UInt64 conn = stack_a.ConnectWithTfo(client_ep, server_ep, early, sizeof(early));
        CHECK(0 != conn);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn));
        // The buffered early data flushed after the handshake: the server
        // received it (this also proves the fast-open path was exercised).
        for (UInt32 i = 0; i < 300 && rx_tfo.size() < sizeof(early); ++i) {
            pump();
        }
        CHECK(sizeof(early) == rx_tfo.size());

        // The server pushes data TO the client; the client answers with pure
        // ACKs. The client's ACK must NOT carry the TSopt: its fast-open SYN
        // had no TSopt, so timestamps were never negotiated (both-sides
        // rule) - even though the server's SYN+ACK did answer with one.
        const Byte payload[1024] = {0x42};
        CHECK(stack_b.Send(tfo_conn, payload, sizeof(payload)));
        for (UInt32 i = 0; i < 300 && 0 == backend_a.TxPending(); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        Byte out[65536];
        const bool ts_opt = AckHasTsOpt(backend_a, out);
        std::fprintf(stderr, "[ts-both-sides] TFO client ACK carries TSopt: %s\n", ts_opt ? "YES" : "no");
        CHECK(!ts_opt);  // the client never offered timestamps -> must not use them

        // Control: a normal Connect (SYN carries the TSopt by default) MUST
        // negotiate timestamps (the option appears on its ACK). This pins
        // the observation method, not just the negative. Use a fresh client
        // port so the 4-tuple does not collide with the live TFO connection.
        xtcp::core::Endpoint client_ep2 = client_ep;
        client_ep2.port = 40001;
        const UInt64 conn2 = stack_a.Connect(client_ep2, server_ep);
        CHECK(0 != conn2);
        for (UInt32 i = 0; i < 300 && xtcp::core::TcpState::kEstablished != stack_a.ConnectionState(conn2); ++i) {
            pump();
        }
        CHECK(xtcp::core::TcpState::kEstablished == stack_a.ConnectionState(conn2));
        CHECK(stack_a.Send(conn2, payload, sizeof(payload)));
        for (UInt32 i = 0; i < 300 && rx_normal.size() < sizeof(payload); ++i) {
            pump();
        }
        CHECK(sizeof(payload) == rx_normal.size());
        // Control: the server pushes data; the client's ACK on a normally
        // negotiated connection MUST carry the TSopt (both SYNs offered).
        CHECK(stack_b.Send(normal_conn, payload, sizeof(payload)));
        for (UInt32 i = 0; i < 300 && 0 == backend_a.TxPending(); ++i) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const bool ts_opt2 = AckHasTsOpt(backend_a, out);
        std::fprintf(stderr, "[ts-both-sides] normal client ACK carries TSopt: %s\n", ts_opt2 ? "YES" : "no");
        CHECK(ts_opt2);  // both SYNs offered -> timestamps active
    }
    xtcp::buf::ShutdownPools();
    std::fprintf(stderr, g_failures ? "TS_BOTH_SIDES: FAILED (%d)\n" : "TS_BOTH_SIDES: ALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}

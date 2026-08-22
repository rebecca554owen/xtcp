/**
 * @file echo.cpp
 * @brief Dual-mode echo sample: server (passive open) and client (active
 *        open) on the XTCP stack, wired back to back over in-memory
 *        backends. The server runs on a dedicated thread (Listen +
 *        accept + echo), the client on the main thread (Connect + send +
 *        verify the echoed payload).
 *          echo --port 8080 --msgs 100 --size 1400
 *        Exit code 0 = every message echoed back byte-identical.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
    UInt32 ToU32(const char* s) noexcept {
        return static_cast<UInt32>(std::strtoul(s, NULLPTR, 10));
    }
}

int main(int argc, char** argv) {
    UInt16 port = 8080;
    UInt32 msgs = 100;
    UInt32 size = 1400;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if ("--port" == a && i + 1 < argc) {
            port = static_cast<UInt16>(ToU32(argv[++i]));
        } else if ("--msgs" == a && i + 1 < argc) {
            msgs = ToU32(argv[++i]);
        } else if ("--size" == a && i + 1 < argc) {
            size = ToU32(argv[++i]);
        }
    }

    xtcp::buf::InitPools();

    // One process, two stacks wired back to back over in-memory backends.
    // The server thread pumps traffic between the two backends.
    xtcp::ndi::ManualBackend server_backend, client_backend;
    xtcp::XtcpStack server_stack(&server_backend);
    xtcp::XtcpStack client_stack(&client_backend);
    server_backend.SetRxHandler([&server_stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (buf.IsEmpty()) return;  // pool exhausted; drop
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        server_stack.OnPacket(std::move(buf));
    });
    client_backend.SetRxHandler([&client_stack](xtcp::ndi::Packet&& p) {
        xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(p.len);
        if (buf.IsEmpty()) return;  // pool exhausted; drop
        std::memcpy(buf.Data(), p.data, p.len);
        buf.SetLen(p.len);
        client_stack.OnPacket(std::move(buf));
    });

    // Server mode (passive open) on its own thread.
    std::atomic<UInt64> echoed{0};
    std::atomic<UInt64> echoed_bytes{0};
    std::atomic<bool> server_ready{false};
    std::atomic<bool> server_failed{false};
    std::atomic<bool> client_done{false};
    std::thread server_thread([&]() {
        xtcp::core::Endpoint local;
        local.family = 4;
        local.addr[0] = 0x0A000002;  // 10.0.0.2
        local.port = port;
        if (!server_stack.Listen(local)) {
            server_failed.store(true, std::memory_order_relaxed);
            server_ready.store(true, std::memory_order_relaxed);
            return;
        }
        server_stack.SetAcceptHandler([](UInt64 id, const xtcp::core::Endpoint& remote,
                                         const xtcp::core::Endpoint&) {
            std::fprintf(stderr, "[server] accept id=%llu from %u.%u.%u.%u:%u\n",
                         (unsigned long long)id,
                         (remote.addr[0] >> 24) & 0xFF, (remote.addr[0] >> 16) & 0xFF,
                         (remote.addr[0] >> 8) & 0xFF, remote.addr[0] & 0xFF, remote.port);
            return true;
        });
        server_stack.SetRecvHandler([&server_stack, &echoed, &echoed_bytes](
                                         UInt64 id, const Byte* data, UInt32 len) {
            echoed.fetch_add(1, std::memory_order_relaxed);
            echoed_bytes.fetch_add(len, std::memory_order_relaxed);
            server_stack.Send(id, data, len);  // echo back
        });
        std::fprintf(stderr, "[server] listening on 10.0.0.2:%u\n", port);
        server_ready.store(true, std::memory_order_relaxed);

        // Pumps both directions until the client signals completion.
        Byte out[65536];
        bool done = false;
        while (!done) {
            bool moved = false;
            while (0 != server_backend.TxPending()) {
                const UInt32 n = server_backend.PollTx(out);
                if (0 < n) {
                    client_backend.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            while (0 != client_backend.TxPending()) {
                const UInt32 n = client_backend.PollTx(out);
                if (0 < n) {
                    server_backend.Inject(out, n, 0x0800);
                    moved = true;
                }
            }
            // The client is the authoritative terminator: it closes after
            // `msgs` echoes (or aborts on timeout/send failure). Exit the
            // pump once it is done and nothing is left in flight. NOTE: the
            // old condition also compared `msgs <= echoed` - but `echoed`
            // counts RECV CALLBACKS (one per ~MSS-sized segment), not
            // messages: a message larger than the MSS arrives as multiple
            // segments, so the pump exited after `msgs` SEGMENTS (about a
            // quarter of one 32KB message) and starved the rest of the
            // transfer (the client then hit its echo timeout).
            if (client_done.load(std::memory_order_relaxed) &&
                0 == server_backend.TxPending() && 0 == client_backend.TxPending()) {
                done = true;
            }
            server_stack.PollAckTimers();  // delayed ACKs / RTO on the server side
            if (!moved) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });
    while (!server_ready.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (server_failed.load(std::memory_order_relaxed)) {
        std::fprintf(stderr, "[echo] server listen failed\n");
        return 1;
    }

    // Client mode (active open): connect, send, verify the echo.
    std::vector<Byte> payload(size);
    for (UInt32 i = 0; i < size; ++i) {
        payload[i] = static_cast<Byte>(i & 0xFF);
    }

    std::atomic<UInt64> echoed_ok{0};
    std::atomic<UInt64> mismatches{0};
    std::atomic<UInt64> recv_bytes{0};
    std::atomic<bool> established{false};
    client_stack.SetStateHandler([&established](UInt64, xtcp::core::TcpState st) {
        if (xtcp::core::TcpState::kEstablished == st) {
            established.store(true, std::memory_order_relaxed);
        }
    });
    client_stack.SetRecvHandler([&](UInt64, const Byte* data, UInt32 len) {
        // TCP is a byte stream: an echo may arrive fragmented across several
        // recv calls when size exceeds the MSS. Compare every byte against the
        // payload pattern by accumulated byte count, not per-message length.
        if (0 == size) {
            recv_bytes.fetch_add(len, std::memory_order_relaxed);
            return;
        }
        const UInt64 base = recv_bytes.load(std::memory_order_relaxed);
        bool match = true;
        for (UInt32 j = 0; j < len; ++j) {
            if (data[j] != payload[static_cast<size_t>((base + j) % size)]) {
                match = false;
                break;
            }
        }
        recv_bytes.fetch_add(len, std::memory_order_relaxed);
        if (match) {
            echoed_ok.fetch_add((base + len) / size - base / size,
                                std::memory_order_relaxed);
        } else {
            mismatches.fetch_add(1, std::memory_order_relaxed);
        }
    });

    xtcp::core::Endpoint local, remote;
    local.family = 4;
    local.addr[0] = 0x0A000001;  // 10.0.0.1
    local.port = 40000;
    remote.family = 4;
    remote.addr[0] = 0x0A000002;  // 10.0.0.2
    remote.port = port;

    const UInt64 conn = client_stack.Connect(local, remote);
    if (0 == conn) {
        std::fprintf(stderr, "[client] connect failed\n");
        return 1;
    }
    std::fprintf(stderr, "[client] connecting id=%llu to 10.0.0.2:%u\n",
                 (unsigned long long)conn, port);

    const auto t0 = std::chrono::steady_clock::now();
    UInt32 i = 0;
    for (; i < msgs; ++i) {
        // Data may be queued before Established (full client semantics).
        if (!client_stack.Send(conn, payload.data(), size)) {
            UInt32 inflight, cwnd, ssthresh, snd_wnd, retx, dup_acks, fast_rec;
            UInt64 rto_deadline;
            UInt32 front_seq, snd_una;
            UInt16 lp, rp;
            client_stack.ConnStats(conn, inflight, cwnd, ssthresh, snd_wnd, retx,
                                   rto_deadline, dup_acks, fast_rec, front_seq, snd_una, lp, rp);
            std::fprintf(stderr, "[client] send %u failed: inflight=%u cwnd=%u ssthresh=%u wnd=%u retx=%u dup=%u fast=%u snd_una=%llu front=%llu\n",
                         i, inflight, cwnd, ssthresh, snd_wnd, retx, dup_acks, fast_rec,
                         (unsigned long long)snd_una, (unsigned long long)front_seq);
            break;
        }
        // Wait for the echo of message i before sending the next.
        const UInt64 want = echoed_ok.load(std::memory_order_relaxed);
        for (UInt32 spin = 0; spin < 1000; ++spin) {
            if (want < echoed_ok.load(std::memory_order_relaxed)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            client_stack.PollAckTimers();
        }
        if (want == echoed_ok.load(std::memory_order_relaxed)) {
            std::fprintf(stderr, "[client] msg %u: no echo within 1s\n", i);
            break;
        }
    }
    client_done.store(true, std::memory_order_relaxed);  // let the pump loop exit
    const auto t1 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t1 - t0).count();

    std::fprintf(stderr, "[client] sent=%u echoed=%llu mismatches=%llu established=%d\n",
                 i, (unsigned long long)echoed_ok.load(),
                 (unsigned long long)mismatches.load(), established.load() ? 1 : 0);
    if (0 < secs) {
        std::fprintf(stderr, "[client] %u msgs x %u B in %.3fs = %.1f KiB/s\n",
                     i, size, secs, (double)echoed_bytes.load() / 1024.0 / secs);
    }
    client_stack.Close(conn);
    const auto t2 = std::chrono::steady_clock::now();
    server_thread.join();
    const auto t3 = std::chrono::steady_clock::now();
    std::fprintf(stderr, "[echo] close->join %.0f ms\n",
                 std::chrono::duration<double, std::milli>(t3 - t2).count());
    xtcp::buf::ShutdownPools();
    return (0 < mismatches.load(std::memory_order_relaxed) || i < msgs) ? 1 : 0;
}

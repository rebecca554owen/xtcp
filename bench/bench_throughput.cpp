/**
 * @file bench_throughput.cpp
 * @brief Back-to-back stack throughput benchmark: two XtcpStack instances
 *        over manual backends; measures pure protocol-processing rate.
 *
 * Output: JSON lines (bytes, seconds, mbps, kpps).
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/qdisc/qdisc.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {
    typedef std::chrono::steady_clock Clock;

    struct Bench {
        UInt64 bytes_sent = 0;
        UInt64 bytes_recv = 0;
        UInt64 pumps = 0;
    };

    void Pump(xtcp::ndi::ManualBackend& from, xtcp::ndi::ManualBackend& to, UInt16 eth_type, Bench& bench) {
        Byte out[65536];
        while (0 != from.TxPending()) {
            const UInt32 got = from.PollTx(out);
            if (0 == got) {
                break;
            }
            to.Inject(out, got, eth_type);
            ++bench.pumps;
        }
    }

    Double RunRoundTrip(UInt64 total_bytes, UInt32 chunk, Int32 qdisc_mode, bool quickack,
                        const char* cc_name, UInt32 sleep_ms) {
        xtcp::ndi::ManualBackend backend_a;
        xtcp::ndi::ManualBackend backend_b;
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);
        if (NULLPTR != cc_name && 0 != cc_name[0]) {
            stack_a.SetDefaultCongestionControl(cc_name);
            stack_b.SetDefaultCongestionControl(cc_name);
        }
        xtcp::qdisc::XtcpQdisc* qdisc = NULLPTR;
        if (0 != qdisc_mode) {
            xtcp::qdisc::RegisterFqDefault();
            xtcp::qdisc::QdiscParams params;
            params.pacing_enabled = (1 == qdisc_mode);
            qdisc = xtcp::qdisc::CreateQdisc("fq", params);
            if (NULLPTR != qdisc) {
                stack_b.SetTxQdisc(qdisc);
            }
        } else if (0 > qdisc_mode) {
            // Null qdisc (no lock, no logic, pass-through): isolates the
            // per-packet path cost (enqueue+drain+dequeue vs direct Tx).
            struct NullQ {
                xtcp::buf::BufRef held;
                xtcp::buf::BufRef held2;
            };
            xtcp::qdisc::RegisterQdisc([]() -> const xtcp::qdisc::XtcpQdiscOps& {
                static xtcp::qdisc::XtcpQdiscOps ops;
                ops.name = "null";
                ops.init = [](xtcp::qdisc::XtcpQdisc* q, const xtcp::qdisc::QdiscParams*) {
                    q->private_data = new (std::nothrow) NullQ();
                    return (NULLPTR == q->private_data) ? -1 : 0;
                };
                ops.destroy = [](xtcp::qdisc::XtcpQdisc* q) {
                    delete static_cast<NullQ*>(q->private_data);
                    q->private_data = NULLPTR;
                };
                ops.enqueue = [](xtcp::qdisc::XtcpQdisc* q, UInt64, xtcp::buf::BufRef&& p) {
                    if (p.IsEmpty() || 0 == p.Len()) return -1;
                    static_cast<NullQ*>(q->private_data)->held = std::move(p);
                    return 0;
                };
                ops.dequeue = [](xtcp::qdisc::XtcpQdisc* q, xtcp::core::TimePoint, xtcp::core::TimePoint* next) {
                    if (next) *next = 0;
                    NullQ* nq = static_cast<NullQ*>(q->private_data);
                    if (nq->held.IsEmpty()) return xtcp::buf::BufRef();
                    xtcp::buf::BufRef out = std::move(nq->held);
                    return out;
                };
                ops.has_backlog = [](const xtcp::qdisc::XtcpQdisc* q) {
                    const NullQ* nq = static_cast<const NullQ*>(q->private_data);
                    return !nq->held.IsEmpty();
                };
                ops.enqueue_drain = [](xtcp::qdisc::XtcpQdisc* q, UInt64, xtcp::buf::BufRef&& p,
                                       xtcp::core::TimePoint, xtcp::buf::BufRef* out,
                                       xtcp::core::TimePoint* next) {
                    if (next) *next = 0;
                    if (NULLPTR != out) *out = xtcp::buf::BufRef();
                    if (p.IsEmpty() || 0 == p.Len()) return -1;
                    NullQ* nq = static_cast<NullQ*>(q->private_data);
                    if (!nq->held.IsEmpty()) {  // backlog: queue behind it
                        nq->held2 = std::move(p);
                        return 0;
                    }
                    if (NULLPTR != out) *out = std::move(p);  // empty: emit now
                    return 0;
                };
                ops.change = [](xtcp::qdisc::XtcpQdisc*, const xtcp::qdisc::QdiscParams*) { return 0; };
                ops.reset = [](xtcp::qdisc::XtcpQdisc* q) {
                    static_cast<NullQ*>(q->private_data)->held = xtcp::buf::BufRef();
                };
                return ops;
            }());
            xtcp::qdisc::QdiscParams params;
            qdisc = xtcp::qdisc::CreateQdisc("null", params);
            if (NULLPTR != qdisc) {
                stack_b.SetTxQdisc(qdisc);
            }
        }

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

        Bench bench;
        UInt64 receiver_conn = 0;
        bool quickack_set = false;
        stack_b.SetRecvHandler([&bench, &receiver_conn](UInt64 conn_id, const Byte*, UInt32 len) {
            bench.bytes_recv += len;
            if (0 == receiver_conn) {
                receiver_conn = conn_id;
            }
        });

        const UInt16 eth_type = 0x0800;
        xtcp::core::Endpoint local_a, remote_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = 40000;
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = 443;

        stack_b.Listen(remote_a);
        const UInt64 conn = stack_a.Connect(local_a, remote_a);
        if (0 == conn) {
            return 0.0;
        }
        // Throughput benchmark: measure the ideal send rate, so disable
        // Nagle (RFC 896) - small chunks would otherwise wait for ACKs.
        const Int32 on = 1;
        stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on));
        // Handshake.
        Pump(backend_a, backend_b, eth_type, bench);
        Pump(backend_b, backend_a, eth_type, bench);
        Pump(backend_a, backend_b, eth_type, bench);

        std::vector<Byte> payload(chunk);
        std::memset(payload.data(), 0x5A, payload.size());

        const auto start = Clock::now();
        UInt64 guard = 0;
        while (bench.bytes_recv < total_bytes) {
            // Send as much as the window allows. The target check runs
            // before Send() so a chunk is never accepted-and-counted past
            // the goal (the condition-call ordering would over-accept one
            // chunk, breaking the sent==recv accounting).
            bool sent_any = false;
            UInt32 inner = 0;
            while (bench.bytes_recv < total_bytes && bench.bytes_sent < total_bytes && inner < 1000000) {
                if (!stack_a.Send(conn, payload.data(), chunk)) {
                    break;
                }
                bench.bytes_sent += chunk;
                sent_any = true;
                Pump(backend_a, backend_b, eth_type, bench);
                Pump(backend_b, backend_a, eth_type, bench);
                ++inner;
            }
            if (!sent_any) {
                // Window full: drain ACKs by pumping one round.
                Pump(backend_b, backend_a, eth_type, bench);
                Pump(backend_a, backend_b, eth_type, bench);
            }
            // ACK every received segment immediately once the receiver
            // connection id is known: a super-MSS chunk (chunk > MSS) is
            // segmented, and the odd trailing segment would otherwise wait
            // the full delayed-ACK interval, stalling the next chunk behind
            // the send-buffer quota.
            if (0 != receiver_conn && !quickack_set) {
                if (quickack) {
                    stack_b.SetOption(receiver_conn, xtcp::options::kTcpQuickack, &on, sizeof(on));
                }
                quickack_set = true;
            }
            // Delayed-ACK / RTO / persist timers drive the buffered sends;
            // without this the >MSS chunks stall at the send buffer.
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (1000000 < ++guard) {
                break;  // safety
            }
            if (0 < sleep_ms) {
                std::this_thread::sleep_for(std::chrono::microseconds(sleep_ms));
            }
        }
        // Deliver any bytes still buffered in flight (Send() may have
        // accepted one chunk more than the receiver has drained), so the
        // reported sent/received counts converge.
        UInt32 drain_guard = 0;
        while (bench.bytes_recv < bench.bytes_sent && 1000000 > ++drain_guard) {
            Pump(backend_b, backend_a, eth_type, bench);
            Pump(backend_a, backend_b, eth_type, bench);
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
        }
        const auto end = Clock::now();
        const Double seconds = std::chrono::duration<Double>(end - start).count();
        if (NULLPTR != qdisc) {
            xtcp::qdisc::DestroyQdisc(qdisc);
        }

        // Report on the actually received bytes.
        const Double mbps = (bench.bytes_recv * 8.0) / 1000000.0 / seconds;
        const Double kpps = (bench.pumps) / 1000.0 / seconds;
        std::printf("{\"bytes_sent\":%llu,\"bytes_recv\":%llu,\"seconds\":%.6f,\"mbps\":%.2f,\"kpps\":%.2f}\n",
                    (unsigned long long)bench.bytes_sent,
                    (unsigned long long)bench.bytes_recv,
                    seconds, mbps, kpps);
        return mbps;
    }
}

int main(int argc, char** argv) {
    UInt64 total = 64ull * 1024 * 1024;  // 64 MB default
    UInt32 chunk = 1024;
    Int32 qdisc_mode = 0;
    bool quickack = true;
    if (2 <= argc) {
        total = static_cast<UInt64>(std::strtoull(argv[1], NULLPTR, 10));
    }
    if (3 <= argc) {
        chunk = static_cast<UInt32>(std::strtoul(argv[2], NULLPTR, 10));
    }
    if (4 <= argc) {
        qdisc_mode = static_cast<Int32>(std::strtol(argv[3], NULLPTR, 10));
    }
    if (5 <= argc) {
        quickack = (0 != std::strtol(argv[4], NULLPTR, 10));
    }
    const char* cc_name = (6 <= argc) ? argv[5] : NULLPTR;
    UInt32 sleep_ms = 0;
    if (7 <= argc) {
        sleep_ms = static_cast<UInt32>(std::strtoul(argv[6], NULLPTR, 10));
    }
    xtcp::buf::InitPools();

    const UInt32 kRounds = 3;
    Double best = 0.0;
    for (UInt32 r = 0; r < kRounds; ++r) {
        const Double mbps = RunRoundTrip(total, chunk, qdisc_mode, quickack, cc_name, sleep_ms);
        if (mbps > best) {
            best = mbps;
        }
    }
    std::printf("{\"best_mbps\":%.2f,\"rounds\":%u,\"chunk\":%u,\"qdisc\":%d,\"quickack\":%d,\"cc\":\"%s\",\"sleep_us\":%u}\n",
                best, kRounds, chunk, qdisc_mode, quickack ? 1 : 0,
                (NULLPTR != cc_name && 0 != cc_name[0]) ? cc_name : "kcc", sleep_ms);

    xtcp::buf::ShutdownPools();
    return 0;
}

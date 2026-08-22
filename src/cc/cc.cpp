/**
 * @file cc.cpp
 * @brief CC registry implementation (kernel tcp_register_congestion_control
 *        semantics).
 */

#include <xtcp/cc/cc.h>

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

namespace xtcp {
    namespace cc {
        namespace {
            std::mutex g_syncobj;
            std::unordered_map<std::string, XtcpCongestionOps> g_registry;
            std::atomic<bool> g_builtin_registered{false};
        }

        void RegisterBuiltinCc() noexcept {
            // Register first, THEN set the flag: a concurrent caller must
            // never see "registered" while the built-ins are still missing
            // (otherwise FindCongestionControl returns NULL and connections
            // silently fall back to Reno).
            if (g_builtin_registered.load(std::memory_order_acquire)) {
                return;
            }
            RegisterKcc();
            RegisterBbrv1();
            RegisterCubic();
            g_builtin_registered.store(true, std::memory_order_release);
        }

        bool RegisterCongestionControl(const XtcpCongestionOps& ops) noexcept {
            if (NULLPTR == ops.name) {
                return false;
            }
            std::lock_guard<std::mutex> scope(g_syncobj);
            auto it = g_registry.find(ops.name);
            if (it != g_registry.end() && NULLPTR != it->second.name) {
                return false;  // an active algorithm already holds the name
            }
            // Overwrite (new entry or a disabled one): keeps previously
            // returned pointers valid (no UAF).
            g_registry[ops.name] = ops;
            return true;
        }

        bool UnregisterCongestionControl(const char* name) noexcept {
            std::lock_guard<std::mutex> scope(g_syncobj);
            auto it = g_registry.find(NULLPTR != name ? name : "");
            if (it == g_registry.end()) {
                return false;
            }
            // Mark disabled instead of erasing: connections holding the ops
            // pointer from FindCongestionControl keep a valid (read-only)
            // structure - erasing would leave them dangling (UAF).
            it->second.name = NULLPTR;
            return true;
        }

        const XtcpCongestionOps* FindCongestionControl(const char* name) noexcept {
            std::lock_guard<std::mutex> scope(g_syncobj);
            auto it = g_registry.find(NULLPTR != name ? name : "");
            if (it == g_registry.end() || NULLPTR == it->second.name) {
                return NULLPTR;  // missing or disabled
            }
            return &it->second;
        }

        bool GetCongestionControl(const char* name, XtcpCongestionOps& out) noexcept {
            std::lock_guard<std::mutex> scope(g_syncobj);
            auto it = g_registry.find(NULLPTR != name ? name : "");
            if (it == g_registry.end() || NULLPTR == it->second.name) {
                return false;  // missing or disabled
            }
            out = it->second;  // atomic struct copy under g_syncobj
            return true;
        }

        void ApplyRateSample(XtcpConnCc* sk, const XtcpCongestionOps* ops, const RateSample* rs,
                             UInt32 ack) noexcept {
            if (NULLPTR == sk || NULLPTR == ops || NULLPTR == rs) {
                return;
            }
            if (NULLPTR != ops->cong_control) {
                ops->cong_control(sk, rs);
                return;
            }
            // Classic path: pkts_acked + cong_avoid.
            if (NULLPTR != ops->pkts_acked && 0 < rs->rtt_us) {
                AckSample sample;
                sample.rtt_us = rs->rtt_us;
                sample.acked = rs->acked;
                sample.delivered = rs->delivered;
                sample.inflight = sk->inflight;
                ops->pkts_acked(sk, &sample);
            }
            if (NULLPTR != ops->cong_avoid) {
                // Kernel tcp_cong_avoid(sk, ack, acked) semantics: ack is the
                // ACKed sequence number, NOT the congestion window (the
                // window is read from sk). Passing snd_cwnd here would hand
                // a classic-path plugin a window size where it expects an
                // ACK (contract violation, cc.h:64).
                ops->cong_avoid(sk, ack, rs->acked);
            }
        }
    }
}

/**
 * @file async.cpp
 * @brief Async Proactor layer implementation.
 */

#include <xtcp/async/async.h>

#include <mutex>
#include <vector>

namespace xtcp {
    namespace async {
        namespace {
            // Guards all AsyncStack shared state: pending_connects_,
            // connect_done_, accept_done_ and accept_cbs_ (a single file-scope
            // mutex keeps the fix inside this translation unit; contention is
            // negligible for connect/listen/poll completion traffic).
            //
            // Lock ordering (deadlock-freedom): the state handler and the
            // MIMT on-flow callback are invoked by the stack with the shard
            // lock held, so they take this mutex AFTER the shard lock.
            // Poll()/AsyncConnect()/AsyncListen() therefore never hold this
            // mutex while acquiring a shard lock: ConnectionState()/Listen()/
            // Connect() are queried outside the critical section.
            std::mutex g_async_mutex;
        }

        AsyncStack::AsyncStack(ndi::Backend* backend) noexcept : stack_(backend) {
            // Bind the stack state handler to drive connect completions.
            // kEstablished -> success; kClosed -> failure (RST, or a close
            // before the handshake completed); any other state is still an
            // in-progress handshake and the entry stays pending.
            stack_.SetStateHandler([this](UInt64 conn_id, core::TcpState state) {
                if (core::TcpState::kEstablished != state && core::TcpState::kClosed != state) {
                    return;
                }
                std::lock_guard<std::mutex> lock(g_async_mutex);
                auto it = pending_connects_.find(conn_id);
                if (it == pending_connects_.end()) {
                    // Not a tracked connect (or already completed).
                    return;
                }
                PendingConnect p = std::move(it->second);
                pending_connects_.erase(it);
                p.conn_id = conn_id;
                p.failed = (core::TcpState::kEstablished != state);
                connect_done_.push_back(std::move(p));
            });
        }

        void AsyncStack::AsyncConnect(const core::Endpoint& local, const core::Endpoint& remote,
                                      ConnectHandler cb) noexcept {
            if (!cb) {
                return;
            }
            const UInt64 id = stack_.Connect(local, remote);
            if (0 == id) {
                // Immediate failure: queue a completion fired on Poll().
                PendingConnect p;
                p.cb = std::move(cb);
                p.conn_id = 0;
                p.failed = true;
                std::lock_guard<std::mutex> lock(g_async_mutex);
                connect_done_.push_back(std::move(p));
                return;
            }
            PendingConnect p;
            p.cb = std::move(cb);
            p.conn_id = id;
            p.failed = false;
            std::lock_guard<std::mutex> lock(g_async_mutex);
            pending_connects_[id] = std::move(p);
        }

        bool AsyncStack::AsyncListen(const core::Endpoint& local, AcceptHandler cb) noexcept {
            if (!cb) {
                return false;
            }
            if (!stack_.Listen(local)) {
                // Listen failed (e.g. EADDRINUSE): keep the previous accept
                // callback untouched and do not arm the MIMT flow delivery.
                // The async layer has no per-listen completion to carry the
                // error through Poll(), so the failure is reported to the
                // caller synchronously via the return value.
                return false;
            }
            // Per-listener accept callback (Bug E): a second AsyncListen on a
            // DIFFERENT port must not clobber the first listener's callback.
            // Every listener is routed by EndpointKey(local); accepted flows
            // carry the same key (stamped by the stack at delivery), so Poll()
            // delivers each accept to its own listener's handler.
            const UInt64 key = EndpointKey(local);
            {
                std::lock_guard<std::mutex> lock(g_async_mutex);
                accept_cbs_[key] = std::move(cb);
            }
            // All listeners share the single MIMT flow-delivery hook; the
            // flow's listener key selects the correct per-listener callback.
            stack_.StartMimt([this](std::shared_ptr<mimt::MimtFlow> flow) {
                // Accept is delivered via Poll() (async dispatch guarantee).
                std::lock_guard<std::mutex> lock(g_async_mutex);
                accept_done_.push_back(AcceptEntry{
                    flow->ListenerKey(),
                    [flow](AcceptHandler h) { h(flow); },
                });
            });
            return true;
        }

        bool AsyncStack::AsyncStopListen(const core::Endpoint& local) noexcept {
            // Remove the per-listener accept callback (under g_async_mutex)
            // FIRST, then stop the underlying stack listener (its syncobj_ is
            // acquired WITHOUT g_async_mutex, preserving the lock order). A
            // queued-but-undelivered accept for this listener is still
            // dispatched by Poll() to the removed handler slot - the callback
            // reference is released at the erase, so the dispatch is a no-op.
            const UInt64 key = EndpointKey(local);
            bool had_cb = false;
            {
                std::lock_guard<std::mutex> lock(g_async_mutex);
                had_cb = (0 < accept_cbs_.erase(key));
            }
            const bool stopped = stack_.StopListen(local);
            return had_cb || stopped;
        }

        UInt32 AsyncStack::Poll() noexcept {
            UInt32 fired = stack_.DispatchMimt();
            // Pending-connect sweep: a connect can reach kEstablished/kClosed
            // with no further segment for the state handler to observe (the
            // handshake completion raced registration, or the SYN handshake
            // timed out with no peer packet at all). Re-check each pending
            // connection's state directly. ConnectionState() takes a shard
            // lock, so it is read OUTSIDE g_async_mutex (lock ordering); the
            // completion is re-validated under the lock so exactly one path
            // (handler or sweep) delivers the result (strict 1:1).
            std::vector<UInt64> candidates;
            {
                std::lock_guard<std::mutex> lock(g_async_mutex);
                candidates.reserve(pending_connects_.size());
                for (const auto& kv : pending_connects_) {
                    candidates.push_back(kv.first);
                }
            }
            for (UInt64 id : candidates) {
                const core::TcpState state = stack_.ConnectionState(id);
                if (core::TcpState::kEstablished != state && core::TcpState::kClosed != state) {
                    continue;
                }
                std::lock_guard<std::mutex> lock(g_async_mutex);
                auto it = pending_connects_.find(id);
                if (it == pending_connects_.end()) {
                    continue;  // the state handler already completed it
                }
                PendingConnect p = std::move(it->second);
                pending_connects_.erase(it);
                p.conn_id = id;
                p.failed = (core::TcpState::kClosed == state);
                connect_done_.push_back(std::move(p));
            }
            // Connect completions (fired outside the lock: user callbacks may
            // re-enter AsyncConnect/AsyncListen).
            std::deque<PendingConnect> connects;
            {
                std::lock_guard<std::mutex> lock(g_async_mutex);
                connects.swap(connect_done_);
            }
            for (PendingConnect& p : connects) {
                if (p.cb) {
                    p.cb(p.failed ? Result::kClosed : Result::kOk, p.conn_id);
                    ++fired;
                }
            }
            // Accept completions: route each flow to its own listener's
            // callback (Bug E). Handlers are snapshotted under the lock, the
            // user callbacks fire outside it.
            std::deque<AcceptEntry> accepts;
            std::vector<AcceptHandler> handlers;
            {
                std::lock_guard<std::mutex> lock(g_async_mutex);
                accepts.swap(accept_done_);
                handlers.reserve(accepts.size());
                for (const AcceptEntry& entry : accepts) {
                    auto it = accept_cbs_.find(entry.key);
                    handlers.push_back((it == accept_cbs_.end()) ? AcceptHandler()
                                                                 : it->second);
                }
            }
            for (size_t i = 0; i < accepts.size(); ++i) {
                if (accepts[i].dispatch && handlers[i]) {
                    accepts[i].dispatch(handlers[i]);
                    ++fired;
                }
            }
            return fired;
        }
    }
}

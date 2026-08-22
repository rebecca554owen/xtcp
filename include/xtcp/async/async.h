#pragma once

/**
 * @file async.h
 * @brief Async Proactor layer (G14): AsyncConnect/AsyncListen over
 *        XtcpStack. Completion callbacks are guaranteed async — they fire
 *        from Poll(), never on the initiator's stack. No built-in
 *        coroutines; users may wrap with their own.
 */

#include <xtcp/stdafx.h>
#include <xtcp/ndi.h>
#include <xtcp/core/stack.h>
#include <xtcp/mimt/mimt.h>

#include <deque>
#include <memory>
#include <unordered_map>

namespace xtcp {
    namespace async {
        using xtcp::mimt::Result;

        /**
         * @brief Connect completion handler.
         * @param ec     Result code.
         * @param conn_id Connection id (0 only when the connect failed IMMEDIATELY,
 *        i.e. the stack rejected it synchronously; a failure that surfaces
 *        later - RST, SYN timeout - delivers the real (nonzero) id so the
 *        app can clean up).
         */
        typedef std::function<void(Result ec, UInt64 conn_id)> ConnectHandler;
        /**
         * @brief Accepted-flow handler (listen side).
         * @warning Shares the name with xtcp::AcceptHandler (core/stack.h) but
         *          has a DIFFERENT signature (void(shared_ptr<mimt::MimtFlow>)
         *          vs bool(conn_id,remote,local)). Bringing both namespaces
         *          into scope with `using namespace xtcp; using namespace
         *          xtcp::async;` makes the name ambiguous - qualify it
         *          (xtcp::async::AcceptHandler / xtcp::AcceptHandler) instead.
         */
        typedef std::function<void(std::shared_ptr<mimt::MimtFlow> flow)> AcceptHandler;

        /**
         * @brief Async stack facade (Proactor).
         */
        class AsyncStack {
        public:
            explicit AsyncStack(ndi::Backend* backend) noexcept;
            virtual ~AsyncStack() noexcept = default;

            /**
             * @brief Initiates a connection; completion fires on Poll().
             * @note Failure completions (RST, SYN retransmission timeout) are
             *       triggered by the connection reclamation driven by
             *       PollAckTimers() - applications that only call Poll() must
             *       periodically call Stack().PollAckTimers() as well, or a
             *       dead-port/timeout connect never completes.
             */
            void AsyncConnect(const core::Endpoint& local, const core::Endpoint& remote,
                              ConnectHandler cb) noexcept;
            /**
             * @brief Listens and delivers each accepted connection as a flow
             *        (completion fires on Poll()).
             * @return true when the listener was registered (accepted flows
             *         will be delivered); false on failure - a duplicate or
             *         wildcard-conflicting endpoint (EADDRINUSE semantics of
             *         the underlying Listen) or a null callback - in which
             *         case no listener is registered, the previous accept
             *         callback on that endpoint is left untouched, and the
             *         callback never fires.
             */
            bool AsyncListen(const core::Endpoint& local, AcceptHandler cb) noexcept;
            /**
             * @brief Stops a listener: removes the accept callback AND stops
             *        the underlying stack listener, so no further flows are
             *        delivered to the handler for that endpoint.
             * @param local The listener endpoint.
             * @return true when the listener + its accept callback existed and
             *         were removed.
             */
            bool AsyncStopListen(const core::Endpoint& local) noexcept;
            /**
             * @brief Feeds a received packet (backend rx).
             */
            void OnPacket(buf::BufRef&& packet) noexcept { stack_.OnPacket(std::move(packet)); }
            /**
             * @brief Dispatches all pending completions (event loop).
             * @return Number of completions dispatched.
             */
            UInt32 Poll() noexcept;
            /**
             * @brief Access to the underlying stack (Send/Close).
             */
            XtcpStack& Stack() noexcept { return stack_; }

        private:
            struct PendingConnect {
                ConnectHandler cb;
                UInt64         conn_id = 0;
                bool           failed  = false;
            };
            typedef std::function<void(AcceptHandler)> AcceptDispatch;
            /**
             * @brief A queued accept completion: the routing key of the
             *        listener that accepted the flow plus the dispatcher that
             *        delivers the flow to the accept handler.
             */
            struct AcceptEntry {
                UInt64        key = 0;  /**< EndpointKey(local) of the accepting listener */
                AcceptDispatch dispatch;
            };

            XtcpStack   stack_;
            std::deque<PendingConnect> connect_done_;
            std::deque<AcceptEntry>     accept_done_;
            std::unordered_map<UInt64, PendingConnect> pending_connects_;
            /** Per-listener accept handlers (keyed by EndpointKey(local)):
             *  each listener routes its accepted flows to its own callback
             *  instead of one stack-wide callback that a second AsyncListen
             *  would clobber (Bug E). */
            std::unordered_map<UInt64, AcceptHandler> accept_cbs_;
        };
    }
}

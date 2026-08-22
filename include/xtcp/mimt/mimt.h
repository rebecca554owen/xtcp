#pragma once

/**
 * @file mimt.h
 * @brief MIMT (audit-mode) flow: a TCP stream delivered to the application
 *        as async Proactor callbacks. The peer sees a normal connection to
 *        the real destination; the user controls read/write.
 *
 * Completion callbacks are guaranteed to be dispatched asynchronously (never
 * on the initiator's stack): they fire from Dispatch(), which the owning
 * event loop calls outside the rx/send paths. The ONE exception: an
 * AsyncClose issued on an ALREADY-closed flow must still complete its
 * caller's handler exactly once (1:1), so it fires the cached kClosed
 * completion inline after releasing the lock (no reentrancy - the flow is
 * already terminal).
 */

#include <xtcp/stdafx.h>

#include <deque>
#include <functional>
#include <mutex>
#include <vector>

namespace xtcp {
    namespace mimt {
        /**
         * @brief Result code.
         */
        enum class Result : Int32 {
            kOk        = 0,
            kWouldBlock = -1,
            kInvalid   = -2,
            kClosed    = -3,
            kInFlight  = -4,   /**< Operation already pending (1:1 rule) */
            kNoBuffer  = -5,
        };

        /**
         * @brief Read completion handler.
         * @param ec   Result code.
         * @param bytes Bytes transferred.
         */
        typedef std::function<void(Result ec, UInt32 bytes)> ReadHandler;
        /**
         * @brief Write completion handler.
         */
        typedef std::function<void(Result ec, UInt32 bytes)> WriteHandler;
        /**
         * @brief Close completion handler.
         */
        typedef std::function<void(Result ec)> CloseHandler;
        /**
         * @brief Received-data source (rx path feeds the flow).
         */
        typedef std::function<void(const Byte* data, UInt32 len)> RxSource;

        /**
         * @brief MIMT audit flow (async Proactor stream).
         */
        class MimtFlow {
        public:
            MimtFlow() = default;
            virtual ~MimtFlow() noexcept = default;

            MimtFlow(const MimtFlow&) = delete;
            MimtFlow& operator=(const MimtFlow&) = delete;

            /**
             * @brief Requests an async read.
             * @param buf Destination buffer.
             * @param len Capacity.
             * @param cb  Completion handler.
             * @return kOk (completion queued), kInFlight when a read is
             *         already pending (strict 1:1 pairing), kClosed when the
             *         flow is already closed, or kInvalid for NULLPTR/zero-length
             *         buffers or a missing callback.
             * @note THREAD SAFETY: every entry point serializes on a flow-local
             *          mutex, so AsyncRead/AsyncWrite/AsyncClose may be issued
             *          from a user thread concurrently with the event loop's
             *          Dispatch* (pinned by test_mimt_threads). Completion
             *          callbacks fire OUTSIDE the lock, so a callback may
             *          re-enter Async* freely. The completion callbacks
             *          themselves run on the thread that calls Dispatch().
             * @warning The buffer is NOT filled during the call: Dispatch()
             *          fills it (and fires the completion) asynchronously. @a buf
             *          must therefore stay valid until the completion callback
             *          fires after the owning event loop calls Dispatch() -
             *          passing a stack/transient buffer that goes out of scope
             *          first is a use-after-free (Dispatch may never run before
             *          the caller's stack unwinds).
             * @note FILL SEMANTICS: the completion delivers min(len, bytes
             *          buffered at dispatch time) - the read drains consecutive
             *          queued chunks up to @p len and short-reads ONLY when the
             *          queue runs out (stream semantics; wire segmentation is
             *          never exposed as artificial read boundaries). Exactly one
             *          completion fires per accepted AsyncRead (1:1 pairing).
             */
            Result AsyncRead(void* buf, UInt32 len, ReadHandler cb) noexcept;
            /**
             * @brief Requests an async write.
             * @param buf Source data (referenced only during the call).
             * @param len Length.
             * @param cb  Completion handler.
             * @return kOk (completion queued), kInFlight when the flow's write
             *         queue is full (bounded): the writer is outpacing the
             *         sink, so the caller must wait for a write completion
             *         before reissuing. The queue is bounded - it never grows
             *         without limit. kClosed when the flow is already closed,
             *         kInvalid for NULLPTR/zero-length buffers or a missing
             *         callback.
             * @note THREAD SAFETY: AsyncWrite is serialized on the flow-local
             *          mutex - user-thread calls are safe concurrently with
             *          the event loop's Dispatch* (completion callbacks fire
             *          outside the lock).
             */
            Result AsyncWrite(const void* buf, UInt32 len, WriteHandler cb) noexcept;
            /**
             * @brief Requests an async close.
             * @warning Limitation: this completes every pending async
             *          operation (1:1 pairing) but does NOT propagate a
             *          FIN/close to the underlying TCP connection - the peer
             *          never sees a close from this layer. Closing the peer
             *          side is the owning stack's responsibility (see the
             *          implementation note in mimt.cpp).
             */
            Result AsyncClose(CloseHandler cb) noexcept;
            /**
             * @brief Feeds received data into the flow (rx path).
             * @return kOk when buffered, kClosed when the flow is closed,
             *         kNoBuffer when the rx queue is full (drop-tail: the
             *         chunk was NOT consumed - the data is lost unless the
             *         caller re-presents it later).
             */
            Result OnData(const Byte* data, UInt32 len) noexcept;
            /**
             * @brief Dispatches pending completions (must be called by the
             *        owning event loop; never inside the rx path).
             * @return Number of completions dispatched.
             * @note THREAD SAFETY: Dispatch is serialized on the flow-local
             *          mutex, so it may be called from a user thread
             *          concurrently with Async*. The write sink is invoked
             *          OUTSIDE the flow lock (lock order is uniformly shard
             *          -> flow - the old sink-under-lock path was a deadlock
             *          pair, eliminated with the DispatchWrite rework), so a
             *          user-thread Dispatch no longer inverts shard/flow
             *          ordering. Prefer calling Dispatch from the event-loop
             *          thread regardless: the completion callbacks run on the
             *          calling thread, and a flow must NOT be destroyed on
             *          another thread while this one is mid-Dispatch (the
             *          sink loop runs without the flow lock).
             */
            UInt32 Dispatch() noexcept;
            /**
             * @brief Installs the write sink (emits application data to the
             *        connection).
             */
            void SetWriteSink(std::function<bool(const Byte*, UInt32)> sink) noexcept {
                write_sink_ = std::move(sink);
            }

            bool IsClosed() const noexcept { return closed_; }
            /**
             * @brief Forcibly closes the flow (owning-stack reclaim path).
             *        Marks the flow closed and completes EVERY pending async
             *        operation exactly once with kClosed - once the underlying
             *        connection is reclaimed this flow is never dispatched
             *        again, so any pending AsyncRead/AsyncWrite would otherwise
             *        hang forever. Idempotent (safe to call after AsyncClose).
             */
            void Close() noexcept;

            /**
             * @brief Sets the routing key of the accepting listener (which
             *        local endpoint accepted this flow). Set by the owning
             *        stack when the flow is delivered; the async layer uses it
             *        to route the accept to the per-listener callback.
             */
            void SetListenerKey(UInt64 key) noexcept { listener_key_ = key; }
            /**
             * @brief The routing key of the accepting listener (0 when the
             *        stack did not stamp one).
             */
            UInt64 ListenerKey() const noexcept { return listener_key_; }

        private:
            struct PendingRead {
                void*       buf = NULLPTR;
                UInt32      len = 0;
                ReadHandler cb;
            };
            struct PendingWrite {
                std::vector<Byte> data;
                UInt32            offset = 0;
                WriteHandler      cb;
            };
            struct PendingClose {
                CloseHandler cb;
            };

            bool DispatchRead() noexcept;
            bool DispatchWrite() noexcept;
            bool DispatchClose() noexcept;

            std::deque<std::vector<Byte>> rx_queue_;
            UInt32        rx_queued_ = 0;  /**< Running total bytes in rx_queue_ (O(1) OnData cap check) */
            PendingRead   pending_read_;
            bool          read_pending_ = false;
            std::deque<PendingWrite> write_queue_;
            bool          write_pending_ = false;
            PendingClose  pending_close_;
            bool          close_pending_ = false;
            std::function<bool(const Byte*, UInt32)> write_sink_;
            bool          closed_ = false;
            UInt64        listener_key_ = 0;  /**< Accept-routing key (which listener accepted this flow) */
            /**
             * @brief Serializes all flow state (async ops vs event-loop
             *        dispatch). The lock order is always shard -> flow
             *        (OnData and Dispatch* run under the shard lock; Async*
             *        from user threads take only the flow lock), so no
             *        inversion exists. Completion callbacks fire OUTSIDE the
             *        lock so an app callback may re-enter Async* freely.
             */
            mutable std::mutex sync_;
        };
    }
}

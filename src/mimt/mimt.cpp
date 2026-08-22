/**
 * @file mimt.cpp
 * @brief MIMT async flow implementation (Proactor, async dispatch).
 *
 * Thread model: every public entry point serializes on sync_ (a flow-local
 * mutex). The event loop calls OnData / Dispatch* under the stack's shard
 * lock (shard -> flow order); user threads call Async* taking only the flow
 * lock - no lock-order inversion exists. Completion callbacks are fired
 * OUTSIDE sync_ so an app callback may re-enter Async* freely.
 */

#include <xtcp/mimt/mimt.h>

#include <mutex>

namespace {
    /** Max bytes buffered in a flow's rx queue before OnData drops (drop-tail). */
    constexpr UInt32 kRxQueueByteCap = 1U * 1024U * 1024U;
    /** Max queued async writes per flow: a writer that outpaces the sink is
     *  refused with kInFlight instead of growing write_queue_ without bound. */
    constexpr UInt32 kWriteQueueCap = 16;
}

namespace xtcp {
    namespace mimt {
        Result MimtFlow::OnData(const Byte* data, UInt32 len) noexcept {
            std::lock_guard<std::mutex> scope(sync_);
            if (closed_) {
                return Result::kClosed;
            }
            if (0 == len) {
                return Result::kOk;
            }
            if (len > kRxQueueByteCap) {
                return Result::kNoBuffer;  // drop: single chunk over capacity
            }
            if (rx_queued_ + len > kRxQueueByteCap) {
                return Result::kNoBuffer;  // drop: rx queue over capacity
            }
            std::vector<Byte> chunk(data, data + len);
            rx_queue_.push_back(std::move(chunk));
            rx_queued_ += len;
            return Result::kOk;
        }

        Result MimtFlow::AsyncRead(void* buf, UInt32 len, ReadHandler cb) noexcept {
            std::lock_guard<std::mutex> scope(sync_);
            if (closed_) {
                return Result::kClosed;
            }
            if (read_pending_) {
                return Result::kInFlight;  // strict 1:1 pairing
            }
            if (NULLPTR == buf || 0 == len || !cb) {
                return Result::kInvalid;
            }
            // Park the request; Dispatch() fills the buffer and fires the
            // completion when data arrives (async dispatch guarantee).
            PendingRead p;
            p.buf = buf;
            p.len = len;
            p.cb = std::move(cb);
            pending_read_ = std::move(p);
            read_pending_ = true;
            return Result::kOk;
        }

        Result MimtFlow::AsyncWrite(const void* buf, UInt32 len, WriteHandler cb) noexcept {
            std::lock_guard<std::mutex> scope(sync_);
            if (closed_) {
                return Result::kClosed;
            }
            // Bounded write queue (Bug C): a writer that fills the queue faster
            // than the sink drains it must NOT grow write_queue_ without bound.
            // kInFlight tells the caller a write is still in flight - reissue
            // once a completion fires (the queue drains toward the sink).
            if (write_queue_.size() >= kWriteQueueCap) {
                return Result::kInFlight;
            }
            if (NULLPTR == buf || 0 == len || !cb) {
                return Result::kInvalid;
            }
            PendingWrite p;
            p.data.assign(static_cast<const Byte*>(buf), static_cast<const Byte*>(buf) + len);
            p.cb = std::move(cb);
            write_queue_.push_back(std::move(p));
            write_pending_ = true;
            return Result::kOk;
        }

        Result MimtFlow::AsyncClose(CloseHandler cb) noexcept {
            std::unique_lock<std::mutex> scope(sync_);
            // Documented limitation: closing the local flow completes all
            // pending async operations (1:1 pairing) but does NOT propagate a
            // FIN/close to the underlying TCP connection, so the peer never
            // sees a close from this layer. The architecture is unchanged by
            // design (the flow is owned by the event loop / owning stack).
            if (closed_) {
                // Already closed: the PREVIOUS close already fired its own
                // handler, but THIS caller's handler must still complete
                // exactly once (1:1 from the caller's perspective) - dropping
                // it would hang a caller awaiting its close completion
                // (audit A-4). Fire after releasing the lock: the handler may
                // re-enter the flow API (the mutex is non-recursive).
                CloseHandler done = std::move(cb);
                scope.unlock();
                if (done) {
                    done(Result::kClosed);
                }
                return Result::kOk;
            }
            if (close_pending_) {
                return Result::kInFlight;
            }
            PendingClose p;
            p.cb = std::move(cb);
            pending_close_ = std::move(p);
            close_pending_ = true;
            return Result::kOk;
        }

        bool MimtFlow::DispatchRead() noexcept {
            ReadHandler cb;
            UInt32 n = 0;
            bool fired = false;
            {
                std::lock_guard<std::mutex> scope(sync_);
                if (!read_pending_ || !pending_read_.cb) {
                    return false;
                }
                if (rx_queue_.empty()) {
                    return false;  // still waiting for data
                }
                // Fill to the REQUESTED length: keep consuming consecutive
                // queued chunks until the caller's buffer is satisfied or the
                // queue drains (short-read only when genuinely out of data).
                // A single-chunk fill can complete with n < len whenever the
                // peer's segmentation split data at a non-chunk boundary
                // (e.g. a 1328-byte wire segment covering two 1024-byte
                // writes); a caller that waits for its full requested length
                // before re-parking would then strand - read_pending_ is
                // already consumed, the queue still holds bytes, and no one
                // ever dispatches them (deadlock observed under ARM/QEMU
                // single-core scheduling where coalescing actually occurs).
                UInt32 done = 0;
                while (done < pending_read_.len && !rx_queue_.empty()) {
                    std::vector<Byte>& front = rx_queue_.front();
                    const UInt32 take = static_cast<UInt32>(front.size()) <
                                                (pending_read_.len - done)
                                            ? static_cast<UInt32>(front.size())
                                            : (pending_read_.len - done);
                    std::memcpy(static_cast<Byte*>(pending_read_.buf) + done,
                                front.data(), take);
                    done += take;
                    rx_queued_ -= take;
                    if (take == front.size()) {
                        rx_queue_.pop_front();
                    } else {
                        front.erase(front.begin(), front.begin() + take);
                    }
                }
                n = done;
                cb = std::move(pending_read_.cb);
                pending_read_.cb = NULLPTR;
                read_pending_ = false;
                fired = true;
            }
            if (fired && cb) {
                cb(Result::kOk, n);
            }
            return fired;
        }

        bool MimtFlow::DispatchWrite() noexcept {
            struct Completion {
                WriteHandler cb;
                Result       r;
                UInt32       n;
            };
            std::vector<Completion> completions;
            bool fired = false;
            // Lock-order discipline (D11): the write sink is the owning
            // stack's SendData, which takes the SHARD lock (stack.cpp
            // BindDataPath's SetWriteSink). The recv path takes shard ->
            // sync_ (OnSegment -> OnData), so calling the sink under sync_
            // here would invert the order (sync_ -> shard) - a real deadlock
            // pair (TSan lock-order-inversion). Deliver OUTSIDE sync_: move
            // the queued writes out under the lock, push them to the sink
            // without holding it, then re-lock to commit / cancel.
            std::deque<PendingWrite> outs;
            {
                std::lock_guard<std::mutex> scope(sync_);
                if (!write_pending_) {
                    return false;
                }
                if (write_queue_.empty() || !write_sink_) {
                    // Sink failure (or no sink installed): the queued writes
                    // can never proceed. Complete every remaining callback
                    // with an error result and clear the queue so no accepted
                    // write is stranded (1:1). A closed flow must report the
                    // terminal kClosed instead of kWouldBlock: a dead
                    // connection can never accept the write, so kWouldBlock
                    // ("retry later") would make the application retry forever
                    // against a connection that will never recover (mirror of
                    // Close()'s kClosed completions).
                    while (!write_queue_.empty()) {
                        WriteHandler cb = std::move(write_queue_.front().cb);
                        write_queue_.pop_front();
                        write_pending_ = !write_queue_.empty();
                        if (cb) {
                            completions.push_back({std::move(cb), closed_ ? Result::kClosed : Result::kWouldBlock, 0});
                            fired = true;
                        }
                    }
                } else {
                    outs.swap(write_queue_);
                    write_pending_ = false;
                }
            }
            if (outs.empty()) {
                for (Completion& c : completions) {
                    if (c.cb) {
                        c.cb(c.r, c.n);
                    }
                }
                return fired;
            }
            // Deliver to the sink OUTSIDE the lock.
            bool sink_ok = true;
            while (!outs.empty() && sink_ok) {
                PendingWrite& front = outs.front();
                const UInt32 n = static_cast<UInt32>(front.data.size() - front.offset);
                sink_ok = write_sink_(front.data.data() + front.offset, n);
                if (sink_ok) {
                    completions.push_back({std::move(front.cb), Result::kOk, n});
                    outs.pop_front();
                    fired = true;
                }
            }
            if (!outs.empty() && !sink_ok) {
                // Sink failure mid-burst: the remaining writes can never
                // proceed - cancel them (1:1), same as the empty case.
                std::lock_guard<std::mutex> scope(sync_);
                while (!outs.empty()) {
                    PendingWrite& front = outs.front();
                    if (front.cb) {
                        completions.push_back({std::move(front.cb), closed_ ? Result::kClosed : Result::kWouldBlock, 0});
                        fired = true;
                    }
                    outs.pop_front();
                }
            }
            for (Completion& c : completions) {
                if (c.cb) {
                    c.cb(c.r, c.n);
                }
            }
            return fired;
        }

        void MimtFlow::Close() noexcept {
            // Forced shutdown by the owning stack: the underlying connection
            // is gone, so this flow can never be dispatched again. The flow is
            // terminating: every accepted async operation must complete exactly
            // once (1:1 pairing). Complete the pending read and all queued
            // writes with kClosed, clear buffered rx data, then fire the close
            // handler (if one was parked). Idempotent. Callbacks fire outside
            // the lock.
            struct Completion {
                ReadHandler  rd;
                WriteHandler wr;
                CloseHandler cl;
                Result       r;
                UInt32       n;
            };
            std::vector<Completion> completions;
            {
                std::lock_guard<std::mutex> scope(sync_);
                if (closed_) {
                    return;  // idempotent: completions already fired
                }
                closed_ = true;
                if (read_pending_ && pending_read_.cb) {
                    ReadHandler cb = std::move(pending_read_.cb);
                    pending_read_.cb = NULLPTR;
                    read_pending_ = false;
                    completions.push_back({std::move(cb), NULLPTR, NULLPTR, Result::kClosed, 0});
                }
                while (!write_queue_.empty()) {
                    WriteHandler cb = std::move(write_queue_.front().cb);
                    write_queue_.pop_front();
                    write_pending_ = !write_queue_.empty();
                    if (cb) {
                        completions.push_back({NULLPTR, std::move(cb), NULLPTR, Result::kClosed, 0});
                    }
                }
                rx_queue_.clear();
                rx_queued_ = 0;
                if (close_pending_) {
                    close_pending_ = false;
                    CloseHandler cb = std::move(pending_close_.cb);
                    pending_close_.cb = NULLPTR;
                    if (cb) {
                        completions.push_back({NULLPTR, NULLPTR, std::move(cb), Result::kOk, 0});
                    }
                }
            }
            for (Completion& c : completions) {
                if (c.rd) {
                    c.rd(c.r, c.n);
                } else if (c.wr) {
                    c.wr(c.r, c.n);
                } else if (c.cl) {
                    c.cl(c.r);
                }
            }
        }

        bool MimtFlow::DispatchClose() noexcept {
            bool was_pending = false;
            {
                std::lock_guard<std::mutex> scope(sync_);
                was_pending = close_pending_;
            }
            if (was_pending) {
                Close();  // internally locked, completes the parked handler
            }
            return was_pending;
        }

        UInt32 MimtFlow::Dispatch() noexcept {
            UInt32 fired = 0;
            if (DispatchRead()) ++fired;
            if (DispatchWrite()) ++fired;
            if (DispatchClose()) ++fired;
            return fired;
        }
    }
}

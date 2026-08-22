#pragma once

/**
 * @file timer.h
 * @brief Per-core timer wheel: min-heap with generation-based cancellation.
 * @note Single-threaded (per shard); not thread-safe by design.
 */

#include <xtcp/stdafx.h>

#include <functional>
#include <queue>
#include <unordered_set>
#include <vector>

namespace xtcp {
    namespace core {
        typedef UInt64 TimePoint;  /**< Monotonic microseconds */
        typedef UInt64 TimerId;    /**< Monotonic sequence */

        /**
         * @brief Timer callback.
         */
        typedef std::function<void()> TimerCallback;

        /**
         * @brief Min-heap timer wheel with lazy cancellation.
         */
        class TimerWheel {
        public:
            TimerWheel() = default;
            virtual ~TimerWheel() noexcept = default;

            /**
             * @brief Schedules a callback.
             * @param due Absolute expiry (monotonic microseconds).
             * @param cb Callback to fire.
             * @return TimerId for cancellation.
             */
            TimerId Add(TimePoint due, TimerCallback cb) noexcept;
            /**
             * @brief Cancels a timer (lazy: heap entry stays, skipped on fire).
             * @param id TimerId from Add().
             */
            void Remove(TimerId id) noexcept;
            /**
             * @brief Fires all timers due at or before now.
             * @param now Monotonic microseconds.
             * @return Number of callbacks invoked.
             */
            size_t AdvanceTo(TimePoint now) noexcept;
            /**
             * @brief Number of live (uncancelled) timers.
             */
            size_t Size() const noexcept { return live_; }

        private:
            struct Entry {
                TimePoint due;
                UInt64    seq;
                TimerCallback cb;
                bool operator>(const Entry& rhs) const {
                    if (due != rhs.due) {
                        return due > rhs.due;
                    }
                    return seq > rhs.seq;
                }
            };

            std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> heap_;
            std::unordered_set<UInt64> cancel_set_;
            UInt64 next_seq_ = 0;
            size_t live_     = 0;
        };
    }
}

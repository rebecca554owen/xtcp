/**
 * @file timer.cpp
 * @brief Min-heap timer wheel implementation with lazy cancellation.
 */

#include <xtcp/core/timer.h>

namespace xtcp {
    namespace core {
        namespace {

            /**
             * @brief Read-only access to the underlying container of a priority queue.
             * @note std::priority_queue keeps its container protected; exposing it
             *       lets Remove() test a TimerId against the authoritative heap
             *       instead of duplicating heap membership in a second structure.
             */
            template <typename T, typename Container, typename Compare>
            struct HeapContainerAccess : std::priority_queue<T, Container, Compare> {
                static const Container& Get(const std::priority_queue<T, Container, Compare>& q) noexcept {
                    return q.*(&HeapContainerAccess::c);
                }
            };

        }

        TimerId TimerWheel::Add(TimePoint due, TimerCallback cb) noexcept {
            Entry entry;
            entry.due = due;
            entry.seq = next_seq_;
            entry.cb = std::move(cb);
            heap_.push(std::move(entry));
            ++next_seq_;
            ++live_;
            return entry.seq;
        }

        void TimerWheel::Remove(TimerId id) noexcept {
            if (cancel_set_.erase(id)) {
                if (0 < live_) {
                    --live_;
                }
            }
        }

        size_t TimerWheel::AdvanceTo(TimePoint now) noexcept {
            size_t fired = 0;
            const UInt64 round_end = next_seq_;  // timers added during callbacks run on the next round
            while (!heap_.empty()) {
                const Entry& top = heap_.top();
                if (top.due > now || round_end <= top.seq) {
                    break;
                }
                Entry entry = std::move(const_cast<Entry&>(top));
                heap_.pop();
                if (cancel_set_.erase(entry.seq)) {
                    continue;  // cancelled: live_ already decremented in Remove()
                }
                if (0 < live_) {
                    --live_;
                }
                if (entry.cb) {
                    entry.cb();
                    ++fired;
                }
            }
            return fired;
        }
    }
}

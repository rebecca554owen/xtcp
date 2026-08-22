#pragma once

/**
 * @file diff_harness.h
 * @brief Differential testing harness: drives a TCP implementation through
 *        scripted scenarios and records a normalized event stream. The
 *        reference (lwIP) and xtcp are each driven through the same
 *        scenarios and their event streams compared.
 *
 * The lwIP adapter is an interface: populate it once lwIP is vendored
 * (see docs/TEST_PLAN.md, differential layer).
 */

#include <xtcp/stdafx.h>

#include <functional>
#include <string>
#include <vector>

namespace xtcp {
    namespace harness {
        /**
         * @brief One normalized event (protocol-agnostic).
         */
        struct Event {
            enum Kind : Byte {
                kConnect    = 0,  /**< Connection established */
                kClose      = 1,  /**< Connection closed */
                kSend       = 2,  /**< Data sent (client -> server) */
                kRecv       = 3,  /**< Data received (server side) */
                kSegment    = 4,  /**< A TCP segment was emitted */
                kRetransmit = 5,  /**< A segment was retransmitted */
            };
            Kind    kind   = kSend;
            UInt32  bytes  = 0;   /**< Data bytes (kSend/kRecv) */
            UInt32  seq    = 0;   /**< Segment seq (kSegment) */
            UInt32  ack    = 0;   /**< Segment ack (kSegment) */
            UInt16  flags  = 0;   /**< Segment flags (kSegment) */
        };

        /**
         * @brief An implementation under test (xtcp or lwIP adapter).
         */
        class StackUnderTest {
        public:
            virtual ~StackUnderTest() noexcept = default;
            /**
             * @brief Runs the scenario; appends normalized events.
             * @param events Receives the event stream.
             */
            virtual void Run(std::vector<Event>& events) = 0;
        };

        /**
         * @brief Runs a scenario on an implementation and returns its events.
         */
        inline std::vector<Event> RunScenario(StackUnderTest& sut) noexcept {
            std::vector<Event> events;
            sut.Run(events);
            return events;
        }

        /**
         * @brief Compares two event streams; returns the first divergence.
         * @return -1 when identical, else the mismatch index.
         */
        inline Int32 CompareStreams(const std::vector<Event>& a, const std::vector<Event>& b) noexcept {
            const size_t n = (a.size() < b.size()) ? a.size() : b.size();
            for (size_t i = 0; i < n; ++i) {
                const Event& ea = a[i];
                const Event& eb = b[i];
                if (ea.kind != eb.kind || ea.bytes != eb.bytes) {
                    return static_cast<Int32>(i);
                }
                if (Event::kSegment == ea.kind) {
                    if (ea.flags != eb.flags) {
                        return static_cast<Int32>(i);
                    }
                }
            }
            return (a.size() == b.size()) ? -1 : static_cast<Int32>(n);
        }
    }
}

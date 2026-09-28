#pragma once
// Placeholder telemetry/flow-control types for openppp2 XtcpRuntime.
// Standalone - no dependency on stack.h (avoids circular include).

#include <cstdint>

namespace xtcp {
namespace core {

enum class SendAdmissionReason : uint8_t {
    kNone             = 0,
    kNonSendableState = 1,
    kSndBufQuota      = 2,
    kPacing           = 3,
};

struct SendAdmissionSnapshot {
    uint64_t admitted_us       = 0;
    uint64_t rejected_us       = 0;
    uint64_t queue_depth       = 0;
    SendAdmissionReason reason = SendAdmissionReason::kNone;
    uint64_t pacing_deadline   = 0;
    uint64_t attempted_len     = 0;
    uint64_t pending_send      = 0;
    uint64_t cwnd_bytes        = 0;
    uint64_t inflight          = 0;
    uint64_t snd_buf           = 0;
    uint64_t snd_wnd           = 0;
};

struct AckReleaseTelemetrySnapshot {
    uint64_t valid_acks                           = 0;
    uint64_t ack_advance_events                    = 0;
    uint64_t ack_advance_bytes                     = 0;
    uint64_t pending_flush_attempts                = 0;
    uint64_t pending_flush_pacing                  = 0;
    uint64_t pending_flush_window_cwnd             = 0;
    uint64_t pending_flush_fast_recovery_pipe      = 0;
    uint64_t pending_flush_packet_allocation         = 0;
    uint64_t tx_sink_packets                           = 0;
    uint64_t tx_sink_bytes                             = 0;
    uint64_t rate_change_events                        = 0;
    uint64_t rate_change_with_pending                  = 0;
    uint64_t rate_change_flush_packets                 = 0;
    uint64_t rate_change_flush_bytes                   = 0;
    uint64_t rate_change_new_rate_sum                  = 0;
    uint64_t rate_change_old_rate_sum                  = 0;
    uint64_t rate_change_deadline_active               = 0;
    uint64_t rate_change_deadline_remaining_us_sum     = 0;
};

struct TsoGateTelemetrySnapshot {
    uint64_t total_gated       = 0;
    uint64_t total_passthrough    = 0;
    uint64_t direct_candidates    = 0;
    uint64_t direct_disabled      = 0;
    uint64_t direct_emitted       = 0;
    uint64_t direct_fast_recovery = 0;
    uint64_t direct_outstanding   = 0;
    uint64_t direct_pacing        = 0;
    uint64_t direct_pending       = 0;
    uint64_t direct_pool_limit    = 0;
    uint64_t direct_window_cwnd   = 0;
    uint64_t flush_candidates     = 0;
    uint64_t flush_disabled       = 0;
    uint64_t flush_emitted        = 0;
    uint64_t flush_fast_recovery  = 0;
    uint64_t flush_outstanding    = 0;
    uint64_t flush_pacing         = 0;
    uint64_t flush_window_cwnd    = 0;
};

struct ReceiveStateSnapshot {
    uint64_t receive_window    = 0;
    uint64_t advertised_window = 0;
    uint64_t buffered_bytes    = 0;
};

enum class ReceiveResumeResult : uint8_t {
    kResumed           = 0,
    kNotBlocked        = 1,
    kReceiveWindowFull = 2,
    kConnectionMissing = 3,
};

} // namespace core
} // namespace xtcp

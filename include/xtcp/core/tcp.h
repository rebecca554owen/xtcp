#pragma once

/**
 * @file tcp.h
 * @brief TCP segment format (RFC 793), connection state machine (minimal
 *        set), listener with SYN queue.
 *
 * RFC acceptance gates for this unit: RFC 793 (state table, segment
 * processing), RFC 1122 section 4.2 (host requirements), RFC 5961
 * (blind-attack mitigation: RST validation, challenge ACK).
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>
#include <xtcp/core/timer.h>
#include <xtcp/core/tfo.h>
#include <atomic>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace xtcp {
    namespace cc {
        // Forward declarations: the CC hook table lives in cc/cc.h; TcpConn
        // only holds a pointer to it and opaque sample values.
        struct XtcpCongestionOps;
        struct RateSample;
        struct AckSample;
        struct KccTelemetrySnapshot;
    }
    namespace core {
        /**
         * @brief Per-connection fields the CC hooks operate on (kernel
         *        tcp_sock field equivalents, same names and semantics).
         */
        struct XtcpConnCc {
            UInt32  snd_cwnd       = 10;      /**< Congestion window (packets); RFC 6928 initial window (10 segs, Linux initcwnd) */
            UInt32  snd_ssthresh   = 0x7FFFFFFF;
            UInt64  pacing_rate    = 0;       /**< Bytes per second */
            UInt64  delivered      = 0;       /**< Total bytes delivered */
            UInt64  delivered_mstamp = 0;     /**< Last delivery timestamp (ms) */
            UInt64  lost           = 0;       /**< Total lost bytes */
            UInt64  lsndtime       = 0;       /**< Last send time (ms) */
            UInt32  srtt_us        = 0;       /**< Smoothed RTT (us) */
            UInt32  mdev_us        = 0;       /**< RTT variance (us) */
            UInt32  mss            = 1460;
            UInt32  rtt_min_us     = 0;       /**< min RTT (us) */
            UInt32  rcv_wnd        = 65535;
            UInt32  snd_wnd        = 65535;
            UInt32  inflight       = 0;       /**< Bytes in flight */
            UInt32  app_limited    = 0;       /**< Application-limited flag */
            UInt32  snd_cwnd_cnt   = 0;       /**< Bytes acked toward the next CA increment (kernel tcp_sock equivalent) */
            void*   ca_priv        = NULLPTR; /**< Algorithm private state */
        };

        /**
         * @brief RFC 1982 sequence comparison: true when a is "before" b.
         */
        inline bool SeqLt(UInt32 a, UInt32 b) noexcept {
            return static_cast<Int32>(a - b) < 0;
        }
        inline bool SeqLe(UInt32 a, UInt32 b) noexcept {
            return a == b || SeqLt(a, b);
        }

        /**
         * @brief TCP protocol states (RFC 793).
         */
        enum class TcpState : Byte {
            kClosed      = 0,
            kListen      = 1,
            kSynSent     = 2,
            kSynRcvd     = 3,
            kEstablished = 4,
            kFinWait1    = 5,
            kFinWait2    = 6,
            kCloseWait   = 7,
            kLastAck     = 8,
            kClosing     = 9,
            kTimeWait    = 10,
        };

        /**
         * @brief Why SendData last rejected application data.
         */
        enum class SendAdmissionReason : Byte {
            kNone = 0,
            kNonSendableState = 1,
            kSndBufQuota = 2,
        };

        /**
         * @brief Snapshot captured at a SendData rejection for diagnostics.
         * @note This is observational only: it neither admits data nor alters
         *       TCP timers, queues, congestion control, or pacing.
         */
        struct SendAdmissionSnapshot {
            UInt64 generation = 0;
            SendAdmissionReason reason = SendAdmissionReason::kNone;
            TcpState state = TcpState::kClosed;
            UInt32 attempted_len = 0;
            UInt32 pending_send = 0;
            UInt32 inflight = 0;
            UInt32 snd_buf = 0;
            UInt32 snd_wnd = 0;
            UInt64 cwnd_bytes = 0;
            TimePoint pacing_deadline = 0;
        };

        /**
         * @brief Cumulative ACK-release telemetry; all fields are observational.
         */
        struct AckReleaseTelemetrySnapshot {
            UInt64 valid_acks = 0;
            UInt64 ack_advance_events = 0;
            UInt64 ack_advance_bytes = 0;
            UInt64 pending_flush_attempts = 0;
            UInt64 tx_sink_packets = 0;
            UInt64 tx_sink_bytes = 0;
            UInt64 pending_flush_pacing = 0;
            UInt64 pending_flush_window_cwnd = 0;
            UInt64 pending_flush_fast_recovery_pipe = 0;
            UInt64 pending_flush_packet_allocation = 0;
            // ACK-side congestion-control pacing-rate changes. The flush fields
            // describe the ACK's pre-rate-update buffered-data flush only.
            UInt64 rate_change_events = 0;
            UInt64 rate_change_with_pending = 0;
            UInt64 rate_change_old_rate_sum = 0;
            UInt64 rate_change_new_rate_sum = 0;
            UInt64 rate_change_flush_packets = 0;
            UInt64 rate_change_flush_bytes = 0;
            UInt64 rate_change_deadline_active = 0;
            UInt64 rate_change_deadline_remaining_us_sum = 0;
        };

        /**
         * @brief Cumulative super-MSS TSO gate telemetry; observational only.
         * @note Each candidate is classified by its first blocking gate, or as
         *       emitted when it took the TSO path. Flush candidates account for
         *       the queued remainder at each flush-loop iteration.
         */
        struct TsoGateTelemetrySnapshot {
            UInt64 direct_candidates = 0;
            UInt64 direct_disabled = 0;
            UInt64 direct_pending = 0;
            UInt64 direct_outstanding = 0;
            UInt64 direct_fast_recovery = 0;
            UInt64 direct_window_cwnd = 0;
            UInt64 direct_pacing = 0;
            UInt64 direct_pool_limit = 0;
            UInt64 direct_emitted = 0;
            UInt64 flush_candidates = 0;
            UInt64 flush_disabled = 0;
            UInt64 flush_outstanding = 0;
            UInt64 flush_fast_recovery = 0;
            UInt64 flush_window_cwnd = 0;
            UInt64 flush_pacing = 0;
            UInt64 flush_emitted = 0;
        };

        /**
         * @brief TCP flags (RFC 793).
         */
        enum TcpFlag : UInt16 {
            kFlagFin  = 0x0001,
            kFlagSyn  = 0x0002,
            kFlagRst  = 0x0004,
            kFlagPsh  = 0x0008,
            kFlagAck  = 0x0010,
            kFlagUrg  = 0x0020,
            kFlagEce  = 0x0040,
            kFlagCwr  = 0x0080,
        };

        /**
         * @brief TCP header; options parsed via ParseTcpOpts/TcpOpts
         *        (MSS, wscale, SACK, timestamps, TFO cookie, MD5).
         */
        struct TcpHdr {
            UInt16 sport   = 0;
            UInt16 dport   = 0;
            UInt32 seq     = 0;
            UInt32 ack     = 0;
            UInt16 flags   = 0;   /**< Flag field (fin..cwr, 8 bits parsed) */
            UInt16 window  = 0;
            UInt16 checksum = 0;
            UInt16 urgent  = 0;
            Byte    hdr_len = 20;  /**< Header length in bytes */
            UInt16 payload_off = 20;

            bool IsSyn() const noexcept { return 0 != (flags & kFlagSyn); }
            bool IsAck() const noexcept { return 0 != (flags & kFlagAck); }
            bool IsFin() const noexcept { return 0 != (flags & kFlagFin); }
            bool IsRst() const noexcept { return 0 != (flags & kFlagRst); }
            bool IsEce() const noexcept { return 0 != (flags & kFlagEce); }
            bool IsCwr() const noexcept { return 0 != (flags & kFlagCwr); }
            bool IsUrg() const noexcept { return 0 != (flags & kFlagUrg); }
        };

        /**
         * @brief Parses a TCP header from a segment.
         * @param data Segment bytes.
         * @param len  Segment length.
         * @param out  Filled on success.
         * @return True when the header is valid.
         */
        bool ParseTcp(const Byte* data, UInt32 len, TcpHdr& out) noexcept;

        /**
         * @brief Parsed TCP options (RFC 793 / RFC 7323).
         */
        struct TcpOpts {
            bool    has_wscale  = false;
            Byte    wscale      = 0;    /**< Window scale factor (0-14) */
            bool    has_sack    = false;
            bool    has_timestamp = false;
            UInt32  ts_val      = 0;
            UInt32  ts_ecr      = 0;
            bool    has_mss     = false;
            UInt16  mss         = 1460;
            Byte    sack_count  = 0;    /**< SACK blocks present (RFC 2018) */
            UInt32  sack[4][2]  = { { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 } };  /**< [left, right) edges */
            bool    has_tfo     = false;/**< TFO cookie present (RFC 7413) */
            Byte    tfo_cookie[8] = { 0 };
        };

        /**
         * @brief Parses TCP options from a segment.
         * @param data Segment bytes (TCP header start).
         * @param len  Segment length.
         * @param hdr_len TCP header length (from the data-offset field).
         * @param out  Filled on success.
         * @return True when options parse without malformation.
         */
        bool ParseTcpOpts(const Byte* data, UInt32 len, UInt32 hdr_len, TcpOpts& out) noexcept;

        /**
         * @brief Endpoint (family + address + port).
         */
        struct Endpoint {
            Byte    family = 4;
            UInt32  addr[4] = { 0, 0, 0, 0 };
            UInt16  port   = 0;
        };

        /**
         * @brief Output sink: receives complete IP packets to transmit.
         */
        typedef std::function<void(buf::BufRef&&)> TxSink;
        enum class ReceiveResumeResult : Byte {
            kResumed,
            kNotBlocked,
            kReceiveWindowFull,
            kConnectionMissing,
        };

        struct ReceiveStateSnapshot final {
            bool rcv_blocked = false;
            UInt32 ooo_bytes = 0;
            UInt32 pending_frontier_bytes = 0;
            UInt32 window = 0;
            UInt16 advertised_window = 0;
        };
        /**
         * @brief Received in-order data callback.
         * @param data Buffer (valid only during the callback).
         * @param len  Bytes.
         * @return true when the data was accepted; false rejects it (back-
         *         pressure). A rejected segment is not acknowledged: rcv_nxt_
         *         does not advance, so the peer RTOs and retransmits instead
         *         of silently losing application data.
         */
        typedef std::function<bool(const Byte* data, UInt32 len)> RecvCallback;
        /**
         * @brief Timer-driven state-change notification (the stack registers
         *        it so timer-only transitions - RTO exhaustion, keepalive
         *        abort, FIN-WAIT-2 timeout - can reach the application).
         * @param state The new state (e.g. kClosed).
         */
        typedef std::function<void(TcpState state)> StateChangeCallback;

        /**
         * @brief TCP connection: state machine with retransmission, RTO
         *        (Jacobson, RFC 6298), sliding window, fast retransmit.
         * @note The shard drives timers via NextRetransmitTime() /
         *       OnRetransmitTimer() with monotonic time.
         */
        class TcpConn {
        public:
            /**
             * @brief Our RFC 7323 window-scale offer (shift count sent in
             *        every SYN). The scale takes effect only when the peer
             *        answers WSOPT (both-sides rule): rcv_wscale_ is set to
             *        this value at handshake completion iff the peer's
             *        SYN/SYN+ACK carried the option, else 0 (unscaled).
             */
            static constexpr Byte kWindowScaleOffer = 7;

            TcpConn(TcpState state, const Endpoint& local, const Endpoint& remote, UInt32 iss, UInt32 irs, TxSink sink) noexcept;
            virtual ~TcpConn() noexcept;

            /**
             * @brief Selects the congestion-control algorithm by name.
             * @param name Registered algorithm (cc/cc.h), or NULLPTR/empty
             *        for the built-in Reno (RFC 5681) default.
             * @return True when the algorithm was found and installed, or when
 *         NULLPTR/empty selected the built-in Reno default.
             */
            bool SetCongestionControl(const char* name) noexcept;
            bool GetKccTelemetry(cc::KccTelemetrySnapshot& out) const noexcept;

            /**
             * @brief Processes one incoming TCP segment (IP payload).
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param now  Monotonic time (microseconds) for RTT sampling.
             */
            void OnSegment(const Byte* data, UInt32 len, TimePoint now = 0) noexcept;
            /**
             * @brief Sends application data (window permitting).
             * @param data Payload bytes (referenced only during the call).
             * @param len  Payload length.
             * @param now  Monotonic time.
 * @return True when the data was accepted (sent or buffered); false when the
 *         call cannot accept it - the per-connection send quota is exhausted
 *         (caller must back off and retry later) or the connection is not in
 *         a send-ready state (handshake in flight / closing). A full window
 *         or a pacing gate buffers the data instead of failing
 *         (full Linux send semantics).
             */
            bool SendData(const Byte* data, UInt32 len, TimePoint now) noexcept;
            /**
             * @brief Copies the latest SendData rejection snapshot.
             * @return True when at least one rejection has been observed.
             */
            bool LastSendAdmission(SendAdmissionSnapshot& out) const noexcept;
            /**
             * @brief Copies cumulative ACK-release telemetry.
             */
            AckReleaseTelemetrySnapshot AckReleaseTelemetry() const noexcept;
            /**
             * @brief Copies cumulative super-MSS TSO gate telemetry.
             */
            TsoGateTelemetrySnapshot TsoGateTelemetry() const noexcept;
            /**
             * @brief Re-sends buffered data after a window update.
             * @param now Monotonic time.
             */
            void Flush(TimePoint now) noexcept;
            /**
             * @brief Sends app data queued during the SYN/SYN+ACK handshake
             *        once the connection is Established (full client mode).
             * @param now Monotonic time.
             */
            void FlushPendingSend(TimePoint now) noexcept;
            /**
             * @brief Fires every due timer (delayed-ACK, RTO, persist) and
             *        flushes buffered sends under ONE lock acquisition.
             * @param now Monotonic time.
             * @return Number of timers fired.
             */
            UInt32 OnPoll(TimePoint now) noexcept;
            /**
             * @brief Bytes currently buffered for sending (window/pacing
             *        constrained). 0 = nothing pending.
             */
            UInt32 PendingSendBytes() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return static_cast<UInt32>(PendingSendSizeNoLock());
            }
            /**
 * @brief Initiates active close (sends FIN).
 * @param now Monotonic time (currently unused - the implementation reads
 *        its own monotonic clock; kept for signature stability).
             */
            void Close(TimePoint now = 0) noexcept;
            /**
             * @brief Aborts the connection (sends RST).
             */
            void Abort() noexcept;
            /**
             * @brief Sends an empty ACK segment.
             */
            void SendAck() noexcept;
            /**
             * @brief Attempts to reopen an application-blocked receive window.
             * @return Detailed outcome distinguishing latch/window state.
             */
            ReceiveResumeResult ResumeReceiveDetailed() noexcept;
            bool ResumeReceive() noexcept {
                return ReceiveResumeResult::kResumed == ResumeReceiveDetailed();
            }
            ReceiveStateSnapshot ReceiveState() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return {rcv_blocked_, ooo_bytes_, pending_frontier_bytes_, window_, AdvertisedWindow()};
            }
            /**
             * @brief Sends the SYN segment (active-open path, SynSent).
             * @note Caller invokes after creating the connection in SynSent.
             */
            void SendSyn() noexcept;
            /**
             * @brief Sends SYN with early data (TCP Fast Open, RFC 7413).
             * @param data Early payload (zero-RTT data).
             * @param len  Payload length.
             * @return True when sent (SynSent).
             */
            bool SendSynWithData(const Byte* data, UInt32 len) noexcept;
            /**
             * @brief Accepts early data carried in a SYN (server side).
             * @param data Payload bytes.
             * @param len  Payload length.
             */
            void AcceptEarlyData(const Byte* data, UInt32 len) noexcept;
            /**
             * @brief Arms the delayed ACK to announce the receive-window
             *        reopening after backpressure (RFC 1122 s4.2.3.4: the
             *        receiver must advertise a nonzero window when it can
             *        accept data again - without it, recovery waits on the
             *        peer's persist probe).
             */
            void ArmWindowUpdateAck(TimePoint now) noexcept;
            /**
             * @brief Sends the SYN+ACK segment (passive-open path, SynRcvd).
             */
            void SendSynAck() noexcept;
            /**
             * @brief Builds a stateless SYN+ACK (SYN-cookie mode, RFC 4987):
             *        the ISN carries the cookie, no connection is created.
             * @param local  Our endpoint (the listener).
             * @param remote Peer endpoint.
             * @param cookie ISN (the computed cookie).
             * @param ack    ACK value (peer SYN seq + 1).
             * @param wscale Our advertised window-scale factor.
             * @return Packet ready to transmit; empty on allocation failure.
             */
            static buf::BufRef BuildSynAckPacket(const Endpoint& local, const Endpoint& remote,
                                                 UInt32 cookie, UInt32 ack, Byte wscale,
                                                 const Byte* md5_key = NULLPTR,
                                                 UInt32 md5_key_len = 0) noexcept;
            /**
             * @brief Next retransmission deadline, 0 when none pending.
             */
            TimePoint NextRetransmitTime() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return rto_deadline_;
            }
            /**
             * @brief Next ACK deadline (delayed ACK), 0 when none pending.
             */
            TimePoint NextAckTime() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return ack_deadline_;
            }
            /**
             * @brief Earliest armed timer deadline (steady-clock microseconds,
             *        the PollAckTimers clock).
             * @return The minimum of the delayed-ACK/RTO/TLP/persist/MTU-probe/
             *         FIN-WAIT-2/keepalive/user-timeout deadlines, plus the
             *         pacing deadline when buffered sends wait on the pacing
             *         clock; 0 when timer work is due immediately (CLOSED
             *         reclamation or un-paced buffered sends) and
             *         ~(TimePoint)0 when nothing is pending. A
             *         TIME-WAIT connection reports its 2MSL deadline.
             * @note  OPENPPP2 integration patch (tools/xtcp-patches/
             *        0001-next-timer-deadline.patch): enables deadline-driven
             *        polling in the host event loop instead of a fixed
             *        cadence.
             */
            TimePoint NextTimerDeadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                if (TcpState::kClosed == state_) {
                    return 0;  // the sweep's reclamation pass is due now
                }
                if (TcpState::kTimeWait == state_) {
                    return timewait_deadline_;
                }
                TimePoint next = ~(TimePoint)0;
                const auto consider = [&next](TimePoint due) noexcept {
                    if (0 != due && due < next) {
                        next = due;
                    }
                };
                consider(ack_deadline_);
                consider(rto_deadline_);
                consider(persist_deadline_);
                consider(mtu_probe_deadline_);
                if (TcpState::kFinWait2 == state_) {
                    consider(finwait2_deadline_);
                }
                if (tlp_armed_) {
                    consider(tlp_deadline_);
                }
                if (0 < user_timeout_us_ && 0 != first_outstanding_) {
                    consider(first_outstanding_ + user_timeout_us_);
                }
                if (0 < keepalive_idle_ && TcpState::kEstablished == state_) {
                    const UInt64 idle_us =
                        (0 < keepalive_probes_) ? keepalive_intvl_ : keepalive_idle_;
                    consider(last_rx_ + idle_us);
                }
                if (0 < PendingSendSizeNoLock()) {
                    // A zero peer window cannot be opened by the pacing clock.
                    // Wake only for the actual recovery timers (persist/RTO/...)
                    // instead of returning a stale pacing deadline and spinning
                    // the host loop while the colocated receiver is starved.
                    if (0 == snd_wnd_ && 0 != persist_deadline_) {
                        return next;
                    }
                    // Buffered sends: when a pacing clock is armed the flush
                    // cannot make progress before pacing_deadline_, so wake
                    // AT the deadline instead of reporting "due now" and
                    // letting the host event loop busy-spin on a gated
                    // buffer. Other armed timers (persist/RTO/...) still win
                    // when earlier.
                    if (0 < cc_.pacing_rate && 0 != pacing_deadline_) {
                        // A pacing tick cannot make progress when the
                        // outstanding flight already fills a hard send
                        // limit. ACK/window updates and recovery timers will
                        // invoke the flush path when that limit changes; do
                        // not schedule pacing-only wakeups in between.
                        // Keep the zero-window/no-persist case timer-driven
                        // once so FlushPendingSend can arm persist.
                        const UInt32 inflight = snd_nxt_ - snd_una_;
                        bool window_blocked = (inflight >= snd_wnd_) || (inflight >= snd_buf_);
                        if (!fast_recovery_) {
                            const UInt64 cwnd_bytes = static_cast<UInt64>(cc_.snd_cwnd) * peer_mss_;
                            window_blocked = window_blocked || (inflight >= cwnd_bytes);
                        }
                        if (!window_blocked || (0 == snd_wnd_ && 0 == persist_deadline_)) {
                            consider(pacing_deadline_);
                        }
                        return next;
                    }
                    return 0;  // buffered sends ride the next sweep
                }
                return next;
            }

            /**
             * @brief Enables TCP-MD5 (RFC 2385) with the given key.
             * @param key Secret key bytes.
             * @param key_len Key length in bytes (0 disables MD5).
             */
            void SetMd5Key(const Byte* key, UInt32 key_len) noexcept {
                md5_key_len_ = (NULLPTR == key || 0 == key_len) ? 0 : key_len;
                if (0 < md5_key_len_) {
                    md5_key_len_ = (64 < md5_key_len_) ? 64 : md5_key_len_;
                    std::memcpy(md5_key_, key, md5_key_len_);
                }
            }
            /**
             * @brief True when TCP-MD5 signing is enabled.
             */
            bool Md5Enabled() const noexcept { return 0 < md5_key_len_; }
            /**
             * @brief Current MD5 key (or NULLPTR when disabled).
             */
            const Byte* Md5Key() const noexcept { return (0 < md5_key_len_) ? md5_key_ : NULLPTR; }
            UInt32 Md5KeyLen() const noexcept { return md5_key_len_; }
            /**
             * @brief Records the peer's advertised MSS (RFC 879).
             * @note A TCP_MAXSEG user ceiling (user_mss_, Linux semantics)
             *       caps every application of the peer's MSS: the effective
             *       send MSS never exceeds min(user_mss_, peer MSS). The
             *       ceiling applies to the handshake value too, so a
             *       pre-connect maxseg setting is honored (Linux parity).
             */
            void SetPeerMss(UInt16 mss) noexcept {
                // RFC 1122 §4.2.2.6: an MSS option of 0 means the peer did not
                // signal a usable MSS - use the IPv4 default of 536 (a 0 MSS
                // would divide by zero in cwnd math). Sub-256 values are
                // unusable in practice, so clamp them up too.
                if (0 == mss) {
                    mss = 536;
                } else if (mss < 256) {
                    mss = 256;
                }
                if (0 < user_mss_ && user_mss_ < mss) {
                    mss = static_cast<UInt16>(user_mss_);  // TCP_MAXSEG ceiling
                }
                peer_mss_ = mss;
                cc_.mss = mss;
            }
            UInt16 PeerMss() const noexcept { return peer_mss_; }
            /**
             * @brief Maximum data payload that can safely enter retransmission state.
             * @note Keeps peer_mss_ intact for congestion-control/window accounting,
             *       but reserves the option space a later fresh-TS RTO rebuild
             *       needs. MD5 and timestamps are mutually exclusive on this
             *       stack, so MD5 retains its larger 20-byte reservation.
             */
            UInt16 DataPayloadCap() const noexcept {
                static constexpr UInt32 kMaxWirePacketBytes = 1500;
                const UInt32 ip_hdr_len = (6 == remote_.family) ? 40 : 20;
                const UInt32 option_len = Md5Enabled() ? 20 : (timestamps_ok_ ? 12 : 0);
                const UInt32 wire_cap = kMaxWirePacketBytes - ip_hdr_len - 20 - option_len;
                return static_cast<UInt16>((peer_mss_ < wire_cap) ? peer_mss_ : wire_cap);
            }
            /** @brief TCP_MAXSEG ceiling (Linux semantics); 0 = unset. */
            void SetUserMss(UInt32 mss) noexcept { user_mss_ = mss; }
            UInt32 UserMss() const noexcept { return user_mss_; }
            /**
             * @brief RFC 2385: verifies the TCP-MD5 digest of an inbound
             *        segment (t = the TCP segment, local/remote = this side's
             *        endpoints for an inbound segment from the peer).
             * @return true when the digest matches (or no MD5 option is present).
             */
            static bool VerifyMd5Segment(const Byte* key, UInt32 key_len,
                                         const Endpoint& local, const Endpoint& remote,
                                         Byte* t, UInt32 tcp_len) noexcept;
            /**
             * @brief RFC 1191 path-MTU reduction: lowers the effective MSS
             *        after an ICMP "fragmentation needed" for this flow, and
             *        arms the periodic re-probe (the path may have grown).
             * @param next_hop_mtu MTU announced by the router.
             */
            void OnMtuReduced(UInt16 next_hop_mtu) noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                // RFC 879 floor: never let the MSS fall below 256 - a
                // spoofed/pathological ICMP must not force byte-at-a-time sending.
                UInt32 new_mss = (next_hop_mtu > 40) ? (next_hop_mtu - 40) : 256;
                if (new_mss < 256) {
                    new_mss = 256;
                }
                if (new_mss < peer_mss_) {
                    if (0 == orig_peer_mss_) {
                        orig_peer_mss_ = peer_mss_;  // remember the negotiated MSS
                    }
                    peer_mss_ = static_cast<UInt16>(new_mss);
                    cc_.mss = peer_mss_;
                    ResplitRetransQueue(DataPayloadCap());
                    mtu_probe_deadline_ = MtuNowUs() + mtu_probe_interval_;
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /**
             * @brief Sets the periodic MTU re-probe interval (RFC 1191:
             *        the path MTU may have increased). Default 600 s.
             */
            void SetMtuProbeInterval(UInt32 us) noexcept { mtu_probe_interval_ = (0 == us) ? 1 : us; }
            /**
             * @brief Monotonic microseconds (steady clock).
             */
            static UInt64 MtuNowUs() noexcept {
                return static_cast<UInt64>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
            }

            /**
             * @brief Sets the per-connection send buffer quota (bytes).
             *        Bounds the retransmission queue, hence the connection's
             *        worst-case memory: snd_buf_ + ooo limit + fixed overhead.
             */
            void SetSndBuf(UInt32 bytes) noexcept { snd_buf_ = (0 == bytes) ? kMinSndBuf : bytes; }
            UInt32 SndBuf() const noexcept { return snd_buf_; }
            /**
             * @brief In-flight unacknowledged bytes (send-side occupancy).
             */
            UInt32 SndInflight() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return snd_nxt_ - snd_una_;
            }
            /**
             * @brief Current congestion window (segments).
             */
            UInt32 Cwnd() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.snd_cwnd;
            }
            /**
             * @brief Smoothed RTT in microseconds (0 before the first sample).
             */
            UInt32 SrttUs() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return srtt_;
            }
            /**
             * @brief Current slow-start threshold (segments).
             */
            UInt32 Ssthresh() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.snd_ssthresh;
            }
            /**
             * @brief Peer's currently advertised window (bytes).
             */
            UInt32 SndWnd() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return snd_wnd_;
            }
            /**
             * @brief Total retransmissions performed.
             */
            UInt32 RetransmitCount() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return retransmit_count_;
            }
            /**
             * @brief Seconds-worth of MSL x2: how long TIME-WAIT connections
             *        linger before reclamation (RFC 793 2MSL). Default 120 s.
             */
            void SetTwoMsl(UInt32 us) noexcept { two_msl_us_ = (0 == us) ? 1 : us; }
            /**
             * @brief Fast-path poll skip: false when this connection has no
             *        armed timers and no buffered sends, so the stack-wide
             *        sweep skips it without locking (lock-free read).
             */
            bool TimersDirty() const noexcept {
                return timers_dirty_.load(std::memory_order_relaxed);
            }
            UInt64 TimeWaitDeadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return timewait_deadline_;
            }
            /**
             * @brief Enables/disables immediate ACKs (Linux TCP_QUICKACK):
             *        one-shot semantics - the flag auto-clears after the
             *        first ACK, so re-enable via SetOption each time.
             */
            void SetQuickAck(bool on) noexcept { quickack_ = on; }
            /**
             * @brief RFC 2018: records whether the peer advertised
             *        SACK-permitted on its SYN/SYN+ACK (the server learns it
             *        from the client's SYN; the client from the SYN+ACK).
             */
            void SetSackOk(bool on) noexcept { sack_ok_ = on; }
            /** @brief RFC 7323: the peer's SYN carried the TSopt (both sides
             *         must offer for the option to activate). */
            void SetPeerTimestampsOffered(bool on) noexcept { peer_ts_offered_ = on; }
            /**
             * @brief Enables TSO direct-sends: super-MSS application sends
             *        go to the backend in ONE segment (the NIC segments).
             *        Set by the stack on the connect path when the backend
             *        advertises kCapTsoTx and no tx qdisc is mounted. The send
             *        path still gates
             *        every direct send on an empty retransmission queue and
             *        the window/cwnd bounds - recovery is never entered
             *        with an oversized entry.
             */
            void SetTsoTx(bool on) noexcept { tso_tx_ = on; }
            /** @brief Whether TSO direct-sends are enabled. */
            bool TsoTx() const noexcept { return tso_tx_; }
            /** @brief Enable partial TCP checksum emission for a capable backend. */
            void SetChecksumPartialTx(bool on) noexcept { checksum_partial_tx_ = on; }
            /** @brief Number of unacknowledged segments (diagnostics/tests:
             *         the TSO-direct gate requires an empty queue). */
            UInt32 RetransQueueSize() const noexcept {
                return static_cast<UInt32>(retrans_queue_.size());
            }
            bool QuickAck() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return quickack_;
            }
            /**
             * @brief Sets the FIN-WAIT-2 timeout (Linux tcp_fin_timeout):
             *        after our FIN is ACKed, a peer that never sends its own
             *        FIN would hold the connection forever. Default 60 s.
             */
            void SetFinWait2Timeout(UInt32 us) noexcept { finwait2_timeout_ = (0 == us) ? 1 : us; }
            /**
             * @brief FIN-WAIT-2 reclamation deadline (0 = not armed).
             */
            UInt64 FinWait2Deadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return finwait2_deadline_;
            }
            /**
             * @brief Sets the SYN retransmission budget (Linux TCP_SYNCNT).
             *        After this many unanswered retransmits the handshake
             *        is abandoned. Default 6.
             */
            void SetSynRetries(UInt32 n) noexcept { syn_retries_ = n; }
            UInt32 SynRetries() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return syn_retries_;
            }
            /**
             * @brief Stores the peer's TFO cookie (RFC 7413) for a future
             *        fast-open SYN. Obtained from the SYN+ACK option.
             */
            void SetTfoCookie(const Byte* cookie) noexcept {
                if (NULLPTR != cookie) {
                    std::memcpy(tfo_cookie_, cookie, 8);
                    has_tfo_cookie_ = true;
                    if (tfo_cb_) {
                        tfo_cb_(cookie);
                    }
                } else {
                    has_tfo_cookie_ = false;
                }
            }
            void SetTfoCookieCallback(std::function<void(const Byte*)> cb) noexcept {
                tfo_cb_ = std::move(cb);
            }
            bool HasTfoCookie() const noexcept { return has_tfo_cookie_; }
            const Byte* TfoCookie() const noexcept { return has_tfo_cookie_ ? tfo_cookie_ : NULLPTR; }
            /**
             * @brief RFC 7413: verifies a client's TFO cookie (server side).
             *        The cookie is keyed by the CLIENT address (remote_), so
             *        a cookie generated for one client cannot be replayed
             *        from another IP (Generate must use the same address).
             */
            bool VerifyTfoCookie(const Byte* cookie) const noexcept {
                if (NULLPTR == cookie) {
                    return false;
                }
                UInt32 bound[4];
                TfoBoundAddr(bound);
                return tfo_.Check(bound, cookie);
            }
            /**
             * @brief Sets the base RTO (RFC 6298 default 1 s; tests and
             *        low-latency deployments may lower it).
             *
             *        The value is clamped to the 60 s UpdateRto cap so an
             *        over-large explicit RTO cannot stall retransmission for
             *        minutes at a time. The lower bound is left at 1 us: tests
             *        intentionally set sub-200 ms RTOs to speed up retry
             *        scenarios, and SetRto is an explicit configuration (the
             *        200 ms floor only applies to measured RTOs).
             */
            void SetRto(UInt32 us) noexcept {
                rto_ = (0 == us) ? 1 : us;
                if (rto_ > 60ull * 1000000u) {
                    rto_ = 60 * 1000000u;  // 60 s cap, mirrors UpdateRto
                }
            }
            void EnterTimeWait(TimePoint now) noexcept {
                timewait_deadline_ = now + two_msl_us_;
                // Defensive: a TIME-WAIT conn must stay in the sweep so it is
                // reclaimed at the deadline. The normal call sites pair this
                // with Transition(kTimeWait) (which sets dirty), but a future
                // direct caller must not strand the conn un-swept forever
                // (conn-cap leak).
                timers_dirty_.store(true, std::memory_order_relaxed);
            }
            /**
             * @brief Configures keepalive (Linux TCP_KEEPIDLE/INTVL/CNT).
             * @param idle_us Idle time before the first probe (0 = disabled).
             * @param intvl_us Probe interval.
             * @param cnt     Failed probes before aborting the connection.
             * @note Linux parity: disabling (idle_us = 0) does NOT reset the
             *       unanswered-probe counter. Re-enabling after unanswered
             *       probes with a smaller cnt can abort at the next idle
             *       check (keepalive audit m3 - documented, not a bug).
             */
            void SetKeepalive(UInt64 idle_us, UInt64 intvl_us, UInt32 cnt) noexcept {
                keepalive_idle_ = idle_us;
                keepalive_intvl_ = (0 == intvl_us) ? 1000000 : intvl_us;
                keepalive_cnt_ = (0 == cnt) ? 8 : cnt;
                if (0 < keepalive_idle_) {
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /**
             * @brief TCP_USER_TIMEOUT (Linux parity): the maximum time the
             *        oldest unacknowledged segment may stay outstanding before
             *        the connection is aborted (0 = disabled; the RTO-retry
             *        budget still bounds it). The check runs on the timer
             *        sweep, so the abort fires without any packet activity.
             */
            void SetUserTimeout(UInt64 timeout_us) noexcept {
                user_timeout_us_ = timeout_us;
                if (0 < user_timeout_us_) {
                    timers_dirty_.store(true, std::memory_order_relaxed);
                }
            }
            /** @brief Configured TCP_USER_TIMEOUT (0 = disabled). */
            UInt64 UserTimeout() const noexcept { return user_timeout_us_; }
            /**
             * @brief Next zero-window persist probe time (0 = none pending).
             */
            UInt64 PersistDeadline() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return persist_deadline_;
            }
            /**
             * @brief Sets the persist probe interval (RFC 1122 zero-window
             *        probing). Default 1 s, exponential backoff to 60 s.
             *        The probe itself is fired by OnPersistTimer.
             */
            void SetPersistInterval(UInt32 us) noexcept {
                persist_interval_ = (0 == us) ? 1 : us;
                persist_base_ = persist_interval_;
            }
            /**
             * @brief Fires the RFC 1122 zero-window probe (1 byte).
             */
            void OnPersistTimer(TimePoint now) noexcept;
            /**
             * @brief Current pacing rate (bytes/sec) of a connection.
             */
            UInt64 PacingRate() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return cc_.pacing_rate;
            }
            UInt64 KeepaliveIdle() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_idle_;
            }
            UInt64 KeepaliveInterval() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_intvl_;
            }
            UInt32 KeepaliveCount() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return keepalive_cnt_;
            }
            /**
             * @brief Duplicate-ACK counter.
             */
            UInt32 DupAcks() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return dup_acks_;
            }
            /**
             * @brief True when RFC 5681 fast recovery is active.
             */
            bool FastRecovery() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return fast_recovery_;
            }
            /**
             * @brief Sequence number of the oldest unacknowledged segment
             *        (the retransmit target), 0 when the queue is empty.
             */
            UInt32 FrontSeq() const noexcept {
                std::lock_guard<std::recursive_mutex> scope(syncobj_);
                return retrans_queue_.empty() ? 0 : retrans_queue_.front().seq;
            }
            /**
             * @brief Handles the retransmission timer (exponential backoff).
             * @param now Monotonic time.
             */
            void OnRetransmitTimer(TimePoint now) noexcept;
            /**
             * @brief Current RTO (microseconds).
             */
            UInt32 Rto() const noexcept { return rto_; }

            TcpState State() const noexcept { return state_; }
            UInt32 SndNxt() const noexcept { return snd_nxt_; }
            UInt32 SndUna() const noexcept { return snd_una_; }
            UInt32 RcvNxt() const noexcept { return rcv_nxt_; }
            UInt32 Window() const noexcept { return window_; }
            /**
             * @brief Bytes awaiting acknowledgment.
             */
            UInt32 InflightBytes() const noexcept { return snd_nxt_ - snd_una_; }
            /**
             * @brief A sent (possibly unacknowledged) segment retained for
             *        zero-copy retransmission. Public so the migration
             *        checkpoint can carry the retransmission queue.
             */
            struct SentSeg {
                UInt32      seq = 0;
                UInt32      len = 0;
                TimePoint   sent_at = 0;
                UInt32      rto = 0;       /**< Current per-segment RTO */
                UInt32      retries = 0;
                UInt32      sacked = 0;    /**< Bytes SACKed within this segment (RFC 6675 pipe) */
                buf::BufRef data;          /**< Payload reference (zero-copy retransmit) */
            };

            /**
             * @brief Serializes connection state for migration. Carries the
             *        full send-side transmission state so a migrated
             *        connection can still retransmit its in-flight segments
             *        and flush its buffered application data: a checkpoint
             *        with only the sequence numbers leaves the restored
             *        connection with snd_nxt_ > snd_una_ but no segments to
             *        retransmit - the RTO path sees an empty queue and the
             *        flow stalls forever (in-flight data unrecoverable).
             */
            struct ConnCheckpoint {
                TcpState state      = TcpState::kClosed;
                UInt32   snd_una    = 0;
                UInt32   snd_nxt    = 0;
                UInt32   rcv_nxt    = 0;
                UInt32   snd_wnd    = 65535;
                UInt32   window     = 65535;
                UInt32   rcv_wnd    = 65535;  /**< RX acceptance window (SetRcvBuf) - without it a migrated conn drops data beyond the default */
                Byte     rcv_wscale = 0;  /**< Negotiated receive scale (RFC 7323) */
                Byte     snd_wscale = 0;  /**< Peer's window scale (needed to read future window fields) */
                UInt32   rto        = 1000000;
                UInt32   srtt       = 0;
                UInt32   rttvar     = 0;
                std::vector<Byte>              pending_send;  /**< Buffered application bytes */
                std::size_t pending_send_offset = 0; /**< Consumed prefix in the retained buffer */
                std::deque<SentSeg>            retrans_queue; /**< In-flight, unacknowledged segments */
            };
            /**
             * @brief Produces a migration checkpoint.
             */
            ConnCheckpoint MakeCheckpoint() const noexcept;
            /**
             * @brief Applies a migration checkpoint (restore path).
             * @param ckpt State captured on the source shard.
             */
            void ApplyCheckpoint(const ConnCheckpoint& ckpt) noexcept;
            /**
             * @brief Installs the in-order receive callback.
             */
            void SetRecvHandler(RecvCallback cb) noexcept { recv_cb_ = std::move(cb); }
            /** @brief RFC 793 urgent-data notification (SO_OOBINLINE): fires
             *         once per URG segment, after the inline data delivery.
             *         The urgent bytes are delivered with the normal stream
             *         (the TCP semantics of the modern OOBINLINE usage). */
            void SetUrgentCallback(std::function<void()> cb) noexcept {
                urgent_cb_ = std::move(cb);
            }
            /**
             * @brief Installs the timer-driven state-change notification.
             */
            void SetStateChangeCallback(StateChangeCallback cb) noexcept { state_change_cb_ = std::move(cb); }
            /**
             * @brief Sets the TCP_NODELAY flag (Nagle disable).
             * @note Controls the Nagle algorithm (RFC 896 / Minshall
             *       variant: a small segment waits for aggregation while
             *       inflight >= MSS).
             */
            void SetNodelay(bool enabled) noexcept { nodelay_ = enabled; }
            /**
             * @brief TCP_NODELAY flag.
             */
            bool Nodelay() const noexcept { return nodelay_; }
            /**
             * @brief Requests ECN negotiation (RFC 3168) on this connection.
             * @param enabled When true, SYN carries the ECE flag.
             */
            void SetEcnRequested(bool enabled) noexcept { ecn_requested_ = enabled; }
            /**
             * @brief ECN requested on this connection (RFC 3168).
             */
            bool EcnRequested() const noexcept { return ecn_requested_; }
            /**
             * @brief Suppresses SACK-permitted on the SYN (RFC 5827 ER tests
             *        and kernel tcp_sack=0 parity): the connection then runs
             *        without SACK, so RACK's sack_ok_ gate never fires and
             *        the Early-Retransmit dupthresh applies.
             * @param disabled When true, the SYN omits SACK-permitted.
             */
            void SetNoSackPermitted(bool disabled) noexcept { no_sack_permitted_ = disabled; }
            /**
             * @brief SACK-permitted suppressed on this connection.
             */
            bool NoSackPermitted() const noexcept { return no_sack_permitted_; }
            /**
             * @brief ECN negotiated (both ends offered ECE).
             */
            bool EcnActive() const noexcept { return ecn_active_; }
            /**
             * @brief RFC 3168 s6.1.3: records that the receiver detected a
             *        CE-marked IP packet (ECN field = 11). The next ACKs then
             *        echo ECE until the sender answers with CWR.
             */
            void SetCeSeen() noexcept { ecn_ce_seen_ = true; }
            /**
             * @brief RFC 3168 s6.1.3: ACK flags include ECE once CE was
             *        detected on an ECN-active connection.
             */
            UInt16 AckFlags() const noexcept {
                return static_cast<UInt16>(kFlagAck |
                                           ((ecn_active_ && ecn_ce_seen_) ? kFlagEce : 0));
            }
            /**
             * @brief Advertised receive-window field (RFC 1122 s4.2.3.4):
             *        zero while the app is backpressuring (recv_cb_ rejected
             *        data) - the peer stops sending and persists instead of
             *        retransmitting into a window it cannot use. Cleared by
             *        ResumeReceive() when application capacity returns. Reflects the out-of-order
             *        buffer occupancy: buffered OOO bytes are receive memory
             *        already consumed, so the free capacity is
             *        window_ - ooo_bytes_.
             */
            UInt16 AdvertisedWindow() const noexcept {
                if (rcv_blocked_ || ooo_bytes_ + pending_frontier_bytes_ >= window_) {
                    return 0;
                }
                return static_cast<UInt16>((window_ - ooo_bytes_ - pending_frontier_bytes_) >> rcv_wscale_);
            }
            /**
             * @brief Configures our receive-buffer capacity (the advertised
             *        receive window). The window the peer may fill, bounded by
             *        the negotiated scale's representable range. Larger values
             *        raise the per-connection in-flight ceiling on high-BDP
             *        links; the default (65535) matches the legacy behavior.
             * @param bytes Receive capacity in bytes (clamped to
             *        [1, 65535 << 7]).
             */
            void SetRcvBuf(UInt32 bytes) noexcept {
                constexpr UInt32 kMaxRcvBuf = 65535u << 7;  // wscale 7 offer ceiling
                const UInt32 v = (bytes < 1) ? 1u : ((bytes > kMaxRcvBuf) ? kMaxRcvBuf : bytes);
                window_ = v;
                rcv_wnd_ = v;
                cc_.rcv_wnd = v;
            }
            /**
             * @brief Sets our advertised window-scale factor (0-14, RFC 7323).
             */
            void SetRcvWscale(Byte factor) noexcept { rcv_wscale_ = (14 < factor) ? 14 : factor; }
            /**
             * @brief Peer's negotiated window-scale factor.
             */
            Byte SndWscale() const noexcept { return snd_wscale_; }
            /**
             * @brief Sets the peer's window-scale factor (passive-open path).
             */
            void SetSndWscale(Byte factor) noexcept { snd_wscale_ = (14 < factor) ? 14 : factor; }

        private:
            std::size_t PendingSendSizeNoLock() const noexcept {
                return pending_send_.size() - pending_send_offset_;
            }
            bool PendingSendEmptyNoLock() const noexcept {
                return pending_send_.size() == pending_send_offset_;
            }
            void AppendPendingSendNoLock(const Byte* data, UInt32 len) noexcept;
            void ConsumePendingSendFrontNoLock() noexcept;
            void RequeuePendingSendNoLock(std::vector<Byte>& data, std::size_t offset) noexcept;
            void Transition(TcpState next) noexcept;
            void SendSegment(UInt32 seq, UInt32 ack, UInt16 flags, const Byte* payload, UInt32 payload_len) noexcept;
            Byte BuildSackRanges(UInt32* out, Byte max_pairs) const noexcept;
            void SendChallengeAck() noexcept;
            void SendDupAck() noexcept;
            void UpdateRto(UInt32 sample_us) noexcept;
            void ArmRetransmit(TimePoint now, UInt32 interval_us = 0) noexcept;
            void RetransmitFront(TimePoint now, bool fresh_ts = false) noexcept;
            void ResplitRetransQueue(UInt16 payload_cap) noexcept;
            void OnAckReceived(UInt32 ack, bool ece, TimePoint now, const TcpOpts* opts) noexcept;
            void RackDetectLoss(TimePoint now) noexcept;
            UInt32 PipeBytes() const noexcept;
            void RetransmitEarliestMissing(TimePoint now, const TcpOpts* opts) noexcept;
            /**
             * @brief Processes peer data arriving in a closing state
             *        (FIN-WAIT-1/2, CLOSE-WAIT): deliver, reassemble
             *        out-of-order, re-ACK.
             * @return true when the peer's FIN was consumed by this call
             *         (in-order pure FIN, or a buffered out-of-order FIN
             *         whose gap filled) - the closing-state caller must
             *         then advance the state machine (RFC 793), otherwise
             *         an ACKed-but-untransitioned FIN skips 2MSL.
             */
            bool ProcessClosingData(const Byte* payload, UInt32 payload_len, UInt32 seq,
                                    bool has_fin, TimePoint now, UInt32 ts_val = 0) noexcept;
            void CutCwnd() noexcept;
            void NotifyStateChanged() noexcept;
            void MaybeFinishClose(TimePoint now) noexcept;
            static TimePoint NowUs() noexcept;
            /**
             * @brief Binds the TFO cookie to the full (client, server)
             *        endpoint triple (client IP, server IP, server port).
             *        A cookie learned on one listener cannot be replayed on
             *        another (the client IP is unchanged but the server port
             *        differs). XOR-folds the 4 address words together with
             *        the server port so both endpoints influence the hash.
             */
            void TfoBoundAddr(UInt32 out[4]) const noexcept {
                for (UInt32 i = 0; i < 4; ++i) {
                    out[i] = remote_.addr[i] ^ local_.addr[i];
                }
                out[0] ^= local_.port;
            }

            TcpState    state_;
            Endpoint    local_;
            Endpoint    remote_;
            UInt32      iss_      = 0;
            UInt32      irs_      = 0;
            UInt32      snd_una_  = 0;
            UInt32      snd_nxt_  = 0;
            UInt32      rcv_nxt_  = 0;
            UInt32      rcv_wnd_  = 65535;
            UInt32      snd_wnd_  = 65535;
            UInt32      snd_wl1_  = 0;   /**< RFC 793 SND.WL1: ack of last window update */
            UInt32      snd_wl2_  = 0;   /**< RFC 793 SND.WL2: seq of last window update */
            UInt32      window_   = 65535;
            UInt32      srtt_     = 0;      /**< Smoothed RTT (us) */
            UInt32      rttvar_   = 0;      /**< RTT variance (us) */
            UInt32      rto_      = 1000000; /**< RTO (us), RFC 6298 initial 1s */
            UInt32      two_msl_us_ = 120 * 1000000;  /**< 2MSL (RFC 793), default 120 s */
            UInt64      timewait_deadline_ = 0;       /**< TIME-WAIT reclamation deadline (us) */
            UInt32      persist_interval_ = 1000000;  /**< Zero-window probe interval (us) */
            UInt32      persist_base_     = 1000000;  /**< User-configured persist base (us); backoff only moves persist_interval_ */
            UInt64      persist_deadline_ = 0;        /**< Next zero-window probe time */
            UInt64      keepalive_idle_ = 0;          /**< Idle before keepalive probes (us); 0 = off */
            UInt64      keepalive_intvl_ = 75 * 1000000; /**< Keepalive probe interval (us); Linux TCP_KEEPINTVL 75 s */
            UInt32      keepalive_cnt_ = 8;           /**< Failed probes before abort */
            UInt32      keepalive_probes_ = 0;        /**< Consecutive unanswered probes */
            TimePoint   last_rx_ = 0;                 /**< Last inbound segment time (keepalive idle) */
            UInt16      orig_peer_mss_ = 0;           /**< Negotiated MSS before PMTUD reduction */
            UInt32      user_mss_ = 0;                /**< TCP_MAXSEG ceiling (0 = unset, Linux semantics) */
            UInt32      mtu_probe_interval_ = 600 * 1000000;  /**< RFC 1191 re-probe interval (us) */
            UInt64      mtu_probe_deadline_ = 0;      /**< Next MTU re-probe time */
            std::atomic<bool> timers_dirty_{true};    /**< Any timer armed / buffered sends (poll skip fast path) */
            TimePoint   rto_deadline_ = 0;
            UInt32      dup_acks_ = 0;
            UInt32      fast_retransmit_seq_ = 0;
            bool        ack_pending_ = false;
            UInt32      ack_count_ = 0;
            TimePoint   ack_deadline_ = 0;
            TimePoint   challenge_deadline_ = 0;  /**< RFC 5961 challenge-ACK window end (us) */
            UInt32      challenge_count_ = 0;     /**< Challenge ACKs sent in current window */
            TimePoint   dupack_deadline_ = 0;     /**< dup-ACK rate-limit window end (us) */
            UInt32      dupack_count_ = 0;        /**< Dup-ACKs sent in current window */
            struct OutSeg {
                std::vector<Byte> data;
                bool fin = false;  // RFC 793: the segment carried the FIN flag
                UInt32 ts_val = 0; // RFC 7323: the segment's TSval (TsRecent on drain)
            };
            bool TrimOooToFrontier() noexcept;
            std::map<UInt32, OutSeg> ooo_;       /**< Out-of-order reassembly buffer (seq -> segment) */
            UInt32      ooo_bytes_ = 0;
            /**
             * The in-order segment at RCV.NXT rejected by recv_cb_. Retaining
             * it lets ResumeReceiveDetailed redeliver the gap without waiting
             * for a peer RTO. It shares the receive-window occupancy ledger
             * with ooo_bytes_.
             */
            std::unique_ptr<OutSeg> pending_frontier_;
            UInt32      pending_frontier_bytes_ = 0;
            std::deque<SentSeg> retrans_queue_;
            size_t      retrans_queue_bytes_ = 0; /**< Total bytes queued in retrans_queue_ (C2: cap enforcement) */
            static constexpr size_t kMaxRetransQueueBytes = 1048576;  /**< 1 MiB per-conn cap (C2 fix) */

            /**
             * @brief Enforce the per-connection retransmission queue byte cap (C2 fix).
             *        Drops oldest segments from the front until under cap.
             */
            void EnforceRetransQueueCap() noexcept {
                while (!retrans_queue_.empty() && retrans_queue_bytes_ > kMaxRetransQueueBytes) {
                    size_t front_size = retrans_queue_.front().data.Len();
                    retrans_queue_bytes_ -= front_size;
                    retrans_queue_.pop_front();
                }
            }

            Byte        md5_key_[64];
            UInt32      md5_key_len_ = 0;
            UInt16      peer_mss_ = 1460;  /**< Peer-advertised MSS (default 1460) */
            static constexpr UInt32 kMinSndBuf = 4096;
            static constexpr UInt32 kDefaultSndBuf = 65536;  /**< 64 KiB per-conn quota */
            // L3 fix: reserve capacity to reduce reallocations during handshake
            static constexpr UInt32 kPendingSendReserve = 1024;
            UInt32      snd_buf_ = kDefaultSndBuf;
            std::vector<Byte> pending_send_;  /**< App data queued while SYN/SYN+ACK is in flight (full client semantics) */
            std::size_t pending_send_offset_ = 0; /**< Avoid copying the unsent suffix after a partial flush */
            SendAdmissionSnapshot last_send_admission_;  /**< Updated only by rejected SendData calls. */
            std::atomic<UInt64> ack_release_valid_acks_{0};
            std::atomic<UInt64> ack_release_advance_events_{0};
            std::atomic<UInt64> ack_release_advance_bytes_{0};
            std::atomic<UInt64> ack_release_pending_flush_attempts_{0};
            std::atomic<UInt64> ack_release_tx_sink_packets_{0};
            std::atomic<UInt64> ack_release_tx_sink_bytes_{0};
            std::atomic<UInt64> ack_release_pending_flush_pacing_{0};
            std::atomic<UInt64> ack_release_pending_flush_window_cwnd_{0};
            std::atomic<UInt64> ack_release_pending_flush_fast_recovery_pipe_{0};
            std::atomic<UInt64> ack_release_pending_flush_packet_allocation_{0};
            std::atomic<UInt64> ack_release_rate_change_events_{0};
            std::atomic<UInt64> ack_release_rate_change_with_pending_{0};
            std::atomic<UInt64> ack_release_rate_change_old_rate_sum_{0};
            std::atomic<UInt64> ack_release_rate_change_new_rate_sum_{0};
            std::atomic<UInt64> ack_release_rate_change_flush_packets_{0};
            std::atomic<UInt64> ack_release_rate_change_flush_bytes_{0};
            std::atomic<UInt64> ack_release_rate_change_deadline_active_{0};
            std::atomic<UInt64> ack_release_rate_change_deadline_remaining_us_sum_{0};
            std::atomic<UInt64> tso_gate_direct_candidates_{0};
            std::atomic<UInt64> tso_gate_direct_disabled_{0};
            std::atomic<UInt64> tso_gate_direct_pending_{0};
            std::atomic<UInt64> tso_gate_direct_outstanding_{0};
            std::atomic<UInt64> tso_gate_direct_fast_recovery_{0};
            std::atomic<UInt64> tso_gate_direct_window_cwnd_{0};
            std::atomic<UInt64> tso_gate_direct_pacing_{0};
            std::atomic<UInt64> tso_gate_direct_pool_limit_{0};
            std::atomic<UInt64> tso_gate_direct_emitted_{0};
            std::atomic<UInt64> tso_gate_flush_candidates_{0};
            std::atomic<UInt64> tso_gate_flush_disabled_{0};
            std::atomic<UInt64> tso_gate_flush_outstanding_{0};
            std::atomic<UInt64> tso_gate_flush_fast_recovery_{0};
            std::atomic<UInt64> tso_gate_flush_window_cwnd_{0};
            std::atomic<UInt64> tso_gate_flush_pacing_{0};
            std::atomic<UInt64> tso_gate_flush_emitted_{0};
            mutable std::recursive_mutex syncobj_;  /**< Guards state changes (multi-thread safe) */
            TxSink      sink_;
            RecvCallback recv_cb_;
            std::function<void()> urgent_cb_;  /**< RFC 793 urgent-data notification */
            StateChangeCallback state_change_cb_; /**< Timer-driven state-change notify (stack-registered) */
            bool        close_pending_ = false;   /**< Close() deferred the FIN until buffered data drains */
            bool        nodelay_ = false;
            bool        quickack_ = false;  /**< TCP_QUICKACK: immediate ACKs */
            Byte        tfo_cookie_[8] = { 0 };  /**< Peer TFO cookie (RFC 7413) */
            bool        has_tfo_cookie_ = false;
            std::vector<Byte> tfo_syn_data_;  /**< Early data carried on the SYN (retransmit with it) */
            xtcp::core::TfoCookie tfo_;  /**< Server-side TFO cookie generator (RFC 7413) */
            std::function<void(const Byte*)> tfo_cb_;  /**< Notifies the stack of a learned cookie */
            UInt32      syn_retries_ = 6;   /**< TCP_SYNCNT: handshake retransmit budget */
            UInt32      syn_retry_count_ = 0;/**< Consecutive unanswered SYN/SYN+ACK retransmits */
            UInt32      syn_rto_ = 0;   /**< Handshake retransmit backoff (us); 0 = base rto_ */
            UInt32      fin_rto_ = 0;   /**< FIN retransmit backoff (us); 0 = base rto_ */
            UInt32      finwait2_timeout_ = 60 * 1000000;  /**< Linux tcp_fin_timeout (us) */
            UInt64      finwait2_deadline_ = 0;            /**< FIN-WAIT-2 reclamation time */
            bool        ecn_requested_ = false;
            bool        no_sack_permitted_ = false; /**< Suppress SACK-permitted on SYN (RFC 5827 ER / tcp_sack=0 parity) */
            bool        peer_syn_sack_ = false;  /**< Peer's SYN carried SACK-permitted (RFC 2018: both sides must offer) */
            bool        ecn_active_ = false;
            bool        ecn_ce_seen_ = false; /**< RFC 3168 s6.1.3: received a CE-marked IP packet */
            bool        rcv_blocked_ = false;    /**< App backpressure: advertise window 0 (RFC 1122 s4.2.3.4) */
            TimePoint   ecn_reduce_at_ = 0;  /**< Last ECE-driven cwnd cut (RFC 3168 s6.1.2: once per RTT) */
            UInt64      user_timeout_us_ = 0; /**< TCP_USER_TIMEOUT: abort when the oldest unacked exceeds this (0 = disabled) */
            bool        cwr_pending_ = false; /**< Next data segment carries CWR (RFC 3168 s6.1.2) */
            Byte        rcv_wscale_ = 0;   /**< Our advertised window scale */
            Byte        snd_wscale_ = 0;   /**< Peer's window scale */
            XtcpConnCc  cc_;               /**< Congestion-control state (KCC by default; Reno RFC 5681 when no ops are plugged) */
            std::unique_ptr<cc::XtcpCongestionOps> cc_ops_owner_;  /**< Connection-owned hook-table copy (registry race-free) */
            const cc::XtcpCongestionOps* cc_ops_ = NULLPTR;  /**< Plugged algorithm (NULLPTR = Reno); points at cc_ops_owner_ */
            bool        fast_recovery_ = false;  /**< RFC 5681 fast recovery active */
            UInt32      recover_fs_ = 0;   /**< RFC 6937 PRR: flight size at the recovery entry */
            UInt32      prr_delivered_ = 0; /**< RFC 6937 PRR: bytes delivered during recovery */
            UInt32      prr_out_ = 0;       /**< RFC 6937 PRR: bytes sent during recovery */
            bool        sack_ok_ = false;        /**< RFC 2018: peer negotiated SACK (SACK-permitted on SYN/SYN+ACK) */
            bool        timestamps_ok_ = false;  /**< RFC 7323: peer negotiated TCP timestamps (both SYNs carried TSopt) */
            bool        peer_ts_offered_ = false; /**< RFC 7323: the peer's SYN carried the TSopt */
            bool        syn_ts_offered_ = false;  /**< RFC 7323: OUR SYN/SYN+ACK carried the TSopt (both-sides rule) */
            bool        ts_enabled_ = true;      /**< RFC 7323: the stack offers timestamps on its SYNs */
            UInt32      ts_recent_ = 0;          /**< RFC 7323: TsRecent - the peer's TSval of the last in-order segment (PAWS anchor + ts_ecr source) */
            UInt32      ts_recent_stamp_ = 0;    /**< RFC 7323 s5.5: ms clock when TsRecent was stored (PAWS aging - a 24-day idle relaxes the check) */
            bool        tso_tx_ = false;         /**< TSO direct-sends enabled (backend kCapTsoTx + no qdisc) */
            bool        checksum_partial_tx_ = false; /**< Backend accepts TCP pseudo-header checksum seeds */
            UInt32      retransmit_count_ = 0;   /**< Total retransmissions (RTO + fast) */
            UInt32      rack_losses_ = 0;        /**< RFC 8985 RACK: loss verdicts that entered recovery */
            UInt32      er_losses_ = 0;          /**< RFC 5827 Early Retransmit: ER entries that entered recovery */
            UInt32      dsack_undos_ = 0;        /**< RFC 2883 D-SACK: spurious-recovery undos */
            UInt32      dsack_left_ = 0;         /**< RFC 2883: most recent duplicate's left edge (receiver) */
            UInt32      dsack_right_ = 0;        /**< RFC 2883: most recent duplicate's right edge (receiver) */
            bool        dsack_pending_ = false;  /**< RFC 2883: a duplicate awaits the next ACK's first SACK block */
            UInt32      sack_retx_next_ = 0;     /**< Next missing range to retransmit (SACK recovery) */
            UInt32      last_retx_seq_ = 0;      /**< Last SACK-path retransmit range start (storm gate) */
            UInt32      last_retx_len_ = 0;      /**< Last SACK-path retransmit length (storm gate) */
            UInt32      dsack_retx_seq_ = 0;     /**< RFC 2883: most recent retransmitted range start (persists across ACKs) */
            UInt32      dsack_retx_len_ = 0;     /**< RFC 2883: most recent retransmitted range length (persists across ACKs) */
            UInt32      prior_cwnd_ = 0;         /**< Pre-recovery cwnd (spurious fast-recovery undo) */
            UInt32      prior_ssthresh_ = 0;     /**< Pre-recovery ssthresh (spurious fast-recovery undo) */
            bool        undo_marker_ = false;    /**< No-SACK fast-recovery entry: undo candidate */
            UInt32      rto_ts_val_ = 0;         /**< RFC 3522 Eifel: TSval of the last data retransmission */
            bool        rto_pending_ = false;    /**< RFC 3522 Eifel: an RTO retransmission awaits its ACK */
            TimePoint   tlp_deadline_ = 0;       /**< Tail-loss probe deadline (RFC 8985 TLP) */
            bool        tlp_armed_ = false;      /**< A TLP probe is pending */
            TimePoint   first_outstanding_ = 0;  /**< Send time of the oldest unacked segment (TCP_USER_TIMEOUT anchor; immune to the Karn sent_at clear) */
            UInt32      rack_seq_ = 0;           /**< RFC 8985 RACK: seq of the most recently delivered segment */
            TimePoint   rack_time_ = 0;          /**< RACK: send time of the most recently delivered segment */
            UInt32      rack_reo_wnd_ = 0;       /**< RACK: reorder window (us); shrinks toward min-RTT/4 */
            TimePoint   pacing_deadline_ = 0;    /**< Next allowed send time (pacing, bytes/sec) */
            TimePoint   last_rate_sample_ = 0;   /**< Last rate-sample time (for interval_us) */
            UInt64      last_delivered_ = 0;     /**< cc_.delivered at the last emitted rate sample (delivered-delta base) */
        };

        /**
         * @brief Passive listener with SYN queue.
         */
        class TcpListener {
        public:
            TcpListener(const Endpoint& local, UInt32 backlog, TxSink sink) noexcept;
            virtual ~TcpListener() noexcept;

            /**
             * @brief Handles a SYN addressed to the listener.
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param remote Source endpoint.
             * @return True when the SYN was accepted.
             */
            bool OnSyn(const Byte* data, UInt32 len, const Endpoint& remote) noexcept;
            /**
             * @brief Accepts a completed handshake (ACK arriving after
             *        SYN+ACK), moving the flow to Established.
             * @param data Segment bytes.
             * @param len  Segment length.
             * @param remote Source endpoint.
             */
            void OnSynAck(const Byte* data, UInt32 len, const Endpoint& remote) noexcept;
            /**
             * @brief Number of pending handshakes.
             */
            UInt32 Pending() const noexcept { return pending_; }
            /**
             * @brief Configures the receive-buffer capacity advertised in the
             *        listener's SYN+ACK (default 0 = the 65535 protocol
             *        default, matching the pre-config legacy behavior).
             */
            void SetRcvBuf(UInt32 bytes) noexcept { rcv_buf_ = bytes; }

        private:
            struct SynEntry {
                Endpoint remote;
                UInt32   iss = 0;
                UInt64   created_us = 0;  /**< SYN arrival tick (stale-entry expiry) */
            };

            Endpoint    local_;
            UInt32      backlog_ = 0;
            UInt32      pending_ = 0;
            UInt32      next_iss_ = 0;
            UInt32      rcv_buf_ = 0;  /**< Advertised receive capacity for the SYN+ACK (0 = 65535 default) */
            SynEntry*   syn_queue_ = NULLPTR;
            TxSink      sink_;
        };
    }
}
#include <chrono>

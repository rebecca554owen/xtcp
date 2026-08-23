#pragma once

/**
 * @file stack.h
 * @brief Stack-level integration: NDI backend in, IP routing to connections,
 *        TCP lifecycle (listen/connect/data), back-to-back interop.
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>
#include <xtcp/ndi.h>
#include <xtcp/core/ip.h>
#include <xtcp/core/scheduler.h>
#include <xtcp/core/tcp.h>
#include <xtcp/cc/cc.h>
#include <xtcp/mimt/mimt.h>
#include <xtcp/core/syncookies.h>
#include <xtcp/qdisc/qdisc.h>
#include <xtcp/options/options.h>
#include <deque>

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace xtcp {
    /**
     * @brief Received-data callback (application side).
     */
    typedef std::function<void(UInt64 conn_id, const Byte* data, UInt32 len)> RecvHandler;
typedef std::function<bool(UInt64 conn_id, const Byte* data, UInt32 len)> RecvHandlerChecked;
    /**
     * @brief Connection-state-change callback.
     */
    typedef std::function<void(UInt64 conn_id, core::TcpState state)> StateHandler;
    /**
     * @brief Connection-accept callback (server/passive-open mode).
     * @param conn_id New connection handle.
     * @param remote  Peer endpoint.
     * @param local   Our endpoint (the listener).
     * @return True to accept; false to refuse (immediate RST, RFC 793).
     * @warning Shares the name with xtcp::async::AcceptHandler (async.h) but
     *          has a DIFFERENT signature (bool(conn_id,remote,local) vs
     *          void(shared_ptr<mimt::MimtFlow>)). Bringing both namespaces
     *          into scope with `using namespace xtcp; using namespace
     *          xtcp::async;` makes the name ambiguous - qualify it
     *          (xtcp::AcceptHandler / xtcp::async::AcceptHandler) instead.
     */
    typedef std::function<bool(UInt64 conn_id, const core::Endpoint& remote,
                               const core::Endpoint& local)> AcceptHandler;
    /**
     * @brief MIMT flow delivery callback (audit mode).
     * @param flow Async stream bound to a connection.
     */
    typedef std::function<void(std::shared_ptr<mimt::MimtFlow> flow)> MimtOnFlow;

    /**
     * @brief Stable hash of an endpoint (family + address words + port).
     *        Shared routing key: listener MD5 / TFO cookie caches and the
     *        async layer's per-listener accept routing all use the same
     *        mapping, so a listener endpoint and the flows it accepts hash
     *        to the same key.
     */
    inline UInt64 EndpointKey(const core::Endpoint& ep) noexcept {
        UInt64 h = (static_cast<UInt64>(ep.port) << 16) ^ ep.family;
        const UInt32 words = (6 == ep.family) ? 4 : 1;
        for (UInt32 i = 0; i < words; ++i) {
            h ^= static_cast<UInt64>(ep.addr[i]);
            h *= 0x9E3779B97F4A7C15ull;
            h ^= h >> 31;
        }
        return h;
    }

    /**
     * @brief Stack instance wiring a backend into the IP/TCP core.
     */
    class XtcpStack {
    public:
        /** @brief Connection shard count (fixed: conn_id encodes the shard). */
        static constexpr UInt32 kShardCount = 8;
        /** @brief Per-shard state (forward decl: defined below). */
        struct Shard;

        explicit XtcpStack(ndi::Backend* backend) noexcept;
        virtual ~XtcpStack() noexcept;
        /**
         * @note MIMT FLOW LIFETIME: a mimt::MimtFlow delivered via the
         *          mimt_on_flow_ callback may safely OUTLIVE this stack: the
         *          destructor closes every flow (pending async ops complete
         *          with kClosed, 1:1 pairing) before the shards are freed, so
         *          a late Dispatch()/AsyncWrite() is a safe kClosed no-op
         *          rather than a use-after-free. Flows are inert after the
         *          owning stack is destroyed.
         * @brief Starts listening on an endpoint.
         * @return true when the listener was registered; false when the
         *         endpoint conflicts with an existing listener (EADDRINUSE:
         *         exact duplicate, or a wildcard overlapping a specific
         *         address).
         */
        bool Listen(const core::Endpoint& local) noexcept;
        /**
         * @brief Stops listening on an endpoint: removes the exact-matching
         *        listener registered with Listen so new SYNs to the port are
         *        no longer accepted, and the endpoint becomes available for a
         *        fresh Listen again.
         * @return true when an exact-matching listener was removed; false when
         *         nothing was listening on the endpoint.
         */
        bool StopListen(const core::Endpoint& local) noexcept;
        /**
         * @brief Initiates a connection (active open, sends SYN).
         * @return ConnId, or 0 on failure.
         */
        UInt64 Connect(const core::Endpoint& local, const core::Endpoint& remote) noexcept;
        /**
         * @brief Initiates a connection with TCP-MD5 (RFC 2385) pre-configured
         *        on the SYN (Linux TCP_MD5SIG is set before connect()).
         * @return ConnId, or 0 on failure.
         */
        UInt64 ConnectWithMd5(const core::Endpoint& local, const core::Endpoint& remote,
                              const Byte* key, UInt32 len) noexcept;
        /**
         * @brief Initiates a TCP Fast Open connection (RFC 7413): when a
         *        cookie was cached from a prior handshake, the SYN carries
         *        it plus the early data; without a cookie the SYN goes out
         *        plain and the early data is buffered until the handshake
         *        completes (RFC 7413 server refuses cookie-less SYN data).
         * @return ConnId, or 0 on failure.
         */
        UInt64 ConnectWithTfo(const core::Endpoint& local, const core::Endpoint& remote,
                              const Byte* data, UInt32 len) noexcept;
        /**
         * @brief Sends data on an established connection.
         */
        bool Send(UInt64 conn_id, const Byte* data, UInt32 len) noexcept;
        /**
         * @brief Attempts to reopen a checked-handler-blocked receive window.
         * @param state Optional post-attempt receive state snapshot.
         */
        core::ReceiveResumeResult ResumeReceiveDetailed(
            UInt64 conn_id, core::ReceiveStateSnapshot* state = NULLPTR) noexcept;
        bool ResumeReceive(UInt64 conn_id) noexcept {
            return core::ReceiveResumeResult::kResumed == ResumeReceiveDetailed(conn_id);
        }
        bool ReceiveState(UInt64 conn_id, core::ReceiveStateSnapshot& state) const noexcept;
        /**
         * @brief Sends a SYN with early data (TCP Fast Open, RFC 7413).
         * @return True when the SYN was emitted (SynSent); the data rides
         *         the SYN only when a cached cookie exists, otherwise it is
         *         buffered and flushed once the handshake completes.
         */
        bool TfoSendSynData(UInt64 conn_id, const Byte* data, UInt32 len) noexcept;
        /**
         * @brief Closes a connection (FIN).
         */
        void Close(UInt64 conn_id) noexcept;
        /**
         * @brief Aborts a connection with RST (Linux close + SO_LINGER 0).
         */
        void Abort(UInt64 conn_id) noexcept;
        /**
         * @brief Receives a packet from the backend (rx path).
         */
        void OnPacket(buf::BufRef&& packet) noexcept;

        /**
         * @brief Installs the received-data callback (application side).
         * @warning The callback runs on the rx/send path WITH THE SHARD LOCK
         *          HELD. It must NOT re-enter any stack-level API
         *          (OnPacket/PollAckTimers/DispatchMimt/Send/Close/Connect/
         *          ConnectionState/...): taking another shard lock from inside
         *          can deadlock against the rx thread. Defer any stack call
         *          to the owning event loop.
         * @warning CROSS-SHARD REENTRANCY: calling Send/Close on a connection
         *          that lives in another shard from inside this callback may
         *          deadlock under a multi-threaded driver (two threads each
         *          holding one shard lock and waiting on the other's). A
         *          single-threaded driver is safe - such calls just take the
         *          other shard lock in order.
         * @warning Must be set BEFORE any packet/send threads start: the setter
         *          writes recv_handler_ without a lock while OnPacket/Send read
         *          it on the rx/tx hot path (data race otherwise).
         * @warning BORROWED POINTER: the data pointer is valid ONLY for the
         *          duration of the callback - it points into a pool block that
         *          is released when OnPacket returns. Consume it synchronously
         *          (copy out / dispatch); never queue it for another thread.
         *          The MIMT layer (OnData) copies for the same reason.
         */
         void SetRecvHandler(RecvHandler handler) noexcept {
             // Legacy void handler: treated as always accepting (no
             // backpressure signal). Apps that must exert RFC 1122
             // zero-window backpressure use SetRecvHandlerChecked instead.
             recv_handler_ = [h = std::move(handler)](UInt64 id, const Byte* d, UInt32 n) mutable {
                 if (h) {
                     h(id, d, n);
                 }
                 return true;
             };
         }
         /**
          * @brief Installs a receive handler that can exert backpressure.
          *        Return false when the data cannot be accepted (e.g. the
          *        application buffer is full): the TCP layer rolls RCV.NXT
          *        back, advertises a zero receive window (RFC 1122 s4.2.3.4)
          *        and the peer persists instead of retransmitting into an
          *        unusable window. Call ResumeReceive() after application
          *        capacity becomes available to advertise the reopened window.
          * @warning Same reentrancy/lifetime rules as SetRecvHandler.
          */
         void SetRecvHandlerChecked(RecvHandlerChecked handler) noexcept { recv_handler_ = std::move(handler); }
        /**
         * @brief Installs the urgent-data notification (RFC 793 SO_OOBINLINE):
         *        fires once per URG segment, after the inline delivery. The
         *        urgent bytes arrive with the normal stream; this is the
         *        out-of-band signal the app uses to switch modes.
         * @warning Same reentrancy/lifetime rules as SetRecvHandler.
         */
        void SetUrgentHandler(std::function<void(UInt64 conn_id)> handler) noexcept {
            urgent_handler_ = std::move(handler);
        }
        /**
         * @brief Installs the connection-state-change callback.
         * @warning Same reentrancy rule as SetRecvHandler: invoked with the
         *          shard lock held; must NOT re-enter stack-level APIs.
         * @warning CROSS-SHARD REENTRANCY: calling Send/Close on a connection
         *          in another shard from inside this callback may deadlock
         *          under a multi-threaded driver (inverted lock order across
         *          shards). Safe when a single thread drives the stack.
         * @warning Must be set BEFORE any packet/send threads start (unlocked
         *          write of state_handler_ - startup configuration only).
         */
        void SetStateHandler(StateHandler handler) noexcept { state_handler_ = std::move(handler); }
        /**
         * @brief Sets the acceptance callback for passive-open connections.
         *        Without it, every connection is accepted (RFC 793).
         * @warning Same reentrancy rule as SetRecvHandler: invoked with the
         *          shard lock held; must NOT re-enter stack-level APIs.
         * @warning CROSS-SHARD REENTRANCY: calling Send/Close on a connection
         *          in another shard from inside this callback may deadlock
         *          under a multi-threaded driver (inverted lock order across
         *          shards). Safe when a single thread drives the stack.
         * @warning Must be set BEFORE any packet/send threads start (unlocked
         *          write of accept_handler_ - startup configuration only).
         */
        void SetAcceptHandler(AcceptHandler handler) noexcept { accept_handler_ = std::move(handler); }
        /**
         * @brief Enables TCP-MD5 (RFC 2385) signing on one connection.
         */
        void SetMd5Key(UInt64 conn_id, const Byte* key, UInt32 len) noexcept;
        /**
         * @brief Enables TCP-MD5 (RFC 2385) for all connections accepted on
         *        the given listener endpoint.
         */
        void SetMd5KeyForListener(const core::Endpoint& local, const Byte* key, UInt32 len) noexcept;
        /**
         * @brief Enables MIMT audit mode: every connection's stream is
         *        delivered to the application as an async MimtFlow instead
         *        of the plain recv handler. The peer sees a normal
         *        connection to the real destination.
         * @param on_flow Delivery callback (one per connection).
         * @warning Same reentrancy rule as SetRecvHandler: on_flow runs on
         *          the rx path with the shard lock held and must NOT
         *          re-enter stack-level APIs.
         * @warning CROSS-SHARD REENTRANCY: calling Send/Close on a connection
         *          in another shard from inside on_flow may deadlock under a
         *          multi-threaded driver (inverted lock order across shards).
         *          Safe when a single thread drives the stack.
         */
        /**
         * @brief Installs the MIMT on-flow hook (accept-side flow delivery).
         * @param on_flow Called (under the shard lock) for every connection
         *                accepted by a listener when MIMT mode is active.
         * @note GLOBAL SCOPE (audit A-1): while the hook is armed, a SYN to
         *       ANY destination creates a connection and SYN+ACK - including
         *       ports with no listener - because the hook is the intercept
         *       point for TUN-style traffic (a proxy flow is created for
         *       every packet it forwards). The RFC 793 closed-port RST is
         *       therefore bypassed while a hook is installed. AsyncListen
         *       uses this hook for per-listener delivery, so its
         *       AsyncStopListen stops ACCEPT DELIVERY but not wire
         *       acceptance; call StartMimt(NULLPTR) to disarm the hook.
         * @note THREAD-SAFE: the hook is written under mimt_hook_mutex_ and
         *       read under the same mutex inside BindDataPath, so calling
         *       this at runtime (e.g. from AsyncListen) cannot race the
         *       event-loop thread's flow creation.
         */
        void StartMimt(MimtOnFlow on_flow) noexcept {
            std::lock_guard<std::mutex> scope(mimt_hook_mutex_);
            mimt_on_flow_ = std::move(on_flow);
        }
        /**
         * @brief Dispatches pending MIMT flow completions.
         * @return Number of completions dispatched.
         */
        UInt32 DispatchMimt() noexcept;
        /**
         * @brief Dispatches pending MIMT flow completions for ONE shard.
         *
         * Shard-affine event loops (one worker owning shards
         * {index, index+kShardCount, ...}) must use this overload instead of
         * the all-shard sweep: flow callbacks then always fire on the owning
         * worker's thread, restoring the single-threaded relay invariant and
         * eliminating cross-worker shard-lock contention.
         * @param shard_index Shard to pump (must be < kShardCount).
         * @return Number of completions dispatched on that shard.
         */
        UInt32 DispatchMimt(UInt32 shard_index) noexcept;
        /**
         * @brief Static shard index encoded in a conn_id ((id >> 56) % kShardCount).
         */
        static UInt32 ShardIndexOf(UInt64 conn_id) noexcept {
            return static_cast<UInt32>(conn_id >> 56) % kShardCount;
        }
        /**
         * @brief Sweeps timer-driven work on all connections (delayed-ACK,
         *        RTO/TLP/persist/keepalive/user-timeout timers, buffered
         *        flushes, DMA retry drain, closed/TIME-WAIT reclamation).
         * @return Number of timer events fired across all connections.
         */
        UInt32 PollAckTimers() noexcept;
        /**
         * @brief Sentinel returned by NextTimerDeadlineUs() when no timer
         *        work is pending anywhere in the stack.
         * @note  OPENPPP2 integration patch (tools/xtcp-patches/
         *        0001-next-timer-deadline.patch).
         */
        static constexpr UInt64 kNoTimerDeadline = ~static_cast<UInt64>(0);
        /**
         * @brief Earliest pending timer deadline across all connections
         *        (steady-clock microseconds, the PollAckTimers clock).
         * @return The minimum of every per-connection timer deadline and the
         *         qdisc pacing time; a value at or below the current clock
         *         means PollAckTimers is due now; kNoTimerDeadline when
         *         nothing is pending (the next packet/send/close arms the
         *         next deadline).
         * @note  O(1) when every shard is idle (the same sweep hints the
         *        PollAckTimers fast path uses); O(live connections) only on
         *        shards with armed timers.
         */
        UInt64 NextTimerDeadlineUs() noexcept;
        /**
         * @brief Sweeps timer-driven work for ONE shard (shard-affine loops).
         * @param shard_index Shard to sweep (must be < kShardCount).
         * @return Number of timer events fired on that shard.
         */
        UInt32 PollAckTimers(UInt32 shard_index) noexcept;
        /**
         * @brief Total live connections (all shards).
         */
        UInt32 ConnectionCount() const noexcept;
        /**
         * @brief Total IP datagrams successfully reassembled from fragments
         *        (IPv4 + IPv6, monotonic evidence counter).
         */
        UInt64 FragmentsReassembled() const noexcept;
        /**
         * @brief The FSM state of one connection (diagnostics).
         * @note Unknown/nonexistent ids also report core::TcpState::kClosed -
         *       indistinguishable from a genuinely closed connection. Use
         *       ConnectionExists() to tell "never existed / already reaped"
         *       apart from "exists in kClosed".
         */
        core::TcpState ConnectionState(UInt64 conn_id) const noexcept;
        /**
         * @brief Resolves a packet's connection shard by its 5-tuple (the
         *        DMA retry path attributes deferred segments this way).
         * @return The shard the packet's flow belongs to, or NULLPTR when
         *         the packet is not a parseable TCP packet.
         */
        Shard* ShardOfPacket(const ndi::Packet& p) noexcept;
        /**
         * @brief The shard that owns a connection id (diagnostics / tests).
         */
        Shard* ShardOf(UInt64 conn_id) const noexcept;
        /**
         * @brief Whether a connection id is currently live in the stack.
         * @param conn_id Connection handle.
         * @return True when the id maps to a live connection; false for
         *         unknown ids (never allocated, already reaped, or the
         *         connection object was torn down). Complements
         *         ConnectionState(), which reports kClosed for missing ids.
         */
        bool ConnectionExists(UInt64 conn_id) const noexcept;
        /**
         * @brief TIME-WAIT reclamation deadline of a connection (diagnostics).
         */
        UInt64 ConnTimeWaitDeadline(UInt64 conn_id) const noexcept;
        /**
         * @brief Sets the hard cap on live connections (SYN-flood bound).
         */
        void SetMaxConnections(UInt32 n) noexcept { max_conns_ = (0 == n) ? 1 : n; }
        /**
         * @brief Configures the receive-buffer capacity (advertised receive
         *        window) for every connection created from now on. Applied at
         *        conn creation (client and server side); the default (0)
         *        leaves the 65535 protocol default.
         * @warning Startup configuration only (conn-creation path).
         */
        void SetRcvBuf(UInt32 bytes) noexcept { rcv_buf_ = bytes; }
        /**
         * @brief Configures the send-buffer quota (per-connection in-flight
         *        bound) for every connection created from now on. The default
         *        (0) leaves the 64 KiB protocol default. Without this the
         *        receive-window configuration (SetRcvBuf) is defeated on
         *        high-BDP paths: the sender's in-flight is capped at
         *        min(cwnd, peer window, snd_buf_) - the fixed 64 KiB quota.
         * @warning Startup configuration only (conn-creation path).
         */
        void SetSndBuf(UInt32 bytes) noexcept { snd_buf_ = bytes; }
        /**
         * @brief Enables RFC 4987 SYN-cookie mode once live connections reach
         *        the threshold (0 = use max_conns_; values above max_conns_ are
         *        clamped to it, so cookie mode engages at the cap and cannot
         *        be disabled via this knob - Linux-like flood defense).
         * @warning Startup configuration only: set before any packet threads
         *          start (unlocked write of syncookie_threshold_).
         */
        void SetSyncookieThreshold(UInt32 n) noexcept { syncookie_threshold_ = n; }
        /**
         * @brief Sets the 2MSL linger for TIME-WAIT reclamation (RFC 793).
         * @param us Microseconds (default 120 s).
         * @warning Startup configuration only: set before any packet threads
         *          start (unlocked write of two_msl_us_).
         */
        void SetTwoMsl(UInt32 us) noexcept { two_msl_us_ = (0 == us) ? 1 : us; }
        /**
         * @brief Attaches a tx qdisc (FQ sch_fq semantics by default).
         *        Emitted packets are enqueued, then drained on the pacing
         *        clock (PollAckTimers). Ownership stays with the caller.
         * @param q Instance; NULLPTR detaches (direct backend tx).
         * @warning Startup configuration only: set before any packet/send
         *          threads start. The setter writes the bare tx_qdisc_ pointer
         *          without a lock while PollAckTimers/DrainTxQdisc read it on
         *          the hot path - calling it at runtime is a data race.
         */
        void SetTxQdisc(qdisc::XtcpQdisc* q) noexcept { tx_qdisc_ = q; }
        /**
* @brief Selects the congestion-control algorithm on one connection.
         * @param conn_id Connection handle.
 * @param name Registered algorithm name (cc/cc.h); NULLPTR/empty, or
 *        the literal "reno", select the built-in Reno (RFC 5681) default.
 * @return True when the named algorithm was found, or when
 *         NULLPTR/empty/"reno" selected the built-in Reno.
         */
        bool SetCongestionControl(UInt64 conn_id, const char* name) noexcept;
        /**
         * @brief Current pacing rate (bytes/sec) of a connection.
         */
        UInt64 ConnPacingRate(UInt64 conn_id) const noexcept {
            Shard* shard = ShardOf(conn_id);
            std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
            auto it = shard->conns_.find(conn_id);
            if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
                return 0;
            }
            return it->second->conn->PacingRate();
        }
        /**
         * @brief Peer's negotiated/current MSS of a connection.
         */
        UInt16 ConnPeerMss(UInt64 conn_id) const noexcept {            Shard* shard = ShardOf(conn_id);            std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
            auto it = shard->conns_.find(conn_id);
            if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
                return 0;
            }
            return it->second->conn->PeerMss();
        }
        /**
         * @brief Number of unacknowledged segments on a connection
         *        (diagnostics / tests: the TSO-direct gate requires an
         *        empty retransmission queue).
         */
        UInt32 ConnOutstandingSegments(UInt64 conn_id) const noexcept {
            Shard* shard = ShardOf(conn_id);
            std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
            auto it = shard->conns_.find(conn_id);
            if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
                return 0;
            }
            return it->second->conn->RetransQueueSize();
        }
        /**
         * @brief Total retransmissions on a connection (RTO + fast + RACK).
         */
        UInt32 ConnRetransmitCount(UInt64 conn_id) const noexcept {
            Shard* shard = ShardOf(conn_id);
            std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
            auto it = shard->conns_.find(conn_id);
            if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
                return 0;
            }
            return it->second->conn->RetransmitCount();
        }
        /**
         * @brief Per-connection TCP_INFO-style diagnostics (one lock).
         */
        struct ConnInfo {
            UInt32 cwnd = 0;         /**< Congestion window (segments) */
            UInt32 ssthresh = 0;     /**< Slow-start threshold (segments) */
            UInt32 snd_wnd = 0;      /**< Peer's advertised window (bytes) */
            UInt32 rtt_us = 0;       /**< Smoothed RTT (us) */
            UInt64 pacing_bps = 0;   /**< Current pacing rate (bytes/s) */
            UInt32 rto_us = 0;       /**< Current RTO (us) */
            UInt32 inflight = 0;     /**< Bytes in flight */
        };
        /**
         * @brief Snapshot of one connection's transmission state.
         */
        bool ConnGetInfo(UInt64 conn_id, ConnInfo& out) const noexcept {
            Shard* shard = ShardOf(conn_id);
            std::lock_guard<std::recursive_mutex> scope(shard->syncobj_);
            auto it = shard->conns_.find(conn_id);
            if (it == shard->conns_.end() || NULLPTR == it->second->conn) {
                return false;
            }
            out.cwnd = it->second->conn->Cwnd();
            out.ssthresh = it->second->conn->Ssthresh();
            out.snd_wnd = it->second->conn->SndWnd();
            out.rtt_us = it->second->conn->SrttUs();
            out.pacing_bps = it->second->conn->PacingRate();
            out.rto_us = it->second->conn->Rto();
            out.inflight = it->second->conn->InflightBytes();
            return true;
        }
        /** @brief Reads optional KCC state for one connection. */
        bool ConnGetKccTelemetry(
            UInt64 conn_id, cc::KccTelemetrySnapshot& out) const noexcept;
        /**
         * @brief Reads the latest SendData rejection snapshot for a connection.
         * @return True when the connection exists; @a out is zeroed on failure.
         * @note Diagnostics only; the snapshot is updated only when SendData
         *       rejects application data.
         */
        bool ConnLastSendAdmission(UInt64 conn_id,
                                   core::SendAdmissionSnapshot& out) const noexcept;
        /**
         * @brief Aggregates read-only ACK-release telemetry across live connections.
         */
        core::AckReleaseTelemetrySnapshot AckReleaseTelemetry() const noexcept;
        /** Reads cumulative ACK-release telemetry for one connection. */
        bool ConnAckReleaseTelemetry(
            UInt64 conn_id, core::AckReleaseTelemetrySnapshot& out) const noexcept;
        /**
         * @brief Aggregates read-only super-MSS TSO gate telemetry.
         */
        core::TsoGateTelemetrySnapshot TsoGateTelemetry() const noexcept;
        /**
         * @brief Sets the algorithm applied to all new connections.
         * @param name Registered algorithm name; NULLPTR/empty = Reno.
         */
        void SetDefaultCongestionControl(const char* name) noexcept;
        /**
         * @brief Returns the algorithm applied to all new connections.
         * @return Default CC name ("" = Reno, the built-in fallback).
         */
        const char* DefaultCongestionControl() const noexcept { return default_cc_.c_str(); }
        /**
         * @brief Requests ECN negotiation (RFC 3168) on all new connections.
         * @warning Startup configuration only: set before any packet threads
         *          start (unlocked write of default_ecn_).
         */
        void SetDefaultEcn(bool on) noexcept { default_ecn_ = on; }
        /**
         * @brief Suppresses SACK-permitted on all new connections (RFC 5827
         *        ER tests / kernel tcp_sack=0 parity).
         * @warning Startup configuration only: set before any packet threads
         *          start (unlocked write of default_no_sack_).
         */
        void SetDefaultNoSack(bool on) noexcept { default_no_sack_ = on; }
        /**
         * @brief Per-connection send-path diagnostics (for tests/samples).
         * @note Unknown/nonexistent ids zero every output parameter (all 0,
         *       ports 0) with no success signal; call ConnectionExists()
         *       first when an all-zero result needs disambiguation.
         */
        void ConnStats(UInt64 conn_id, UInt32& inflight, UInt32& cwnd,
                       UInt32& ssthresh, UInt32& snd_wnd, UInt32& retx,
                       UInt64& rto_deadline, UInt32& dup_acks, UInt32& fast_rec,
                       UInt32& front_seq, UInt32& snd_una, UInt16& local_port,
                       UInt16& remote_port) const noexcept;
        /**
         * @brief Local (source) endpoint of a connection (sockname / getsockname).
         * @param conn_id Connection handle.
         * @param out     Receives the local endpoint (family/address/port).
         * @return True when the connection exists; false leaves @a out untouched.
         * @note The port reflects the actual bound port: when Connect was
         *       called with local.port == 0, out.port is the assigned
         *       ephemeral port (IANA dynamic range).
         */
        bool GetLocalEndpoint(UInt64 conn_id, core::Endpoint& out) const noexcept;
        /**
         * @brief Remote (peer) endpoint of a connection (peername / getpeername).
         * @param conn_id Connection handle.
         * @param out     Receives the remote endpoint (family/address/port).
         * @return True when the connection exists; false leaves @a out untouched.
         */
        bool GetRemoteEndpoint(UInt64 conn_id, core::Endpoint& out) const noexcept;
        /**
         * @brief Total packets emitted to the backend (diagnostics).
         */
        UInt64 TxCount() const noexcept {
            UInt64 total = 0;
            for (UInt32 i = 0; i < kShardCount; ++i) {
                total += tx_count_[i].load(std::memory_order_relaxed);
            }
            return total;
        }
        /**
         * @brief Sets a per-connection option (Linux setsockopt style).
         * @param conn_id Connection handle.
         * @param opt     Option id (options/options.h).
         * @param value   Option value.
         * @param len     Value length.
         * @return True when the option was applied.
         */
        bool SetOption(UInt64 conn_id, options::SocketOption opt,
                       const void* value, UInt32 len) noexcept;
        /**
         * @brief Reads a per-connection option.
         * @return True when the option was read.
         */
        bool GetOption(UInt64 conn_id, options::SocketOption opt,
                       void* out, UInt32& len) const noexcept;
        /**
         * @brief Configures keepalive on a connection (microsecond precision).
         * @param idle_us Idle time before the first probe (0 = disabled).
         * @param intvl_us Probe interval.
         * @param cnt      Failed probes before aborting the connection.
         */
        void SetKeepalive(UInt64 conn_id, UInt64 idle_us, UInt64 intvl_us, UInt32 cnt) noexcept;
        /**
         * @brief TCP_USER_TIMEOUT: abort the connection when its oldest
         *        unacknowledged segment stays outstanding longer than the
         *        bound (0 = disabled; the RTO-retry budget still bounds it).
         */
        void SetUserTimeout(UInt64 conn_id, UInt64 timeout_us) noexcept;
        /**
         * @brief Sets the FIN-WAIT-2 reclamation timeout (Linux
         *        tcp_fin_timeout): a peer that never sends its FIN holds the
         *        closing side in FIN-WAIT-2; the connection is reclaimed once
         *        the deadline elapses.
         */
        void SetFinWait2Timeout(UInt64 conn_id, UInt32 us) noexcept;
        /**
         * @brief Sets the RFC 1191 periodic MTU re-probe interval: arms ONE
         *        recovery probe after a PMTU reduction (it restores the
         *        negotiated MSS on expiry; it is NOT re-armed afterwards -
         *        the next ICMP reduction arms it again). Default 600 s.
         */
        void SetMtuProbeInterval(UInt64 conn_id, UInt32 us) noexcept;
        /**
         * @brief Sets the RFC 1122 zero-window persist probe interval.
         */
        void SetPersistInterval(UInt64 conn_id, UInt32 us) noexcept;
        /**
         * @brief Stores a TFO cookie for a peer (RFC 7413): reconnections to
         *        that address carry the cookie automatically (Linux keeps it
         *        per socket across fast-open reconnects).
         */
        void SetTfoCookieFor(const core::Endpoint& remote, const Byte* cookie) noexcept;
        /**
         * @brief Reads the cached TFO cookie for a peer.
         * @return True when a cookie is cached.
         */
        bool GetTfoCookieFor(const core::Endpoint& remote, Byte out[8]) const noexcept;

    private:
        struct ConnEntry {
            UInt64              id = 0;
            core::Endpoint      local;
            core::Endpoint      remote;
            core::FlowKey       key;
            core::TcpConn*      conn = NULLPTR;  /**< Slab-allocated (perf #4): see ConnSlab */
            // Pacing bridge cache (perf): the CC pacing rate only changes per
            // RTT, but SendOne used to call get_pacing_rate (qdisc mutex +
            // hash) on EVERY segment - a 35% throughput regression with a
            // mounted qdisc (measured). Cache the last rate this conn had the
            // qdisc set to; when it is unchanged the qdisc calls are skipped.
            // The qdisc instance is part of the key: swapping qdiscs (user
            // calls SetTxQdisc again) invalidates the cache (the new qdisc
            // has no rate for this flow yet). Written only under the shard
            // lock (SendOne runs under it) - no atomicity needed.
            UInt64              qdisc_rate_cached = 0;
            const qdisc::XtcpQdisc* qdisc_cached = NULLPTR;
        };

        /**
         * @brief Per-shard connection slab (perf #4): ConnEntry + TcpConn are
         *        placement-new'd into fixed chunks (one malloc per 64 conns)
         *        and recycled via a free-slot list, eliminating the two
         *        per-connection mallocs on the SYN/Connect paths. Slot
         *        addresses are STABLE for the life of the slab (chunks are
         *        never moved), so the flow_slots_ ConnEntry* routes and the
         *        conn sink captures stay valid. NOT thread-safe: used only
         *        under the owning shard's lock.
         */
        struct ConnSlab {
            static constexpr UInt32 kChunkSlots = 64;
            struct Chunk {
                alignas(core::TcpConn) Byte conns[kChunkSlots * sizeof(core::TcpConn)];
                alignas(ConnEntry)     Byte entries[kChunkSlots * sizeof(ConnEntry)];
            };
            std::vector<std::unique_ptr<Chunk>> chunks_;
            std::vector<UInt32>                 free_slots_;
            UInt32                              next_slot_ = 0;

            UInt32 TotalSlots() const noexcept { return static_cast<UInt32>(chunks_.size()) * kChunkSlots; }
            core::TcpConn* ConnAt(UInt32 idx) const noexcept {
                return reinterpret_cast<core::TcpConn*>(
                    chunks_[idx / kChunkSlots]->conns + (idx % kChunkSlots) * sizeof(core::TcpConn));
            }
            ConnEntry* EntryAt(UInt32 idx) const noexcept {
                return reinterpret_cast<ConnEntry*>(
                    chunks_[idx / kChunkSlots]->entries + (idx % kChunkSlots) * sizeof(ConnEntry));
            }
            /** @brief Reserves a slot; returns the entry (conn NULLPTR until
             *         the caller placement-news it) and the matching TcpConn
             *         storage, or false on OOM. */
            bool AllocSlot(ConnEntry*& entry, core::TcpConn*& conn) noexcept {
                entry = NULLPTR;
                conn = NULLPTR;
                UInt32 idx = 0;
                if (!free_slots_.empty()) {
                    idx = free_slots_.back();
                    free_slots_.pop_back();
                } else if (next_slot_ < TotalSlots()) {
                    idx = next_slot_++;
                } else {
                    auto chunk = std::make_unique<Chunk>();  // one malloc per 64 conns
                    if (NULLPTR == chunk.get()) {
                        return false;
                    }
                    chunks_.push_back(std::move(chunk));
                    idx = next_slot_++;
                }
                entry = EntryAt(idx);
                conn = ConnAt(idx);
                new (entry) ConnEntry();
                return true;
            }
            /** @brief Destroys the conn + entry and recycles the slot. */
            void FreeSlot(ConnEntry* e) noexcept {
                if (NULLPTR == e) {
                    return;
                }
                if (NULLPTR != e->conn) {
                    e->conn->~TcpConn();
                    e->conn = NULLPTR;
                }
                // Locate the owning chunk by address containment (the chunks
                // are separate allocations - pointer arithmetic across them
                // would be UB). Frees are rare (connection close), so the
                // linear scan is fine.
                const Byte* eb = reinterpret_cast<const Byte*>(e);
                UInt32 idx = 0;
                bool found = false;
                for (UInt32 c = 0; c < chunks_.size() && !found; ++c) {
                    const Byte* base = chunks_[c]->entries;
                    const Byte* end = base + kChunkSlots * sizeof(ConnEntry);
                    if (eb >= base && eb < end) {
                        idx = c * kChunkSlots + static_cast<UInt32>((eb - base) / sizeof(ConnEntry));
                        found = true;
                    }
                }
                e->~ConnEntry();
                if (found) {
                    free_slots_.push_back(idx);
                }
            }
        };

        /**
         * @brief A shard owns a subset of connections; each shard has its own
         *        lock so different connections process in parallel on multi-core.
         */
    public:
        struct Shard {
            std::recursive_mutex                              syncobj_;
            ConnSlab                                        slab_;  /**< ConnEntry/TcpConn pool (perf #4) */
            std::unordered_map<UInt64, ConnEntry*>             conns_;
            // DMA/PCIe TX backpressure retry queue: packets the backend
            // rejected (Tx returned false / TxBatch partial) are held here
            // (FIFO, ownership retained) and drained on the next
            // PollAckTimers sweep - the stack never drops at the wire
            // boundary (ndi.h Tx contract).
            // MPSC lock-free chain: RetryBatchSharded can
            // reach a FOREIGN shard's retry queue from a user thread holding
            // ITS OWN shard's lock - a std::deque push there raced the
            // sweep's locked pop (UB). The chain head is atomic: producers
            // CAS-push (lock-free, no shard-to-shard lock edge), the sweep
            // (the single consumer, inside the shard lock) exchanges the
            // whole chain, reverses it (push order) and drains FIFO; any
            // still-rejected tail is re-linked onto the head for the next
            // round. Chain order is FIFO: push appends at the head with
            // order preserved by the reverse-on-drain.
            struct TxRetry {
                buf::BufRef ref;
                UInt16      eth_type = 0;
                TxRetry*    next = nullptr;  // chain link (owned by the node)
            };
            // Bounded retry queue: a permanently-full backend ring (long-lived
            // over-provision) must not grow memory without bound. At the cap,
            // newly rejected packets are dropped - the TCP RTO re-covers the
            // bytes, the same recovery net the pool-exhaustion path uses.
            // 64K nodes ~ 64B each ~ 4MB worst case per shard.
            static constexpr UInt32 kTxRetryCap = 65536;
            std::atomic<UInt32>                                tx_retry_count_{0};
            std::atomic<TxRetry*>                             tx_retry_head_{nullptr};
            // Flat open-addressing flow route table (perf #3): one hash
            // computation per packet serves BOTH the shard selection and the
            // bucket probe, and the probe chain stays in a dense vector (no
            // per-insert node allocation, no second hash). The value is the
            // ConnEntry*: the RX hot path resolves the connection with one
            // probe. Lifetime contract: every conns_ erase is preceded by the
            // flow route erase (or the guarded reclaim at PollAckTimers,
            // which compares the pointer before erasing), so a route never
            // dangles. A same-tuple reconnect overwrites the route with the
            // new entry; the old (TIME-WAIT) entry's reclaim then fails the
            // pointer compare and leaves the new route intact.
            // Slot state: h == 0 = empty (probe stops); entry == NULLPTR
            // with h != 0 = tombstone (probe continues). Table hashes are
            // normalized (| 1) so no live key maps to the empty sentinel.
            struct FlowSlot {
                UInt64         h = 0;
                core::FlowKey  key;
                ConnEntry*     entry = NULLPTR;
            };
            std::vector<FlowSlot> flow_slots_;
            UInt32              flow_mask_ = 0;  /**< capacity - 1 (0 = uninitialized) */
            UInt32              flow_live_ = 0;  /**< live routes */
            UInt32              flow_used_ = 0;  /**< live + tombstones */

            static UInt64 FlowHashOf(const core::FlowKey& key) noexcept {
                // Mirror of stack.cpp FinalMix (the shard-selection
                // finalizer): applying it before % kShardCount spreads flows
                // evenly (the raw polynomial's low bits are biased by the
                // low address/port bits). Bit 32 is forced to 1 to normalize
                // away the empty-slot sentinel (h == 0) WITHOUT disturbing
                // the low bits used for the shard selection (a forced low
                // bit would collapse % 8 onto the odd shards only).
                UInt64 h = core::scheduler_hash::HashFlowKey(key);
                h ^= h >> 33;
                h *= 0xFF51AFD7ED558CCDull;
                h ^= h >> 33;
                h *= 0xC4CEB9FE1A85EC53ull;
                h ^= h >> 33;
                return h | (1ull << 32);
            }
            void FlowInit(UInt32 capacity) noexcept {
                flow_mask_ = capacity - 1;
                flow_slots_.resize(capacity);
            }
            ConnEntry* FlowFind(UInt64 h, const core::FlowKey& key) noexcept {
                if (0 == flow_mask_) {
                    return NULLPTR;
                }
                UInt32 idx = static_cast<UInt32>(h) & flow_mask_;
                for (UInt32 i = 0; i <= flow_mask_; ++i) {
                    const FlowSlot& s = flow_slots_[idx];
                    if (0 == s.h) {
                        return NULLPTR;  // probe chain ends at the first empty slot
                    }
                    if (s.h == h && s.key == key) {
                        return s.entry;  // live entry, or NULLPTR for a tombstone
                    }
                    idx = (idx + 1) & flow_mask_;
                }
                return NULLPTR;
            }
            void FlowInsert(UInt64 h, const core::FlowKey& key, ConnEntry* e) noexcept {
                if (0 == flow_mask_ || flow_used_ * 2 >= flow_mask_ + 1) {
                    FlowGrow();
                }
                UInt32 idx = static_cast<UInt32>(h) & flow_mask_;
                for (UInt32 i = 0; i <= flow_mask_; ++i) {
                    FlowSlot& s = flow_slots_[idx];
                    if (0 == s.h || (s.h == h && s.key == key)) {
                    if (0 == s.h) {
                        ++flow_used_;
                    }
                    s.h = h;
                    s.key = key;
                    if (NULLPTR == s.entry) {
                        ++flow_live_;  // tombstone reused: the live count grows
                    }
                    s.entry = e;
                    return;
                    }
                    idx = (idx + 1) & flow_mask_;
                }
                // Probe exhausted (all slots live/tombstone): grow and retry.
                FlowGrow();
                FlowInsert(h, key, e);
            }
            void FlowErase(UInt64 h, const core::FlowKey& key) noexcept {
                if (0 == flow_mask_) {
                    return;
                }
                UInt32 idx = static_cast<UInt32>(h) & flow_mask_;
                for (UInt32 i = 0; i <= flow_mask_; ++i) {
                    FlowSlot& s = flow_slots_[idx];
                    if (0 == s.h) {
                        return;  // not present
                    }
                    if (s.h == h && s.key == key) {
                        s.entry = NULLPTR;  // tombstone (probe chains stay intact)
                        --flow_live_;
                        return;
                    }
                    idx = (idx + 1) & flow_mask_;
                }
            }
            void FlowGrow() noexcept {
                const UInt32 old_cap = (0 == flow_mask_) ? 0 : flow_mask_ + 1;
                const UInt32 new_cap = (0 == old_cap) ? 256 : old_cap * 2;
                std::vector<FlowSlot> old = std::move(flow_slots_);
                flow_mask_ = new_cap - 1;
                flow_slots_.resize(new_cap);
                flow_live_ = 0;
                flow_used_ = 0;
                for (const FlowSlot& s : old) {
                    if (NULLPTR != s.entry) {
                        // Rehash (the fresh table is at most half full: no
                        // recursive growth).
                        UInt32 idx = static_cast<UInt32>(s.h) & flow_mask_;
                        for (UInt32 i = 0; i <= flow_mask_; ++i) {
                            FlowSlot& d = flow_slots_[idx];
                            if (0 == d.h) {
                                d = s;
                                ++flow_live_;
                                ++flow_used_;
                                break;
                            }
                            idx = (idx + 1) & flow_mask_;
                        }
                    }
                }
            }
            std::unordered_map<UInt64, std::shared_ptr<mimt::MimtFlow>> mimt_flows_;
            ~Shard() noexcept {
                // Free every remaining entry (conns_ holds the live ones; the
                // slab chunks free their raw storage afterwards).
                for (auto& kv : conns_) {
                    slab_.FreeSlot(kv.second);
                }
            }
            /**
             * @brief Sweep activity hint: true when some connection in this
             *        shard may need polling (armed timer / buffered data /
             *        closing state). Set by every stack.cpp operation that
             *        touches a connection; cleared only when a full sweep
             *        finds no dirty connection. When false, PollAckTimers
             *        skips the shard with no lock and no map traversal.
             */
            std::atomic<UInt32>                             sweep_hint_{1};
        };

    private:
        void Emit(UInt64 conn_id, ConnEntry* conn, buf::BufRef&& packet) noexcept;
        void EmitLocked(UInt64 conn_id, ConnEntry* conn, buf::BufRef&& packet) noexcept;
        void SendOne(UInt64 conn_id, ConnEntry* conn, UInt16 eth_type, buf::BufRef&& packet) noexcept;
        void DrainTxQdisc(core::TimePoint now) noexcept;
        void EmitOrRetry(Shard& shard, ndi::Packet&& out) noexcept;
        void RetryBatch(Shard& shard, ndi::Packet* packets, UInt32 from, UInt32 count) noexcept;
        /** @brief Attributes a qdisc-drained batch's rejected packets to
         *         their connections' shards (dequeue carries no flow id). */
        void RetryBatchSharded(ndi::Packet* packets, UInt32 from, UInt32 count) noexcept;
        /** @brief Arms a shard's sweep hint: a connection in it may need polling. */
        static void MarkSweep(Shard& shard) noexcept {
            // fetch_or: this runs LOCK-FREE from foreign-shard
            // retry pushes; a plain store(true) could be overwritten by the
            // sweep's own clear (store(false)) racing it - the hint would be
            // lost and the retry chain starve one round. The atomic RMW
            // cannot be swallowed.
            shard.sweep_hint_.fetch_or(1u, std::memory_order_relaxed);
        }
        core::FlowKey KeyOf(const core::Endpoint& local, const core::Endpoint& remote) const noexcept;
        bool IsListening(const core::Endpoint& local) const noexcept;
        static UInt32 DeriveIss(const core::Endpoint& local, const core::Endpoint& remote) noexcept;
        /** Exact-key MD5 lookup with a wildcard (0.0.0.0 / ::) listener
         *  fallback: a wildcard listener's key enforces MD5 for SYNs to any
         *  specific destination (mirror of ListenerMatches). */
        bool LookupListenerMd5Key(const core::Endpoint& dst, Byte* out_key, UInt32* out_len) const noexcept;
        void BindDataPath(UInt64 id, Shard& shard, const core::Endpoint& local,
                          const core::Endpoint& remote, core::TcpConn& conn,
                          bool as_accept) noexcept;
        Shard* ShardOf(const core::FlowKey& key) noexcept;

        ndi::Backend*            backend_ = NULLPTR;
        ndi::BackendCaps         caps_ = ndi::kCapNone;  /**< Cached backend caps (Caps() is constant for the backend's lifetime; snapshot at construction so Emit avoids a per-packet virtual call) */
        std::vector<core::Endpoint> listeners_;
        std::unordered_map<UInt64, std::array<Byte, 64>> listener_md5_;  /**< listener addr hash -> key */
        std::unordered_map<UInt64, UInt32> listener_md5_len_;
        std::unique_ptr<Shard[]> shards_;
        RecvHandlerChecked      recv_handler_;
        std::function<void(UInt64)> urgent_handler_;  /**< RFC 793 urgent-data notification (SO_OOBINLINE) */
        StateHandler             state_handler_;
        AcceptHandler            accept_handler_;
        MimtOnFlow               mimt_on_flow_;
        mutable std::mutex       mimt_hook_mutex_;  /**< Guards mimt_on_flow_ (StartMimt vs BindDataPath read; lock order: shard -> hook) */
        mutable std::recursive_mutex syncobj_;  /**< Guards listeners_/ipfrag_/listener_md5_ (recv_handler_ is written lock-free by the setters - see their startup-only warning) */
        core::IpFragTable            ipfrag_;   /**< IP fragment reassembly (RFC 791/8200); single instance (non-first fragments carry no ports to shard on); guarded by syncobj_ */
        std::atomic<UInt64>      next_id_{0};   /**< Global connection counter (shard-encoded ids) */
        std::atomic<UInt32>      conn_count_{0};/**< Live connections (all shards) */
        UInt32                   max_conns_ = 16384;  /**< Hard cap (SYN-flood / memory bound) */
        std::string              default_cc_ = "kcc";  /**< CC algorithm for new connections (KCC is the default; "" = Reno, "kcc"/"bbr"/"cubic" selectable) */
        bool                     default_ecn_ = false;  /**< RFC 3168 ECN on new connections */
        bool                     default_no_sack_ = false;  /**< Suppress SACK-permitted on new connections */
        core::Syncookies         syncookies_;  /**< RFC 4987 stateless SYN-flood defense */
        UInt32                   syncookie_threshold_ = 0;  /**< Cookie mode above this many live conns (0 = use max_conns_) */
        UInt32                   two_msl_us_ = 120 * 1000000;  /**< 2MSL for TIME-WAIT reclamation (us) */
        UInt32                   rcv_buf_ = 0;  /**< Receive-buffer capacity for new conns (0 = 65535 default) */
        UInt32                   snd_buf_ = 0;  /**< Send-buffer quota for new conns (0 = 65536 default) */
        std::atomic<UInt16>      next_ephemeral_{49152};  /**< Ephemeral port allocator (IANA dynamic range) */
        qdisc::XtcpQdisc*        tx_qdisc_ = NULLPTR;  /**< Optional tx qdisc (FQ/pacing), caller-owned */
        std::atomic<core::TimePoint> qdisc_next_pacing_{0};  /**< Next qdisc drain time (0 = none); written by DrainTxQdisc, read by PollAckTimers (relaxed) */
        std::atomic<UInt32>          closed_rst_count_ = 0;   /**< Closed-port RSTs sent in the current 1s window (Linux tcp_rst_ratelimit token bucket; best-effort, relaxed atomics - OnPacket runs per-shard concurrently) */
        std::atomic<core::TimePoint> closed_rst_window_ = 0;  /**< Closed-port RST window end (us; 0 = first SYN after (re)arm) */
        mutable std::recursive_mutex tfo_sync_;  /**< Guards tfo_cookies_ */
        // peer hash -> (TFO cookie, last-use ticks). Bounded (kTfoCookieCacheMax)
    // with oldest-first eviction: an unbounded cache grows without limit as
    // a long-lived client meets distinct remotes (audit C-1).
    static constexpr UInt32 kTfoCookieCacheMax = 64;
    mutable std::unordered_map<UInt64, std::pair<std::array<Byte, 8>, UInt64>> tfo_cookies_;
        std::atomic<UInt64>      tx_count_[kShardCount]; /**< Packets emitted per shard (avoids a shared atomic line) */
    };
}



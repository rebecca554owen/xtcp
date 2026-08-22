#pragma once

/**
 * @file manual.h
 * @brief Manual packet I/O backend: user injects packets, polls tx output.
 */

#include <xtcp/ndi.h>

#include <deque>
#include <mutex>

namespace xtcp {
    namespace ndi {
        /**
         * @brief Manual backend for tests and TAP pipelines.
         *
         * Inject() delivers a packet synchronously to the rx handler
         * (simulating zero-copy delivery). Tx() output is queued and
         * retrieved via PollTx().
         */
        class ManualBackend final : public Backend {
        public:
            // No `noexcept` here: the tx queue is a std::deque whose default
            // constructor is noexcept(false) in libstdc++, so an explicit
            // `= default noexcept` would be deleted (exception-spec mismatch)
            // and the class would not compile on GCC/Clang (MSVC deque is
            // noexcept, which is why this only broke on Linux builds).
            ManualBackend() = default;
            virtual ~ManualBackend() noexcept;

            ManualBackend(const ManualBackend&) = delete;
            ManualBackend& operator=(const ManualBackend&) = delete;

            /**
             * @brief Injects a borrowed packet into the rx path.
             * @param data Packet bytes. Borrowed, not copied: the buffer must
             *             stay valid until this call returns (delivery is
             *             synchronous).
             * @param len Packet length.
             * @param eth_type Ethernet type.
             */
            void Inject(const Byte* data, UInt32 len, UInt16 eth_type) noexcept;
            /**
             * @brief Injects a packet into the rx path (zero-copy capable).
             * @param packet Packet to deliver. When `packet.owned` is
             *               non-empty the pool buffer is adopted by the rx
             *               handler without copying (zero-copy rx); otherwise
             *               `packet.data` is borrowed and must stay valid
             *               until this call returns.
             */
            void Inject(Packet&& packet) noexcept;
            /**
             * @brief Pops the oldest transmitted packet.
             * @param out Buffer for the packet data (must hold >= 65536 bytes).
             * @return Packet length, 0 when the tx queue is empty.
             */
            UInt32 PollTx(Byte* out) noexcept;
            /**
             * @brief Pops up to max_packets packets under ONE lock.
             * @param out Contiguous buffer for all packet data.
             * @param out_cap Capacity of out.
             * @param lens Out: each packet's length (count entries).
             * @param max_packets Maximum packets to pop.
             * @return Number of packets popped (0 = empty).
             */
            UInt32 PollTxBatch(Byte* out, UInt32 out_cap, UInt32* lens, UInt32 max_packets) noexcept;
            /**
             * @brief Number of packets awaiting PollTx.
             */
            UInt64 TxPending() const noexcept;
            /**
             * @brief Overrides the tx queue drop-oldest bound.
             * @param cap New bound (packets); must be > 0. Defaults to
             *            kDefaultTxQueueMax. When the queue holds `cap`
             *            packets the oldest is dropped before enqueueing.
             */
            void SetTxQueueCap(UInt32 cap) noexcept;

        public:
            /**
             * @brief Enqueues one packet. The manual backend always accepts
             *        (the drop-oldest bound is a test-only safety net at
             *        kDefaultTxQueueMax packets); returns true.
             */
            virtual bool Tx(Packet&& packet) noexcept override;
            virtual UInt32 TxBatch(Packet* packets, UInt32 count) noexcept override;
            virtual void SetRxHandler(RxHandler handler) noexcept override;
            virtual BackendCaps Caps() const noexcept override { return kCapNone; }

        private:
            static constexpr UInt32 kDefaultTxQueueMax = 1u << 20;

            /**
             * @brief Enqueues one packet under the drop-oldest bound (shared
             *        by Tx and TxBatch).
             */
            void BoundedEnqueue(Packet&& packet) noexcept;
            RxHandler               rx_handler_;
            std::deque<Packet>      tx_queue_;
            UInt32                  tx_queue_max_ = kDefaultTxQueueMax;
            mutable std::mutex      syncobj_;
        };
    }
}

/**
 * @file manual.cpp
 * @brief Manual backend implementation.
 */

#include <xtcp/ndi/manual.h>

namespace xtcp {
    namespace ndi {
        void ManualBackend::Inject(const Byte* data, UInt32 len, UInt16 eth_type) noexcept {
            Packet packet;
            packet.data     = const_cast<Byte*>(data);
            packet.len      = len;
            packet.eth_type = eth_type;
            Inject(std::move(packet));
        }

        void ManualBackend::Inject(Packet&& packet) noexcept {
            RxHandler handler;
            {
                std::lock_guard<std::mutex> scope(syncobj_);
                handler = rx_handler_;
            }
            if (handler) {
                handler(std::move(packet));
            }
        }

        UInt32 ManualBackend::PollTx(Byte* out) noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            if (tx_queue_.empty()) {
                return 0;
            }
            Packet packet = std::move(tx_queue_.front());
            tx_queue_.pop_front();
            UInt32 ret = 0;
            if (NULLPTR != out && 0 < packet.len) {
                const Byte* src = NULLPTR;
                if (!packet.owned.IsEmpty()) {
                    src = packet.owned.Data();
                } else if (NULLPTR != packet.data) {
                    src = packet.data;
                }
                if (NULLPTR != src) {
                    std::memcpy(out, src, packet.len);
                    ret = packet.len;
                }
            }
            // packet.owned (if any) releases its pool reference here; the
            // fallback malloc'd buffer is freed below.
            if (packet.owned.IsEmpty() && NULLPTR != packet.data) {
                xtcp::Mfree(packet.data);
            }
            return ret;
        }

        UInt32 ManualBackend::PollTxBatch(Byte* out, UInt32 out_cap, UInt32* lens, UInt32 max_packets) noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            UInt32 count = 0;
            UInt32 off = 0;
            while (count < max_packets && !tx_queue_.empty() && off < out_cap) {
                Packet& packet = tx_queue_.front();
                UInt32 n = 0;
                const Byte* src = NULLPTR;
                if (!packet.owned.IsEmpty()) {
                    src = packet.owned.Data();
                    n = packet.len;  // authoritative length (set by Emit)
                } else if (NULLPTR != packet.data) {
                    src = packet.data;
                    n = packet.len;
                }
                if (0 == n || NULLPTR == src) {
                    // Un-emittable packet (zero length or a failed fallback
                    // copy): pop it like PollTx does, so it cannot stall the
                    // queue head and block every later packet.
                    if (packet.owned.IsEmpty() && NULLPTR != packet.data) {
                        xtcp::Mfree(packet.data);
                    }
                    tx_queue_.pop_front();
                    continue;
                }
                if (n > out_cap - off) {
                    break;  // caller drains the remainder next round
                }
                std::memcpy(out + off, src, n);
                lens[count] = n;
                ++count;
                off += n;
                if (packet.owned.IsEmpty() && NULLPTR != packet.data) {
                    xtcp::Mfree(packet.data);
                }
                tx_queue_.pop_front();
            }
            return count;
        }

        UInt64 ManualBackend::TxPending() const noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            return tx_queue_.size();
        }

        ManualBackend::~ManualBackend() noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            while (!tx_queue_.empty()) {
                Packet& packet = tx_queue_.front();
                if (packet.owned.IsEmpty() && NULLPTR != packet.data) {
                    xtcp::Mfree(packet.data);
                }
                tx_queue_.pop_front();
            }
        }

        void ManualBackend::BoundedEnqueue(Packet&& packet) noexcept {
            // Hard bound on the tx queue: prevents unbounded growth when the
            // consumer (PollTx) stops draining (Bug 5). Real tests sit orders
            // of magnitude below the cap, so the drop path is never hit in
            // practice; when it is, dropping the OLDEST packet keeps memory
            // bounded and makes room for the freshest traffic.
            if (0 == tx_queue_max_) {
                // Zero cap: drop the packet. A malloc'd fallback buffer (Tx/
                // TxBatch's local `copy`) must be freed here - the parameter
                // aliases it, and returning without freeing leaks one buffer
                // per packet (exercised by test_txqueue_overflow).
                if (packet.owned.IsEmpty() && NULLPTR != packet.data) {
                    xtcp::Mfree(packet.data);
                    packet.data = NULLPTR;
                }
                return;  // zero cap: drop everything
            }
            if (tx_queue_.size() >= tx_queue_max_) {
                Packet& oldest = tx_queue_.front();
                if (oldest.owned.IsEmpty() && NULLPTR != oldest.data) {
                    xtcp::Mfree(oldest.data);
                }
                tx_queue_.pop_front();
            }
            tx_queue_.emplace_back(std::move(packet));
        }

        void ManualBackend::SetTxQueueCap(UInt32 cap) noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            tx_queue_max_ = cap;
        }

        bool ManualBackend::Tx(Packet&& packet) noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            if (!packet.owned.IsEmpty()) {
                // Zero-copy tx: hold the pool-buffer reference until PollTx.
                BoundedEnqueue(std::move(packet));
            return true;
        }
        // Fallback: copy the borrowed payload (the source buffer may be
            // released as soon as the producer's call stack unwinds).
            Packet copy;
            copy.eth_type = packet.eth_type;
            copy.len = packet.len;
            if (NULLPTR != packet.data && 0 < packet.len) {
                Byte* buf = static_cast<Byte*>(xtcp::Malloc(packet.len));
                if (NULLPTR == buf) {
                    return false;  // OOM: cannot accept the packet
                }
                std::memcpy(buf, packet.data, packet.len);
                copy.data = buf;
            }
            BoundedEnqueue(std::move(copy));
            return true;
        }

        UInt32 ManualBackend::TxBatch(Packet* packets, UInt32 count) noexcept {
            // One lock for the whole batch; per-packet semantics are identical
            // to Tx: zero-copy move of owned buffers and the kTxQueueMax
            // drop-oldest bound. A rejected packet is dropped (count not
            // credited) - mirroring Tx's OOM drop.
            std::lock_guard<std::mutex> scope(syncobj_);
            UInt32 accepted = 0;
            for (UInt32 i = 0; i < count; ++i) {
                Packet& packet = packets[i];
                if (!packet.owned.IsEmpty()) {
                    BoundedEnqueue(std::move(packet));
                    ++accepted;
                    continue;
                }
                Packet copy;
                copy.eth_type = packet.eth_type;
                copy.len = packet.len;
                if (NULLPTR != packet.data && 0 < packet.len) {
                    Byte* buf = static_cast<Byte*>(xtcp::Malloc(packet.len));
                    if (NULLPTR == buf) {
                        continue;  // OOM: drop rather than enqueue a dead packet
                    }
                    std::memcpy(buf, packet.data, packet.len);
                    copy.data = buf;
                }
                BoundedEnqueue(std::move(copy));
                ++accepted;
            }
            return accepted;
        }

        void ManualBackend::SetRxHandler(RxHandler handler) noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            rx_handler_ = std::move(handler);
        }
    }
}

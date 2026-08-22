#pragma once

/**
 * @file ndi.h
 * @brief NDI (Network Data-plane Interface): packet I/O backend abstraction.
 *
 * Backends deliver packets via rx and consume packets via tx. The manual
 * backend is the default v1 implementation; TAP/TUN drivers and DPDK/EFVI
 * are user-provided or reserved backends behind this interface.
 */

#include <xtcp/stdafx.h>
#include <xtcp/buf/bufref.h>

#include <functional>

namespace xtcp {
    namespace ndi {
        /**
         * @brief Backend capability flags (bitmask).
         */
        enum BackendCaps : UInt32 {
            kCapNone        = 0x0000,
            /**
             * @brief Hardware TSO offload on tx. When declared (and no tx
             *        qdisc is mounted), the stack's TSO-direct path hands
             *        the whole super-segment to the backend in ONE Tx call
             *        (the NIC segments): the FSM's SendData passes
             *        super-MSS sends straight through when the retransmission
             *        queue is empty, the window/cwnd fit, and the pool's
             *        biggest class holds the super-segment (32KB). The RTO
             *        path re-emits it whole. Backends without the cap get
             *        MSS-sized segments as before.
             */
            kCapTsoTx       = 0x0002,  /**< Hardware TSO offload on tx */
            /**
             * @brief Hardware TX checksum offload. Informational: the stack
             *        always computes the segment checksums (the copy and
             *        checksum are fused into one pass, so offloading saves
             *        almost nothing); the flag tells a backend the packets
             *        it receives carry valid checksums.
             */
            kCapChecksumTx  = 0x0004,  /**< Hardware TX checksum offload */
        };

        /**
         * @brief A packet flowing through the data plane.
         * @note Ownership is transferable. When `owned` is non-empty the
         *       packet owns a pool buffer (zero-copy rx: the stack adopts it
         *       without copying); otherwise `data` borrows a buffer and the
         *       stack must copy it into a pool block.
         */
        struct Packet {
            Byte*       data     = NULLPTR;  /**< Packet buffer (borrowed or owned.payload) */
            UInt32      len      = 0;        /**< Packet length in bytes */
            UInt16      eth_type = 0;        /**< Ethernet type (0x0800 IPv4, 0x86DD IPv6) */
            buf::BufRef owned;               /**< Optional owned pool buffer (zero-copy rx) */
        };

        /**
         * @brief Packet receive handler.
         */
        typedef std::function<void(Packet&&)> RxHandler;

        /**
         * @brief Abstract packet I/O backend.
         */
        class Backend {
        public:
            virtual ~Backend() noexcept = default;
            /**
             * @brief Sends a packet to the wire (DMA ring / device write).
             * @param packet Packet to transmit (moved).
             * @return True when the packet was accepted (consumed). False
             *         when the transmit ring/queue is FULL: the packet is
             *         NOT consumed - the caller retains ownership and must
             *         retry later (the stack defers rejected packets on a
             *         per-shard retry queue and drains them on the next
             *         timer poll). A backend must never silently drop.
             */
            virtual bool Tx(Packet&& packet) noexcept = 0;
            /**
             * @brief Transmits a batch of packets to the wire.
             * @param packets Packets to transmit (each moved).
             * @param count Number of packets in packets.
             * @return Number of packets ACCEPTED for transmission. The
             *         unaccepted tail ([accepted, count)) is NOT consumed -
             *         the caller retains ownership and retries later (DMA
             *         ring-full semantics: rte_eth_tx_burst-style partial
             *         acceptance).
             *
             * Default implementation: one Tx() per packet, so existing
             * backends inherit correct behavior unchanged. Backends that can
             * amortize per-packet overhead (a single lock, a single syscall
             * or ring-buffer write) override this with a batched path.
             */
            virtual UInt32 TxBatch(Packet* packets, UInt32 count) noexcept {
                UInt32 accepted = 0;
                for (UInt32 i = 0; i < count; ++i) {
                    if (!Tx(std::move(packets[i]))) {
                        break;
                    }
                    ++accepted;
                }
                return accepted;
            }
            /**
             * @brief Installs the receive handler.
             * @param handler Called for every received packet.
             */
            virtual void SetRxHandler(RxHandler handler) noexcept = 0;
            /**
             * @brief Returns backend offload capabilities.
             * @return Bitmask of BackendCaps.
             */
            virtual BackendCaps Caps() const noexcept = 0;
        };
    }
}

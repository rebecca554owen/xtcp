/**
 * @file tun_ndi.h
 * @brief Linux TUN device NDI backend (example implementation).
 */

#pragma once

#include <xtcp/ndi.h>
#include <xtcp/buf/bufref.h>

#include <cstdint>
#include <cstring>
#include <deque>
#include <linux/if.h>

namespace xtcp {
    namespace samples {
        /**
         * @brief Linux TUN backend: reads IP packets from /dev/net/tun and
         *        writes emitted packets back to the device.
         * @note Linux-only (part of the tun2socks example, not the library).
         */
        class TunBackend final : public ndi::Backend {
        public:
            TunBackend() = default;
            virtual ~TunBackend() noexcept;

            /**
             * @brief Opens and configures the TUN device.
             * @param dev_name Output device name (e.g. "xtcp0").
             * @return True on success.
             */
            bool Open(const char* dev_name) noexcept;
            /**
             * @brief Assigns the interface address (ioctl SIOCSIFADDR).
             */
            bool AssignAddress(UInt32 addr, UInt32 netmask) noexcept;
            /**
             * @brief Assigns an IPv6 address to the interface.
             * @param addr16 16-byte IPv6 address.
             */
            bool AssignAddress6(const Byte addr16[16]) noexcept;
            /**
             * @brief Brings the interface up (IFF_UP).
             */
            bool BringUp() noexcept;
            /**
             * @brief Blocks reading one packet from the TUN.
             * @param buf Destination buffer.
             * @param cap Capacity.
             * @return Bytes read, or 0 on EOF/error.
             */
            UInt32 ReadPacket(Byte* buf, UInt32 cap) noexcept;
            /**
             * @brief Raw TUN fd (diagnostics).
             */
            Int32 Fd() const noexcept { return fd_; }
            /**
             * @brief Actual device name (as created by TUNSETIFF).
             */
            const char* Name() const noexcept { return name_; }
            /**
             * @brief Drains emitted packets to the TUN (returns when empty).
             * @return Number of packets written.
             */
            UInt32 DrainTx() noexcept;

        public:
            virtual bool Tx(ndi::Packet&& packet) noexcept override;
            virtual void SetRxHandler(ndi::RxHandler handler) noexcept override;
            virtual ndi::BackendCaps Caps() const noexcept override {
                // TSO: the vnet_hdr GSO frames are segmented by the kernel
                // (hardware or software GSO). ChecksumTx: every packet the
                // stack emits carries a valid checksum (the vnet_hdr's csum
                // fields stay zero - the kernel trusts the packet).
                return static_cast<ndi::BackendCaps>(
                    (tso_ok_ ? ndi::kCapTsoTx : ndi::kCapNone) | ndi::kCapChecksumTx);
            }

        private:
            /** @brief virtio_net_hdr (IFF_VNET_HDR): 10 bytes before the L3. */
            struct VnetHdr {
                Byte   flags = 0;       /**< 0: the stack computed the checksums */
                Byte   gso_type = 0;    /**< 1 = TCPv4, 4 = TCPv6 (VIRTIO_NET_HDR_GSO_*) */
                UInt16 hdr_len = 0;     /**< L3+L4 header length (segmentation cut point) */
                UInt16 gso_size = 0;    /**< Segment payload size (the MSS) */
                UInt16 csum_start = 0;  /**< Unused: checksum already computed */
                UInt16 csum_offset = 0; /**< Unused */
            };

            Int32                       fd_ = -1;
            char                        name_[IFNAMSIZ] = "xtcp0";  /**< Actual device name (from TUNSETIFF) */
            ndi::RxHandler              rx_handler_;
            std::deque<buf::BufRef>     tx_queue_;  /**< Zero-copy: holds pool-buffer ownership until written */
            bool                        tso_ok_ = false;  /**< IFF_VNET_HDR + TUNSETOFFLOAD succeeded */
            UInt32                      mtu_ = 1500;      /**< Interface MTU (SIOCGIFMTU) */
        };
    }
}

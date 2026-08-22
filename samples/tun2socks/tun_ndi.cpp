/**
 * @file tun_ndi.cpp
 * @brief Linux TUN backend implementation.
 */

#include "tun_ndi.h"

#include <cstring>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include <deque>

namespace xtcp {
    namespace samples {
        namespace {
            constexpr const char* kTunDevice = "/dev/net/tun";
            constexpr UInt32 kMaxFrame = 65536;
        }

        TunBackend::~TunBackend() noexcept {
            if (0 <= fd_) {
                ::close(fd_);
                fd_ = -1;
            }
        }

        bool TunBackend::Open(const char* dev_name) noexcept {
            fd_ = ::open(kTunDevice, O_RDWR | O_NONBLOCK);
            if (fd_ < 0) {
                return false;
            }
            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            // IFF_VNET_HDR: the virtio-net header prepends every frame, so
            // TSO/GRO offloads work (the kernel segments our GSO frames on
            // tx and coalesces on rx). Without it a GSO frame would be
            // dropped as oversized (the MTU check). IFF_NAPI is NOT set:
            // it costs ~20us of RTT (measured on WSL2) while its GRO
            // benefit never engages there (the tun's non-NAPI RX never
            // coalesces regardless).
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
            if (NULLPTR != dev_name) {
                std::strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
            }
            if (0 != ::ioctl(fd_, TUNSETIFF, &ifr)) {
                ::close(fd_);
                fd_ = -1;
                return false;
            }
            // Capture the ACTUAL device name (the kernel may have picked a
            // different one if the requested name was taken); the address/
            // route ioctls must target it.
            std::strncpy(name_, ifr.ifr_name, IFNAMSIZ - 1);
            name_[IFNAMSIZ - 1] = 0;
            // Enable the tx offloads (checksum + TSO4/TSO6). The kernel
            // segments our GSO frames at gso_size. If the offload cannot be
            // enabled, the backend degrades to plain MTU-sized frames.
            // Enable the tx offloads (checksum + TSO4/TSO6). Some kernels
            // (e.g. WSL2) reject TUNSETOFFLOAD outright (EINVAL even with
            // zero flags) - the ioctl is only a feature advertisement; the
            // kernel's tun_get_user parses the vnet_hdr and software-GSOs
            // the frame regardless, so the backend still advertises the TSO
            // capability and the stack's TSO-direct path stays engaged.
            unsigned offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            if (0 != ::ioctl(fd_, TUNSETOFFLOAD, &offload)) {
                offload = TUN_F_CSUM | TUN_F_TSO4;
                if (0 != ::ioctl(fd_, TUNSETOFFLOAD, &offload)) {
                    // Kernel without TUNSETOFFLOAD: the vnet_hdr GSO frames
                    // are still segmented by the kernel's software GSO.
                }
            }
            tso_ok_ = true;
            // Read the interface MTU for the GSO frame detection and the
            // vnet_hdr's gso_size.
            Int32 s = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (0 <= s) {
                struct ifreq mifr;
                std::memset(&mifr, 0, sizeof(mifr));
                std::strncpy(mifr.ifr_name, name_, IFNAMSIZ - 1);
                if (0 == ::ioctl(s, SIOCGIFMTU, &mifr) && 0 < mifr.ifr_mtu) {
                    mtu_ = static_cast<UInt32>(mifr.ifr_mtu);
                }
                ::close(s);
            }
            return true;
        }

        bool TunBackend::AssignAddress(UInt32 addr, UInt32 netmask) noexcept {
            Int32 s = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                return false;
            }
            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, name_, IFNAMSIZ - 1);

            struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
            sa->sin_family = AF_INET;
            sa->sin_addr.s_addr = htonl(addr);
            const bool addr_ok = (0 == ::ioctl(s, SIOCSIFADDR, &ifr));

            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, name_, IFNAMSIZ - 1);
            sa = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
            sa->sin_family = AF_INET;
            sa->sin_addr.s_addr = htonl(netmask);
            const bool mask_ok = (0 == ::ioctl(s, SIOCSIFNETMASK, &ifr));
            ::close(s);
            return addr_ok && mask_ok;
        }

        bool TunBackend::AssignAddress6(const Byte addr16[16]) noexcept {
            Int32 s = ::socket(AF_INET6, SOCK_DGRAM, 0);
            if (s < 0) {
                return false;
            }
            // The kernel's inet6_ioctl reads a sockaddr_in6 (28 bytes) at
            // offset 16 of the ioctl argument - beyond the 24-byte ifr_ifru
            // union but within the ioctl copy length. The standard userspace
            // pattern (iproute2) passes a buffer that fits the full
            // sockaddr_in6 after the ifreq header.
            struct {
                struct ifreq ifr;
                Byte         extra[16];
            } req;
            std::memset(&req, 0, sizeof(req));
            std::strncpy(req.ifr.ifr_name, name_, IFNAMSIZ - 1);
            struct sockaddr_in6* sa6 = reinterpret_cast<struct sockaddr_in6*>(&req.ifr.ifr_addr);
            sa6->sin6_family = AF_INET6;
            std::memcpy(sa6->sin6_addr.s6_addr, addr16, 16);
            const bool ok = (0 == ::ioctl(s, SIOCSIFADDR, &req.ifr));
            if (!ok) {
                // Fallback: some kernels dispatch SIOCSIFADDR to inet_ioctl
                // for AF_INET sockets; retry on one.
                ::close(s);
                s = ::socket(AF_INET, SOCK_DGRAM, 0);
                if (s < 0) {
                    return false;
                }
                struct {
                    struct ifreq ifr;
                    Byte         extra[16];
                } req4;
                std::memset(&req4, 0, sizeof(req4));
                std::strncpy(req4.ifr.ifr_name, name_, IFNAMSIZ - 1);
                struct sockaddr_in6* sa4 = reinterpret_cast<struct sockaddr_in6*>(&req4.ifr.ifr_addr);
                sa4->sin6_family = AF_INET6;
                std::memcpy(sa4->sin6_addr.s6_addr, addr16, 16);
                const bool ok4 = (0 == ::ioctl(s, SIOCSIFADDR, &req4.ifr));
                ::close(s);
                return ok4;
            }
            ::close(s);
            return true;
        }

        bool TunBackend::BringUp() noexcept {
            Int32 s = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                return false;
            }
            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, name_, IFNAMSIZ - 1);
            if (0 != ::ioctl(s, SIOCGIFFLAGS, &ifr)) {
                ::close(s);
                return false;
            }
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            const bool ok = (0 == ::ioctl(s, SIOCSIFFLAGS, &ifr));
            ::close(s);
            return ok;
        }

        UInt32 TunBackend::ReadPacket(Byte* buf, UInt32 cap) noexcept {
            // IFF_VNET_HDR: every frame is prefixed by the 10-byte classic
            // virtio_net_hdr (flags/gso_type/hdr_len/gso_size/csum_start/
            // csum_offset - sizeof(struct virtio_net_hdr) is 10, not 12).
            // Skip it and return the bare L3 packet, like IFF_NO_PI.
            constexpr UInt32 kVnetHdrLen = 10;
            const ssize_t n = ::read(fd_, buf, cap);
            if (n <= static_cast<ssize_t>(kVnetHdrLen)) {
                return 0;  // EAGAIN / EOF / header-only
            }
            const UInt32 len = static_cast<UInt32>(n) - kVnetHdrLen;
            std::memmove(buf, buf + kVnetHdrLen, len);
            return len;
        }

        UInt32 TunBackend::DrainTx() noexcept {
            UInt32 written = 0;
            while (tx_queue_.empty() == false) {
                buf::BufRef& packet = tx_queue_.front();
                if (packet.IsEmpty()) {
                    tx_queue_.pop_front();
                    continue;
                }
                const UInt32 len = packet.Len();
                const Byte* data = packet.Data();
                // TSO frame (IFF_VNET_HDR): a packet larger than the MTU is
                // the stack's TSO super-segment - prepend the virtio_net_hdr
                // so the kernel segments it (gso_size = the MSS = MTU minus
                // the header cut). Normal frames carry the vnet_hdr too (10
                // zero bytes): the TUN expects it on EVERY frame.
                VnetHdr vh;
                if (len > mtu_) {
                    const UInt32 ip_hdr = static_cast<UInt32>(data[0] & 0x0F) << 2;
                    vh.gso_type = (6 == (data[0] >> 4)) ? 4 : 1;  // TCPV6 / TCPV4
                    vh.hdr_len = static_cast<UInt16>(ip_hdr + ((data[ip_hdr + 12] >> 4) << 2));
                    vh.gso_size = static_cast<UInt16>(mtu_ - vh.hdr_len);
                }
                struct iovec iov[2];
                iov[0].iov_base = &vh;
                iov[0].iov_len = sizeof(vh);
                iov[1].iov_base = const_cast<Byte*>(data);
                iov[1].iov_len = len;
                const ssize_t n = ::writev(fd_, iov, 2);
                if (n <= 0) {
                    break;
                }
                tx_queue_.pop_front();  // refcount drops, buffer returns to the pool
                ++written;
            }
            return written;
        }

        bool TunBackend::Tx(ndi::Packet&& packet) noexcept {
            // Zero-copy tx: the stack hands us the pool buffer's ownership;
            // hold the reference until DrainTx writes it (no byte copy).
            // Returns true (accepted); the tx queue is bounded by the
            // consumer's drain cadence (the TUN write is synchronous in
            // DrainTx, so the queue stays small).
            if (NULLPTR != packet.data && 0 < packet.len) {
                if (!packet.owned.IsEmpty()) {
                    tx_queue_.push_back(std::move(packet.owned));
                } else {
                    // Backend without ownership: copy into a pool block.
                    buf::BufRef buf = buf::BufRef::Acquire(packet.len);
                    if (!buf.IsEmpty()) {
                        std::memcpy(buf.Data(), packet.data, packet.len);
                        buf.SetLen(packet.len);
                        tx_queue_.push_back(std::move(buf));
                    }
                }
            }
            return true;
        }

        void TunBackend::SetRxHandler(ndi::RxHandler handler) noexcept {
            rx_handler_ = std::move(handler);
        }
    }
}

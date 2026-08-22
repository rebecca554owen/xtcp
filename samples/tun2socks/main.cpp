/**
 * @file main.cpp
 * @brief tun2socks example: Linux TUN + XtcpStack + MIMT audit mode.
 *
 * All TCP flows arriving on the TUN are delivered to the application as
 * async MimtFlow streams (the peer sees a normal connection to the real
 * destination). The example prints the first 64 bytes of each flow; real
 * users forward the stream (e.g. to a SOCKS5 server).
 *
 * Usage (Linux):
 *   sudo ./tun2socks
 *   ip addr add 10.0.0.1/24 dev xtcp0   (or let the sample assign)
 *   ip link set xtcp0 up
 *   ip route add default via 10.0.0.1 dev xtcp0
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include "tun_ndi.h"

#include <cstdio>
#include <cstring>

#include <unistd.h>

int main() {
    xtcp::buf::InitPools();

    xtcp::samples::TunBackend tun;
    if (!tun.Open("xtcp0")) {
        std::fprintf(stderr, "tun2socks: cannot open TUN device (root?)\n");
        return 1;
    }

    xtcp::XtcpStack stack(&tun);

    // MIMT audit mode: every connection's stream is delivered here.
    stack.StartMimt([](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
        // In a real tun2socks, forward the flow to a SOCKS5 proxy.
        // Here we echo the first chunk back (audit probe).
        std::fprintf(stderr, "tun2socks: flow accepted\n");
        // The AsyncRead buffer must OUTLIVE the completion callbacks (they
        // run later, on the event-loop thread) - a stack local captured by
        // value would be filled into a dead pointer and echo stale data.
        auto buf = std::make_shared<std::vector<Byte>>(256);
        flow->AsyncRead(buf->data(), static_cast<UInt32>(buf->size()),
                        [flow, buf](xtcp::mimt::Result ec, UInt32 n) mutable {
            if (xtcp::mimt::Result::kOk == ec && 0 < n) {
                std::fprintf(stderr, "tun2socks: %u bytes from flow\n", n);
                flow->AsyncWrite(buf->data(), n, [flow](xtcp::mimt::Result, UInt32) {});
                flow->AsyncRead(buf->data(), static_cast<UInt32>(buf->size()),
                                [flow, buf](xtcp::mimt::Result, UInt32) mutable {});
            }
        });
    });

    tun.AssignAddress(0x0A000001, 0xFFFFFF00);  // 10.0.0.1/24
    tun.BringUp();
    std::fprintf(stderr, "tun2socks: running on xtcp0 (10.0.0.1/24)\n");

    // Event loop: read TUN packets, drain tx, dispatch MIMT completions.
    Byte packet[65536];
    while (true) {
        UInt32 processed = 0;
        const UInt32 n = tun.ReadPacket(packet, sizeof(packet));
        if (0 < n) {
            ++processed;
            // TUN frames are <= MTU (1500) + headers; the largest pool tier
            // is 32768 bytes with a 16-byte header, so the max allocatable is
            // 32752. Clamp: requesting more than that always returns empty.
            const UInt32 cap = (n <= 32752) ? n : 32752;
            xtcp::buf::BufRef buf = xtcp::buf::BufRef::Acquire(cap);
            if (!buf.IsEmpty()) {
                std::memcpy(buf.Data(), packet, cap);
                buf.SetLen(cap);
                stack.OnPacket(std::move(buf));
            }
        }
        tun.DrainTx();
        stack.DispatchMimt();
        stack.PollAckTimers();  // drive SYN/ACK retransmit, delayed-ACK, keepalive, TIME-WAIT timers
        if (0 == processed) {
            ::usleep(500);  // idle: avoid busy-waiting at 100% CPU
        }
    }
    return 0;
}

#pragma once

/**
 * @file pcap_reader.h
 * @brief Lightweight pcap file reader (no libpcap dependency): parses the
 *        classic pcap container and yields records (timestamp, payload).
 *        Supports microsecond and nanosecond magic.
 */

#include <xtcp/stdafx.h>

#include <vector>

namespace xtcp {
    namespace pcap {
        /**
         * @brief One captured record.
         */
        struct Record {
            UInt64  ts_sec  = 0;
            UInt64  ts_frac = 0;
            bool    nanos   = false; /**< true: ts_frac is in nanoseconds; false: microseconds */
            UInt16  network = 0;  /**< Link-layer type (1 Ethernet, 101 raw IP) */
            UInt32  orig_len = 0; /**< Original on-wire length before snaplen truncation */
            std::vector<Byte> data;
        };

        /**
         * @brief Parses a pcap buffer into records.
         * @param buf  File bytes.
         * @param len  Length.
         * @param out  Records.
         * @return True when the container parsed.
         * @note  Timestamp resolution is reported per-record via Record::nanos
         *        (nanosecond magic 0xA1B23C4D/0x4D3C2BA1); otherwise ts_frac is
         *        microseconds. Allocation of record data may throw std::bad_alloc.
         */
        bool ParsePcap(const Byte* buf, UInt32 len, std::vector<Record>& out);
    }
}

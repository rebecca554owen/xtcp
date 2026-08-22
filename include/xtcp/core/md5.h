#pragma once

/**
 * @file md5.h
 * @brief RFC 1321 MD5 message-digest (used by TCP-MD5, RFC 2385).
 */

#include <xtcp/stdafx.h>

#include <cstddef>
#include <cstdint>

namespace xtcp {
    namespace core {
        /** @brief RFC 1321 MD5 context. */
        struct Md5Ctx {
            std::uint32_t state[4];
            std::uint32_t count[2];
            std::uint8_t  buffer[64];
        };

        void Md5Init(Md5Ctx& ctx) noexcept;
        void Md5Update(Md5Ctx& ctx, const void* data, std::size_t len) noexcept;
        void Md5Final(Md5Ctx& ctx, std::uint8_t digest[16]) noexcept;
        /** @brief One-shot digest over [data, data+len). */
        void Md5Compute(const void* data, std::size_t len, std::uint8_t digest[16]) noexcept;
    }
}

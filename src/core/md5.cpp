/**
 * @file md5.cpp
 * @brief RFC 1321 MD5 message-digest implementation.
 */

#include <xtcp/core/md5.h>

#include <cstring>

namespace xtcp {
    namespace core {
        namespace {
            constexpr std::uint32_t kS[64] = {
                7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
            };
            constexpr std::uint32_t kK[64] = {
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
            };

            inline std::uint32_t RotateLeft(std::uint32_t x, std::uint32_t n) noexcept {
                return (x << n) | (x >> (32 - n));
            }
        }

        void Md5Init(Md5Ctx& ctx) noexcept {
            ctx.state[0] = 0x67452301;
            ctx.state[1] = 0xefcdab89;
            ctx.state[2] = 0x98badcfe;
            ctx.state[3] = 0x10325476;
            ctx.count[0] = 0;
            ctx.count[1] = 0;
        }

        namespace {
            void Transform(Md5Ctx& ctx, const std::uint8_t block[64]) noexcept {
                std::uint32_t m[16];
                for (std::size_t i = 0; i < 16; ++i) {
                    m[i] = static_cast<std::uint32_t>(block[i * 4]) |
                           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
                           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
                           (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
                }
                std::uint32_t a = ctx.state[0], b = ctx.state[1];
                std::uint32_t c = ctx.state[2], d = ctx.state[3];
                for (std::uint32_t i = 0; i < 64; ++i) {
                    std::uint32_t f, g;
                    if (i < 16) {
                        f = (b & c) | (~b & d);
                        g = i;
                    } else if (i < 32) {
                        f = (d & b) | (~d & c);
                        g = (5 * i + 1) % 16;
                    } else if (i < 48) {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                    } else {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                    }
                    const std::uint32_t temp = d;
                    d = c;
                    c = b;
                    b = b + RotateLeft(a + f + kK[i] + m[g], kS[i]);
                    a = temp;
                }
                ctx.state[0] += a;
                ctx.state[1] += b;
                ctx.state[2] += c;
                ctx.state[3] += d;
            }
        }

        void Md5Update(Md5Ctx& ctx, const void* data, std::size_t len) noexcept {
            const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
            const std::uint32_t idx = (ctx.count[0] >> 3) & 63;
            ctx.count[0] += static_cast<std::uint32_t>(len) << 3;
            if (ctx.count[0] < (static_cast<std::uint32_t>(len) << 3)) {
                ++ctx.count[1];
            }
            ctx.count[1] += static_cast<std::uint32_t>(len) >> 29;
            std::size_t part = 64 - idx;
            if (len >= part) {
                std::memcpy(ctx.buffer + idx, p, part);
                Transform(ctx, ctx.buffer);
                std::size_t i;
                for (i = part; i + 63 < len; i += 64) {
                    Transform(ctx, p + i);
                }
                std::memcpy(ctx.buffer, p + i, len - i);
            } else {
                std::memcpy(ctx.buffer + idx, p, len);
            }
        }

        void Md5Final(Md5Ctx& ctx, std::uint8_t digest[16]) noexcept {
            std::uint8_t bits[8];
            for (std::size_t i = 0; i < 8; ++i) {
                bits[i] = static_cast<std::uint8_t>(ctx.count[i >> 2] >> ((i % 4) * 8));
            }
            // RFC 1321: compute the padding length from the pre-padding
            // position (count[0] is a BIT count), mirroring the reference
            // MD5Final: index = (count[0]>>3) & 0x3f; padLen =
            // (index < 56) ? 56 - index : 120 - index. PADDING[0] = 0x80.
            const std::uint32_t idx = (ctx.count[0] >> 3) & 63;
            const std::size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);
            std::uint8_t padding[64];
            std::memset(padding, 0, sizeof(padding));
            padding[0] = 0x80;
            Md5Update(ctx, padding, padlen);
            Md5Update(ctx, bits, 8);
            for (std::size_t i = 0; i < 4; ++i) {
                for (std::size_t j = 0; j < 4; ++j) {
                    digest[i * 4 + j] = static_cast<std::uint8_t>(ctx.state[i] >> (j * 8));
                }
            }
        }

        void Md5Compute(const void* data, std::size_t len, std::uint8_t digest[16]) noexcept {
            Md5Ctx ctx;
            Md5Init(ctx);
            Md5Update(ctx, data, len);
            Md5Final(ctx, digest);
        }
    }
}

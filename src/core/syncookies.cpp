/**
 * @file syncookies.cpp
 * @brief SYN cookie implementation (RFC 4987 style).
 */

#include <xtcp/core/syncookies.h>

#include <chrono>
#include <random>

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#endif

namespace xtcp {
    namespace core {
        namespace {
            constexpr UInt32 kTimeBits = 24;    /**< Rolling time counter bits */
            constexpr UInt32 kTimeMask = (1u << kTimeBits) - 1;
            constexpr UInt32 kMssBits = 3;      /**< MSS index bits */
            constexpr UInt32 kMssMask = (1u << kMssBits) - 1;

            inline UInt32 Rotl(UInt32 x, UInt32 n) noexcept {
                return (x << n) | (x >> (32 - n));
            }
            void FillCryptoBytes(Byte* out, UInt32 len) noexcept {
                // OS CSPRNG first (mirror of tfo.cpp); std::random_device as
                // the portable fallback. Never a clock-derived value: a
                // clock/address-derived secret was brute-forceable from one
                // captured cookie pair (~2^32 cheap hash evals, seconds).
#if defined(_WIN32)
                if (BCRYPT_SUCCESS(BCryptGenRandom(
                        NULLPTR, reinterpret_cast<PUCHAR>(out), len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
                    return;
                }
#endif
                std::random_device rd;
                for (UInt32 i = 0; i + sizeof(UInt32) <= len; i += sizeof(UInt32)) {
                    const UInt32 v = rd();
                    std::memcpy(out + i, &v, sizeof(v));
                }
            }
        }

        Syncookies::Syncookies() noexcept {
            // 128-bit per-process secret from the OS CSPRNG: extracting it
            // from captured cookies is infeasible, so forgery stays bounded
            // by the per-attempt probability (~2^-23: 2^-5 verified hash
            // bits x the 60 s freshness window), not by secret recovery.
            Byte buf[16];
            FillCryptoBytes(buf, sizeof(buf));
            std::memcpy(&secret_[0], buf, 8);
            std::memcpy(&secret_[1], buf + 8, 8);
            if (0 == (secret_[0] | secret_[1])) {
                secret_[1] = 1;  // never an all-zero secret
            }
        }

        UInt32 Syncookies::FoldAddr(const UInt32 addr[4]) noexcept {
            // Mirror of scheduler_hash::HashFlowKey (scheduler.h): fold all 4
            // 32-bit words of the 128-bit address through the h*31 polynomial
            // so two IPv6 peers sharing only a /32 prefix still hash apart.
            UInt64 h = 0;
            h = h * 31 + addr[0];
            h = h * 31 + addr[1];
            h = h * 31 + addr[2];
            h = h * 31 + addr[3];
            h ^= h >> 32;
            return static_cast<UInt32>(h);
        }

        UInt32 Syncookies::Compute(const UInt32 saddr[4], const UInt32 daddr[4],
                                   UInt16 sport, UInt16 dport,
                                   UInt32 seq, UInt32 time_sec, Byte mss_index) noexcept {
            return Compute(FoldAddr(saddr), FoldAddr(daddr), sport, dport, seq, time_sec, mss_index);
        }

        bool Syncookies::Verify(UInt32 cookie, UInt32 ack_seq, const UInt32 saddr[4],
                                const UInt32 daddr[4], UInt16 sport, UInt16 dport,
                                UInt32 seq, UInt32 time_sec, UInt32 window_sec,
                                Byte& mss_index) noexcept {
            return Verify(cookie, ack_seq, FoldAddr(saddr), FoldAddr(daddr), sport, dport,
                          seq, time_sec, window_sec, mss_index);
        }

        UInt32 Syncookies::Hash(UInt32 saddr, UInt32 daddr, UInt16 sport, UInt16 dport,
                                UInt32 seq) const noexcept {
            // Keyed mix over the full 128-bit secret (both 64-bit halves
            // enter the state; the output is 32 bits, so the forgery bound
            // is the per-attempt probability, not the secret width - the
            // secret's job is to make extraction infeasible).
            UInt32 h = static_cast<UInt32>(secret_[0] ^ secret_[1]);
            h ^= saddr;
            h = Rotl(h, 13) * 0x5BD1E995u;
            h ^= daddr;
            h = Rotl(h, 13) * 0x5BD1E995u;
            h ^= static_cast<UInt32>(sport) | (static_cast<UInt32>(dport) << 16);
            h = Rotl(h, 13) * 0x5BD1E995u;
            h ^= seq;
            h = Rotl(h, 7) * 0x5BD1E995u;
            h ^= static_cast<UInt32>(secret_[0] >> 32);
            h = Rotl(h, 13) * 0x5BD1E995u;
            h ^= static_cast<UInt32>(secret_[1]);
            h = Rotl(h, 7) * 0x5BD1E995u;
            h ^= static_cast<UInt32>(secret_[1] >> 32);
            h = Rotl(h, 13) * 0x5BD1E995u;
            h ^= h >> 15;
            return h;
        }

        UInt32 Syncookies::Compute(UInt32 saddr, UInt32 daddr, UInt16 sport, UInt16 dport,
                                   UInt32 seq, UInt32 time_sec, Byte mss_index) noexcept {
            // Layout (32 bits): [31..27] = 5 verified hash bits, [26..3] = 24
            // bits of (hash XOR rolling time), [2..0] = 3 MSS-index bits. The
            // time never displaces the verified bits; per-attempt forgery is
            // 2^-5 x (window / 2^24) ~ 2^-23 (the other hash bits sit under
            // the time XOR and are not verified).
            const UInt32 h = Hash(saddr, daddr, sport, dport, seq);
            const UInt32 t = time_sec & kTimeMask;
            return (h & ~(kTimeMask << kMssBits | kMssMask)) |
                   (((h & kTimeMask) ^ t) << kMssBits) |
                   (static_cast<UInt32>(mss_index) & kMssMask);
        }

        bool Syncookies::Verify(UInt32 cookie, UInt32 ack_seq, UInt32 saddr, UInt32 daddr,
                                UInt16 sport, UInt16 dport, UInt32 seq, UInt32 time_sec,
                                UInt32 window_sec, Byte& mss_index) noexcept {
            if (ack_seq != (cookie + 1)) {
                return false;
            }
            const UInt32 h = Hash(saddr, daddr, sport, dport, seq);
            // The top 5 hash bits must match exactly (2^-5 per-attempt pass;
            // combined with the 60 s freshness filter ~2^-23 overall).
            if ((h & ~(kTimeMask << kMssBits | kMssMask)) !=
                (cookie & ~(kTimeMask << kMssBits | kMssMask))) {
                return false;
            }
            // Recover the encoded timestamp and check the freshness window.
            const UInt32 t_rec = (((cookie >> kMssBits) & kTimeMask) ^ (h & kTimeMask));
            const UInt32 t_now = time_sec & kTimeMask;
            // The age must wrap WITH THE FIELD WIDTH (2^24), not the UInt32
            // width: a cookie issued just before the time-field wrap would
            // otherwise read ~2^32 - (t_rec - t_now) seconds old - huge for
            // the entire next 2^24-second cycle, so every in-flight
            // handshake at the wrap boundary failed (audit gap 1 test
            // caught this: a UInt32-subtraction wrap is NOT a field wrap).
            const UInt32 age = (t_now - t_rec) & kTimeMask;
            if (age > window_sec) {
                return false;  // stale cookie
            }
            mss_index = static_cast<Byte>(cookie & kMssMask);
            return true;
        }
    }
}

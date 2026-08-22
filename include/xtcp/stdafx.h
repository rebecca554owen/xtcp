#pragma once

/**
 * @file stdafx.h
 * @brief Central XTCP master header: platform macros, type aliases,
 *        mandatory macros. Read before adding any type.
 *
 * Style: rigorously aligned with openppp2 ppp/stdafx.h.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

/* ------------------------------------------------------------------ */
/* Platform macro pairing (mirrors openppp2 stdafx.h)                  */
/* ------------------------------------------------------------------ */

#if defined(_WIN64)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(_WIN32)
#if !defined(WIN32)
#define WIN32 1
#endif
#endif

#if defined(WIN32)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(__linux__)
#if !defined(_LINUX)
#define _LINUX 1
#endif
#if !defined(LINUX)
#define LINUX 1
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#if !defined(_MACOS)
#define _MACOS 1
#endif
#if !defined(MACOS)
#define MACOS 1
#endif
#endif

#if defined(_LINUX)
#define XTCP_LINUX 1
#endif
#if defined(_WIN32)
#define XTCP_WINDOWS 1
#endif

/* ------------------------------------------------------------------ */
/* Architecture detection (runtime-dispatch correctness: the stack    */
/* runs on x86, ARM, RISC-V...; every SIMD/CPU-specific path must be  */
/* gated by XTCP_X86, never by compiler vendor alone - _MSC_VER also  */
/* fires on ARM64 MSVC, __GNUC__ also fires on ARM GCC/Clang)         */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define XTCP_X86 1
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)
#define XTCP_ARM 1
#endif

#if defined(__riscv) || defined(__riscv__)
#define XTCP_RISCV 1
#endif

/* ------------------------------------------------------------------ */
/* Mandatory macros                                                    */
/* ------------------------------------------------------------------ */

#if !defined(NULL)
#define NULL 0
#endif

#if !defined(NULLPTR)
#define NULLPTR nullptr
#endif

#if !defined(elif)
#define elif else if
#endif

/* ------------------------------------------------------------------ */
/* Fixed-width type aliases (column-aligned, openppp2 style)           */
/* ------------------------------------------------------------------ */

typedef unsigned char                                          Byte;
typedef signed char                                            SByte;
typedef signed short int                                        Int16;
typedef signed int                                              Int32;
typedef signed long long                                        Int64;
typedef unsigned short int                                      UInt16;
typedef unsigned int                                            UInt32;
typedef unsigned long long                                      UInt64;
typedef double                                                  Double;
typedef float                                                   Single;
typedef bool                                                    Boolean;
typedef signed char                                             Char;

/* ------------------------------------------------------------------ */
/* Memory (openppp2 style: no raw new/delete in runtime paths)         */
/* ------------------------------------------------------------------ */

namespace xtcp {
    /**
     * @brief Allocates memory through the library allocator.
     * @param size Bytes to allocate.
     * @return Non-null pointer on success, NULLPTR on failure.
     */
    inline void* Malloc(UInt64 size) noexcept { return std::malloc(static_cast<size_t>(size)); }
    /**
     * @brief Releases memory allocated by xtcp::Malloc.
     * @param ptr Pointer to release (may be NULLPTR).
     */
    inline void Mfree(void* ptr) noexcept { std::free(ptr); }
}

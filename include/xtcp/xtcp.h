#pragma once

/**
 * @file xtcp.h
 * @brief XTCP entry header: version and namespace.
 *
 * XTCP is a high-performance, hot-pluggable parallel TCP/IP userspace
 * protocol stack (C++17, Linux + Windows).
 */

#define XTCP_VERSION "0.1.0"

#if !defined(NULLPTR)
#define NULLPTR nullptr
#endif

#if !defined(elif)
#define elif else if
#endif

namespace xtcp {
    /**
     * @brief Returns the library version string.
     * @return Version string, never NULLPTR.
     */
    inline const char* Version() noexcept { return XTCP_VERSION; }
}

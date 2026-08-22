/**
 * @file test_stop_listen.cpp
 * @brief StopListen regression test (F5): listeners_ was strictly grow-only -
 *        a listening port could never be closed. StopListen removes the
 *        exact-matching listener (within the syncobj_ lock) so the endpoint
 *        stops conflicting and becomes available for a fresh Listen again.
 *
 * Key assertions:
 *   1. Listen() on a fresh port succeeds.
 *   2. A duplicate Listen() on the same port fails (EADDRINUSE) - proves the
 *      first listener holds the port.
 *   3. StopListen() returns true (exact match found and removed).
 *   4. A second StopListen() returns false (nothing left to remove).
 *   5. Listen() on the same port now succeeds again - the removed listener no
 *      longer conflicts, so the port is usable again.
 *   6. StopListen() on a never-listened port returns false.
 *   7. Exact-match only: a different address on the same port is not removed
 *      by StopListen.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>

#include <cstdio>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

int main() {
    xtcp::buf::InitPools();
    xtcp::ndi::ManualBackend backend;
    xtcp::XtcpStack stack(&backend);

    xtcp::core::Endpoint ep;
    ep.family = 4;
    ep.addr[0] = 0x0A000001;  // 10.0.0.1
    ep.port = 9443;

    // 1. Fresh listen succeeds.
    CHECK(stack.Listen(ep));
    // 2. Duplicate is EADDRINUSE while the listener holds the port.
    CHECK(!stack.Listen(ep));
    // 3. StopListen removes the exact-matching listener.
    CHECK(stack.StopListen(ep));
    // 4. Nothing left: a second StopListen returns false.
    CHECK(!stack.StopListen(ep));
    // 5. The port is usable again: a fresh Listen succeeds.
    CHECK(stack.Listen(ep));

    // 6. Never-listened endpoint: false.
    xtcp::core::Endpoint never;
    never.family = 4;
    never.addr[0] = 0x0A000002;  // 10.0.0.2
    never.port = 9444;
    CHECK(!stack.StopListen(never));

    // 7. Exact-match only: a different address on the same port is not removed.
    CHECK(stack.StopListen(ep));        // remove ep (registered at step 5)
    CHECK(stack.Listen(ep));            // re-register
    xtcp::core::Endpoint other;
    other.family = 4;
    other.addr[0] = 0x0A000002;  // 10.0.0.2, same port as ep
    other.port = 9443;
    CHECK(!stack.StopListen(other));    // different addr: not removed
    CHECK(stack.StopListen(ep));        // exact match: removed
    CHECK(!stack.StopListen(ep));       // already gone

    xtcp::buf::ShutdownPools();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_stop_listen: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_stop_listen: all passed\n");
    return 0;
}

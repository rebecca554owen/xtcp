/**
 * @file test_cc_unregister.cpp
 * @brief CC registry lifecycle regression:
 *   - Unregister marks the entry disabled (name = NULLPTR) instead of
 *     erasing it: pointers already returned by FindCongestionControl stay
 *     valid and callable (no use-after-free).
 *   - Re-registering the same name overwrites the disabled entry in place.
 *   - RegisterBuiltinCc sets its "already registered" flag only AFTER all
 *     built-ins are present in the registry.
 *
 * The assertions encode the FIXED behavior of src/cc/cc.cpp:
 *   UnregisterCongestionControl  -> it->second.name = NULLPTR (no erase)
 *   RegisterCongestionControl    -> overwrites a disabled entry
 *   FindCongestionControl        -> NULLPTR for a disabled entry
 *   RegisterBuiltinCc            -> store(flag) after all registers
 */

#include <xtcp/cc/cc.h>

#include <cstdio>
#include <cstring>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

namespace {
    int g_marker  = 1;
    int g_marker2 = 2;

    void TestInit(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->ca_priv = &g_marker;
    }
    void TestRelease(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->ca_priv = NULLPTR;
    }
    void TestInit2(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->ca_priv = &g_marker2;
    }
    void TestRelease2(xtcp::cc::XtcpConnCc* sk) noexcept {
        sk->ca_priv = NULLPTR;
    }
}

static void TestCcLifecycle() {
    // 1. Register a test CC.
    xtcp::cc::XtcpCongestionOps ops;
    ops.name = "test_unreg";
    ops.init = TestInit;
    ops.release = TestRelease;
    CHECK(xtcp::cc::RegisterCongestionControl(ops));

    // 2. Find and hold the returned pointer.
    const xtcp::cc::XtcpCongestionOps* held = xtcp::cc::FindCongestionControl("test_unreg");
    CHECK(NULLPTR != held);
    CHECK(0 == std::strcmp("test_unreg", held->name));

    // 3. Unregister: mark disabled, must NOT erase the map entry.
    CHECK(xtcp::cc::UnregisterCongestionControl("test_unreg"));

    // 4. Find returns NULL for a disabled algorithm.
    CHECK(NULLPTR == xtcp::cc::FindCongestionControl("test_unreg"));

    // 5. Held ops pointer stays valid (no UAF): the name field now carries
    //    the disabled marker (NULLPTR), and the function table is still
    //    dereferenceable/callable through the held pointer.
    CHECK(NULLPTR == held->name);          // disabled marker, not dangling
    xtcp::cc::XtcpConnCc sk;
    held->init(&sk);                        // harmless call through held ptr
    CHECK(&g_marker == sk.ca_priv);
    held->release(&sk);
    CHECK(NULLPTR == sk.ca_priv);

    // 6. Re-register the same name: overwrites the disabled entry in place.
    xtcp::cc::XtcpCongestionOps ops2;
    ops2.name = "test_unreg";
    ops2.init = TestInit2;
    ops2.release = TestRelease2;
    CHECK(xtcp::cc::RegisterCongestionControl(ops2));

    // 7. Find now returns the NEW ops table.
    const xtcp::cc::XtcpCongestionOps* fresh = xtcp::cc::FindCongestionControl("test_unreg");
    CHECK(NULLPTR != fresh);
    CHECK(0 == std::strcmp("test_unreg", fresh->name));   // active again
    CHECK(fresh->init == TestInit2);                       // new table, not stale
    fresh->init(&sk);
    CHECK(&g_marker2 == sk.ca_priv);
    fresh->release(&sk);
}

static void TestBuiltinTiming() {
    // The "already registered" flag is stored only AFTER all built-ins are
    // in the registry: the instant RegisterBuiltinCc returns, every built-in
    // must be findable. A flag-set-before-registration ordering would expose
    // a window where FindCongestionControl returns NULL despite the flag.
    xtcp::cc::RegisterBuiltinCc();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("kcc"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("bbr"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("cubic"));

    // Idempotent second call: built-ins remain registered.
    xtcp::cc::RegisterBuiltinCc();
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("kcc"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("bbr"));
    CHECK(NULLPTR != xtcp::cc::FindCongestionControl("cubic"));
}

int main() {
    TestCcLifecycle();
    TestBuiltinTiming();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_cc_unregister: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_cc_unregister: all passed\n");
    return 0;
}

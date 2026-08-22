/**
 * @file test_plugin.cpp
 * @brief Plugin registry tests: static registration, context lifecycle,
 *        drain semantics, dynamic module load.
 */

#include <xtcp/plugin/plugin.h>

#include <cstdio>

static int g_failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                \
        }                                                                \
    } while (0)

extern void XtcpRegisterSamplePlugin() noexcept;

static void TestStaticRegistration() {
    xtcp::plugin::PluginRegistry& registry = xtcp::plugin::PluginRegistry::Instance();
    XtcpRegisterSamplePlugin();

    const xtcp::plugin::ModuleId id = registry.Lookup("sample");
    CHECK(0 != id);
    CHECK(id == registry.Lookup("sample"));  // idempotent name lookup

    xtcp::plugin::ModuleContextRef ctx = registry.CreateContext(id);
    CHECK(ctx.IsValid());
    CHECK(NULLPTR != ctx.Get());
    ctx = xtcp::plugin::ModuleContextRef();  // release
}

static void TestDrainSemantics() {
    xtcp::plugin::PluginRegistry& registry = xtcp::plugin::PluginRegistry::Instance();
    const xtcp::plugin::ModuleId id = registry.Lookup("sample");
    CHECK(0 != id);

    // One live context holds the module.
    xtcp::plugin::ModuleContextRef ctx = registry.CreateContext(id);
    CHECK(ctx.IsValid());

    // Unload enters draining; the live context keeps the module alive.
    CHECK(registry.Unload(id));
    CHECK(!registry.Unload(id));  // already draining

    // New contexts are refused while draining.
    xtcp::plugin::ModuleContextRef refused = registry.CreateContext(id);
    CHECK(!refused.IsValid());

    // Dropping the last context completes the drain.
    ctx = xtcp::plugin::ModuleContextRef();
    CHECK(0 == registry.Lookup("sample"));  // module fully unloaded
}

static void TestDynamicModule() {
#if defined(_WIN32) && defined(XTCP_HAVE_TEST_DLL)
    xtcp::plugin::PluginRegistry& registry = xtcp::plugin::PluginRegistry::Instance();
    const xtcp::plugin::ModuleId id = registry.Load("test_plugin_dll.dll", "sample_dynamic");
    CHECK(0 != id);
    xtcp::plugin::ModuleContextRef ctx = registry.CreateContext(id);
    CHECK(ctx.IsValid());
    ctx = xtcp::plugin::ModuleContextRef();
    CHECK(registry.Unload(id));
#endif
}

int main() {
    TestStaticRegistration();
    TestDrainSemantics();
    TestDynamicModule();
    if (0 < g_failures) {
        std::fprintf(stderr, "test_plugin: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("test_plugin: all passed\n");
    return 0;
}

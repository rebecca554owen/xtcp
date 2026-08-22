/**
 * @file test_plugin_dll.cpp
 * @brief Dynamic plugin module (compiled as a DLL) for load tests.
 */

#include <xtcp/plugin/plugin.h>

#include <new>

namespace {
    class DllContext final : public xtcp::plugin::IModuleContext {
    public:
        UInt64 marker = 0xD1CE;
    };

    class DllModule final : public xtcp::plugin::IProtocolModule {
    public:
        virtual bool Probe(const xtcp::plugin::ModuleVersion& framework) noexcept override {
            return framework.CompatibleWith(xtcp::plugin::ModuleVersion());
        }
        virtual xtcp::plugin::IModuleContext* Create(const xtcp::plugin::ModuleInit& init) noexcept override {
            (void)init;
            return new (std::nothrow) DllContext();
        }
        virtual void Destroy(xtcp::plugin::IModuleContext* context) noexcept override {
            delete context;
        }
        virtual const xtcp::plugin::ProtocolStats* GetStats() noexcept override {
            return &stats_;
        }

    private:
        xtcp::plugin::ProtocolStats stats_;
    };

    DllModule g_dll_module;
}

#if defined(_WIN32)
#define XTCP_EXPORT extern "C" __declspec(dllexport)
#else
#define XTCP_EXPORT extern "C" __attribute__((visibility("default")))
#endif

XTCP_EXPORT xtcp::plugin::IProtocolModule* XtcpGetModule() noexcept {
    return &g_dll_module;
}

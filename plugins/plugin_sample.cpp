/**
 * @file plugin_sample.cpp
 * @brief Sample protocol module (static registration + dynamic export).
 */

#include <xtcp/plugin/plugin.h>

namespace {
    class SampleContext final : public xtcp::plugin::IModuleContext {
    public:
        UInt64 value = 0;
    };

    class SampleModule final : public xtcp::plugin::IProtocolModule {
    public:
        virtual bool Probe(const xtcp::plugin::ModuleVersion& framework) noexcept override {
            return framework.CompatibleWith(xtcp::plugin::ModuleVersion());
        }
        virtual xtcp::plugin::IModuleContext* Create(const xtcp::plugin::ModuleInit& init) noexcept override {
            (void)init;
            return new (std::nothrow) SampleContext();
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

    SampleModule g_sample_module;
}

#if defined(_WIN32)
#define XTCP_EXPORT extern "C" __declspec(dllexport)
#else
#define XTCP_EXPORT extern "C" __attribute__((visibility("default")))
#endif

XTCP_EXPORT xtcp::plugin::IProtocolModule* XtcpGetModule() noexcept {
    return &g_sample_module;
}

/**
 * @brief Registers the sample module into the framework (static path).
 */
void XtcpRegisterSamplePlugin() noexcept {
    xtcp::plugin::PluginRegistry::Instance().RegisterStatic("sample", &g_sample_module);
}

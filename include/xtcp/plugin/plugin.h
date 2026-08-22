#pragma once

/**
 * @file plugin.h
 * @brief Plugin system: C++ ABI modules with drain semantics (new/old
 *        coexistence). Modules register per-slot implementations; contexts
 *        are reference-counted; unload waits for natural drain.
 */

#include <xtcp/stdafx.h>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace xtcp {
    namespace plugin {
        /**
         * @brief Module version (semver).
         */
        struct ModuleVersion {
            UInt32 major = 1;
            UInt32 minor = 0;
            UInt32 patch = 0;

            bool CompatibleWith(const ModuleVersion& other) const noexcept {
                return major == other.major;
            }
        };

        /**
         * @brief Module initialization payload.
         */
        struct ModuleInit {
            ModuleVersion version;
        };

        /**
         * @brief Per-instance statistics (opaque to the framework).
         */
        struct ProtocolStats {
            UInt64 events = 0;
            UInt64 errors = 0;
        };

        /**
         * @brief Module context: one instance bound to a consumer.
         */
        class IModuleContext {
        public:
            virtual ~IModuleContext() noexcept = default;
        };

        /**
         * @brief Protocol module interface (C++ ABI, user-selected).
         */
        class IProtocolModule {
        public:
            virtual ~IProtocolModule() noexcept = default;
            /**
             * @brief Load-time self check.
             * @return True when the module accepts the framework version.
             */
            virtual bool Probe(const ModuleVersion& framework) noexcept = 0;
            /**
             * @brief Creates a context instance.
             * @return Instance owned by the caller (ModuleContextRef).
             */
            virtual IModuleContext* Create(const ModuleInit& init) noexcept = 0;
            /**
             * @brief Destroys a context instance.
             */
            virtual void Destroy(IModuleContext* context) noexcept = 0;
            /**
             * @brief Returns module statistics.
             */
            virtual const ProtocolStats* GetStats() noexcept = 0;
        };

        typedef UInt64 ModuleId;

        /**
         * @brief Reference-counted module handle (RAII).
         */
        class ModuleContextRef {
        public:
            ModuleContextRef() noexcept = default;
            virtual ~ModuleContextRef() noexcept;
            ModuleContextRef(const ModuleContextRef&) = delete;
            ModuleContextRef& operator=(const ModuleContextRef&) = delete;
            ModuleContextRef(ModuleContextRef&& other) noexcept;
            ModuleContextRef& operator=(ModuleContextRef&& other) noexcept;

            IModuleContext* Get() const noexcept { return context_; }
            bool IsValid() const noexcept { return NULLPTR != context_; }

        private:
            ModuleContextRef(ModuleId module, IModuleContext* context) noexcept;
            void Release() noexcept;

            ModuleId        module_  = 0;
            IModuleContext* context_ = NULLPTR;

            friend class PluginRegistry;
        };

        /**
         * @brief Plugin registry: load/unload (drain), lookup, context
         *        creation. Thread-safe (control plane).
         */
        class PluginRegistry {
        public:
            static PluginRegistry& Instance() noexcept;

            /**
             * @brief Registers a statically-linked module.
             * @param name Module name (unique).
             * @param module Module pointer (owned by the caller).
             * @return ModuleId, 0 on failure.
             */
            ModuleId RegisterStatic(const char* name, IProtocolModule* module) noexcept;
            /**
             * @brief Loads a dynamic module (.dll/.so).
             * @param path Library path.
             * @param name Expected module name (may be NULLPTR for the
             *             exported name).
             * @return ModuleId, 0 on failure.
             */
            ModuleId Load(const char* path, const char* name = NULLPTR) noexcept;
            /**
             * @brief Requests unload; module enters draining and is released
             *        once all contexts are gone.
             * @return True when accepted.
             */
            bool Unload(ModuleId id) noexcept;
            /**
             * @brief Looks up a module id by name.
             */
            ModuleId Lookup(const char* name) const noexcept;
            /**
             * @brief Creates a context from a module.
             * @return Reference, or empty on failure.
             */
            ModuleContextRef CreateContext(ModuleId id) noexcept;

        private:
            struct Entry {
                std::string         name;
                IProtocolModule*    module     = NULLPTR;
                void*               handle     = NULLPTR;  /**< dlopen/LoadLibrary */
                bool                dynamic    = false;
                bool                draining   = false;
                UInt64              refcount   = 0;
                ModuleId            id         = 0;
            };

            PluginRegistry() noexcept;
            ~PluginRegistry() noexcept;
            PluginRegistry(const PluginRegistry&) = delete;
            PluginRegistry& operator=(const PluginRegistry&) = delete;

            void ReleaseModule(Entry& entry) noexcept;

            mutable std::mutex                          syncobj_;
            std::unordered_map<ModuleId, Entry>         modules_;
            ModuleId                                    next_id_ = 1;

            friend class ModuleContextRef;
        };
    }
}

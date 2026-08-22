/**
 * @file plugin.cpp
 * @brief Plugin registry with drain semantics (C++ ABI modules).
 */

#include <xtcp/plugin/plugin.h>

#include <new>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace xtcp {
    namespace plugin {
        namespace {
            constexpr const char* kExportName = "XtcpGetModule";

            typedef IProtocolModule* (*GetModuleFn)() noexcept;

            /**
             * @brief Unloads a loaded library handle.
             * @note ::FreeLibrary/::dlclose runs the module's DllMain and
             *       static destructors (arbitrary third-party code). It must
             *       NEVER be called while the registry lock is held.
             */
            void UnloadLibrary(void*& handle) noexcept {
                if (NULLPTR == handle) {
                    return;
                }
#if defined(_WIN32)
                ::FreeLibrary(static_cast<HMODULE>(handle));
#else
                ::dlclose(handle);
#endif
                handle = NULLPTR;
            }
        }

        ModuleContextRef::ModuleContextRef(ModuleId module, IModuleContext* context) noexcept
            : module_(module), context_(context) {}

        ModuleContextRef::~ModuleContextRef() noexcept {
            Release();
        }

        ModuleContextRef::ModuleContextRef(ModuleContextRef&& other) noexcept {
            module_ = other.module_;
            context_ = other.context_;
            other.module_ = 0;
            other.context_ = NULLPTR;
        }

        ModuleContextRef& ModuleContextRef::operator=(ModuleContextRef&& other) noexcept {
            if (this != &other) {
                Release();
                module_ = other.module_;
                context_ = other.context_;
                other.module_ = 0;
                other.context_ = NULLPTR;
            }
            return *this;
        }

        void ModuleContextRef::Release() noexcept {
            if (NULLPTR == context_ || 0 == module_) {
                return;
            }
            PluginRegistry& registry = PluginRegistry::Instance();
            IProtocolModule* module = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(registry.syncobj_);
                auto it = registry.modules_.find(module_);
                if (it != registry.modules_.end()) {
                    module = it->second.module;
                }
            }
            if (NULLPTR != module) {
                module->Destroy(context_);
            }
            void* unload = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(registry.syncobj_);
                auto it = registry.modules_.find(module_);
                if (it != registry.modules_.end()) {
                    PluginRegistry::Entry& entry = it->second;
                    if (0 < entry.refcount) {
                        --entry.refcount;
                    }
                    if (entry.draining && 0 == entry.refcount) {
                        registry.ReleaseModule(entry);
                        unload = entry.handle;
                        entry.handle = NULLPTR;
                        registry.modules_.erase(it);
                    }
                }
            }
            UnloadLibrary(unload);
            module_ = 0;
            context_ = NULLPTR;
        }

        PluginRegistry::PluginRegistry() noexcept = default;

        PluginRegistry& PluginRegistry::Instance() noexcept {
            static PluginRegistry instance;
            return instance;
        }

        PluginRegistry::~PluginRegistry() noexcept {
            std::vector<void*> unloads;
            unloads.reserve(modules_.size());
            for (auto& kv : modules_) {
                ReleaseModule(kv.second);
                if (NULLPTR != kv.second.handle) {
                    unloads.push_back(kv.second.handle);
                    kv.second.handle = NULLPTR;
                }
            }
            modules_.clear();
            for (void* h : unloads) {
                UnloadLibrary(h);
            }
        }

        void PluginRegistry::ReleaseModule(Entry& entry) noexcept {
            if (NULLPTR != entry.module && entry.dynamic) {
                // Dynamic modules delete themselves on unload; static ones
                // are owned by the caller.
                entry.module = NULLPTR;
            }
            // The library handle is intentionally left in entry.handle:
            // unloading it (UnloadLibrary) executes the module's DllMain and
            // static destructors, i.e. arbitrary third-party code, so it must
            // never run while syncobj_ is held. Callers extract the handle
            // inside the lock and unload it after releasing the lock.
        }

        ModuleId PluginRegistry::RegisterStatic(const char* name, IProtocolModule* module) noexcept {
            if (NULLPTR == name || NULLPTR == module) {
                return 0;
            }
            // Static modules must pass the same version check as dynamic ones.
            if (!module->Probe(ModuleVersion())) {
                return 0;
            }
            std::lock_guard<std::mutex> scope(syncobj_);
            for (const auto& kv : modules_) {
                if (kv.second.name == name) {
                    return 0;  // duplicate name
                }
            }
            Entry entry;
            entry.name = name;
            entry.module = module;
            entry.dynamic = false;
            entry.id = next_id_;
            modules_.emplace(next_id_, std::move(entry));
            return next_id_++;
        }

        ModuleId PluginRegistry::Load(const char* path, const char* name) noexcept {
            if (NULLPTR == path) {
                return 0;
            }
            void* handle = NULLPTR;
#if defined(_WIN32)
            // Resolve relative paths against the executable directory (never
            // the process CWD) and load with a restricted search order
            // (LOAD_LIBRARY_SEARCH_*) to shrink the DLL hijack surface.
            std::string load_path;
            const char* load_path_c = path;
            const bool absolute = ('\0' != path[0]
                && (('\\' == path[0] || '/' == path[0])
                    || (':' == path[1] && ('\\' == path[2] || '/' == path[2]))));
            if (!absolute) {
                char exe_path[MAX_PATH];
                const DWORD len = ::GetModuleFileNameA(NULLPTR, exe_path, MAX_PATH);
                if (0 < len && len < MAX_PATH) {
                    char* slash = NULLPTR;
                    for (char* p = exe_path; '\0' != *p; ++p) {
                        if ('\\' == *p || '/' == *p) {
                            slash = p;
                        }
                    }
                    if (NULLPTR != slash) {
                        load_path.assign(exe_path, static_cast<size_t>(slash - exe_path + 1));
                        load_path += path;
                        load_path_c = load_path.c_str();
                    }
                }
            }
            handle = ::LoadLibraryExA(load_path_c, NULLPTR,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
            handle = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
            if (NULLPTR == handle) {
                return 0;
            }
            GetModuleFn get_module = NULLPTR;
#if defined(_WIN32)
            get_module = reinterpret_cast<GetModuleFn>(::GetProcAddress(static_cast<HMODULE>(handle), kExportName));
#else
            get_module = reinterpret_cast<GetModuleFn>(::dlsym(handle, kExportName));
#endif
            if (NULLPTR == get_module) {
#if defined(_WIN32)
                ::FreeLibrary(static_cast<HMODULE>(handle));
#else
                ::dlclose(handle);
#endif
                return 0;
            }
            IProtocolModule* module = get_module();
            if (NULLPTR == module || !module->Probe(ModuleVersion())) {
#if defined(_WIN32)
                ::FreeLibrary(static_cast<HMODULE>(handle));
#else
                ::dlclose(handle);
#endif
                return 0;
            }
            const char* module_name = name;
            std::string default_name;
            if (NULLPTR == module_name) {
                // Derive a stable name from the DLL basename (e.g.
                // "C:\\path\\foo.dll" -> "foo") instead of a shared
                // sentinel, so distinct DLLs can coexist.
                const char* base = path;
                for (const char* p = path; '\0' != *p; ++p) {
                    if ('\\' == *p || '/' == *p) {
                        base = p + 1;
                    }
                }
                default_name.assign(base);
                const char* dot = NULLPTR;
                for (const char* p = base; '\0' != *p; ++p) {
                    if ('.' == *p) {
                        dot = p;
                    }
                }
                if (NULLPTR != dot && base != dot) {
                    default_name.erase(static_cast<size_t>(dot - base));
                }
                module_name = default_name.c_str();
            }
            ModuleId result = 0;
            void* unload = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(syncobj_);
                for (const auto& kv : modules_) {
                    if (kv.second.name == module_name) {
                        unload = handle;
                        break;
                    }
                }
                if (NULLPTR == unload) {
                    Entry entry;
                    entry.name = module_name;
                    entry.module = module;
                    entry.handle = handle;
                    entry.dynamic = true;
                    entry.id = next_id_;
                    modules_.emplace(next_id_, std::move(entry));
                    result = next_id_++;
                }
            }
            UnloadLibrary(unload);
            return result;
        }

        bool PluginRegistry::Unload(ModuleId id) noexcept {
            void* unload = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(syncobj_);
                auto it = modules_.find(id);
                if (it == modules_.end()) {
                    return false;
                }
                Entry& entry = it->second;
                if (entry.draining) {
                    return false;
                }
                entry.draining = true;
                if (0 == entry.refcount) {
                    ReleaseModule(entry);
                    unload = entry.handle;
                    entry.handle = NULLPTR;
                    modules_.erase(it);
                }
            }
            UnloadLibrary(unload);
            return true;
        }

        ModuleId PluginRegistry::Lookup(const char* name) const noexcept {
            if (NULLPTR == name) {
                return 0;
            }
            std::lock_guard<std::mutex> scope(syncobj_);
            for (const auto& kv : modules_) {
                if (kv.second.name == name) {
                    return kv.first;
                }
            }
            return 0;
        }

        ModuleContextRef PluginRegistry::CreateContext(ModuleId id) noexcept {
            IProtocolModule* module = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(syncobj_);
                auto it = modules_.find(id);
                if (it == modules_.end() || it->second.draining || NULLPTR == it->second.module) {
                    return ModuleContextRef();
                }
                ++it->second.refcount;
                module = it->second.module;
            }
            ModuleInit init;
            init.version = ModuleVersion();
            IModuleContext* context = module->Create(init);
            if (NULLPTR == context) {
                void* unload = NULLPTR;
                {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    auto it = modules_.find(id);
                    if (it != modules_.end()) {
                        PluginRegistry::Entry& entry = it->second;
                        if (0 < entry.refcount) {
                            --entry.refcount;
                        }
                        if (entry.draining && 0 == entry.refcount) {
                            ReleaseModule(entry);
                            unload = entry.handle;
                            entry.handle = NULLPTR;
                            modules_.erase(it);
                        }
                    }
                }
                UnloadLibrary(unload);
                return ModuleContextRef();
            }
            return ModuleContextRef(id, context);
        }
    }
}

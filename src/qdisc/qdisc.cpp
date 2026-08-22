/**
 * @file qdisc.cpp
 * @brief Qdisc registry implementation.
 */

#include <xtcp/qdisc/qdisc.h>

#include <mutex>
#include <string>
#include <unordered_map>

namespace xtcp {
    namespace qdisc {
        namespace {
            std::mutex g_syncobj;
            std::unordered_map<std::string, XtcpQdiscOps> g_registry;
        }

        bool RegisterQdisc(const XtcpQdiscOps& ops) noexcept {
            if (NULLPTR == ops.name || NULLPTR == ops.enqueue || NULLPTR == ops.dequeue) {
                return false;
            }
            std::lock_guard<std::mutex> scope(g_syncobj);
            if (g_registry.find(ops.name) != g_registry.end()) {
                return false;
            }
            g_registry.emplace(ops.name, ops);
            return true;
        }

        bool UnregisterQdisc(const char* name) noexcept {
            std::lock_guard<std::mutex> scope(g_syncobj);
            return 1 == g_registry.erase(NULLPTR != name ? name : "");
        }

        const XtcpQdiscOps* FindQdisc(const char* name) noexcept {
            std::lock_guard<std::mutex> scope(g_syncobj);
            auto it = g_registry.find(NULLPTR != name ? name : "");
            if (it == g_registry.end()) {
                return NULLPTR;
            }
            return &it->second;
        }

        XtcpQdisc* CreateQdisc(const char* name, const QdiscParams& params) noexcept {
            XtcpQdiscOps snapshot;
            {
                std::lock_guard<std::mutex> scope(g_syncobj);
                auto it = g_registry.find(NULLPTR != name ? name : "");
                if (it == g_registry.end()) {
                    return NULLPTR;
                }
                snapshot = it->second;
            }
            XtcpQdisc* q = new (std::nothrow) XtcpQdisc();
            if (NULLPTR == q) {
                return NULLPTR;
            }
            XtcpQdiscOps* owned = new (std::nothrow) XtcpQdiscOps(snapshot);
            if (NULLPTR == owned) {
                delete q;
                return NULLPTR;
            }
            q->ops = owned;
            q->params = params;
            q->private_data = NULLPTR;
            if (NULLPTR != owned->init && 0 != owned->init(q, &params)) {
                delete owned;
                delete q;
                return NULLPTR;
            }
            return q;
        }

        void DestroyQdisc(XtcpQdisc* q) noexcept {
            if (NULLPTR == q) {
                return;
            }
            const XtcpQdiscOps* ops = NULLPTR;
            {
                // Serialize against any in-flight ops entry point
                // (enqueue/dequeue/has_backlog) that reads private_data under
                // syncobj_: destroy must not race another thread's use of the
                // same private_data. The lock is released before `delete q`
                // destroys the (now-unlocked) mutex member.
                std::lock_guard<std::mutex> scope(q->syncobj_);
                if (NULLPTR != q->ops && NULLPTR != q->ops->destroy) {
                    q->ops->destroy(q);
                }
                ops = q->ops;
            }
            delete const_cast<XtcpQdiscOps*>(ops);
            delete q;
        }
    }
}

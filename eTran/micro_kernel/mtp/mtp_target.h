#pragma once
/*
 * mtp_target.h -- the MTP target runtime for eTran's control path (site T1).
 *
 * NOTHING IN THIS FILE MAY NAME A PROTOCOL. That is the whole point of it: a
 * compiler emits one program header per MTP program, and this file is what
 * those headers are compiled against. If TCP (or Homa, or QUIC) appears here,
 * the split has failed and the next protocol will not plug in.
 *
 * The division of labour, following the MTP paper (arXiv:2509.21550) §4-5:
 *
 *   the COMPILER emits, per program   the TARGET (this file) provides
 *   -------------------------------   ------------------------------------
 *   event structs                     context storage: new_ctx / exists /
 *   the context struct                  get_ctx / del_ctx
 *   the flow-id type + its hash       the guarantee that an id maps to at
 *   processor bodies                    most one live context
 *   the dispatch table                nothing else -- no policy, no protocol
 *
 * STATIC, NOT RUNTIME-GENERIC. ctx_store is a template instantiated once per
 * program with that program's own key and context types, so lookups compile to
 * the same code eTran hand-wrote. There is deliberately no run-time "generic
 * key" or "generic value" anywhere: the compiler knows the program, so the
 * specialisation happens at compile time.
 */
#include <mutex>
#include <unordered_map>

namespace mtp {

/*
 * ctx_store -- MTP's context storage for one context declaration.
 *
 * It BORROWS the map and lock rather than owning them, because eTran already
 * has exactly one such map per context type and several not-yet-ported call
 * sites still reach it directly. Two independent views of one logical store is
 * how state diverges silently, so while the port is in progress there is one
 * map and this is a view onto it. When the last direct user is ported the
 * store can take ownership and the reference members become values.
 *
 * Template parameters, all compiler-supplied:
 *   FlowId  the program's flow-id type          (MTP: `flow_id tcp_fid : (...)`)
 *   Ctx     the program's context struct        (MTP: `context tcp_ctx { ... }`)
 *   Hash/Eq hashing for FlowId
 *   KeyOf   FlowId from a live Ctx
 *   CtxInit stamp a fresh Ctx: its FlowId components, plus any lifecycle
 *           hooks the target hangs off a context (eTran keeps a release
 *           function pointer per context, for instance)
 *
 * KeyOf and CtxInit must agree: KeyOf(c) after CtxInit(c, id) must equal
 * id. The store is keyed by KeyOf so that a context can be removed knowing only
 * itself -- which is what eTran's unreg path needs -- while new_ctx takes an id.
 */
template <class FlowId, class Ctx, class Hash, class Eq, class KeyOf, class CtxInit>
class ctx_store
{
public:
    using map_t = std::unordered_map<FlowId, Ctx *, Hash, Eq>;

    ctx_store(map_t &m, std::mutex &lock) : _m(m), _lock(lock) {}

    /* MTP `exists(ctx)` / context lookup by id. */
    Ctx *get_ctx(const FlowId &id)
    {
        std::lock_guard<std::mutex> g(_lock);
        auto it = _m.find(id);
        return it == _m.end() ? nullptr : it->second;
    }

    bool exists(const FlowId &id) { return get_ctx(id) != nullptr; }

    /*
     * Lookup by something that is NOT the flow id -- an application handle, a
     * file descriptor. MTP has no such instruction and does not need one: the
     * app parser is what turns app-side identity into a flow id. It exists
     * because eTran resolves a socket call by scanning for its opaque handle,
     * and preserving that is what keeps a ported event's behaviour identical.
     * Linear, exactly as eTran's own find_tcp_conn_slowpath is.
     */
    template <class Pred>
    Ctx *find_if(Pred pred)
    {
        std::lock_guard<std::mutex> g(_lock);
        for (auto &kv : _m)
            if (pred(kv.second))
                return kv.second;
        return nullptr;
    }

    /*
     * MTP `new_ctx(fid)`: materialise the context for an id and register it.
     * Value-initialised, so a program that forgets a field gets zero rather
     * than whatever was on the heap.
     */
    Ctx *new_ctx(const FlowId &id)
    {
        Ctx *c = new Ctx();
        if (!c)
            return nullptr;
        CtxInit{}(c, id);
        std::lock_guard<std::mutex> g(_lock);
        _m.insert(std::make_pair(KeyOf{}(c), c));
        return c;
    }

    /* MTP `del_ctx`: unregister. Freeing is the caller's, because eTran hangs
     * a per-context release hook off the object and runs it on its own schedule. */
    void unbind(Ctx *c)
    {
        std::lock_guard<std::mutex> g(_lock);
        _m.erase(KeyOf{}(c));
    }

private:
    map_t &_m;
    std::mutex &_lock;
};

} // namespace mtp

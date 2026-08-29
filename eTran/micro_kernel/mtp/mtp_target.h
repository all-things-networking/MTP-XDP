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
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

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

    /* Live instance count. A program may cap how many contexts it will hold;
     * eTran's accept refuses past MAX_NR_CONN. */
    std::size_t size()
    {
        std::lock_guard<std::mutex> g(_lock);
        return _m.size();
    }

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
     *
     * `init` runs BEFORE the context is published. It carries the processor's
     * field writes, and taking it as a callback is not decoration: eTran
     * registers a context only after filling it, and publishing a half-written
     * context to a store other sites can already reach is a race waiting for a
     * reader. The processor still reads as `ctx = new_ctx(fid); ctx.a = ...`.
     */
    template <class Init>
    Ctx *new_ctx(const FlowId &id, Init init)
    {
        Ctx *c = new Ctx();
        if (!c)
            return nullptr;
        CtxInit{}(c, id);
        init(c);
        std::lock_guard<std::mutex> g(_lock);
        _m.insert(std::make_pair(KeyOf{}(c), c));
        return c;
    }

    /*
     * Create a context that is NOT yet addressable by an id.
     *
     * MTP's new_ctx takes the id, because in MTP a context and its identity
     * arrive together. eTran has a case where they do not: accept() builds the
     * connection that will receive the next SYN before that SYN exists, so its
     * remote address -- three quarters of its id -- is still zero. The donor
     * keeps it off the map entirely (tcp.cc's map "includes all TCP connections
     * of all states except for CONN_WAIT_RX_SYN") and hangs it on the listening
     * context until a SYN gives it an identity, at which point publish() adds
     * it. Modelled as it is rather than given a placeholder id, because a
     * placeholder would be reachable and eTran's is not.
     */
    template <class Init>
    Ctx *alloc(Init init)
    {
        Ctx *c = new Ctx();
        if (!c)
            return nullptr;
        init(c);
        return c;
    }

    /*
     * Register a context that already exists under its CURRENT key.
     *
     * MTP has no instruction for this, because in MTP a context's id does not
     * change. eTran's does: a socket that bind()s is registered under an id
     * fabricated from its handle, and when it later connect()s its address
     * fields are overwritten with the real four-tuple and it is registered
     * AGAIN -- without the first registration being removed. The donor keeps
     * both, so this keeps both. Not a rebind: a second binding.
     */
    void publish(Ctx *c)
    {
        std::lock_guard<std::mutex> g(_lock);
        _m.insert(std::make_pair(KeyOf{}(c), c));
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

/*
 * ctx_bag -- a context declaration whose id may select SEVERAL live instances.
 *
 * MTP has no such thing: §4.1 is that a context id selects *the* instance, and
 * `exists(ctx)` has one answer. A target still has to provide it, because
 * SO_REUSEPORT lets several sockets share one listening endpoint and an
 * arriving packet picks among them by a rule the target chose. Programs that
 * need it say so; programs that do not never instantiate this.
 *
 * Kept deliberately separate from ctx_store rather than generalising that to
 * "zero or more", so that a program using the single-instance store cannot
 * quietly acquire multi-instance semantics.
 */
template <class FlowId, class Ctx, class Hash, class Eq, class CtxInit>
class ctx_bag
{
public:
    using map_t = std::unordered_map<FlowId, std::vector<Ctx *>, Hash, Eq>;

    ctx_bag(map_t &m, std::mutex &lock) : _m(m), _lock(lock) {}

    /*
     * Run `pick` over every instance under this id, UNDER THE LOCK, and return
     * what it chose. Which instance is protocol policy and belongs to the
     * program -- but the choosing has to happen while the set is held, or the
     * program is indexing a vector another thread may have reallocated.
     *
     * An earlier version returned the vector and let the caller index it after
     * the lock was dropped. That is safe only because eTran does all of this on
     * one thread, which is not a property worth depending on silently.
     */
    template <class Pick>
    Ctx *select(const FlowId &id, Pick pick)
    {
        std::lock_guard<std::mutex> g(_lock);
        auto it = _m.find(id);
        if (it == _m.end() || it->second.empty())
            return nullptr;
        return pick(it->second);
    }

    /* As ctx_store::new_ctx, including init-before-publish. */
    template <class Init>
    Ctx *new_ctx(const FlowId &id, Init init)
    {
        Ctx *c = new Ctx();
        if (!c)
            return nullptr;
        CtxInit{}(c, id);
        init(c);
        std::lock_guard<std::mutex> g(_lock);
        _m[id].push_back(c);
        return c;
    }

private:
    map_t &_m;
    std::mutex &_lock;
};

/*
 * work_queue -- contexts with a deferred processor still to run.
 *
 * MTP's dispatch lists a processor and says nothing about when it runs; the
 * target decides (§4.1, "the execution strategy is intentionally left to the
 * target"). eTran's choice for packet GENERATION is to defer it: a processor
 * that must emit a packet parks its context here, and the control loop drains
 * the queue once per pass. That is why a SYN is not sent inside connect().
 *
 * Protocol-independent: what is queued is a context, and what runs on drain is
 * whatever the program supplied.
 */
template <class Ctx>
class work_queue
{
public:
    work_queue(std::list<Ctx *> &q) : _q(q) {}

    void push(Ctx *c) { _q.push_back(c); }

    /* Drain to empty, running `run` on each. Returns how many ran, which is what
     * eTran's control loop uses to decide whether a pass did any work. */
    template <class Run>
    int drain(Run run)
    {
        int work = 0;
        while (!_q.empty()) {
            Ctx *c = _q.front();
            _q.pop_front();
            work += run(c);
        }
        return work;
    }

private:
    std::list<Ctx *> &_q;
};

} // namespace mtp

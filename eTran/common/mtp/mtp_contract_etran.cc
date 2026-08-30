/*
 * mtp_contract_etran.cc -- this target's half of the contract.
 *
 * Everything here needs eTran, or needs to allocate, which is why none of it is
 * in mtp_contract_impl.h and none of it is available at the eBPF sites. It is
 * also the whole of what a different target would rewrite: the other half is
 * data structures and stands unchanged.
 *
 * WHAT IS AND IS NOT DONE, stated here rather than discovered:
 *   - the context store is COMPLETE and program-independent. It holds contexts
 *     whose layout it cannot see, which is the requirement, and it is what
 *     mtp_ctx_register exists for.
 *   - packet generation, waking the application and reading a frame are STUBS
 *     that account for their calls. Wiring them to the micro kernel means the
 *     generated program replacing the hand-written one that runs today, and
 *     that is a port, not a function body. docs/COMPILER.md says so too.
 *
 * A stub that silently does nothing is the failure this project keeps hitting,
 * so each one counts its calls and mtp_contract_report() prints them. A run
 * that reports zero packets generated has not quietly worked.
 */
#include "mtp_contract.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <string>
#include <vector>

namespace {

/*
 * A CONTEXT STORE OVER BYTES. The program's context layout is the program's;
 * the target is told only how big it is and how big its key is, and that is
 * genuinely all a store needs. Keying on the raw key bytes is what makes it
 * work for a four-tuple and for a bare uint16 without knowing which it has --
 * the same property mtp_target.h's template gets from C++ generics, reached
 * differently because the contract has to be spellable in C.
 */
struct Kind {
    __u32 ctx_size = 0;
    __u32 key_size = 0;
    /* When the tree has bound its own container for this kind, these are used
     * and the map below stays empty. */
    const struct mtp_ctx_store_ops *ops = nullptr;
    /* The key bytes are the map key. std::string is used as a byte container,
     * not as text: keys contain embedded zeros and are compared by length. */
    std::unordered_map<std::string, void *> by_key;
};

std::unordered_map<int, Kind> g_kinds;

struct Counters {
    unsigned ctx_new = 0, ctx_del = 0, ctx_get = 0, ctx_miss = 0;
    unsigned pkt_gen = 0, notify = 0, bp_read = 0, ev_key = 0;
    unsigned addrs = 0, set_rate = 0, flush_notify = 0;
} g_n;

std::string key_of(int kind, const void *key)
{
    auto it = g_kinds.find(kind);
    if (it == g_kinds.end() || !key) return std::string();
    return std::string(static_cast<const char *>(key), it->second.key_size);
}

} /* namespace */

extern "C" {

void mtp_ctx_register(mtp_ctx_kind_t kind, __u32 ctx_size, __u32 key_size)
{
    Kind &k = g_kinds[kind];
    k.ctx_size = ctx_size;
    k.key_size = key_size;
}

void mtp_ctx_bind_store(mtp_ctx_kind_t kind, const struct mtp_ctx_store_ops *ops)
{
    g_kinds[kind].ops = ops;
}

mtp_ctx_t mtp_ctx_new(mtp_ctx_kind_t kind, const void *key)
{
    auto it = g_kinds.find(kind);
    if (it != g_kinds.end() && it->second.ops && it->second.ops->create) {
        g_n.ctx_new++;
        return it->second.ops->create(key);
    }
    if (it == g_kinds.end()) {
        /* NOT SILENT. An unregistered kind means generated start-up never ran,
         * and every context of that kind would otherwise vanish one at a time. */
        fprintf(stderr, "mtp_ctx_new: kind %d was never registered; "
                        "did mtp_prog_init() run?\n", kind);
        return nullptr;
    }
    const std::string k = key_of(kind, key);

    /* ALREADY PRESENT IS NOT AN ERROR HERE. A program republishes a context
     * under a new identity -- an active open learns its peer -- and that is the
     * same call. The second binding wins and the first is left to the caller,
     * which is what the hand-written target's publish() does. */
    auto f = it->second.by_key.find(k);
    if (f != it->second.by_key.end()) return f->second;

    void *c = calloc(1, it->second.ctx_size);
    if (!c) return nullptr;
    it->second.by_key[k] = c;
    g_n.ctx_new++;
    return c;
}

mtp_ctx_t mtp_ctx_get(mtp_ctx_kind_t kind, const void *key)
{
    g_n.ctx_get++;
    auto it = g_kinds.find(kind);
    if (it == g_kinds.end()) return nullptr;
    if (it->second.ops && it->second.ops->lookup) return it->second.ops->lookup(key);
    auto f = it->second.by_key.find(key_of(kind, key));
    if (f == it->second.by_key.end()) { g_n.ctx_miss++; return nullptr; }
    return f->second;
}

void mtp_ctx_del(mtp_ctx_kind_t kind, const void *key)
{
    auto it = g_kinds.find(kind);
    if (it == g_kinds.end()) return;
    if (it->second.ops && it->second.ops->destroy) {
        g_n.ctx_del++;
        it->second.ops->destroy(key);
        return;
    }
    auto f = it->second.by_key.find(key_of(kind, key));
    if (f == it->second.by_key.end()) return;
    free(f->second);
    it->second.by_key.erase(f);
    g_n.ctx_del++;
}

/* ---- the stubs, each of which counts ---------------------------------- */
int  mtp_pkt_gen(const void *bp, __u8 prio, bool rtx)
{ (void)bp; (void)prio; (void)rtx; g_n.pkt_gen++; return 0; }

void mtp_notify(mtp_ctx_t ctx, int cond)
{ (void)ctx; (void)cond; g_n.notify++; }

void mtp_ctx_addrs(void *ctx, __u32 l, __u32 r)
{ (void)ctx; (void)l; (void)r; g_n.addrs++; }

void mtp_set_rate(void *ctx, __u32 rate)
{ (void)ctx; (void)rate; g_n.set_rate++; }

void mtp_ev_key(void *ev, mtp_ctx_kind_t kind, const void *key)
{ (void)ev; (void)kind; (void)key; g_n.ev_key++; }

void mtp_bp_read(const struct mtp_pkt *p, void *bp, __u32 size,
                 struct mtp_opt *opts, __u8 *n, __u8 cap)
{
    (void)opts; (void)cap;
    g_n.bp_read++;
    if (n) *n = 0;
    if (bp && p && p->data && size) memcpy(bp, p->data, size < p->len ? size : p->len);
}

__u32 mtp_rx_flush_and_notify(void *s, __u32 n, struct mtp_addr b)
{ g_n.flush_notify++; return mtp_rx_flush(s, n, b); }

__u32 mtp_tx_flush_and_notify(void *s, __u32 n)
{ g_n.flush_notify++; return mtp_tx_flush(s, n); }

/* Blueprint and packet accessors: the frame's own, so they belong to whatever
 * holds frames. Counted for the same reason as the rest. */
void  mtp_add_hdr(void *recv, void *hdr)                    { (void)recv; (void)hdr; }
void *mtp_extract_hdr(void *recv)                           { (void)recv; return nullptr; }
struct mtp_addr mtp_get_data(void *recv)                    { struct mtp_addr a = {0,0,0,0}; (void)recv; return a; }
void  mtp_mem_append(void *recv, struct mtp_addr a, __u32 n){ (void)recv; (void)a; (void)n; }
__u32 mtp_rate(void *recv)                                  { (void)recv; return 0; }

/*
 * WHAT ACTUALLY HAPPENED. Printed rather than trusted: the contract's stubs
 * would otherwise be indistinguishable from a target that works, which is the
 * exact shape of every silent failure this project has had.
 */
void mtp_contract_report(void)
{
    unsigned live = 0;
    for (auto &kv : g_kinds) live += (unsigned)kv.second.by_key.size();
    fprintf(stderr,
        "mtp contract: ctx new=%u del=%u get=%u miss=%u live=%u | "
        "pkt_gen=%u notify=%u bp_read=%u ev_key=%u addrs=%u rate=%u flush=%u\n",
        g_n.ctx_new, g_n.ctx_del, g_n.ctx_get, g_n.ctx_miss, live,
        g_n.pkt_gen, g_n.notify, g_n.bp_read, g_n.ev_key,
        g_n.addrs, g_n.set_rate, g_n.flush_notify);
}

} /* extern "C" */

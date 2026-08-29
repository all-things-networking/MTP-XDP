#pragma once
/*
 * tcp_program.h -- the TCP transport program, in the shape a compiler from an
 * MTP program would emit. Compiled against mtp/mtp_target.h, which knows
 * nothing about TCP.
 *
 * READ THIS AS GENERATED CODE. Everything here is derivable from an MTP program
 * text plus the target's calling convention; nothing here is a hand-tuned
 * decision. A different protocol produces a different file of the same shape --
 * its own events, its own context, its own flow id, its own processors -- and
 * plugs into the same target unchanged. That is the property being built for,
 * and it is why the store below is a TEMPLATE INSTANTIATION rather than a
 * generic run-time key/value map: the compiler knows the program, so TCP's key
 * is TCP's key at compile time.
 *
 * Ported so far:  app_bind.
 * Everything else is still eTran's original code in tcp.cc, on purpose -- one
 * event at a time, each built and measured before the next.
 */
#include <runtime/tcp.h>
#include "mtp/mtp_target.h"

/* eTran's own control-path services, used by the processors below. These are
 * TARGET services, not protocol logic: port allocation and the LRPC notify
 * channel exist for every program this target compiles. */
extern std::unordered_map<struct flow_tuple, struct tcp_connection *,
                          flow_tuple_hash, flow_tuple_equal> tcp_connections;
extern std::mutex tcp_connections_lock;
int alloc_port(uint16_t port);
int record_port(struct app_ctx *actx, uint16_t local_port, uint16_t remote_port);
/* eTran's per-context release hook; no longer static in tcp.cc so that a
 * generated program can install it the way the donor does. */
void tcp_connection_close(struct kref *ref);
void notify_app_tcp_status_bind(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int32_t status);

namespace tcp_prog {

/* ------------------------------------------------------------------ *
 * flow_id tcp_fid : (uint32, uint16, uint32, uint16)
 *
 * Emitted as an alias of eTran's flow_tuple rather than as a fresh struct,
 * because the context (below) is still eTran's tcp_connection and stores its
 * identity in those four fields. When the context declaration itself is ported
 * this becomes a generated struct.
 * ------------------------------------------------------------------ */
using tcp_fid = struct flow_tuple;

/*
 * The bound-but-not-connected flow id, built from the application's socket
 * handle. This is NOT a protocol construct: with no peer there is no four-tuple,
 * so eTran fabricates one out of the handle pointer (tcp.cc:1381-1384 in the
 * donor). MTP permits it -- a context id is "a tuple of values created by the
 * transport program" (§4.1) -- but it means a bound socket's identity is an
 * address. Recorded in the event docs as [GAP: SYNTHETIC-ID]; kept bit-exact
 * here because the same fabrication has to be reproduced by listen() and
 * close(), which have not been ported yet and still read these fields directly.
 */
static inline tcp_fid tcp_fid_from_handle(opaque_ptr h, uint16_t local_port)
{
    return tcp_fid(/* remote_ip   */ (uint16_t)(h >> 16),
                   /* remote_port */ (uint16_t)h,
                   /* local_ip    */ (uint16_t)(h >> 32),
                   /* local_port  */ local_port);
}

/* KeyOf / IdInit -- the pair the target needs to key a context by itself and to
 * stamp a fresh context with its id. Inverses by construction. */
struct tcp_key_of {
    tcp_fid operator()(const struct tcp_connection *c) const {
        return tcp_fid(c->remote_ip, c->remote_port, c->local_ip, c->local_port);
    }
};
struct tcp_ctx_init {
    void operator()(struct tcp_connection *c, const tcp_fid &id) const {
        c->remote_ip = id.remote_ip; c->remote_port = id.remote_port;
        c->local_ip  = id.local_ip;  c->local_port  = id.local_port;
        /* The target's per-context destructor hook. eTran sets this on every
         * context the moment it allocates one (donor tcp.cc:1350); dropping it
         * would leak the connection and its port on close. */
        c->release = tcp_connection_close;
    }
};

using tcp_ctx_store = mtp::ctx_store<tcp_fid, struct tcp_connection,
                                     flow_tuple_hash, flow_tuple_equal,
                                     tcp_key_of, tcp_ctx_init>;

static inline tcp_ctx_store &ctxs()
{
    static tcp_ctx_store s(tcp_connections, tcp_connections_lock);
    return s;
}

/* ------------------------------------------------------------------ *
 * The events
 * ------------------------------------------------------------------ */

/* The target's app_event base: which application thread made the call, and the
 * handles it will be answered on. Not protocol state -- MTP has no type for a
 * file descriptor -- so it rides the base rather than the event. */
struct app_event {
    struct app_ctx_per_thread *tctx;
    opaque_ptr handle;
    int fd;
};

/* event app_bind : app_event { uint32 local_ip; uint16 local_port; bool reuseport; } */
struct app_bind : app_event {
    uint32_t local_ip;
    uint16_t local_port;
    bool reuseport;
};

/* ------------------------------------------------------------------ *
 * app_parser socket { bind -> sock_bind; ... }
 *
 * Turns one socket call into one event and sets its flow id. The id is set
 * HERE, by the parser, which is what lets the processor be written against a
 * context it did not have to go looking for.
 * ------------------------------------------------------------------ */
static inline void sock_bind(struct app_ctx_per_thread *tctx,
                             const struct appout_tcp_bind_t *op,
                             app_bind &ev, tcp_fid &fid)
{
    ev.tctx       = tctx;
    ev.handle     = op->opaque_connection;
    ev.fd         = op->fd;
    ev.local_ip   = op->local_ip;
    ev.local_port = op->local_port;
    ev.reuseport  = op->reuseport;
    fid = tcp_fid_from_handle(ev.handle, ev.local_port);
}

/* ------------------------------------------------------------------ *
 * Processors
 * ------------------------------------------------------------------ */

/*
 * void proc_bind(app_bind ev, tcp_ctx ctx)
 *
 * Returns 0, or a negative errno which the dispatch turns into the single
 * notify(ERROR) -- that is where eTran puts it too (process_tcp_cmd), so the
 * error path is one site rather than one per failure.
 *
 * ORDER NOTE. eTran allocates the context BEFORE testing the port and deletes
 * it again on each failure (donor tcp.cc:1349-1372). Written in MTP shape the
 * allocation moves after the tests, because new_ctx both allocates and
 * registers. That is behaviour-preserving: nothing between eTran's `new` and
 * its `reg_tcp_conn_slowpath` can observe the object -- it is unregistered,
 * unshared and unreachable -- so the only difference is that the failure paths
 * no longer allocate and free.
 */
static inline int proc_bind(const app_bind &ev, const tcp_fid &fid)
{
    /* exists(ctx) -> ERROR. By app handle, not by id: eTran resolves a socket
     * call by scanning for its opaque handle, and a bound socket rebinding to a
     * different port would key differently. Preserved exactly. */
    opaque_ptr h = ev.handle;
    if (ctxs().find_if([h](const struct tcp_connection *c) {
            return c->opaque_connection == h; }))
        return -EADDRINUSE;

    /* alloc_port returns 0 on success. A taken port is allowed through only for
     * a SO_REUSEPORT socket whose application already owns it. */
    if (alloc_port(ev.local_port) != 0) {
        if (!ev.reuseport)
            return -EADDRINUSE;
        if (ev.tctx->actx->ports.find(ev.local_port) == ev.tctx->actx->ports.end())
            return -EADDRINUSE;
        /* this port belongs to this application -- allow it */
    }

    struct tcp_connection *ctx = ctxs().new_ctx(fid);
    if (!ctx)
        return -ENOMEM;

    /* A bind creates a DEGENERATE context: it holds the port and gives listen()
     * something to find. No eBPF state exists yet -- there is no four-tuple to
     * key a bpf_tcp_conn entry on. */
    ctx->type              = TCP_CONN_TYPE_FAKE;
    ctx->reuseport         = ev.reuseport;
    ctx->fd                = ev.fd;
    ctx->tctx              = ev.tctx;
    ctx->opaque_connection = ev.handle;
    ctx->flags             = 0;
    /* ev.local_ip is parsed and discarded: every listener binds to the node's
     * one configured address. The donor reads it into a local and writes
     * `(void)_local_ip; // FIXME` (tcp.cc:1341). Kept as a discard so the
     * program still says the field arrives. */
    (void)ev.local_ip;

    record_port(ctx->tctx->actx, ctx->local_port, 0);

    /* notify(ctx, BOUND) */
    notify_app_tcp_status_bind(ev.tctx, ctx->opaque_connection, ctx->fd, 0);
    return 0;
}

/* ------------------------------------------------------------------ *
 * dispatch tcp_dispatch { app_bind -> { proc_bind }; ... }
 *
 * One generated entry point per event. The processor LIST is the loop body; for
 * app_bind the list is one long. The error notify is emitted once here, which
 * is what `notify(ctx, ERROR); return;` in each guard compiles to.
 * ------------------------------------------------------------------ */
static inline void dispatch_app_bind(struct app_ctx_per_thread *tctx,
                                     const struct appout_tcp_bind_t *op)
{
    app_bind ev;
    tcp_fid fid(0, 0, 0, 0);
    sock_bind(tctx, op, ev, fid);

    if (proc_bind(ev, fid) != 0)
        notify_app_tcp_status_bind(tctx, op->opaque_connection, op->fd, -1);
}

} // namespace tcp_prog

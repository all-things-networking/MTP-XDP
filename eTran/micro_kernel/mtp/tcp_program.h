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
 * Ported so far:  app_bind, app_listen, app_connect, app_accept, tcp_syn
 *                 (and with it the network demux).
 * Everything else is still eTran's original code in tcp.cc, on purpose -- one
 * event at a time, each built and measured before the next.
 */
#include <runtime/tcp.h>
/* Complete types, not just the extern declarations below: proc_connect and
 * proc_accept read etran_tcp->_trans_params and etran_nic->_local_ip. Included
 * here rather than relying on tcp.cc's include order, so the header stands on
 * its own. Both are guarded. */
#include "trans_ebpf.h"
#include "nic.h"
#include "mtp/mtp_target.h"

/* eTran's own control-path services, used by the processors below. These are
 * TARGET services, not protocol logic: port allocation and the LRPC notify
 * channel exist for every program this target compiles. */
extern std::unordered_map<struct flow_tuple, struct tcp_connection *,
                          flow_tuple_hash, flow_tuple_equal> tcp_connections;
extern std::mutex tcp_connections_lock;
extern std::unordered_map<struct listen_tuple, std::vector<struct tcp_listener *>,
                          listen_tuple_hash, listen_tuple_equal> tcp_listeners;
extern std::mutex tcp_listeners_lock;
extern class eTranNIC *etran_nic;
void notify_app_tcp_status_listen(struct app_ctx_per_thread *tctx, opaque_ptr l, int fd, int32_t status);
void notify_app_tcp_conn_open(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int32_t status,
                              struct tcp_connection *conn);
int alloc_port(void);
extern class eTranTCP *etran_tcp;
extern std::list<struct tcp_connection *> tcp_handshake_list;
/* Declared to match the DEFINITION at tcp.cc:554, which takes 12 arguments.
 * Note tcp.cc:67 forward-declares an 11-argument overload of the same name, with
 * no `newfd`, that is never defined -- a pre-existing inconsistency in the donor.
 * Copying that one links against nothing. */
void notify_app_tcp_event_accept(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int newfd,
                                 int32_t status, uint32_t rx_buf_size, uint32_t tx_buf_size,
                                 uint32_t local_ip, uint32_t remote_ip, uint16_t remote_port,
                                 uint32_t qid, bool backlog);
/* The shared suffix of tcp_syn and app_accept: matches a queued SYN against a
 * waiting accept. NOT ported yet -- it belongs with the handshake events -- so it
 * is called here as the donor calls it, and lost its `static` to allow that. */
void tcp_listener_accept(struct tcp_listener *l);
void notify_app_tcp_event_newconn(struct app_ctx_per_thread *tctx, opaque_ptr l, int fd,
                                  uint32_t remote_ip, uint16_t remote_port);
/* Still eTran's, both un-static'd so the generated demux can reach them: the
 * established-connection path and the RST reply are later events. */
void tcp_connection_pkt(struct tcp_connection *c, struct pkt_tcp *p, uint32_t qid,
                        struct tcp_opts *opts);
void send_tcp_reset(struct app_ctx *actx, const struct pkt_tcp *orig_p);
int parse_tcp_opts(struct pkt_tcp *p, struct tcp_opts *opts);
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
 * flow_id tcp_lid : (uint32, uint16)   -- the listening endpoint
 *
 * A SEPARATE context declaration with its own id shape, and a BAG rather than a
 * store: SO_REUSEPORT puts several listening contexts under one id and an
 * arriving SYN picks among them by hashing its four-tuple. MTP's model is that
 * an id selects the instance, so this is the one place the program cannot be
 * written as MTP describes -- recorded as [GAP: REUSEPORT].
 * ------------------------------------------------------------------ */
using tcp_lid = struct listen_tuple;

struct tcp_listen_ctx_init {
    void operator()(struct tcp_listener *l, const tcp_lid &id) const {
        l->listen_port = id.local_port;
        /* id.local_ip is not stored on the listener: eTran keys the bag by the
         * node's single configured address and the listener carries only its
         * port. Kept that way -- see proc_listen. */
    }
};

using tcp_listen_bag = mtp::ctx_bag<tcp_lid, struct tcp_listener,
                                    listen_tuple_hash, listen_tuple_equal,
                                    tcp_listen_ctx_init>;

static inline tcp_listen_bag &listen_ctxs()
{
    static tcp_listen_bag s(tcp_listeners, tcp_listeners_lock);
    return s;
}

/* ------------------------------------------------------------------ *
 * The events
 * ------------------------------------------------------------------ */

/*
 * event tcp_syn : net_event { ... }
 *
 * Carries the packet rather than its parsed fields. eTran does not decode a SYN
 * when it arrives: it copies the first 256 bytes into the backlog and re-parses
 * them at accept time (runtime/tcp.h:129-139), which is why the MSS and
 * timestamp options are read later than they are received. A blueprint-shaped
 * event with seq/window/opts fields would describe a different program.
 */
struct net_event {
    struct pkt_tcp *pkt;
    struct tcp_opts *opts;
    uint32_t qid;
};

struct tcp_syn : net_event {};

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

/*
 * event app_listen : app_event { uint32 pending_cap; }
 *
 * The event doc gives this event local_ip and local_port and has the parser set
 * the flow id from them. NEITHER IS IN THE CALL: appout_tcp_listen_t carries
 * only the two handles, an fd and the backlog (common/intf/intf.h:112-117). The
 * endpoint is recovered from the BOUND context, so the parser cannot set the
 * listening id and the processor derives it.
 */
struct app_listen : app_event {
    opaque_ptr listener_handle;   /* the app's listener object, answered to */
    unsigned int pending_cap;     /* the backlog argument */
};

/*
 * event app_connect : app_event { uint32 remote_ip; uint16 remote_port; }
 *
 * The doc also gives this event local_ip and local_port and reads both in the
 * processor. NEITHER IS IN THE CALL: appout_tcp_open_t is
 * {opaque_connection, fd, remote_ip, remote_port} (intf.h:103-108). The local
 * address is the node's one configured address and the local port is either the
 * bound context's or whatever the allocator hands out.
 */
struct app_connect : app_event {
    uint32_t remote_ip;
    uint16_t remote_port;
};

/*
 * event app_accept : app_event { uint16 local_port; }
 *
 * Carries the listening endpoint's port and the app's handles. The listener is
 * found by scanning the OWNING THREAD's listener list on (port, handle) --
 * tcp.cc:1195-1202 -- not the tcp_listeners bag. A third access path into
 * listening state, and the reason accept is per-thread: a listener registered by
 * one app thread is not acceptable on another.
 */
struct app_accept : app_event {
    opaque_ptr listener_handle;
    uint16_t local_port;
    int newfd;
};

/* ------------------------------------------------------------------ *
 * app_parser socket { bind -> sock_bind; listen -> sock_listen;
 *                     connect -> sock_connect; accept -> sock_accept; ... }
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

static inline void sock_listen(struct app_ctx_per_thread *tctx,
                               const struct appout_tcp_listen_t *op,
                               app_listen &ev)
{
    ev.tctx            = tctx;
    ev.handle          = op->opaque_connection;
    ev.fd              = op->fd;
    ev.listener_handle = op->opaque_listener;
    ev.pending_cap     = op->backlog;
    /* No set_flow_id here: the listening id needs the bound context's port,
     * which this call does not carry. proc_listen derives it. */
}

static inline void sock_connect(struct app_ctx_per_thread *tctx,
                                const struct appout_tcp_open_t *op,
                                app_connect &ev)
{
    ev.tctx        = tctx;
    ev.handle      = op->opaque_connection;
    ev.fd          = op->fd;
    ev.remote_ip   = op->remote_ip;
    ev.remote_port = op->remote_port;
    /* No set_flow_id: the local port is not known until the processor has
     * looked for a bound context or asked the allocator. */
}

static inline void sock_accept(struct app_ctx_per_thread *tctx,
                               const struct appout_tcp_accept_t *op,
                               app_accept &ev)
{
    ev.tctx            = tctx;
    ev.handle          = op->opaque_connection;
    ev.fd              = op->fd;
    ev.listener_handle = op->opaque_listener;
    ev.local_port      = op->local_port;
    ev.newfd           = op->newfd;
}

/* ------------------------------------------------------------------ *
 * net_parser tcp { ... }
 *
 * The packet's flow id, as seen from THIS host: the sender's address is the
 * remote half. eTran writes the same expression inline in tcp_conn_lookup
 * (tcp.cc:688).
 * ------------------------------------------------------------------ */
static inline tcp_fid tcp_fid_of_pkt(const struct pkt_tcp *p)
{
    return tcp_fid(ntohl(p->ip.src), ntohs(p->tcp.src),
                   ntohl(p->ip.dest), ntohs(p->tcp.dest));
}

static inline tcp_lid tcp_lid_of_pkt(const struct pkt_tcp *p)
{
    return tcp_lid(ntohl(p->ip.dest), ntohs(p->tcp.dest));
}

/*
 * Which listening context receives this packet, when several share the id.
 * The choice is eTran's: hash the four-tuple modulo the number of instances
 * (tcp.cc:710). This is the selection MTP cannot express -- [GAP: REUSEPORT] --
 * and it is protocol POLICY, which is why the target's ctx_bag returns all the
 * instances and lets the program choose.
 */
static inline struct tcp_listener *select_listen_ctx(const struct pkt_tcp *p)
{
    std::vector<struct tcp_listener *> *all = listen_ctxs().get_all(tcp_lid_of_pkt(p));
    if (!all || all->empty())
        return nullptr;
    uint32_t h = (ntohl(p->ip.src) ^ ntohl(p->ip.dest) ^
                  ntohs(p->tcp.src) ^ ntohs(p->tcp.dest)) % all->size();
    return (*all)[h];
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

    /* A bind creates a DEGENERATE context: it holds the port and gives listen()
     * something to find. No eBPF state exists yet -- there is no four-tuple to
     * key a bpf_tcp_conn entry on. The writes run inside new_ctx so the context
     * is published only once complete, which is the order the donor uses. */
    struct tcp_connection *ctx = ctxs().new_ctx(fid, [&](struct tcp_connection *c) {
        c->type              = TCP_CONN_TYPE_FAKE;
        c->reuseport         = ev.reuseport;
        c->fd                = ev.fd;
        c->tctx              = ev.tctx;
        c->opaque_connection = ev.handle;
        c->flags             = 0;
    });
    if (!ctx)
        return -ENOMEM;
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

/*
 * void proc_listen(app_listen ev, tcp_listen_ctx ctx)
 *
 * The doc's guards are `!exists(ctx)` and `ctx.state != ST_BOUND`. The second
 * does not exist -- nothing sets a state anywhere. The real guard is
 * `type != TCP_CONN_TYPE_FAKE`, i.e. "this handle is a connection, not a bound
 * socket". The doc's `ctx.state = ST_LISTEN` does not exist either: eTran never
 * marks the bound context as listening; the listener's existence is what says so.
 */
static inline int proc_listen(const app_listen &ev)
{
    /* The bound context, by app handle -- the same scan bind uses. */
    opaque_ptr h = ev.handle;
    struct tcp_connection *bound = ctxs().find_if(
        [h](const struct tcp_connection *c) { return c->opaque_connection == h; });
    if (!bound)
        return -1;                       /* listen() with no bind() */
    if (bound->type != TCP_CONN_TYPE_FAKE)
        return -1;                       /* a connection, not a listening socket */

    /* The listening id uses the node's single configured address, not anything
     * the application asked for -- consistent with bind discarding local_ip. */
    tcp_lid lid(etran_nic->_local_ip, bound->local_port);

    struct tcp_listener *l = listen_ctxs().new_ctx(lid, [&](struct tcp_listener *nl) {
        nl->opaque_listener   = ev.listener_handle;
        nl->tctx              = ev.tctx;
        nl->max_backlog_size  = ev.pending_cap;
        nl->pending_conn      = nullptr;
        nl->c                 = bound;
        nl->fd                = bound->fd;
        /* The owning app thread's list, for teardown. A target ownership detail,
         * not protocol state -- and populated before publication, as the donor
         * does it. */
        ev.tctx->listeners.push_back(nl);
    });
    if (!l)
        return -1;

    /* notify(ctx, LISTENING) -- answered on the BOUND context's fd, as eTran does. */
    notify_app_tcp_status_listen(ev.tctx, ev.listener_handle, bound->fd, 0);
    return 0;
}

/*
 * void proc_connect(app_connect ev, tcp_ctx ctx)
 *
 * Two paths, and the second is why the target needs `publish`. If bind() ran,
 * the context ALREADY EXISTS and is already registered under an id fabricated
 * from the socket handle. connect() overwrites its address fields with the real
 * four-tuple and eTran registers it AGAIN, keeping both entries
 * (tcp.cc:1323, unconditional). The context's identity changes, which MTP has
 * no instruction for; the donor's behaviour is reproduced exactly rather than
 * tidied, because tidying it would be a silent protocol change.
 *
 * As in proc_bind, the allocation moves after the guard that can fail: nothing
 * can observe an unregistered context, so it is behaviour-preserving.
 */
static inline int proc_connect(const app_connect &ev)
{
    opaque_ptr h = ev.handle;
    struct tcp_connection *ctx = ctxs().find_if(
        [h](const struct tcp_connection *c) { return c->opaque_connection == h; });

    uint16_t fresh_port = 0;
    if (!ctx) {
        /* no bind() ran: take an ephemeral port. Which one is on the wire, and
         * no MTP instruction names it. */
        int p = alloc_port();
        if (p == -1)
            return -1;
        fresh_port = (uint16_t)p;
        record_port(ev.tctx->actx, fresh_port, ev.remote_port);
    }

    const tcp_fid fid(ev.remote_ip, ev.remote_port, etran_nic->_local_ip,
                      ctx ? ctx->local_port : fresh_port);

    auto fill = [&](struct tcp_connection *c) {
        c->type              = TCP_CONN_TYPE_NORMAL;
        c->tctx              = ev.tctx;
        c->listener          = nullptr;
        c->reuseport         = false;
        c->opaque_connection = ev.handle;
        c->fd                = ev.fd;
        c->rx_buf_size       = etran_tcp->_trans_params.tcp.rx_buf_size;
        c->tx_buf_size       = etran_tcp->_trans_params.tcp.tx_buf_size;
        c->status            = CONN_WAIT_TX_SYN;
        c->algorithm         = CC_NONE;
        c->cc_idx            = POISON_32;
        c->cc_last_rtt       = TCP_RTT_INIT;
        c->cc_rate           = CC_TIMELY_INIT_RATE;
        c->qid               = POISON_32;
        c->flags             = 0;
        /* Both sequence numbers start at 0 and neither is randomised. */
        c->remote_seq        = 0;
        c->local_seq         = 0;
    };

    if (!ctx) {
        ctx = ctxs().new_ctx(fid, fill);
        if (!ctx)
            return -1;
    } else {
        /* The identity change: stamp the real four-tuple over the synthetic one
         * and register under it, leaving the old entry in place as eTran does. */
        tcp_ctx_init{}(ctx, fid);
        fill(ctx);
        ctxs().publish(ctx);
    }

    /* Joining this list is what schedules gen_syn: the control loop sweeps it
     * and emits the SYN. gen_syn is a separate processor and is not ported yet. */
    tcp_handshake_list.push_back(ctx);

    /* notify(ctx, CONNECTING) -- status 0 means "in progress". The application
     * is notified a SECOND time when the SYN-ACK lands; two notifications for
     * one call has no MTP form. */
    notify_app_tcp_conn_open(ev.tctx, ctx->opaque_connection, ctx->fd, 0, ctx);
    return 0;
}

/*
 * void proc_accept(app_accept ev, tcp_listen_ctx lst, tcp_ctx ctx)
 *
 * Creates the connection that will receive the NEXT SYN. Its remote address is
 * still zero, so it has no flow id yet and is deliberately NOT published --
 * eTran's connection map "includes all TCP connections of all states except for
 * CONN_WAIT_RX_SYN". It lives on the listening context until a SYN gives it an
 * identity. That is `alloc` rather than `new_ctx`, and it is the clearest case
 * in this program of a context existing before its id does.
 */
static inline int proc_accept(const app_accept &ev)
{
    /* The listener, from the owning thread's own list. */
    struct tcp_listener *lst = nullptr;
    for (auto it = ev.tctx->listeners.begin(); it != ev.tctx->listeners.end(); it++) {
        if ((*it)->listen_port == ev.local_port &&
            (*it)->opaque_listener == ev.listener_handle) {
            lst = *it;
            break;
        }
    }
    if (!lst)
        return -1;                      /* no such listener on this thread */
    if (lst->pending_conn)
        return -1;                      /* one waiting accept at a time -- see below */
    if (ctxs().size() > MAX_NR_CONN)
        return -1;

    struct tcp_connection *ctx = ctxs().alloc([&](struct tcp_connection *c) {
        c->type              = TCP_CONN_TYPE_NORMAL;
        c->tctx              = ev.tctx;
        c->listener          = lst;
        c->opaque_connection = ev.handle;
        c->fd                = ev.newfd;
        /* No peer yet: three quarters of the id are zero until a SYN arrives. */
        c->remote_ip         = 0;
        c->remote_port       = 0;
        c->local_ip          = etran_nic->_local_ip;
        c->local_port        = lst->listen_port;
        c->rx_buf_size       = etran_tcp->_trans_params.tcp.rx_buf_size;
        c->tx_buf_size       = etran_tcp->_trans_params.tcp.tx_buf_size;
        c->remote_seq        = 0;
        c->local_seq         = 0;
        c->status            = CONN_WAIT_RX_SYN;
        c->syn_ts            = 0;
        c->syn_attempts      = 0;
        c->algorithm         = CC_NONE;
        c->cc_idx            = 0;
        c->cc_last_tsc       = 0;
        c->cc_last_rtt       = TCP_RTT_INIT;
        c->cc_last_drops     = 0;
        c->cc_last_acks      = 0;
        c->cc_last_ackb      = 0;
        c->cc_last_ecnb      = 0;
        c->cc_rate           = CC_TIMELY_INIT_RATE;
        c->cc_rexmits        = 0;
        c->cc_data           = {0};
        c->cnt_tx_pending    = 0;
        c->ts_tx_pending     = 0;
        c->qid               = POISON_32;
        c->flags             = 0;
    });
    if (!ctx)
        return -1;

    /* The listening context's `pending` slot holds EXACTLY ONE completed
     * connection, whatever max_backlog_size says -- that cap governs the queue
     * of held SYNs, not this. */
    lst->pending_conn = ctx;

    /* If a SYN is already queued, the shared suffix runs now. There is no
     * notify here: the application is told once the SYN-ACK goes out. */
    if (lst->backlog.size() > 0)
        tcp_listener_accept(lst);

    return 0;
}

/*
 * void proc_backlog(tcp_syn ev, tcp_listen_ctx lst)
 *
 * Holds the SYN. Every rejection is silent except the flags check, which the
 * donor logs -- a SYN that is dropped for a full backlog or as a duplicate looks
 * identical to one that never arrived.
 */
static inline void proc_backlog(const tcp_syn &ev, struct tcp_listener *lst)
{
    struct pkt_tcp *p = ev.pkt;

    /* Exactly a SYN. ECE and CWR are permitted because the active opener always
     * sets them; anything else is not this event. */
    if ((TCPH_FLAGS(&p->tcp) & ~(TCP_ECE | TCP_CWR)) != TCP_SYN) {
        fprintf(stderr, "proc_backlog: Not a SYN (flags %x)\n", TCPH_FLAGS(&p->tcp));
        return;
    }

    if (lst->backlog.size() >= lst->max_backlog_size)
        return;                                  /* dropped, silently */

    /* Already holding this four-tuple: a retransmitted SYN. */
    for (auto it = lst->backlog.begin(); it != lst->backlog.end(); it++) {
        struct pkt_tcp *q = (struct pkt_tcp *)it->pkt;
        if (ntohl(q->ip.src) == ntohl(p->ip.src) && ntohs(q->tcp.src) == ntohs(p->tcp.src) &&
            ntohl(q->ip.dest) == ntohl(p->ip.dest) && ntohs(q->tcp.dest) == ntohs(p->tcp.dest))
            return;
    }

    /* The raw bytes, not the decoded fields -- see the event declaration. */
    uint16_t len = sizeof(p->eth) + ntohs(p->ip.len);
    lst->backlog.push_back(backlog_slot((char *)p, len, ev.qid));

    /* notify(lst, LISTEN_NEWCONN) -- proc_backlog and notify_newconn are one
     * function in the donor; kept adjacent so the order is unambiguous. */
    notify_app_tcp_event_newconn(lst->tctx, lst->opaque_listener, lst->fd,
                                 ntohl(p->ip.src), ntohs(p->tcp.src));

    /* proc_passive_open runs only if an accept() is already waiting. It is the
     * suffix shared with app_accept, and is not ported yet. */
    if (lst->pending_conn)
        tcp_listener_accept(lst);
}

/* ------------------------------------------------------------------ *
 * dispatch tcp_dispatch { app_bind -> { proc_bind }; app_listen -> { proc_listen };
 *                         app_connect -> { proc_connect, gen_syn };
 *                         app_accept -> { proc_accept };
 *                         tcp_syn -> { proc_backlog, notify_newconn,
 *                                      proc_passive_open, gen_synack, notify_accept }; }
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

static inline void dispatch_app_listen(struct app_ctx_per_thread *tctx,
                                       const struct appout_tcp_listen_t *op)
{
    app_listen ev;
    sock_listen(tctx, op, ev);

    if (proc_listen(ev) != 0)
        notify_app_tcp_status_listen(tctx, op->opaque_listener, op->fd, -1);
}

static inline void dispatch_app_accept(struct app_ctx_per_thread *tctx,
                                       const struct appout_tcp_accept_t *op)
{
    app_accept ev;
    sock_accept(tctx, op, ev);

    if (proc_accept(ev) != 0)
        notify_app_tcp_event_accept(tctx, op->opaque_connection, op->fd, op->newfd,
                                    -1, 0, 0, 0, 0, 0, 0, 0);
}

static inline void dispatch_app_connect(struct app_ctx_per_thread *tctx,
                                        const struct appout_tcp_open_t *op)
{
    app_connect ev;
    sock_connect(tctx, op, ev);

    /* gen_syn, the second processor in this event's list, is not ported yet: it
     * runs off tcp_handshake_list in the control loop. */
    if (proc_connect(ev) != 0)
        notify_app_tcp_conn_open(tctx, op->opaque_connection, op->fd, -1, nullptr);
}

/*
 * The network dispatch.
 *
 * THE SHAPE IS INVERTED FROM THE DONOR, and this is the substantive change.
 * eTran demuxes context-first: find a connection, and if there is none find a
 * listener, and only then look at the flags. MTP is event-first -- the parser
 * decides WHICH event a packet is, and the context is then found by the event's
 * flow id.
 *
 * What is written here is the honest middle: the context lookups are expressed
 * as the two stores' own operations, keyed by the ids the parser derives, and
 * the listening branch raises a real tcp_syn event. The connection branch still
 * calls eTran's tcp_connection_pkt, which does its own flag dispatch, because
 * tcp_ack / tcp_data / tcp_synack / tcp_rst are not ported yet. When they are,
 * that call disappears and the parser raises those events directly.
 */
static inline int dispatch_net(struct app_ctx *actx, struct pkt_tcp *p, uint32_t qid)
{
    struct tcp_opts opts = {0};
    if (parse_tcp_opts(p, &opts))
        return -1;

    /* An established connection owns the packet if one exists under its id. */
    if (struct tcp_connection *ctx = ctxs().get_ctx(tcp_fid_of_pkt(p))) {
        tcp_connection_pkt(ctx, p, qid, &opts);   /* not ported yet */
        return 0;
    }

    /* Otherwise a listening context may. */
    if (struct tcp_listener *lst = select_listen_ctx(p)) {
        tcp_syn ev;
        ev.pkt = p; ev.opts = &opts; ev.qid = qid;
        proc_backlog(ev, lst);
        return 0;
    }

    /* Neither: reply with a RST unless this already is one. */
    fprintf(stdout, "No connection and listener are found, send RST back, %u, %d\n",
            htons(p->tcp.dest), (TCPH_FLAGS(&p->tcp)));
    if (!(TCPH_FLAGS(&p->tcp) & TCP_RST))
        send_tcp_reset(actx, p);
    return -1;
}

} // namespace tcp_prog

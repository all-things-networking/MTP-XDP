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
 *                 (and with it the network demux), tcp_synack,
 *                 tcp_rst, gen_syn / gen_synack (the deferred generation),
 *                 app_close, the three timer events, and proc_passive_open.
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
extern uint64_t next_tcp_cc_to_tsc;
void snapshot_cc(struct bpf_cc_snapshot *stats, uint32_t cc_idx);
void set_cc_rate(uint32_t cc_idx, uint32_t rate);
void timely_cc(struct tcp_connection *c, struct bpf_cc_snapshot *stats, uint64_t curr_tsc);
void dctcp_wnd_cc(struct tcp_connection *c, struct bpf_cc_snapshot *stats, uint64_t curr_tsc);
void dctcp_rate_cc(struct tcp_connection *c, struct bpf_cc_snapshot *stats, uint64_t curr_tsc);
void handle_retransmission(struct tcp_connection *c, struct bpf_cc_snapshot *stats, uint64_t curr_tsc);
/* Declared to match the DEFINITION at tcp.cc:554, which takes 12 arguments.
 * Note tcp.cc:67 forward-declares an 11-argument overload of the same name, with
 * no `newfd`, that is never defined -- a pre-existing inconsistency in the donor.
 * Copying that one links against nothing. */
void notify_app_tcp_event_accept(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int newfd,
                                 int32_t status, uint32_t rx_buf_size, uint32_t tx_buf_size,
                                 uint32_t local_ip, uint32_t remote_ip, uint16_t remote_port,
                                 uint32_t qid, bool backlog);

void notify_app_tcp_event_newconn(struct app_ctx_per_thread *tctx, opaque_ptr l, int fd,
                                  uint32_t remote_ip, uint16_t remote_port);
/* Still eTran's, both un-static'd so the generated demux can reach them: the
 * established-connection path and the RST reply are later events. */
void tcp_connection_pkt(struct tcp_connection *c, struct pkt_tcp *p, uint32_t qid,
                        struct tcp_opts *opts);
void send_tcp_reset(struct app_ctx *actx, const struct pkt_tcp *orig_p);
int parse_tcp_opts(struct pkt_tcp *p, struct tcp_opts *opts);
void send_tcp_control(struct tcp_connection *c, uint8_t flags, int ts_opt, uint32_t ts_echo,
                      uint16_t mss_opt);
int reg_tcp_conn_ebpf(struct tcp_connection *c, bool listen);
int alloc_port(uint16_t port);
int record_port(struct app_ctx *actx, uint16_t local_port, uint16_t remote_port);
/* eTran's per-context release hook; no longer static in tcp.cc so that a
 * generated program can install it the way the donor does. */
void tcp_connection_close(struct kref *ref);
void notify_app_tcp_status_bind(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int32_t status);
void notify_app_tcp_status_close(struct app_ctx_per_thread *tctx, opaque_ptr c, int fd, int32_t status);

namespace tcp_prog {

/* ------------------------------------------------------------------ *
 * param uint32 tcp_handshake_timeout(50);   // ms
 * param uint32 tcp_close_timeout(100);      // ms
 *
 * MTP `param` declarations (paper §5): constants the program names, which the
 * compiler emits and the target never interprets. They lived in tcp.cc as file
 * -scope consts; a program's parameters belong to the program.
 * ------------------------------------------------------------------ */
const unsigned int TCP_HANDSHAKE_TIMEOUT = 50;
const unsigned int TCP_CLOSE_TIMEOUT = 100;

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

/* The deferred-generation queue. eTran does not emit a SYN inside connect(): the
 * context is parked and the control loop drains it on its next pass. */
static inline mtp::work_queue<struct tcp_connection> &gen_queue()
{
    static mtp::work_queue<struct tcp_connection> q(tcp_handshake_list);
    return q;
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

/*
 * event tcp_synack : net_event { ... }
 *
 * Also carries the packet. The doc's processors omit `ctx.qid = ev.qid`, which
 * eTran does in tcp_connection_pkt before dispatching -- a state write, not
 * bookkeeping: qid is the NIC queue the connection's eBPF state is keyed to.
 */
struct tcp_synack : net_event {};

/* event tcp_rst : net_event { } */
struct tcp_rst : net_event {};

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

/* event app_close : app_event { }
 *
 * Carries nothing beyond the app-side handles. appout_tcp_close_t also has the
 * four-tuple and eTran ignores every field of it. */
struct app_close : app_event {};

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

static inline void sock_close(struct app_ctx_per_thread *tctx,
                              const struct appout_tcp_close_t *op,
                              app_close &ev)
{
    ev.tctx   = tctx;
    ev.handle = op->opaque_connection;
    ev.fd     = op->fd;
    /* appout_tcp_close_t also carries the four-tuple, and eTran ignores every
     * field of it: the context is found by handle like every other socket call. */
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
    return listen_ctxs().select(tcp_lid_of_pkt(p),
        [p](const std::vector<struct tcp_listener *> &all) {
            uint32_t h = (ntohl(p->ip.src) ^ ntohl(p->ip.dest) ^
                          ntohs(p->tcp.src) ^ ntohs(p->tcp.dest)) % all.size();
            return all[h];
        });
}

/* ------------------------------------------------------------------ *
 * Processors
 * ------------------------------------------------------------------ */

/* proc_passive_open is the tail that tcp_syn and app_accept share, so both of
 * their processors reach it and it is declared ahead of both. */
static inline void proc_passive_open(struct tcp_listener *lst);

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

    /* Parking the context here is what schedules gen_syn, the second processor
     * in this event's list. */
    gen_queue().push(ctx);

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
        proc_passive_open(lst);

    return 0;
}

/*
 * void proc_passive_open(tcp_syn ev, tcp_listen_ctx lst, tcp_ctx ctx)
 *
 * The suffix that tcp_syn and app_accept SHARE: either the SYN arrives while an
 * accept() is already waiting, or an accept() arrives while the SYN is queued.
 * MTP has no way to say "these two events share a tail", so it is one processor
 * that both dispatch entries call -- which is what eTran does too.
 *
 * This is where the context created by proc_accept finally acquires an identity.
 * It was made with alloc(), deliberately unpublished, because accept() ran before
 * any peer existed; the SYN supplies the remote half of the flow id and publish()
 * makes it addressable. alloc + publish, the pair, doing the thing they were
 * added for.
 *
 * Two protocol facts the code states plainly:
 *   - local_seq = 1, a CONSTANT initial sequence number. The active side uses 0.
 *     Neither is randomised.
 *   - ECN is enabled only when the SYN carried ECE *and* CWR -- the offer. The
 *     active side treats ECE alone as the acceptance (proc_synack).
 */
static inline void proc_passive_open(struct tcp_listener *lst)
{
    struct tcp_opts opts = {0};

    if (!lst->pending_conn)
        return;                       /* no accept() waiting: the SYN stays queued */

    struct tcp_connection *ctx = lst->pending_conn;

    /* The queued SYN, re-parsed now rather than when it arrived -- eTran stores
     * 256 raw bytes and decodes them here. */
    struct backlog_slot *slot = &lst->backlog.front();
    struct pkt_tcp *pkt = (struct pkt_tcp *)slot->pkt;
    int ret = parse_tcp_opts(pkt, &opts);
    lst->backlog.pop_front();

    if (ret || opts.ts == nullptr || opts.mss == nullptr) {
        fprintf(stderr, "proc_passive_open: failed to parse TCP options\n");
        /* NOTE: the donor returns here too, having already popped the slot and
         * WITHOUT clearing pending_conn -- so the SYN is dropped and the waiting
         * accept() stays waiting. Preserved; it is not this port's to fix. */
        return;
    }

    ctx->qid = slot->qid;

    /* The flow id, from the SYN. */
    const tcp_fid fid(ntohl(pkt->ip.src), ntohs(pkt->tcp.src),
                      etran_nic->_local_ip, lst->listen_port);
    tcp_ctx_init{}(ctx, fid);

    memcpy(ctx->local_mac, (uint8_t *)pkt->eth.dest.addr, ETH_ALEN);
    memcpy(ctx->remote_mac, (uint8_t *)pkt->eth.src.addr, ETH_ALEN);

    ctx->remote_seq = ntohl(pkt->tcp.seqno) + 1;
    ctx->local_seq  = 1;
    ctx->syn_ts     = ntohl(opts.ts->ts_val);

    if ((TCPH_FLAGS(&pkt->tcp) & (TCP_ECE | TCP_CWR)) == (TCP_ECE | TCP_CWR))
        ctx->flags |= ECN_ENABLE;

    /* open_ctx: the eBPF halves, with listen=true. */
    if (reg_tcp_conn_ebpf(ctx, true)) {
        fprintf(stderr, "proc_passive_open: failed to register connection\n");
        return;
    }

    /* The context becomes addressable by its id -- it was not, until now. */
    ctxs().publish(ctx);

    ctx->status    = CONN_WAIT_TX_SYNACK;
    ctx->listen_fd = lst->fd;
    lst->pending_conn = nullptr;

    /* Parks the context for gen_synack. */
    gen_queue().push(ctx);
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
        proc_passive_open(lst);
}

/*
 * void proc_synack(tcp_synack ev, tcp_ctx ctx)
 *
 * The doc splits this into proc_synack / open_ctx / notify_connect / gen_ack.
 * Two notes where it does not match the code:
 *
 *  - `open_ctx` is written as `new_ctx(tcp_fid(...))`, but the context already
 *    exists -- proc_connect made it. What happens here is that its eBPF halves
 *    (classes a and b) are created. In MTP there is ONE context, so a program
 *    cannot say "new_ctx" twice for it; the storage split is the target's.
 *  - `ctx.qid = ev.qid` is missing from the doc entirely.
 *
 * The ORDER is the unusual part and is preserved exactly: the eBPF state is
 * registered and the application is told the connection is open BEFORE the third
 * ACK is emitted. By the time that ACK leaves, connect() has already returned
 * and the fast path is live.
 */
static inline int proc_synack(const tcp_synack &ev, struct tcp_connection *ctx)
{
    struct pkt_tcp *p = ev.pkt;
    const uint32_t ecn_flags = TCPH_FLAGS(&p->tcp) & (TCP_ECE | TCP_CWR);

    /* The NIC queue this connection's eBPF state will be keyed to. */
    ctx->qid = ev.qid;

    /* timer_stop(handshake) */
    ctx->next_timeout_tsc = 0;

    bool ok = true;
    if ((TCPH_FLAGS(&p->tcp) & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)) {
        fprintf(stderr, "proc_synack: unexpected flags %x\n", TCPH_FLAGS(&p->tcp));
        ok = false;
    } else if (ev.opts->ts == nullptr) {
        fprintf(stderr, "proc_synack: no timestamp option received\n");
        ok = false;
    }

    if (ok) {
        memcpy(ctx->local_mac, (uint8_t *)p->eth.dest.addr, ETH_ALEN);
        memcpy(ctx->remote_mac, (uint8_t *)p->eth.src.addr, ETH_ALEN);
        ctx->remote_seq = ntohl(p->tcp.seqno) + 1;
        /* NOT +1: the SYN's octet is already counted in the peer's ack. */
        ctx->local_seq  = ntohl(p->tcp.ackno);
        ctx->syn_ts     = ntohl(ev.opts->ts->ts_val);

        /* ECE alone means the peer accepted ECN; ECE|CWR is the offer, not the
         * acceptance. */
        if (ecn_flags == TCP_ECE)
            ctx->flags |= ECN_ENABLE;

        /* open_ctx: the eBPF halves of this context come into existence here. */
        if (reg_tcp_conn_ebpf(ctx, false)) {
            fprintf(stderr, "proc_synack: failed to register connection\n");
            ok = false;
        }
    }

    if (!ok) {
        /* Undo every field this processor wrote, and rearm the handshake timer
         * so the SYN is retried. */
        memset(ctx->local_mac, 0, ETH_ALEN);
        memset(ctx->remote_mac, 0, ETH_ALEN);
        ctx->remote_seq = 0;
        ctx->local_seq  = 0;
        ctx->syn_ts     = 0;
        ctx->flags      = 0;
        ctx->next_timeout_tsc = get_cycles() + us_to_cycles(TCP_HANDSHAKE_TIMEOUT * 1000);
        return -1;
    }

    ctx->status = CONN_OPEN;

    /* notify(ctx, CONN_OPEN) -- status 1, the SECOND notification connect() gets. */
    notify_app_tcp_conn_open(ctx->tctx, ctx->opaque_connection, ctx->fd, 1, ctx);

    /* gen_ack: the third ACK, after the two above. */
    send_tcp_control(ctx, TCP_ACK, 1, ctx->syn_ts, 0);
    return 0;
}

/*
 * void proc_rst(tcp_rst ev, tcp_ctx ctx)
 *
 * notify_close then proc_teardown, the doc's two processors. Teardown is MTP's
 * del_ctx, which on this target is a reference drop: the release hook installed
 * by CtxInit runs when the last reference goes, and it is that hook which
 * deletes the eBPF state, frees the port, unbinds the context from the store --
 * and emits a RST in reply, because eTran answers a RST with a RST.
 */
static inline void proc_rst(const tcp_rst &ev, struct tcp_connection *ctx)
{
    (void)ev;
    /* notify(ctx, CONN_CLOSE) -- status 0 here means "the peer reset us", not
     * "success". The same notify carries -1 for a failed close. */
    notify_app_tcp_status_close(ctx->tctx, ctx->opaque_connection, ctx->fd, 0);

    /* del_ctx */
    kref_put(&ctx->ref, ctx->release);
}

/*
 * void proc_close(app_close ev, tcp_ctx ctx)
 *
 * mark_closed and gen_rst, the doc's two processors -- but neither is written
 * here, because both are inside the release hook. del_ctx drops the reference
 * and the hook does the whole teardown: unbind, delete the eBPF state, free the
 * port, and EMIT A RST. eTran has no FIN and no teardown handshake; close()
 * resets the connection.
 *
 * The notify carries status 1 here where the peer-reset path carries 0. Same
 * message, two meanings, distinguished only by which processor sent it.
 */
static inline int proc_close(const app_close &ev)
{
    opaque_ptr h = ev.handle;
    struct tcp_connection *ctx = ctxs().find_if(
        [h](const struct tcp_connection *c) { return c->opaque_connection == h; });
    if (!ctx)
        return -1;

    /* del_ctx -- mark_closed and gen_rst both happen in the release hook. */
    kref_put(&ctx->ref, ctx->release);

    /* notify(ctx, CLOSED) */
    notify_app_tcp_status_close(ev.tctx, ev.handle, ev.fd, 1);
    return 0;
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

static inline void dispatch_app_close(struct app_ctx_per_thread *tctx,
                                      const struct appout_tcp_close_t *op)
{
    app_close ev;
    sock_close(tctx, op, ev);

    if (proc_close(ev) != 0)
        notify_app_tcp_status_close(tctx, op->opaque_connection, op->fd, -1);
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
 * void gen_syn(tcp_ctx ctx)        -- the second processor of app_connect
 * void gen_synack(tcp_ctx ctx)     -- and of tcp_syn, with notify_accept
 *
 * Both are deferred: the dispatch parks the context and the control loop drains
 * it. Which of the two runs is decided by the context's status, because that is
 * what eTran's queue carries -- one list for both events.
 *
 * gen_synack sets the connection OPEN *before* the SYN-ACK is emitted and never
 * waits for the third ACK. That is eTran's behaviour, not a simplification here:
 * the passive side is live from that moment.
 */
static inline int run_deferred_gen(struct tcp_connection *ctx)
{
    switch (ctx->status) {
    case CONN_WAIT_TX_SYN:
        ctx->status = CONN_WAIT_RX_SYNACK;
        /* timer_start(handshake, TCP_HANDSHAKE_TIMEOUT) */
        ctx->next_timeout_tsc = get_cycles() + us_to_cycles(TCP_HANDSHAKE_TIMEOUT * 1000);
        /* Always ECN-capable: there is no socket option and no configuration. */
        send_tcp_control(ctx, TCP_SYN | TCP_ECE | TCP_CWR, 1, 0, TCP_MSS);
        return 1;

    case CONN_WAIT_TX_SYNACK:
        ctx->status = CONN_OPEN;
        if (ctx->flags & ECN_ENABLE)
            send_tcp_control(ctx, TCP_SYN | TCP_ACK | TCP_ECE, 1, ctx->syn_ts, TCP_MSS);
        else
            send_tcp_control(ctx, TCP_SYN | TCP_ACK, 1, ctx->syn_ts, TCP_MSS);
        /* notify_accept: the application's accept() returns from here. */
        notify_app_tcp_event_accept(ctx->tctx, ctx->opaque_connection, ctx->listen_fd,
                                    ctx->fd, 0, ctx->rx_buf_size, ctx->tx_buf_size,
                                    ctx->local_ip, ctx->remote_ip, ctx->remote_port,
                                    ctx->qid, !ctx->listener->backlog.empty());
        return 1;

    default:
        return 0;
    }
}

static inline int drain_deferred_gen(void)
{
    return gen_queue().drain(run_deferred_gen);
}

/* ------------------------------------------------------------------ *
 * The three timer events:
 *   handshake_timeout  -> { proc_syn_retry }
 *   cc_interval_timeout -> { proc_congestion, set_tx_rate }
 *   rto_timeout        -> { proc_rto, gen_retransmit }
 *
 * MTP declares timers inside a context and starts them with timer_start (§5.3).
 * THIS TARGET HAS NO TIMER. The control loop sweeps every context once per pass
 * and compares elapsed cycles, so an "expiry" is a predicate evaluated during a
 * sweep -- which is why all three events are raised from one function and why
 * their granularity is the sweep interval rather than the timeout. That is a
 * target realisation of the construct, not a protocol decision: a target with
 * real timers would run the same program without this shape.
 *
 * gen_retransmit does not emit anything here. handle_retransmission sends a
 * DUMMY PACKET carrying FLAG_TO, which makes XDP_EGRESS run and does the actual
 * retransmission there -- see dispatch_tcp_tx in the eBPF program.
 * ------------------------------------------------------------------ */
static inline void dispatch_timers(void)
{
    struct bpf_cc_snapshot stats;
    uint32_t last;
    uint64_t curr_tsc = get_cycles();

    std::list<struct tcp_connection *> to_put;

    next_tcp_cc_to_tsc = UINT64_MAX;

    /* The sweep IS the timer. See mtp::ctx_store::sweep. */
    ctxs().sweep([&](struct tcp_connection *c) {
        
        /* skip tcp_connection created for listener */
        if (unlikely(c->type == TCP_CONN_TYPE_FAKE)) {
            return;
        }

        /* --- proc_syn_retry (EVENT-TIMER-HANDSHAKE 1.3) -------------------- */
        /* handshake timeout */
        if (unlikely(c->status != CONN_OPEN))
        {
            if (c->next_timeout_tsc && c->next_timeout_tsc <= get_cycles()) {
                if (c->status == CONN_WAIT_RX_SYNACK && c->syn_attempts <= 3)
                {
                    c->status = CONN_WAIT_TX_SYN;
                    c->syn_attempts++;
                    /* add to tcp_handshake_list again */
                    tcp_handshake_list.push_back(c);
                }
                else
                {
                    if (c->syn_attempts > 3)
                    {
                        printf("Handshake timeout for connection (%p), %d\n", c, c->syn_attempts);
                        to_put.push_back(c);
                    }
                }
            }
            return;
        }

        next_tcp_cc_to_tsc = std::min(next_tcp_cc_to_tsc, c->cc_last_tsc + us_to_cycles(c->cc_last_rtt * CC_INTERVAL_RTT));

        __u32 t_us = cycles_to_us((curr_tsc - c->cc_last_tsc));
        if (t_us < c->cc_last_rtt * CC_INTERVAL_RTT)
        {
            /* we handle CC event every CC_INTERVAL_RTT RTTs */
            return;
        }

        /* --- proc_congestion + set_tx_rate (EVENT-TIMER-CC 1.3) ------------ */
        /* snapshot cc */
        snapshot_cc(&stats, c->cc_idx);

        /* calculate difference to last time */
        last = c->cc_last_drops;
        c->cc_last_drops = stats.c_drops;
        stats.c_drops -= last;

        last = c->cc_last_acks;
        c->cc_last_acks = stats.c_acks;
        stats.c_acks -= last;

        last = c->cc_last_ackb;
        c->cc_last_ackb = stats.c_ackb;
        stats.c_ackb -= last;

        last = c->cc_last_ecnb;
        c->cc_last_ecnb = stats.c_ecnb;
        stats.c_ecnb -= last;

        /* run congestion control algorithm */
        if (c->algorithm == CC_TIMELY)
        {
            timely_cc(c, &stats, curr_tsc);
            set_cc_rate(c->cc_idx, c->cc_rate);
        }
        else if (c->algorithm == CC_DCTCP_WND)
        {
            dctcp_wnd_cc(c, &stats, curr_tsc);
            set_cc_rate(c->cc_idx, c->cc_rate);
        }
        else if (c->algorithm == CC_DCTCP_RATE)
        {
            dctcp_rate_cc(c, &stats, curr_tsc);
            set_cc_rate(c->cc_idx, c->cc_rate);
        }

        /* --- proc_rto + gen_retransmit (EVENT-TIMER-RTO 1.3) --------------- */
        handle_retransmission(c, &stats, curr_tsc);

        c->cc_last_tsc = curr_tsc;
    });

    /* release references for handshake failed connections */
    while (!to_put.empty())
    {
        struct tcp_connection *c = to_put.front();
        to_put.pop_front();
        kref_put(&c->ref, c->release);   /* del_ctx */
    }

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
        /* Which event this is, is decided HERE rather than inside the
         * connection handler -- that is the event-first shape. Only the
         * SYN-ACK arm is ported so far; the rest still go to eTran's
         * state-then-flags cascade. */
        if (ctx->status == CONN_WAIT_RX_SYNACK) {
            tcp_synack ev;
            ev.pkt = p; ev.opts = &opts; ev.qid = qid;
            if (proc_synack(ev, ctx))
                fprintf(stderr, "proc_synack() failed\n");
            return 0;
        }
        if (ctx->status == CONN_OPEN && (TCPH_FLAGS(&p->tcp) & TCP_RST)) {
            tcp_rst ev;
            ev.pkt = p; ev.opts = &opts; ev.qid = qid;
            proc_rst(ev, ctx);
            return 0;
        }
        tcp_connection_pkt(ctx, p, qid, &opts);   /* remaining arms, not ported */
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

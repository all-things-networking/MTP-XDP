#pragma once
/*
 * homa_program.h -- a SECOND protocol's program, in generated shape.
 *
 * THIS FILE EXISTS TO TEST ONE CLAIM. The whole point of the split is that
 * common/mtp/mtp_target.h names no protocol, so a compiler could emit a
 * different program against it unchanged. That was argued from the target's
 * contents; this is the experiment.
 *
 * Homa is a genuinely different protocol and its bind event is a genuinely
 * different program:
 *
 *   |                | TCP                          | Homa                    |
 *   |----------------|------------------------------|-------------------------|
 *   | context        | tcp_connection, ~40 fields   | homa_socket, 5 fields   |
 *   | flow id        | a four-tuple struct          | a bare uint16_t port    |
 *   | id source      | fabricated from a pointer    | the port the app asked  |
 *   | lifecycle hook | a kref release function      | none                    |
 *   | extra step     | none                         | eBPF socket registration|
 *
 * If mtp::ctx_store instantiates over THAT without a line changing in
 * mtp_target.h, the target is protocol-independent in fact and not only by
 * inspection. Only app_bind is ported -- enough to answer the question.
 */
#include <runtime/homa.h>
#include <runtime/app_if.h>   /* app_ctx_per_thread, and appout_homa_bind_t via intf.h */
#include "nic.h"           /* eTranNIC, complete: proc_bind reads _local_ip */
#include "mtp/mtp_target.h"

extern std::unordered_map<uint16_t, struct homa_socket *> homa_sockets;
extern class eTranNIC *etran_nic;
int alloc_port(uint16_t port);
int record_port(struct app_ctx *actx, uint16_t local_port, uint16_t remote_port);
int unrecord_port(struct app_ctx *actx, uint16_t port);
int free_port(uint16_t port);
void notify_app_homa_status_bind(struct app_ctx_per_thread *tctx, opaque_ptr s, int fd, int32_t status);
/* Homa's own eBPF registration. Protocol-specific, so it is the program that
 * calls it, exactly as TCP's reg_tcp_conn_ebpf is. */
int reg_homa_socket_ebpf(struct app_ctx_per_thread *tctx, uint16_t port);
void unreg_homa_socket_ebpf(uint16_t port);
void notify_app_homa_status_close(struct app_ctx_per_thread *tctx, opaque_ptr s, int fd, int32_t status);

namespace homa_prog {

/* ------------------------------------------------------------------ *
 * flow_id homa_sid : (uint16)
 *
 * A SCALAR. TCP's id is a four-tuple struct with a hand-written hash; Homa's is
 * the local port and nothing else. The target is told the type and asks no
 * further questions -- which is the property under test.
 * ------------------------------------------------------------------ */
using homa_sid = uint16_t;

struct homa_key_of {
    homa_sid operator()(const struct homa_socket *s) const { return s->local_port; }
};
struct homa_ctx_init {
    void operator()(struct homa_socket *s, const homa_sid &id) const {
        s->local_port = id;
        /* No release hook: homa_socket has no kref and no destructor of its own.
         * The TCP program installs one here; this one has nothing to install,
         * and the target does not care either way. */
    }
};

using homa_ctx_store = mtp::ctx_store<homa_sid, struct homa_socket,
                                      std::hash<homa_sid>, std::equal_to<homa_sid>,
                                      homa_key_of, homa_ctx_init>;

static inline homa_ctx_store &ctxs()
{
    /* Homa's socket table has no lock of its own in the donor -- everything runs
     * on T1. The store still wants one, so the program supplies it. */
    static std::mutex lock;
    static homa_ctx_store s(homa_sockets, lock);
    return s;
}

/* ------------------------------------------------------------------ *
 * event app_bind : app_event { uint32 local_ip; uint16 local_port; }
 * ------------------------------------------------------------------ */
struct app_event {
    struct app_ctx_per_thread *tctx;
    opaque_ptr handle;
    int fd;
};

struct app_bind : app_event {
    uint32_t local_ip;
    uint16_t local_port;
};

/* event app_close : app_event { } */
struct app_close : app_event {};

static inline void sock_bind(struct app_ctx_per_thread *tctx,
                             const struct appout_homa_bind_t *op,
                             app_bind &ev, homa_sid &sid)
{
    ev.tctx       = tctx;
    ev.handle     = op->opaque_socket;
    ev.fd         = op->fd;
    ev.local_ip   = op->local_ip;
    ev.local_port = op->local_port;
    /* The id IS the port -- unlike TCP, where a bound socket has no real id and
     * one is fabricated from the handle. */
    sid = op->local_port;
}

/*
 * void proc_bind(app_bind ev, homa_ctx ctx)
 *
 * As in the TCP program, the allocation moves after the guards, which is safe
 * for the same reason: nothing can observe an unregistered context. Homa adds a
 * step TCP does not have -- eBPF socket registration -- and it can fail after
 * the port is taken, so the rollback is the program's business, not the
 * target's.
 */
static inline int proc_bind(const app_bind &ev, const homa_sid &sid)
{
    opaque_ptr h = ev.handle;
    if (ctxs().find_if([h](const struct homa_socket *s) { return s->opaque_socket == h; }))
        return -EADDRINUSE;

    if (alloc_port(ev.local_port) != 0)
        return -EADDRINUSE;

    record_port(ev.tctx->actx, ev.local_port, 0);

    if (reg_homa_socket_ebpf(ev.tctx, ev.local_port)) {
        unrecord_port(ev.tctx->actx, ev.local_port);
        free_port(ev.local_port);
        return -1;
    }

    struct homa_socket *ctx = ctxs().new_ctx(sid, [&](struct homa_socket *s) {
        s->tctx          = ev.tctx;
        s->opaque_socket = ev.handle;
        s->fd            = ev.fd;
        /* Like TCP's bind, the address the application asked for is discarded
         * and the node's single configured one used instead. */
        s->local_ip      = etran_nic->_local_ip;
    });
    if (!ctx)
        return -ENOMEM;
    (void)ev.local_ip;

    notify_app_homa_status_bind(ev.tctx, ctx->opaque_socket, ctx->fd, 0);
    return 0;
}

/*
 * void proc_close(app_close ev, homa_ctx ctx)
 *
 * The other end of the lifecycle, and it exercises the part of the store
 * app_bind did not: unbind. Homa has no kref and no release hook -- where TCP's
 * close drops a reference and lets the hook do the teardown, this one unbinds
 * and frees directly. The store is the same store; only the program differs.
 */
static inline int proc_close(const app_close &ev)
{
    opaque_ptr h = ev.handle;
    struct homa_socket *ctx = ctxs().find_if(
        [h](const struct homa_socket *s) { return s->opaque_socket == h; });
    if (!ctx)
        return -ENOENT;

    /* del_ctx: unbind, then the protocol's own teardown. */
    ctxs().unbind(ctx);
    unreg_homa_socket_ebpf(ctx->local_port);
    unrecord_port(ev.tctx->actx, ctx->local_port);
    free_port(ctx->local_port);

    notify_app_homa_status_close(ev.tctx, ev.handle, ctx->fd, 0);
    delete ctx;
    return 0;
}

static inline void dispatch_app_close(struct app_ctx_per_thread *tctx, opaque_ptr handle)
{
    app_close ev;
    ev.tctx = tctx; ev.handle = handle; ev.fd = -1;
    proc_close(ev);
}

static inline void dispatch_app_bind(struct app_ctx_per_thread *tctx,
                                     const struct appout_homa_bind_t *op)
{
    app_bind ev;
    homa_sid sid = 0;
    sock_bind(tctx, op, ev, sid);

    if (proc_bind(ev, sid) != 0)
        notify_app_homa_status_bind(tctx, op->opaque_socket, op->fd, -1);
}

} // namespace homa_prog

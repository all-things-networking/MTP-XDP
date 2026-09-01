/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#include "prog.h"
#include "prog_proc_control.h"

/* ---- dispatch [control]--------------------------------- */
static inline void mtp_dispatch_app_bind_control(struct app_bind *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_bind(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_app_listen_control(struct app_listen *ev, struct tcp_ctx *c_tcp_ctx, struct tcp_listen_ctx *c_tcp_listen_ctx)
{
    proc_listen(ev, c_tcp_ctx, c_tcp_listen_ctx);
}

static inline void mtp_dispatch_app_accept_control(struct app_accept *ev, struct tcp_listen_ctx *c_tcp_listen_ctx, struct tcp_ctx *c_tcp_ctx)
{
    proc_accept(ev, c_tcp_listen_ctx);
    proc_passive_open(ev, c_tcp_listen_ctx, c_tcp_ctx);
    gen_synack(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_app_connect_control(struct app_connect *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_connect(ev, c_tcp_ctx);
    gen_syn(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_app_close_control(struct app_close *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_close(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_tcp_syn_control(struct tcp_syn *ev, struct tcp_listen_ctx *c_tcp_listen_ctx, struct tcp_ctx *c_tcp_ctx)
{
    proc_syn_queue(ev, c_tcp_listen_ctx);
    proc_passive_open(ev, c_tcp_listen_ctx, c_tcp_ctx);
    gen_synack(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_tcp_synack_control(struct tcp_synack *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_synack(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_tcp_rst_control(struct tcp_rst *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_rst(ev, c_tcp_ctx);
}

static inline void mtp_dispatch_tcp_fin_control(struct tcp_fin *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_fin(ev, c_tcp_ctx);
}

/* ---- start-up------------------------------------------- */
static inline void mtp_prog_init(void)
{
    mtp_ctx_register(MTP_CTX_tcp_ctx, sizeof(struct tcp_ctx), sizeof(struct tcp_fid));
    mtp_ctx_register(MTP_CTX_tcp_listen_ctx, sizeof(struct tcp_listen_ctx), sizeof(struct tcp_lid));
}


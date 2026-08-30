/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#include "prog.h"

/* ---- dispatch------------------------------------------- */
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

static inline void mtp_dispatch_app_send_app(struct app_send *ev, struct tcp_ctx *c_tcp_ctx)
{
    record_data(ev, &c_tcp_ctx->app);
}

static inline void mtp_dispatch_app_recv_app(struct app_recv *ev, struct tcp_ctx *c_tcp_ctx)
{
    proc_drain(ev, &c_tcp_ctx->app);
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

static inline void mtp_dispatch_tcp_ack_ebpf(struct tcp_ack *ev, struct tcp_ctx *c_tcp_ctx, struct tcp_scratch *s)
{
    proc_ack(ev, &c_tcp_ctx->ebpf, &c_tcp_ctx->cc_shared, s);
    proc_fast_retransmit(ev, &c_tcp_ctx->ebpf, &c_tcp_ctx->cc_shared, s);
    proc_window(ev, &c_tcp_ctx->ebpf, s);
    proc_rtt(ev, &c_tcp_ctx->ebpf, &c_tcp_ctx->cc_shared, s);
}

static inline void mtp_dispatch_tcp_data_ebpf(struct tcp_data *ev, struct tcp_ctx *c_tcp_ctx, struct tcp_scratch *s)
{
    proc_seq(ev, &c_tcp_ctx->ebpf, s);
    proc_ooo(ev, &c_tcp_ctx->ebpf, s);
    proc_recv(ev, &c_tcp_ctx->ebpf, s);
}

/* ---- start-up------------------------------------------- */
static inline void mtp_prog_init(void)
{
    mtp_ctx_register(MTP_CTX_tcp_ctx, sizeof(struct tcp_ctx), sizeof(struct tcp_fid));
    mtp_ctx_register(MTP_CTX_tcp_listen_ctx, sizeof(struct tcp_listen_ctx), sizeof(struct tcp_lid));
}


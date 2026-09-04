/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-bisect.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#include "prog.h"
#include "prog_proc_control.h"

/* ---- dispatch [control]--------------------------------- */
static inline void mtp_dispatch_app_bind_control(struct app_bind *ev, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control)
{
    proc_bind(ev, c_tcp_ctx_common, c_tcp_ctx_control);
}

static inline void mtp_dispatch_app_listen_control(struct app_listen *ev, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_listen_ctx_common *c_tcp_listen_ctx_common)
{
    proc_listen(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_listen_ctx_common);
}

static inline void mtp_dispatch_app_accept_control(struct app_accept *ev, struct tcp_listen_ctx_common *c_tcp_listen_ctx_common, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_accept(ev, c_tcp_listen_ctx_common);
    proc_passive_open(ev, c_tcp_listen_ctx_common, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
    gen_synack(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

static inline void mtp_dispatch_app_connect_control(struct app_connect *ev, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_connect(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
    gen_syn(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

static inline void mtp_dispatch_app_close_control(struct app_close *ev, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_close(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

static inline void mtp_dispatch_tcp_syn_control(struct tcp_syn *ev, struct tcp_listen_ctx_common *c_tcp_listen_ctx_common, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_syn_queue(ev, c_tcp_listen_ctx_common);
    proc_passive_open(ev, c_tcp_listen_ctx_common, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
    gen_synack(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

static inline void mtp_dispatch_tcp_synack_control(struct tcp_synack *ev, struct tcp_ctx_common *c_tcp_ctx_common, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_synack(ev, c_tcp_ctx_common, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

static inline void mtp_dispatch_tcp_rst_control(struct tcp_rst *ev, struct tcp_ctx_common *c_tcp_ctx_common)
{
    proc_rst(ev, c_tcp_ctx_common);
}

static inline void mtp_dispatch_tcp_fin_control(struct tcp_fin *ev, struct tcp_ctx_control *c_tcp_ctx_control, struct tcp_ctx_ebpf *c_tcp_ctx_ebpf)
{
    proc_fin(ev, c_tcp_ctx_control, c_tcp_ctx_ebpf);
}

/* ---- start-up------------------------------------------- */
static inline void mtp_prog_init(void)
{
    mtp_ctx_register(MTP_CTX_tcp_ctx, sizeof(struct tcp_ctx), sizeof(struct tcp_fid));
    mtp_ctx_register(MTP_CTX_tcp_listen_ctx, sizeof(struct tcp_listen_ctx), sizeof(struct tcp_lid));
}


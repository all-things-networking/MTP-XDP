/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog.h"
#include "prog_proc_app.h"

/* ---- dispatch [app]------------------------------------- */
static inline void mtp_dispatch_app_send_app(struct app_send *ev, struct tcp_ctx_app *c_tcp_ctx_app)
{
    record_data(ev, c_tcp_ctx_app);
}

static inline void mtp_dispatch_app_recv_app(struct app_recv *ev, struct tcp_ctx_app *c_tcp_ctx_app)
{
    proc_drain(ev, c_tcp_ctx_app);
}


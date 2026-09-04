/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-newconv.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog.h"

/* ---- prototypes----------------------------------------- */
static inline void record_data(struct app_send *ev, struct tcp_ctx_app *ctx_app);
static inline void proc_drain(struct app_recv *ev, struct tcp_ctx_app *ctx_app);

/* ---- record_data  [app]--------------------------------- */
static inline void record_data(struct app_send *ev, struct tcp_ctx_app *ctx_app)
{
    if (ctx_app->txb_allocated < ev->len) {
        return;
    }
    ctx_app->txb_allocated = ctx_app->txb_allocated - ev->len;
    ctx_app->txb_sent = ctx_app->txb_sent + ev->len;
}

/* ---- proc_drain  [app]---------------------------------- */
static inline void proc_drain(struct app_recv *ev, struct tcp_ctx_app *ctx_app)
{
    if (ctx_app->rxb_used < ev->len) {
        return;
    }
    ctx_app->rxb_used = ctx_app->rxb_used - ev->len;
    ctx_app->rxb_bump = ctx_app->rxb_bump + ev->len;
    ctx_app->rxb_head = ctx_app->rxb_head + ev->len;
    ctx_app->force_rx_bump = false;
}


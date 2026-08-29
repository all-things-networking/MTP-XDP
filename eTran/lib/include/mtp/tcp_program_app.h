#pragma once
/*
 * tcp_program_app.h -- the TCP program's application-side half, in generated
 * shape. The third program file, for the third kind of site.
 *
 *   micro_kernel/mtp/tcp_program.h        T1, the control path
 *   micro_kernel/eBPF/tcp/mtp/tcp_program_bpf.h   K1/K2, the eBPF hooks
 *   lib/include/mtp/tcp_program_app.h     T3, the application's own thread
 *
 * All three are compiled against a target that names no protocol -- the first
 * and third against common/mtp/mtp_target.h, the second against its eBPF
 * equivalent. That the C++ target serves two sites unchanged is the evidence
 * that the split is real rather than an arrangement that happens to suit one
 * of them.
 *
 * Ported so far:  app_recv's proc_drain and the enqueue half of send_wnd_update,
 *                 app_send's record_data.
 */

#include <algorithm>
#include <tcp_if.h>
#include <app_if.h>
#include "mtp/mtp_target.h"

namespace tcp_prog_app {

/* ------------------------------------------------------------------ *
 * The context, class (d): eTrantcp_connection.
 *
 * The SAME tcp_ctx the control path and the eBPF sites hold parts of -- one
 * context in the program, four structures in the target. This site's part lives
 * in the application's own address space and the micro kernel never touches it.
 * ------------------------------------------------------------------ */
using tcp_ctx_app = struct eTrantcp_connection;

/*
 * The deferred window-update queue.
 *
 * send_wnd_update does not emit anything where it is decided. The context is
 * parked and a later pass (tcp_ebpf_sync) turns it into a payload-less frame
 * carrying FLAG_SYNC, which exists only to make XDP_EGRESS run -- the paper's
 * "fake packets with the event metadata" again.
 *
 * This is the SECOND independent use of work_queue, and it arrived for the same
 * reason as the first: a processor that must generate a packet cannot do it
 * where it runs. Two sites needing the same primitive unchanged is what makes it
 * a target primitive rather than a convenience.
 */
static inline mtp::work_queue<tcp_ctx_app> wnd_update_queue(struct app_ctx_per_thread *tctx)
{
    /* Per thread, because the frame must go out on the thread that owns the
     * AF_XDP ring -- a placement fact, invisible to the program. The queue is a
     * view over that thread's list, so constructing one is free. */
    return mtp::work_queue<tcp_ctx_app>(tctx->rx_bump_pending_conns);
}

/* ------------------------------------------------------------------ *
 * app_recv -> { proc_drain, send_wnd_update }
 * ------------------------------------------------------------------ */

/*
 * void proc_drain(app_recv ev, tcp_ctx ctx)
 *
 * The application has consumed `len` bytes. Advance the receive ring and record
 * how much window that frees.
 */
static inline int proc_drain(struct app_ctx_per_thread *tctx, tcp_ctx_app *ctx, size_t len)
{
    if (ctx->rxb_used < len) {
        fprintf(stderr, "proc_drain: rxb_used < len\n");
        return -EINVAL;
    }

    ctx->rxb_used -= len;
    ctx->rxb_bump += len;

    ctx->rxb_head += len;
    if (ctx->rxb_head > ctx->rx_buf_size)
        ctx->rxb_head -= ctx->rx_buf_size;

    /* --- send_wnd_update: only the decision, not the packet --------------- */
    /*
     * Worth a packet only once enough has been freed. The three-way min is
     * eTran's: a quarter of the buffer, what a 16-bit window can advertise once
     * scaled, and a 32 KB cap.
     */
    const unsigned int threshold =
        std::min(std::min(ctx->rx_buf_size >> 2,
                          ((unsigned int)0xFFFF) << TCP_WND_SCALE),
                 (unsigned int)32768);

    if (unlikely((ctx->rxb_bump > threshold || ctx->force_rx_bump) &&
                 !ctx->in_rx_bump_pending)) {
        wnd_update_queue(tctx).push(ctx);
        ctx->in_rx_bump_pending = true;
    }

    ctx->force_rx_bump = false;
    return 0;
}

/* ------------------------------------------------------------------ *
 * app_send -> { record_data, gen_seg }
 * ------------------------------------------------------------------ */

/*
 * void record_data(app_send ev, tcp_ctx ctx)
 *
 * The send-side ring bookkeeping: bytes the application reserved become bytes in
 * flight. gen_seg -- cutting them into MSS-sized AF_XDP frames -- is the target's
 * job and stays in tcp_flow_tx_segmentation_zc, for the same reason
 * send_wnd_update's frame does: the program says what happens, and how a frame
 * reaches the wire is the target's business.
 *
 * NOTE the guard order. eTran validates BEFORE segmenting and updates the ring
 * AFTER, so a failed guard leaves the ring untouched -- but a segmentation that
 * partially completes does not, because it cannot report that. Preserved.
 */
static inline int record_data(tcp_ctx_app *ctx, size_t len)
{
    if (unlikely(ctx->status != CONN_OPEN)) {
        fprintf(stderr, "record_data: conn->status != CONN_OPEN\n");
        return -EINVAL;
    }
    if (unlikely(ctx->txb_allocated < len)) {
        fprintf(stderr, "record_data: (%p), txb_allocated(%u) < len(%lu)\n",
                ctx, ctx->txb_allocated, len);
        return -EINVAL;
    }
    return 0;
}

/* The half that runs after gen_seg: what was allocated is now sent. */
static inline void record_data_sent(tcp_ctx_app *ctx, size_t len)
{
    ctx->txb_allocated -= len;
    ctx->txb_sent      += len;
}

} // namespace tcp_prog_app

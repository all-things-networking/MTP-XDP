/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog.h"
#include "prog_proc_bpf.h"

/* ---- dispatch [ebpf]------------------------------------ */
static inline void mtp_dispatch_app_send_ebpf(struct app_send *ev, struct bpf_tcp_conn *c_tcp_ctx_ebpf, struct bpf_cc *c_tcp_ctx_cc_shared, struct gen_tcp_tx_scratch *s)
{
    gen_seg(ev, c_tcp_ctx_ebpf, c_tcp_ctx_cc_shared, s);
}

static inline void mtp_dispatch_app_recv_ebpf(struct app_recv *ev, struct bpf_tcp_conn *c_tcp_ctx_ebpf, struct gen_tcp_tx_scratch *s)
{
    send_wnd_update(ev, c_tcp_ctx_ebpf, s);
}

static inline void mtp_dispatch_tcp_ack_ebpf(struct tcp_ack *ev, struct bpf_tcp_conn *c_tcp_ctx_ebpf, struct bpf_cc *c_tcp_ctx_cc_shared, struct gen_tcp_scratch *s)
{
    proc_ack(ev, c_tcp_ctx_ebpf, c_tcp_ctx_cc_shared, s);
    proc_fast_retransmit(ev, c_tcp_ctx_ebpf, c_tcp_ctx_cc_shared, s);
    proc_window(ev, c_tcp_ctx_ebpf, s);
    proc_rtt(ev, c_tcp_ctx_ebpf, c_tcp_ctx_cc_shared, s);
}

static inline void mtp_dispatch_tcp_data_ebpf(struct tcp_data *ev, struct bpf_tcp_conn *c_tcp_ctx_ebpf, struct gen_tcp_scratch *s)
{
    proc_seq(ev, c_tcp_ctx_ebpf, s);
    proc_ooo(ev, c_tcp_ctx_ebpf, s);
    proc_recv(ev, c_tcp_ctx_ebpf, s);
}

static inline void mtp_dispatch_rto_timeout_ebpf(struct rto_timeout *ev, struct bpf_tcp_conn *c_tcp_ctx_ebpf, struct gen_tcp_tx_scratch *s)
{
    gen_retransmit(ev, c_tcp_ctx_ebpf, s);
}


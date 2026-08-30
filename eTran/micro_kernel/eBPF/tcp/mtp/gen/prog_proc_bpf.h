/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog.h"

/* ---- prototypes----------------------------------------- */
static __always_inline void proc_ack(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s);
static __always_inline void proc_fast_retransmit(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s);
static __always_inline void proc_window(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s);
static __always_inline void proc_rtt(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s);
static __always_inline void proc_seq(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s);
static __always_inline void proc_ooo(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s);
static __always_inline void proc_recv(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s);
static __always_inline void gen_retransmit(struct rto_timeout *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_tx_scratch *s);
static __always_inline void send_wnd_update(struct app_recv *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_tx_scratch *s);
static __always_inline void gen_seg(struct app_send *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_tx_scratch *s);

/* ---- proc_ack  [ebpf]----------------------------------- */
static __always_inline void proc_ack(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s)
{
    s->ack_ok = false;
    s->tx_bump = 0;
    s->trigger_ack = ev->payload_len > 0;
    ctx_cc_shared->cnt_rx_acks = ctx_cc_shared->cnt_rx_acks + 1;
    __u32 first = ctx_ebpf->tx_next_seq - ctx_ebpf->tx_sent;
    if (!((ev->ack) >= (first) && (ev->ack) <= (ctx_ebpf->tx_next_seq + ctx_ebpf->tx_pending))) {
        s->trigger_ack = false;
        return;
    }
    s->tx_bump = ev->ack - first;
    if (s->tx_bump > ctx_ebpf->tx_sent) {
        s->tx_bump = 0;
        s->trigger_ack = false;
        return;
    }
    ctx_cc_shared->cnt_rx_ack_bytes = ctx_cc_shared->cnt_rx_ack_bytes + s->tx_bump;
    if (ev->ecn_ce) {
        ctx_cc_shared->cnt_rx_ecn_bytes = ctx_cc_shared->cnt_rx_ecn_bytes + s->tx_bump;
    }
    ctx_ebpf->tx_sent = ctx_ebpf->tx_sent - s->tx_bump;
    ctx_cc_shared->txp = ctx_ebpf->tx_sent > 0;
    if (s->tx_bump > 0) {
        ctx_ebpf->rx_dupack_cnt = 0;
    }
    s->ack_ok = true;
}

/* ---- proc_fast_retransmit  [ebpf]----------------------- */
static __always_inline void proc_fast_retransmit(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s)
{
    if (!s->ack_ok) {
        return;
    }
    if (s->tx_bump > 0) {
        return;
    }
    if (ctx_ebpf->tx_sent == 0) {
        return;
    }
    if (ev->payload_len != 0) {
        return;
    }
    if (ctx_ebpf->rx_remote_avail != ev->window) {
        return;
    }
    ctx_ebpf->rx_dupack_cnt = ctx_ebpf->rx_dupack_cnt + 1;
    if (ctx_ebpf->rx_dupack_cnt != PARITY_DUP_ACK_THRESH) {
        return;
    }
    s->go_back_pos = ctx_ebpf->tx_sent;
    ctx_ebpf->rx_dupack_cnt = 0;
    ctx_ebpf->tx_next_seq = ctx_ebpf->tx_next_seq - ctx_ebpf->tx_sent;
    ctx_ebpf->rx_remote_avail = ctx_ebpf->rx_remote_avail + ctx_ebpf->tx_sent;
    ctx_ebpf->tx_pending = 0;
    ctx_ebpf->tx_sent = 0;
    ctx_cc_shared->txp = false;
    if (ctx_cc_shared->cnt_tx_drops == 0) {
        ctx_cc_shared->rate = ctx_cc_shared->rate >> 1;
    }
    ctx_cc_shared->cnt_tx_drops = ctx_cc_shared->cnt_tx_drops + 1;
}

/* ---- proc_window  [ebpf]-------------------------------- */
static __always_inline void proc_window(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s)
{
    if (!s->ack_ok) {
        return;
    }
    if (s->tx_bump > 0 || ctx_ebpf->rx_remote_avail < ((__u32)(ev->window) << TCP_WND_SCALE)) {
        ctx_ebpf->rx_remote_avail = (__u32)(ev->window) << TCP_WND_SCALE;
    }
}

/* ---- proc_rtt  [ebpf]----------------------------------- */
static __always_inline void proc_rtt(struct tcp_ack *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_scratch *s)
{
    if (!s->ack_ok) {
        return;
    }
    if (ev->payload_len > 0 && ctx_ebpf->tx_next_ts == 0) {
        ctx_ebpf->tx_next_ts = ev->ts_val;
    }
    if (ev->ts_ecr == 0 || s->tx_bump == 0) {
        return;
    }
    __u32 rtt = (s->now - ev->ts_ecr) / 1000;
    rtt = rtt - (s->tx_bump * 1000000) / LINK_BANDWIDTH;
    if (rtt >= TCP_MAX_RTT) {
        return;
    }
    if (ctx_cc_shared->rtt_est > 0) {
        ctx_cc_shared->rtt_est = (ctx_cc_shared->rtt_est * 7 + rtt) / 8;
    } else {
        ctx_cc_shared->rtt_est = rtt;
    }
}

/* ---- proc_seq  [ebpf]----------------------------------- */
static __always_inline void proc_seq(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s)
{
    if (!s->ack_ok) {
        return;
    }
    __u32 exp_first = ctx_ebpf->rx_next_seq;
    __u32 exp_last = ctx_ebpf->rx_next_seq + ctx_ebpf->rx_avail;
    __u32 pkt_first = ev->seq;
    __u32 pkt_last = ev->seq + ev->payload_len;
    __u32 exp_width = exp_last - exp_first;
    __u32 pkt_width = pkt_last - pkt_first;
    s->seq = ev->seq;
    s->payload_len = ev->payload_len;
    bool first_in = (pkt_first - exp_first) < exp_width;
    bool last_in = (pkt_last - exp_first - 1) < exp_width;
    bool valid = first_in || last_in || (exp_first - pkt_first) < pkt_width || (exp_last - pkt_first - 1) < pkt_width;
    if (!valid) {
        s->trigger_ack = false;
        s->seg_ok = false;
        s->payload_len = 0;
        return;
    }
    if (first_in) {
        s->trim_start = 0;
    } else {
        s->trim_start = exp_first - pkt_first;
    }
    if (last_in) {
        s->trim_end = 0;
    } else {
        s->trim_end = pkt_last - exp_last;
    }
    s->payload_off = s->payload_off + s->trim_start;
    if (ev->payload_len >= s->trim_start + s->trim_end) {
        s->payload_len = ev->payload_len - s->trim_start - s->trim_end;
    }
    s->seq = ev->seq + s->trim_start;
    s->seg_ok = s->seq == ctx_ebpf->rx_next_seq;
}

/* ---- proc_ooo  [ebpf]----------------------------------- */
static __always_inline void proc_ooo(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s)
{
    if (s->seg_ok) {
        return;
    }
    if (s->payload_len == 0) {
        return;
    }
    s->ooo_seg = true;
    if (ctx_ebpf->rx_ooo_len == 0) {
        ctx_ebpf->rx_ooo_start = s->seq;
        ctx_ebpf->rx_ooo_len = s->payload_len;
    } else {
        if (s->seq + s->payload_len == ctx_ebpf->rx_ooo_start) {
            ctx_ebpf->rx_ooo_start = s->seq;
            ctx_ebpf->rx_ooo_len = ctx_ebpf->rx_ooo_len + s->payload_len;
        } else {
            if (ctx_ebpf->rx_ooo_start + ctx_ebpf->rx_ooo_len == s->seq) {
                ctx_ebpf->rx_ooo_len = ctx_ebpf->rx_ooo_len + s->payload_len;
            } else {
                s->payload_len = 0;
                s->drop = true;
            }
        }
    }
}

/* ---- proc_recv  [ebpf]---------------------------------- */
static __always_inline void proc_recv(struct tcp_data *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_scratch *s)
{
    if (!s->seg_ok) {
        return;
    }
    if (s->payload_len == 0) {
        return;
    }
    s->rx_bump = s->payload_len;
    ctx_ebpf->rx_avail = ctx_ebpf->rx_avail - s->payload_len;
    ctx_ebpf->rx_next_pos = ctx_ebpf->rx_next_pos + s->payload_len;
    if (ctx_ebpf->rx_next_pos >= ctx_ebpf->rx_buf_size) {
        ctx_ebpf->rx_next_pos = ctx_ebpf->rx_next_pos - ctx_ebpf->rx_buf_size;
    }
    ctx_ebpf->rx_next_seq = ctx_ebpf->rx_next_seq + s->payload_len;
    if (ctx_ebpf->rx_ooo_len > 0) {
        __u32 exp_first = ctx_ebpf->rx_next_seq;
        __u32 exp_last = ctx_ebpf->rx_next_seq + ctx_ebpf->rx_avail;
        __u32 ooo_first = ctx_ebpf->rx_ooo_start;
        __u32 ooo_last = ctx_ebpf->rx_ooo_start + ctx_ebpf->rx_ooo_len;
        __u32 exp_width = exp_last - exp_first;
        __u32 ooo_width = ooo_last - ooo_first;
        bool first_in = (ooo_first - exp_first) < exp_width;
        bool last_in = (ooo_last - exp_first - 1) < exp_width;
        bool valid = first_in || last_in || (exp_first - ooo_first) < ooo_width || (exp_last - ooo_first - 1) < ooo_width;
        if (!valid) {
            ctx_ebpf->rx_ooo_len = 0;
            s->trigger_ack = false;
            s->clear_ooo = true;
        } else {
            if (first_in) {
                s->trim_start = 0;
            } else {
                s->trim_start = exp_first - ooo_first;
            }
            if (last_in) {
                s->trim_end = 0;
            } else {
                s->trim_end = ooo_last - exp_last;
            }
            ctx_ebpf->rx_ooo_start = ctx_ebpf->rx_ooo_start + s->trim_start;
            ctx_ebpf->rx_ooo_len = ctx_ebpf->rx_ooo_len - s->trim_start - s->trim_end;
            if (ctx_ebpf->rx_ooo_len > 0 && ctx_ebpf->rx_ooo_start == ctx_ebpf->rx_next_seq) {
                s->rx_bump = s->rx_bump + ctx_ebpf->rx_ooo_len;
                ctx_ebpf->rx_avail = ctx_ebpf->rx_avail - ctx_ebpf->rx_ooo_len;
                ctx_ebpf->rx_next_pos = ctx_ebpf->rx_next_pos + ctx_ebpf->rx_ooo_len;
                if (ctx_ebpf->rx_next_pos >= ctx_ebpf->rx_buf_size) {
                    ctx_ebpf->rx_next_pos = ctx_ebpf->rx_next_pos - ctx_ebpf->rx_buf_size;
                }
                ctx_ebpf->rx_next_seq = ctx_ebpf->rx_next_seq + ctx_ebpf->rx_ooo_len;
                ctx_ebpf->rx_ooo_len = 0;
                s->ooo_fin = true;
            }
        }
    }
}

/* ---- gen_retransmit  [ebpf]----------------------------- */
static __always_inline void gen_retransmit(struct rto_timeout *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_tx_scratch *s)
{
    s->tx_ok = ctx_ebpf->tx_sent > 0;
}

/* ---- send_wnd_update  [ebpf]---------------------------- */
static __always_inline void send_wnd_update(struct app_recv *ev, struct bpf_tcp_conn *ctx_ebpf, struct tcp_tx_scratch *s)
{
    if (s->rx_bump == 0) {
        return;
    }
    if (ctx_ebpf->tx_pending == 0) {
        s->wnd_upd = true;
    }
    ctx_ebpf->rx_avail = ctx_ebpf->rx_avail + s->rx_bump;
}

/* ---- gen_seg  [ebpf]------------------------------------ */
static __always_inline void gen_seg(struct app_send *ev, struct bpf_tcp_conn *ctx_ebpf, struct bpf_cc *ctx_cc_shared, struct tcp_tx_scratch *s)
{
    s->tx_ok = false;
    if (s->tx_pos != ctx_ebpf->tx_next_pos) {
        return;
    }
    if (s->tx_pending > 0) {
        ctx_ebpf->tx_pending = ctx_ebpf->tx_pending + s->tx_pending;
    }
    ctx_ebpf->tx_next_seq = ctx_ebpf->tx_next_seq + s->payload_len;
    ctx_ebpf->tx_next_pos = ctx_ebpf->tx_next_pos + s->payload_len;
    if (ctx_ebpf->tx_next_pos >= ctx_ebpf->tx_buf_size) {
        ctx_ebpf->tx_next_pos = ctx_ebpf->tx_next_pos - ctx_ebpf->tx_buf_size;
    }
    ctx_ebpf->tx_sent = ctx_ebpf->tx_sent + s->payload_len;
    ctx_cc_shared->txp = ctx_ebpf->tx_sent > 0;
    ctx_ebpf->tx_pending = ctx_ebpf->tx_pending - s->payload_len;
    s->tx_ok = true;
}


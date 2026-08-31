/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog.h"

/* ---- prototypes----------------------------------------- */
static inline struct mtp_ev_list sock_bind(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_listen(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_accept(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_connect(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_send(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_recv(struct mtp_sock_op op);
static inline struct mtp_ev_list sock_close(struct mtp_sock_op op);
static inline struct mtp_ev_list parse_tcp(pkt_t p, struct ipv4 h);
static inline void proc_bind(struct app_bind *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control);
static inline void proc_listen(struct app_listen *ev, struct tcp_ctx_common *bound_common, struct tcp_ctx_control *bound_control, struct tcp_listen_ctx_common *lst_common);
static inline void proc_accept(struct app_accept *ev, struct tcp_listen_ctx_common *lst_common);
static inline void proc_connect(struct app_connect *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void gen_syn(struct app_connect *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void proc_passive_open(void * ev, struct tcp_listen_ctx_common *lst_common, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void proc_syn_queue(struct tcp_syn *ev, struct tcp_listen_ctx_common *lst_common);
static inline void gen_synack(void * ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void proc_synack(struct tcp_synack *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void proc_rst(struct tcp_rst *ev, struct tcp_ctx_common *ctx_common);
static inline void proc_fin(struct tcp_fin *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);
static inline void proc_close(struct app_close *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf);

/* ---- sock_bind  [control]------------------------------- */
static inline struct mtp_ev_list sock_bind(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_bind ev;
    ev.local_ip = op.local.ip;
    ev.local_port = op.local.port;
    ev.reuseport = op.reuseport;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid((__u32)(op.handle >> 16), (__u16)(op.handle), (__u32)(op.handle >> 32), op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_listen  [control]----------------------------- */
static inline struct mtp_ev_list sock_listen(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_listen ev;
    ev.pending_cap = op.len;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid((__u32)(op.handle >> 16), (__u16)(op.handle), (__u32)(op.handle >> 32), op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_accept  [control]----------------------------- */
static inline struct mtp_ev_list sock_accept(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_accept ev;
    ev.local_port = op.local.port;
    mtp_ev_key(&ev, MTP_CTX_tcp_listen_ctx, &tcp_lid(op.local.ip, op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_connect  [control]---------------------------- */
static inline struct mtp_ev_list sock_connect(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_connect ev;
    ev.remote_ip = op.remote.ip;
    ev.remote_port = op.remote.port;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid((__u32)(op.handle >> 16), (__u16)(op.handle), (__u32)(op.handle >> 32), op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_send  [control]------------------------------- */
static inline struct mtp_ev_list sock_send(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_send ev;
    ev.len = op.len;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid(op.remote.ip, op.remote.port, op.local.ip, op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_recv  [control]------------------------------- */
static inline struct mtp_ev_list sock_recv(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_recv ev;
    ev.len = op.len;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid(op.remote.ip, op.remote.port, op.local.ip, op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- sock_close  [control]------------------------------ */
static inline struct mtp_ev_list sock_close(struct mtp_sock_op op)
{
    struct mtp_ev_list out;
    struct app_close ev;
    mtp_ev_key(&ev, MTP_CTX_tcp_ctx, &tcp_fid(op.remote.ip, op.remote.port, op.local.ip, op.local.port));
    mtp_ev_add(&out, &ev);
    return out;
}

/* ---- parse_tcp  [control]------------------------------- */
static inline struct mtp_ev_list parse_tcp(pkt_t p, struct ipv4 h)
{
    struct mtp_ev_list out;
    struct TCPBP bp = TCPBP_extract(&p);
    __u32 payload_len;
    if (p.len < 20 || bp.data_off * 4 < 20 || bp.data_off * 4 > p.len) {
        return out;
    }
    payload_len = p.len - bp.data_off * 4;
    struct tcp_fid fid = tcp_fid(h.saddr, bp.src_port, h.daddr, bp.dst_port);
    struct tcp_lid lid = tcp_lid(h.daddr, bp.dst_port);
    if ((bp.flags & FLAG_SYN) != 0 && (bp.flags & FLAG_ACK) == 0) {
        struct tcp_syn s;
        s.seq = bp.seq_no;
        s.sport = bp.src_port;
        s.dport = bp.dst_port;
        s.window = bp.window;
        s.local_ip = h.daddr;
        s.remote_ip = h.saddr;
        s.ts_val = mtp_optget_ts_val(bp.opts.opts, bp.opts.opts_n);
        s.has_ts = mtp_opthas_opt_ts(bp.opts.opts, bp.opts.opts_n);
        s.has_mss = mtp_opthas_opt_mss(bp.opts.opts, bp.opts.opts_n);
        s.ece = (bp.flags & FLAG_ECE) != 0;
        s.cwr = (bp.flags & FLAG_CWR) != 0;
        s.qid = p.qid;
        mtp_ev_key(&s, MTP_CTX_tcp_listen_ctx, &lid);
        mtp_ev_add(&out, &s);
        return out;
    }
    if ((bp.flags & FLAG_SYN) != 0) {
        struct tcp_synack sa;
        sa.seq = bp.seq_no;
        sa.ack = bp.ack_seq;
        sa.window = bp.window;
        sa.ts_val = mtp_optget_ts_val(bp.opts.opts, bp.opts.opts_n);
        sa.has_ts = mtp_opthas_opt_ts(bp.opts.opts, bp.opts.opts_n);
        sa.ece = (bp.flags & FLAG_ECE) != 0;
        sa.cwr = (bp.flags & FLAG_CWR) != 0;
        sa.qid = p.qid;
        mtp_ev_key(&sa, MTP_CTX_tcp_ctx, &fid);
        mtp_ev_add(&out, &sa);
        return out;
    }
    if ((bp.flags & FLAG_RST) != 0) {
        struct tcp_rst r;
        r.seq = bp.seq_no;
        r.ack = bp.ack_seq;
        mtp_ev_key(&r, MTP_CTX_tcp_ctx, &fid);
        mtp_ev_add(&out, &r);
        return out;
    }
    if ((bp.flags & FLAG_FIN) != 0) {
        struct tcp_fin f;
        f.seq = bp.seq_no;
        f.ack = bp.ack_seq;
        mtp_ev_key(&f, MTP_CTX_tcp_ctx, &fid);
        mtp_ev_add(&out, &f);
        return out;
    }
    struct tcp_ack a;
    a.seq = bp.seq_no;
    a.ack = bp.ack_seq;
    a.window = bp.window;
    a.flags = bp.flags;
    a.ts_val = mtp_optget_ts_val(bp.opts.opts, bp.opts.opts_n);
    a.ts_ecr = mtp_optget_ts_ecr(bp.opts.opts, bp.opts.opts_n);
    a.payload_len = payload_len;
    a.ecn_ce = (h.tos & IP_ECN_CE) == IP_ECN_CE;
    mtp_ev_key(&a, MTP_CTX_tcp_ctx, &fid);
    mtp_ev_add(&out, &a);
    if (payload_len > 0) {
        struct tcp_data d;
        d.seq = bp.seq_no;
        d.ack = bp.ack_seq;
        d.window = bp.window;
        d.ts_val = mtp_optget_ts_val(bp.opts.opts, bp.opts.opts_n);
        d.ts_ecr = mtp_optget_ts_ecr(bp.opts.opts, bp.opts.opts_n);
        d.payload_len = payload_len;
        d.ecn_ce = (h.tos & IP_ECN_CE) == IP_ECN_CE;
        mtp_ev_key(&d, MTP_CTX_tcp_ctx, &fid);
        mtp_ev_add(&out, &d);
    }
    return out;
}

/* ---- proc_bind  [control]------------------------------- */
static inline void proc_bind(struct app_bind *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control)
{
    struct tcp_fid fid = ctx_common->key;
    (struct tcp_ctx *)mtp_ctx_new(MTP_CTX_tcp_ctx, &fid);
    ctx_control->type = TYPE_FAKE;
    ctx_control->reuseport = ev->reuseport;
    ctx_control->local_port = ev->local_port;
    mtp_notify(ctx_common, MTP_NOTIFY_BOUND);
}

/* ---- proc_listen  [control]----------------------------- */
static inline void proc_listen(struct app_listen *ev, struct tcp_ctx_common *bound_common, struct tcp_ctx_control *bound_control, struct tcp_listen_ctx_common *lst_common)
{
    if (bound_control->type != TYPE_FAKE) {
        return;
    }
    struct tcp_lid lid = tcp_lid(bound_control->local_ip, bound_control->local_port);
    (struct tcp_listen_ctx *)mtp_ctx_new(MTP_CTX_tcp_listen_ctx, &lid);
    lst_common->local_ip = bound_control->local_ip;
    lst_common->local_port = bound_control->local_port;
    lst_common->pending_cap = ev->pending_cap;
    lst_common->pending_n = 0;
    lst_common->has_accepted = false;
    mtp_notify(lst_common, MTP_NOTIFY_LISTENING);
}

/* ---- proc_accept  [control]----------------------------- */
static inline void proc_accept(struct app_accept *ev, struct tcp_listen_ctx_common *lst_common)
{
    if (lst_common->has_accepted) {
        return;
    }
    lst_common->has_accepted = true;
}

/* ---- proc_connect  [control]---------------------------- */
static inline void proc_connect(struct app_connect *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    ctx_control->type = TYPE_NORMAL;
    ctx_control->remote_ip = ev->remote_ip;
    ctx_control->remote_port = ev->remote_port;
    ctx_control->status = CONN_WAIT_TX_SYN;
    ctx_ebpf->rx_next_seq = 0;
    ctx_ebpf->tx_next_seq = PARITY_ISN_ACTIVE;
    ctx_control->syn_attempts = 0;
    struct tcp_fid fid = ctx_common->key;
    (struct tcp_ctx *)mtp_ctx_new(MTP_CTX_tcp_ctx, &fid);
    mtp_notify(ctx_common, MTP_NOTIFY_CONNECTING);
}

/* ---- gen_syn  [control]--------------------------------- */
static inline void gen_syn(struct app_connect *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    if (ctx_control->status != CONN_WAIT_TX_SYN) {
        return;
    }
    ctx_control->status = CONN_WAIT_RX_SYNACK;
    mtp_timer_start(&ctx_common->handshake_timer, ((__u64)(tcp_handshake_timeout) * 1000000ULL));
    struct TCPBP bp;
    bp.src_port = ctx_control->local_port;
    bp.dst_port = ctx_control->remote_port;
    bp.seq_no = ctx_ebpf->tx_next_seq;
    bp.ack_seq = 0;
    bp.window = PARITY_CTRL_WINDOW;
    bp.flags = FLAG_SYN | FLAG_ECE | FLAG_CWR;
    mtp_opt_add(bp.opts.opts, &bp.opts.opts_n, opt_mss(PARITY_MSS));
    mtp_opt_add(bp.opts.opts, &bp.opts.opts_n, opt_ts(0, 0));
    mtp_pkt_gen(&bp, PRIO_CONTROL, false);
}

/* ---- proc_passive_open  [control]----------------------- */
static inline void proc_passive_open(void * ev, struct tcp_listen_ctx_common *lst_common, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    struct pending_syn syn;
    if (!lst_common->has_accepted) {
        if (lst_common->pending_n == 0) {
            return;
        }
        mtp_notify(lst_common, MTP_NOTIFY_NEW_CONN);
        return;
    }
    if (lst_common->pending_n == 0) {
        return;
    }
    syn = lst_common->pending[0];
    if (!syn.has_ts || !syn.has_mss) {
        return;
    }
    ctx_control->qid = syn.qid;
    ctx_control->type = TYPE_NORMAL;
    ctx_control->local_ip = syn.local_ip;
    ctx_control->local_port = syn.dport;
    ctx_control->remote_ip = syn.remote_ip;
    ctx_control->remote_port = syn.sport;
    ctx_ebpf->rx_next_seq = syn.seq + 1;
    ctx_ebpf->tx_next_seq = PARITY_ISN_PASSIVE;
    ctx_control->syn_ts = syn.ts_val;
    if (syn.ece && syn.cwr) {
        ctx_ebpf->ecn_enable = true;
    }
    struct tcp_fid fid = ctx_common->key;
    (struct tcp_ctx *)mtp_ctx_new(MTP_CTX_tcp_ctx, &fid);
    ctx_control->status = CONN_WAIT_TX_SYNACK;
    lst_common->has_accepted = false;
    __u32 i = 0;
    while (i + 1 < lst_common->pending_n) {
        lst_common->pending[i] = lst_common->pending[i + 1];
        i = i + 1;
    }
    lst_common->pending_n = lst_common->pending_n - 1;
}

/* ---- proc_syn_queue  [control]-------------------------- */
static inline void proc_syn_queue(struct tcp_syn *ev, struct tcp_listen_ctx_common *lst_common)
{
    struct pending_syn syn;
    if (lst_common->pending_n >= lst_common->pending_cap) {
        return;
    }
    syn.seq = ev->seq;
    syn.sport = ev->sport;
    syn.dport = ev->dport;
    syn.local_ip = ev->local_ip;
    syn.remote_ip = ev->remote_ip;
    syn.ts_val = ev->ts_val;
    syn.has_ts = ev->has_ts;
    syn.has_mss = ev->has_mss;
    syn.ece = ev->ece;
    syn.cwr = ev->cwr;
    syn.qid = ev->qid;
    syn.valid = true;
    lst_common->pending[lst_common->pending_n] = syn;
    lst_common->pending_n = lst_common->pending_n + 1;
}

/* ---- gen_synack  [control]------------------------------ */
static inline void gen_synack(void * ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    if (ctx_control->status != CONN_WAIT_TX_SYNACK) {
        return;
    }
    ctx_control->status = CONN_OPEN;
    struct TCPBP bp;
    bp.src_port = ctx_control->local_port;
    bp.dst_port = ctx_control->remote_port;
    bp.seq_no = ctx_ebpf->tx_next_seq;
    bp.ack_seq = ctx_ebpf->rx_next_seq;
    bp.window = PARITY_CTRL_WINDOW;
    bp.flags = FLAG_SYN | FLAG_ACK;
    if (ctx_ebpf->ecn_enable) {
        bp.flags = bp.flags | FLAG_ECE;
    }
    mtp_opt_add(bp.opts.opts, &bp.opts.opts_n, opt_mss(PARITY_MSS));
    mtp_opt_add(bp.opts.opts, &bp.opts.opts_n, opt_ts(0, ctx_control->syn_ts));
    mtp_pkt_gen(&bp, PRIO_CONTROL, false);
    mtp_notify(ctx_common, MTP_NOTIFY_ACCEPTED);
}

/* ---- proc_synack  [control]----------------------------- */
static inline void proc_synack(struct tcp_synack *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    if (ctx_control->status != CONN_WAIT_RX_SYNACK) {
        return;
    }
    ctx_control->qid = ev->qid;
    mtp_timer_stop(&ctx_common->handshake_timer);
    if (!ev->has_ts) {
        ctx_ebpf->rx_next_seq = 0;
        ctx_ebpf->tx_next_seq = 0;
        ctx_control->syn_ts = 0;
        ctx_ebpf->ecn_enable = false;
        mtp_timer_start(&ctx_common->handshake_timer, ((__u64)(tcp_handshake_timeout) * 1000000ULL));
        return;
    }
    ctx_ebpf->rx_next_seq = ev->seq + 1;
    ctx_ebpf->tx_next_seq = ev->ack;
    ctx_control->syn_ts = ev->ts_val;
    if (ev->ece && !ev->cwr) {
        ctx_ebpf->ecn_enable = true;
    }
    ctx_control->status = CONN_OPEN;
    mtp_notify(ctx_common, MTP_NOTIFY_CONN_OPEN_OK);
    struct TCPBP bp;
    bp.src_port = ctx_control->local_port;
    bp.dst_port = ctx_control->remote_port;
    bp.seq_no = ctx_ebpf->tx_next_seq;
    bp.ack_seq = ctx_ebpf->rx_next_seq;
    bp.window = PARITY_CTRL_WINDOW;
    bp.flags = FLAG_ACK;
    mtp_opt_add(bp.opts.opts, &bp.opts.opts_n, opt_ts(0, ctx_control->syn_ts));
    mtp_pkt_gen(&bp, PRIO_ACK, false);
}

/* ---- proc_rst  [control]-------------------------------- */
static inline void proc_rst(struct tcp_rst *ev, struct tcp_ctx_common *ctx_common)
{
    mtp_notify(ctx_common, MTP_NOTIFY_PEER_RESET);
    struct tcp_fid dead = ctx_common->key;
    mtp_ctx_del(MTP_CTX_tcp_ctx, &dead);
}

/* ---- proc_fin  [control]-------------------------------- */
static inline void proc_fin(struct tcp_fin *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    if (ctx_control->status != CONN_CLOSED) {
        return;
    }
    struct TCPBP bp;
    bp.src_port = ctx_control->local_port;
    bp.dst_port = ctx_control->remote_port;
    bp.seq_no = ctx_ebpf->tx_next_seq;
    bp.ack_seq = ctx_ebpf->rx_next_seq;
    bp.window = PARITY_CTRL_WINDOW;
    bp.flags = FLAG_ACK;
    mtp_pkt_gen(&bp, PRIO_ACK, false);
}

/* ---- proc_close  [control]------------------------------ */
static inline void proc_close(struct app_close *ev, struct tcp_ctx_common *ctx_common, struct tcp_ctx_control *ctx_control, struct tcp_ctx_ebpf *ctx_ebpf)
{
    ctx_control->status = CONN_CLOSED;
    struct TCPBP bp;
    bp.src_port = ctx_control->local_port;
    bp.dst_port = ctx_control->remote_port;
    bp.seq_no = ctx_ebpf->tx_next_seq;
    bp.ack_seq = ctx_ebpf->rx_next_seq;
    bp.flags = FLAG_RST;
    mtp_pkt_gen(&bp, PRIO_CONTROL, false);
    struct tcp_fid dead = ctx_common->key;
    mtp_ctx_del(MTP_CTX_tcp_ctx, &dead);
    mtp_notify(ctx_common, MTP_NOTIFY_CLOSED);
}


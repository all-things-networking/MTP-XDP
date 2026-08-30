/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog_flow_id.h"

/*
 * A context is ONE declaration in the program. It is emitted as one struct
 * per @placement group because this target keeps those groups in different
 * memories -- an eBPF map, a shared mapping, the control path's heap, the
 * application's. A target with one address space emits one struct from the
 * same program.
 */

enum mtp_ctx_kind {
    MTP_CTX_tcp_ctx,
    MTP_CTX_tcp_listen_ctx,
};

/* ---- tcp_ctx -- @placement("app")----------------------- */
struct tcp_ctx_app {
    __u32 rxb_head;
    __u32 rxb_used;
    __u32 rxb_bump;
    __u32 txb_head;
    __u32 txb_sent;
    __u32 txb_allocated;
    bool force_rx_bump;
    bool in_rx_bump_pending;
};

/* ---- tcp_ctx -- @placement("cc_shared")----------------- */
struct tcp_ctx_cc_shared {
    __u32 cnt_tx_drops;
    __u32 cnt_rx_acks;
    __u32 cnt_rx_ack_bytes;
    __u32 cnt_rx_ecn_bytes;
    __u32 rtt_est;
    __u32 rate;
    bool txp;
};

/* ---- tcp_ctx -- @placement("control")------------------- */
struct tcp_ctx_control {
    __u8 type;
    __u8 state;
    bool reuseport;
    __u16 local_port;
    __u16 remote_port;
    __u32 local_ip;
    __u32 remote_ip;
    __u32 syn_ts;
    __u32 syn_attempts;
    __u32 next_timeout;
    __u32 qid;
    bool ecn_enable;
};

/* ---- tcp_ctx -- @placement("ebpf")---------------------- */
struct tcp_ctx_ebpf {
    __u32 rx_buf_size;
    __u32 tx_buf_size;
    __u32 rx_avail;
    __u32 rx_remote_avail;
    __u32 rx_next_pos;
    __u32 rx_next_seq;
    __u32 rx_dupack_cnt;
    __u32 rx_ooo_start;
    __u32 rx_ooo_len;
    __u32 tx_pending;
    __u32 tx_sent;
    __u32 tx_next_pos;
    __u32 tx_next_seq;
    __u32 tx_next_ts;
};

/* ---- tcp_ctx -- ungrouped (control path)---------------- */
struct tcp_ctx {
    struct tcp_fid key;
    struct mtp_timer handshake_timer;
    struct mtp_timer rto_timer;
    struct tcp_ctx_app app;
    struct tcp_ctx_cc_shared cc_shared;
    struct tcp_ctx_control control;
    struct tcp_ctx_ebpf ebpf;
};

static inline void tcp_ctx_init(struct tcp_ctx *c)
{
    c->control.type = TYPE_FAKE;
    c->control.state = CONN_WAIT_RX_SYN;
}

/* ---- tcp_listen_ctx -- ungrouped (control path)--------- */
struct tcp_listen_ctx {
    struct tcp_lid key;
    __u32 local_ip;
    __u16 local_port;
    __u32 pending_cap;
    __u32 pending_n;
    struct pending_syn pending[PROG_MAX_BACKLOG];
    struct tcp_fid accepted;
    bool has_accepted;
};

static inline void tcp_listen_ctx_init(struct tcp_listen_ctx *c)
{
}


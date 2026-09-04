/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-bisect.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog_flow_id.h"
#include "prog_const.h"
#include "prog_event.h"

struct pending_syn {
    __u32 seq;
    __u16 sport;
    __u16 dport;
    __u32 local_ip;
    __u32 remote_ip;
    __u32 ts_val;
    bool has_ts;
    bool has_mss;
    bool ece;
    bool cwr;
    __u32 qid;
    bool valid;
};

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
    __u16 cnt_tx_drops;
    __u16 cnt_rx_acks;
    __u32 cnt_rx_ack_bytes;
    __u32 cnt_rx_ecn_bytes;
    __u32 rtt_est;
    __u32 rate;
    __u32 txp;
};

/* ---- tcp_ctx -- @placement("control")------------------- */
struct tcp_ctx_control {
    __u8 type;
    __u8 status;
    bool reuseport;
    __u16 local_port;
    __u16 remote_port;
    __u32 local_ip;
    __u32 remote_ip;
    __u32 syn_ts;
    __u32 syn_attempts;
    __u64 next_timeout_tsc;
    __u32 qid;
};

/* ---- tcp_ctx -- @placement("ebpf")---------------------- */
struct tcp_ctx_ebpf {
    __u32 rx_buf_size;
    __u32 tx_buf_size;
    bool ecn_enable;
    __u32 rx_avail;
    __u32 rx_remote_avail;
    __u32 rx_next_pos;
    __u32 rx_next_seq;
    __u16 rx_dupack_cnt;
    __u32 rx_ooo_start;
    __u32 rx_ooo_len;
    __u32 tx_pending;
    __u32 tx_sent;
    __u32 tx_next_pos;
    __u32 tx_next_seq;
    __u32 tx_next_ts;
};

/* ---- tcp_ctx -- unplaced-------------------------------- */
struct tcp_ctx_common {
    struct tcp_fid key;
    struct mtp_timer handshake_timer;
    struct mtp_timer rto_timer;
};

/* ---- tcp_ctx -- composite (a target with one memory)---- */
struct tcp_ctx {
    struct tcp_ctx_common common;
    struct tcp_ctx_app app;
    struct tcp_ctx_cc_shared cc_shared;
    struct tcp_ctx_control control;
    struct tcp_ctx_ebpf ebpf;
};

static inline void tcp_ctx_init(struct tcp_ctx *c)
{
    c->control.type = MTP_TYPE_FAKE;
    c->control.status = MTP_CONN_WAIT_RX_SYN;
}

/* ---- tcp_listen_ctx -- unplaced------------------------- */
struct tcp_listen_ctx_common {
    struct tcp_lid key;
    __u32 local_ip;
    __u16 local_port;
    __u32 pending_cap;
    __u32 pending_n;
    struct pending_syn pending[MTP_PROG_MAX_BACKLOG];
    struct tcp_fid accepted;
    bool has_accepted;
};

/* ---- tcp_listen_ctx -- composite (a target with one memory)- */
struct tcp_listen_ctx {
    struct tcp_listen_ctx_common common;
};

static inline void tcp_listen_ctx_init(struct tcp_listen_ctx *c)
{
}


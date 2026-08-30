/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog_flow_id.h"

struct opt_mss {
    __u8 kind;
    __u8 opt_len;
    __u16 mss;
};

struct opt_nop {
    __u8 kind;
};

struct opt_ts {
    __u8 kind;
    __u8 opt_len;
    __u32 ts_val;
    __u32 ts_ecr;
};

struct tcp_opt {
};

struct tcp_options {
    struct mtp_opt opts[MTP_OPT_CAP];
    __u8 opts_n;
};

struct ipv4 {
    __u32 saddr;
    __u32 daddr;
    __u8 protocol;
    __u8 tos;
};

struct tcp_scratch {
    __u32 seq;
    __u32 ack_seq;
    __u32 ts_val;
    __u32 ts_ecr;
    __u32 now;
    __u32 payload_off;
    __u32 payload_len;
    __u32 rx_bump;
    __u32 tx_bump;
    __u32 go_back_pos;
    __u32 trim_start;
    __u32 trim_end;
    bool trigger_ack;
    bool clear_ooo;
    bool drop;
    bool seg_ok;
    bool ooo_seg;
    bool ooo_fin;
    bool ack_ok;
};

struct TCPBP {
    __u16 src_port;
    __u16 dst_port;
    __u32 seq_no;
    __u32 ack_seq;
    __u8 data_off;
    __u8 flags;
    __u16 window;
    __u16 checksum;
    __u16 urg_ptr;
    struct tcp_options opts;
    struct mtp_addr data;
};

/* ---- option accessors----------------------------------- */
static inline __u32 mtp_optget_mss(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) {
        if (o[i].kind != 2) continue;
        __u32 v = 0;
        for (__u8 b2 = 0; b2 < 2; b2++)
            v = (v << 8) | o[i].data[2 + b2];
        return v;
    }
    return 0;
}
static inline __u32 mtp_optget_ts_ecr(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) {
        if (o[i].kind != 8) continue;
        __u32 v = 0;
        for (__u8 b2 = 0; b2 < 4; b2++)
            v = (v << 8) | o[i].data[6 + b2];
        return v;
    }
    return 0;
}
static inline __u32 mtp_optget_ts_val(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) {
        if (o[i].kind != 8) continue;
        __u32 v = 0;
        for (__u8 b2 = 0; b2 < 4; b2++)
            v = (v << 8) | o[i].data[2 + b2];
        return v;
    }
    return 0;
}
static inline bool mtp_opthas_opt_mss(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) if (o[i].kind == 2) return true;
    return false;
}
static inline bool mtp_opthas_opt_nop(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) if (o[i].kind == 1) return true;
    return false;
}
static inline bool mtp_opthas_opt_ts(const struct mtp_opt *o, __u8 n)
{
    for (__u8 i = 0; i < n; i++) if (o[i].kind == 8) return true;
    return false;
}
static inline struct mtp_opt opt_mss(__u16 mss)
{
    struct mtp_opt o = {0};
    o.kind = 2;
    o.len  = 4;
    o.data[2] = (__u8)((mss >> 8) & 0xff);
    o.data[3] = (__u8)((mss >> 0) & 0xff);
    return o;
}
static inline struct mtp_opt opt_nop(void)
{
    struct mtp_opt o = {0};
    o.kind = 1;
    o.len  = 1;
    return o;
}
static inline struct mtp_opt opt_ts(__u32 ts_val, __u32 ts_ecr)
{
    struct mtp_opt o = {0};
    o.kind = 8;
    o.len  = 10;
    o.data[2] = (__u8)((ts_val >> 24) & 0xff);
    o.data[3] = (__u8)((ts_val >> 16) & 0xff);
    o.data[4] = (__u8)((ts_val >> 8) & 0xff);
    o.data[5] = (__u8)((ts_val >> 0) & 0xff);
    o.data[6] = (__u8)((ts_ecr >> 24) & 0xff);
    o.data[7] = (__u8)((ts_ecr >> 16) & 0xff);
    o.data[8] = (__u8)((ts_ecr >> 8) & 0xff);
    o.data[9] = (__u8)((ts_ecr >> 0) & 0xff);
    return o;
}
static inline struct TCPBP TCPBP_extract(const struct mtp_pkt *p)
{
    struct TCPBP bp = {0};
    mtp_bp_read(p, &bp, sizeof(bp), bp.opts.opts,
                &bp.opts.opts_n, MTP_OPT_CAP);
    return bp;
}



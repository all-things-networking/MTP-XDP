/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-newconv.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "prog_flow_id.h"

enum mtp_event_base { MTP_APP_EVENT, MTP_NET_EVENT, MTP_TIMER_EVENT };

struct app_bind {
    enum mtp_event_base base;   /* app_event */
    __u32 local_ip;
    __u16 local_port;
    bool reuseport;
};

struct app_listen {
    enum mtp_event_base base;   /* app_event */
    __u32 pending_cap;
};

struct app_accept {
    enum mtp_event_base base;   /* app_event */
    __u16 local_port;
};

struct app_connect {
    enum mtp_event_base base;   /* app_event */
    __u32 remote_ip;
    __u16 remote_port;
};

struct app_send {
    enum mtp_event_base base;   /* app_event */
    __u32 len;
};

struct app_recv {
    enum mtp_event_base base;   /* app_event */
    __u32 len;
};

struct app_close {
    enum mtp_event_base base;   /* app_event */
};

struct tcp_syn {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u16 sport;
    __u16 dport;
    __u16 window;
    __u32 local_ip;
    __u32 remote_ip;
    __u32 ts_val;
    bool has_ts;
    bool has_mss;
    bool ece;
    bool cwr;
    __u32 qid;
};

struct tcp_synack {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u32 ack;
    __u16 window;
    __u32 ts_val;
    bool has_ts;
    bool ece;
    bool cwr;
    __u32 qid;
};

struct tcp_ack {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u32 ack;
    __u16 window;
    __u16 flags;
    __u32 ts_val;
    __u32 ts_ecr;
    __u32 payload_len;
    bool ecn_ce;
};

struct tcp_data {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u32 ack;
    __u16 window;
    __u32 ts_val;
    __u32 ts_ecr;
    __u32 payload_len;
    bool ecn_ce;
};

struct tcp_rst {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u32 ack;
};

struct tcp_fin {
    enum mtp_event_base base;   /* net_event */
    __u32 seq;
    __u32 ack;
};

struct handshake_timeout {
    enum mtp_event_base base;   /* timer_event */
};

struct cc_interval_timeout {
    enum mtp_event_base base;   /* timer_event */
};

struct rto_timeout {
    enum mtp_event_base base;   /* timer_event */
};


#pragma once
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include <intf/intf_ebpf.h>

#include "../ebpf_utils.h"
#include "../ebpf_queue.h"
#include "eTran_defs.h"
#include "pacing.h"
#include "common_funcs.h"
#include "mtp_defs.h"
#include "mtp_tcp.h"

#define TCP_ACK_HEADER_CUTOFF (int)(XDP_GEN_PKT_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr) - TS_OPT_SIZE)

#if defined(XDP_DEBUG) || defined(XDP_EGRESS_DEBUG) || defined(XDP_GEN_DEBUG)
#define TCP_LOCK(c)
#define TCP_UNLOCK(c)
#else
// #define TCP_LOCK(c)
// #define TCP_UNLOCK(c)
#define TCP_LOCK(c) bpf_spin_lock(&c->lock)
#define TCP_UNLOCK(c) bpf_spin_unlock(&c->lock)
#endif

#define NULL_CONN __UINT32_MAX__
// we use cc_idx to identify each connection
// TODO: much more configurable
SEC(".data.prev_conn")
__u32 prev_conn[MAX_CPU] = {__UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
                            __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__, __UINT32_MAX__,
};
__u32 prev_conn_li[MAX_CPU];
__u16 prev_conn_lp[MAX_CPU];
__u32 prev_conn_ri[MAX_CPU];
__u16 prev_conn_rp[MAX_CPU];
__u8 prev_conn_ece[MAX_CPU];

/**
 * default value in linux kernel:
 * /proc/sys/net/core/rmem_default 212992
 * /proc/sys/net/core/wmem_default 212992
 */

// FIXME 
#define TCP_WND_SCALE 3

#define TCP_OPT_END_OF_OPTIONS 0
#define TCP_OPT_NO_OP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_TIMESTAMP 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_flow_tuple);
    __type(value, struct bpf_tcp_conn);
    __uint(max_entries, MAX_TCP_FLOWS);
} bpf_tcp_conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bpf_cc);
    __uint(max_entries, MAX_TCP_FLOWS);
    __uint(map_flags, BPF_F_MMAPABLE);
} bpf_cc_map SEC(".maps");

SEC(".bss.tx_cached_ts")
__u64 tx_cached_ts[MAX_CPU];

SEC(".bss.rx_cached_ts")
__u64 rx_cached_ts[MAX_CPU];

static __always_inline int ackqueue_empty(void)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU)) {
        xdp_gen_log_panic("cpu >= MAX_CPU");
        return 1;
    }
    return ack_prod[cpu] == ack_cons[cpu];
}

static __always_inline struct bpf_tcp_ack *dequeue_ack(void)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU)) {
        xdp_gen_log_panic("cpu >= MAX_CPU");
        return NULL;
    }

    struct bpf_tcp_ack *ack;

    if (unlikely(ack_prod[cpu] == ack_cons[cpu])) {
        return NULL;
    }

    __u32 cons = ack_cons[cpu];

    ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &cons);

    ack_cons[cpu] = (ack_cons[cpu] + 1) & (NAPI_BATCH_SIZE - 1);

    return ack;
}

/**
 * @brief This function is called when:
 *        1) xdp_gen is triggered, which indicates that current NAPI batch is finished
 *        2) the connection whose pkt are processed is different from the previous one
 */
static __always_inline int enqueue_prev_ack(__u32 cpu)
{
    struct ebpf_flow_tuple key;
    int ece = 0;

    __u32 prod = ack_prod[cpu];
    __u32 cons = ack_cons[cpu];

    // check if ack queue is full
    if (cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1))) {
        return -1;
    }

    __u32 now = bpf_ktime_get_ns();

    struct bpf_tcp_ack *ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
    if (!ack) {
        return -1;
    }

    ece = prev_conn_ece[cpu];

    key.local_ip = prev_conn_li[cpu];
    key.remote_ip = prev_conn_ri[cpu];
    key.local_port = prev_conn_lp[cpu];
    key.remote_port = prev_conn_rp[cpu];
    
    struct bpf_tcp_conn *c = bpf_map_lookup_elem(&bpf_tcp_conn_map, &key);
    if (!c) {
        return -1;
    }

    TCP_LOCK(c);
    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = c->local_port;
    ack->remote_port = c->remote_port;

    ack->seq = c->tx_next_seq;
    ack->ack = c->rx_next_seq;

    ack->rxwnd = min(c->rx_avail >> TCP_WND_SCALE, 0xFFFF);
    
    ack->ts_val = now;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;

    TCP_UNLOCK(c);

    ack->ecn_flags = ece ? 1 : 0;

    ack_prod[cpu] = (prod + 1) & (NAPI_BATCH_SIZE - 1);

    return 0;
}

static __always_inline int enqueue_ack(struct bpf_tcp_conn *c, struct bpf_tcp_ack *ack, __u32 cpu, __u32 now, bool ece)
{
    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = c->local_port;
    ack->remote_port = c->remote_port;

    ack->seq = c->tx_next_seq;
    ack->ack = c->rx_next_seq;

    ack->rxwnd = min(c->rx_avail >> TCP_WND_SCALE, 0xFFFF);
    
    ack->ts_val = now;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;

    ack->ecn_flags = ece ? 1 : 0;

    ack_prod[cpu] = (ack_prod[cpu] + 1) & (NAPI_BATCH_SIZE - 1);

    return 0;
}

/*static __always_inline __u32 tcp_txavail(const struct bpf_tcp_conn *c)
{
    // flow control window 
    return c->rx_remote_avail - c->tx_sent;
}*/

// Fill TCP header excpet for ports
static __always_inline void fill_tcp_hdr(struct iphdr *iph, struct tcphdr *tcph, struct bpf_tcp_conn *c, __u32 tgt_ts, void *data_end, __u16 flags)
{
    __u32 tx_seq = c->tx_next_seq;
    __u32 rx_wnd = c->rx_avail;
    __u32 ack_seq = c->rx_next_seq;
    __u32 ts_ecr = c->tx_next_ts;
    struct tcp_timestamp_opt *ts_opt = (struct tcp_timestamp_opt *)(tcph + 1);
    if (ts_opt + 1 > data_end) {
        return;
    }
    __u16 len = 5 + TS_OPT_SIZE / 4;
    /* fill tcp header */
    tcph->seq = bpf_htonl(tx_seq);
    tcph->ack_seq = bpf_htonl(ack_seq);
    
    set_tcp_flag(tcph, len, flags);

    ts_opt->kind = TCPI_OPT_TIMESTAMPS;
    ts_opt->length = sizeof(*ts_opt) / 4;
    ts_opt->ts_val = bpf_htonl(tgt_ts);
    ts_opt->ts_ecr = bpf_htonl(ts_ecr);
    
    tcph->window = bpf_htons(rx_wnd) >> TCP_WND_SCALE;
    tcph->urg_ptr = 0;

    // Newer kernel has supported XDP_TXMD_FLAGS_CHECKSUM, ignore the overhead
    tcph->check = 0;
}

static __always_inline __u64 cc_get_desired_tx_ts(struct bpf_cc *cc, __u64 ref_ts, __u32 payload_len)
{
    // TODO: improve precision
    __u64 ns_delta = (__u64)1000000000 * payload_len / cc->rate;
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 3125000000; // 25Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 2500000000; // 20Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 1250000000; // 10Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 500000000; // 4Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 250000000; // 2Gbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 100000000; // 800Mbps
    // __u64 ns_delta = (__u64)1000000000 * payload_len / 25000000; // 200Mbps
    
    __u64 desired_tx_ts = cc->prev_desired_tx_ts + ns_delta;

    desired_tx_ts = max(ref_ts, desired_tx_ts);

    cc->prev_desired_tx_ts = desired_tx_ts;

    return desired_tx_ts;
} 

static __always_inline __u32 fast_retransmit(struct bpf_tcp_conn *c, struct bpf_cc *cc)
{
    __u32 go_back_bytes = c->tx_sent;
    __u32 x;

    /* reset flow state as if we never transmitted those segments */
    c->rx_dupack_cnt = 0;

    c->tx_next_seq -= go_back_bytes;
    if (c->tx_next_pos >= go_back_bytes) {
        c->tx_next_pos -= go_back_bytes;
    } else {
        x = go_back_bytes - c->tx_next_pos;
        c->tx_next_pos = c->tx_buf_size - x;
    }

    c->tx_pending = 0;
    c->rx_remote_avail += go_back_bytes;

    c->tx_sent = 0;
    cc->txp = 0;

    /* cut rate by half if first drop in control interval */
    if (cc->cnt_tx_drops == 0) {
        cc->rate >>= 1;
    }

    cc->cnt_tx_drops++;

    return c->tx_next_pos;
}

// Caller must hold bpf_spin_lock
static __always_inline int tcp_tx_process(struct iphdr *iph, struct tcphdr *tcph, struct bpf_tcp_conn *c,
    struct meta_info *data_meta, void *data_end, struct app_timer_event *ev, struct TCPBP *bp,
    struct bpf_cc *cc)
{
    __u32 rx_bump = data_meta->tx.rx_bump;
    __u32 payload_len = data_meta->tx.plen;
    __u32 tx_pos = data_meta->tx.tx_pos;

    bool wnd_upd = false;

    TCP_LOCK(c);

    /* 
    Receives an update from userspace, specifying the amount of space in the RX buffer
    was freed there.

    Question: could we consider this a part of the eTran-specific TCP implementation
    and have it in an EP? Having rx_bump as a value in the application event
    */
    if (rx_bump) {
        if (c->tx_pending == 0)
            wnd_upd = true;
        c->rx_avail += rx_bump;
    }

    /*
    Userspace may send a dummy packet for synchronization, which might result
    in being sent to the other side to specify the current RX buffer size (window update).

    Question: again, this seems to be a eTran-specific TCP implementation part.
    Can we add it to an EP?
    */
    if (unlikely(data_meta->tx.flag & FLAG_SYNC)) {
        if (wnd_upd) {
            fill_tcp_hdr(iph, tcph, c, ev->timestamp, data_end, TCP_FLAG_ACK);
            fill_ip_hdr(iph, 0, false);
            TCP_UNLOCK(c);
            return XDP_TX;
        }
        TCP_UNLOCK(c);
        return XDP_DROP;
    }

    /*
    When fast-retransmission is done in XDP, we move c->tx_next_pos N steps
    back (go-back-N). And, since, we dispatch packets in batches via AF_XDP, some
    of the already enqueued packets (in TX ring buffer) may need to be dropped,
    as they may be beyond the decreased c->tx_next_pos.
    
    Question: where to put this?
    */
    if (unlikely(tx_pos != c->tx_next_pos)) {
        TCP_UNLOCK(c);
        return XDP_DROP;
    }


    /* Dispatcher */
    struct interm_out int_out;

    if(ev->type == APP_EVENT) {
        if(ev->data_size > 0) { // First packet of batch
            send_ep(ev, c, &int_out, data_meta, cc, tcph, iph, data_end, bp);
        } else {
            following_pkts(bp, c, data_meta, cc, tcph, iph, ev->timestamp, data_end);
        }
    } else if(ev->type == TIMER_EVENT) {
        int xdp_op = ack_timeout_xdp_ep(ev, c, &int_out, data_meta, cc);
        TCP_UNLOCK(c);
        return xdp_op;
    }

    /* End of dispatcher */

    /* Rate limiting stage */

    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU))
        return XDP_DROP;

    __u64 desired_tx_ts = cc_get_desired_tx_ts(cc, ev->timestamp, payload_len);
    
    #ifdef BYPASS_RL
    if (cc->rate >= LINK_BANDWIDTH && !nr_pkts_in_tw[cpu]) {
        // eRPC recommends to bypass rate limiter
        goto bypass_rl;
    }
    #endif

    #ifdef BYPASS_RL
    if ((!nr_pkts_in_tw[cpu] || c->tx_next_seq - c->send_una == payload_len) && desired_tx_ts <= ev->timestamp) {
        goto bypass_rl;
    }
    #endif

    TCP_UNLOCK(c);

    __u32 key = cpu;
    struct timing_wheel *tw_map = bpf_map_lookup_elem(&tw_outer_map, &key);
    if (unlikely(!tw_map)) {
        log_panic("tw_map is NULL");
        return XDP_DROP;
    }

    __u32 idx = tw_insert(cpu, desired_tx_ts);
    if (unlikely(idx == POISON_32)) {
        log_panic("idx == POISON_32");
        return XDP_DROP;
    }

    /* End of rate limiting stage */

    return bpf_redirect_map(tw_map, idx, 0);

#ifdef BYPASS_RL
bypass_rl:
    TCP_UNLOCK(c);
    xdp_egress_log("bypass rate limiter");
    return XDP_TX;
#endif
}


static __always_inline int tcp_rx_process(struct tcphdr *tcph, struct bpf_tcp_conn *c, __u32 pkt_len,
    struct meta_info *data_meta, bool ece, __u32 cpu, struct net_event *ev, struct bpf_cc *cc)
{
    TCP_LOCK(c);
    
    struct interm_out int_out;
    /* Start of dispatcher */
    if(ev->minor_type == NET_EVENT_ACK) {
        cc->cnt_rx_acks++;
        fast_retr_rec_ep(ev, c, &int_out, data_meta, cpu, cc);
        ack_net_ep(ev, c, &int_out, data_meta, cpu, cc);

        TCP_UNLOCK(c);
        return int_out.drop ? XDP_DROP : XDP_REDIRECT;
    } else if (ev->minor_type == NET_EVENT_DATA) {
        verify_trim_data_ep(ev, c, &int_out, data_meta, cpu, cc);
        detect_ooo_data_ep(ev, c, &int_out, data_meta, cpu, cc);
        flush_ooo_data_ep(ev, c, &int_out, data_meta, cpu, cc);
        data_net_ep(ev, c, &int_out, data_meta, cpu, cc);
        send_ack(ev, c, &int_out, data_meta, cpu, cc);
        
        TCP_UNLOCK(c);
        return int_out.drop ? XDP_DROP : XDP_REDIRECT;
    }

    /* End of dispatcher */
    
    return XDP_DROP;
}

static __always_inline bool is_tcp_syn(struct tcphdr *tcp) {
    if (tcp->syn == 1 && tcp->ack == 0) {
        return true;
    }
    return false;
}

static __always_inline bool is_tcp_syn_ack(struct tcphdr *tcp) {
    if (tcp->syn == 1 && tcp->ack == 1) {
        return true;
    }
    return false;
}

static __always_inline bool is_tcp_rst(struct tcphdr *tcp) {
    return tcp->rst == 1;
}
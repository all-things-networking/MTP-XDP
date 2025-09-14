#pragma once

#include "../ebpf_queue.h"

#define TCP_WND_SCALE 3

// ACK
// emulate a per-cpu SCSP queue with BPF_MAP_TYPE_PERCPU_ARRAY
struct bpf_tcp_ack {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;

    __u32 seq; // tx_next_seq
    __u32 ack; // rx_next_seq
    __u32 rxwnd; // rx_avail

    __u32 ts_val; // now
    __u32 ts_ecr; // tx_next_ts

    __u8 ecn_flags;

    // MTP-only entries
    __u8 is_ack;
    __u32 stream_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NAPI_BATCH_SIZE);
  __type(key, __u32);
  __type(value, struct bpf_tcp_ack);
} bpf_tcp_ack_map SEC(".maps");

SEC(".bss.ack_prod")
__u32 ack_prod[MAX_CPU];
SEC(".bss.ack_cons")
__u32 ack_cons[MAX_CPU];

// Fill IP header except for addresses
static __always_inline void fill_ip_hdr(struct iphdr *iph, __u32 payload_len, bool ece)
{
    /* fill ip header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = ece ? IPTOS_ECN_ECT0 : 0;
    iph->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE + payload_len);
    iph->id = bpf_htons(0);
    iph->frag_off = 0;
    iph->ttl = 0xff;
    iph->protocol = IPPROTO_TCP;

    __u64 csum = 0;
    ipv4_csum_inline(iph, &csum);
    iph->check = csum;
}

static __always_inline void set_tcp_flag(struct tcphdr *tcph, __u16 len, __u16 flags)
{
    tcph->res1 = 0;
    tcph->doff = len;
    tcph->fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_FLAG_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
    tcph->ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
    tcph->urg = (flags & TCP_FLAG_URG) ? 1 : 0;
    tcph->ece = (flags & TCP_FLAG_ECE) ? 1 : 0;
    tcph->cwr = (flags & TCP_FLAG_CWR) ? 1 : 0;
}

static __always_inline __u32 xsk_budget_avail(const struct bpf_tcp_conn_per_stream *stream_c)
{
    return stream_c->rx_remote_avail;
}

/**
 * @brief Given a range [start, end), check if a sequence number is in the range,
 *        considering the wrap-around case. excluding indicates whether the seq is exclusive.
 */
static __always_inline bool seq_in_range(__u32 seq, __u32 start, __u32 end, bool excluding)
{
    if (start <= end) {
        return excluding ? (seq > start && seq <= end) : (seq >= start && seq < end);
    } else {
        return excluding ? (seq > start || seq <= end) : (seq >= start || seq < end);
    }
}

/**
 * @brief out-of-order version of tcp_valid_rxseq()
 *        as long as the pkt seq range has overlap with the receive buffer range,
 *        we consider it as a valid pkt
 */
static __always_inline int tcp_valid_rxseq_ooo(struct bpf_tcp_conn *c, __u32 seq, __u32 payload_len, __u32 *trim_start, __u32 *trim_end,
struct bpf_tcp_conn_per_stream *stream_c)
{
    __u32 exp_seq_first = stream_c->rx_next_seq;
    __u32 exp_seq_last = stream_c->rx_next_seq + stream_c->rx_avail;

    __u32 pkt_seq_first = seq;
    __u32 pkt_seq_last = seq + payload_len;

    xdp_log("exp_seq_first(%u), exp_seq_last(%u), pkt_seq_first(%u), pkt_seq_last(%u)", exp_seq_first, exp_seq_last, pkt_seq_first, pkt_seq_last);

    bool valid = seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false) ||
                 seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true) ||
                 seq_in_range(exp_seq_first, pkt_seq_first, pkt_seq_last, false) ||
                 seq_in_range(exp_seq_last, pkt_seq_first, pkt_seq_last, true);
    
    if (!valid) {
        return -1;
    }

    if (seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false)) {
        *trim_start = 0;
    } else {
        *trim_start = exp_seq_first - pkt_seq_first;
    }

    if (seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true)) {
        *trim_end = 0;
    } else {
        *trim_end = pkt_seq_last - exp_seq_last;
    }

    xdp_log("*trim_start(%u), *trim_end(%u)", *trim_start, *trim_end);

    return 0;
}
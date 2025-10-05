#ifndef MTP_DEFS_H
#define MTP_DEFS_H

// Comment this to turn off MTP functions
#define MTP_ON 1

#define NET_EVENT_ACK 1
#define NET_EVENT_DATA 0

#define NET_EVENT 2
#define APP_EVENT 1
#define TIMER_EVENT 0

#define SEG_DATA 1
#define UNSEG_DATA 0

struct ts_option {
    __u32 desired_tx_ts;
};

struct TCPBP {
    __u16 src_port;
    __u16 dest_port;
    __u32 seq_num;
    __u32 ack_seq;
    bool is_ack;
    __u16 rwnd_size;
    struct ts_option ts_opt;
};

struct interm_out {
    bool change_cwnd;
    bool skip_ack_eps;
    bool trigger_ack;
    bool drop;
    bool skip_data_eps;
    __u32 num_acked_bytes;
    __u32 go_back_bytes;
};

// Represents APP and TIMER events in XDP
struct app_timer_event {
    __u8 type;
    // APP fields
    __u32 data_size;
    __u32 timestamp;

    // TIMER fields
    __u32 seq_num;
};
struct net_event {
    __u8 minor_type;
    // ACK
    __u32 ack_seq;
    __u32 rwnd_size;
    __u32 ts_ecr;

    // DATA
    // Question: how are we representing hold_addr?
    __u32 data_len;
    __u32 ts_val;

    // SHARED
    __u32 seq_num;
    bool ecn_mark;
    __u32 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_flow_tuple);
    __type(value, struct TCPBP);
    __uint(max_entries, MAX_TCP_FLOWS);
} bpf_pkt_bp_map SEC(".maps");

static __always_inline
int get_pkt_bp_mtp(struct ebpf_flow_tuple *key, struct TCPBP **bp) {

    *bp = bpf_map_lookup_elem(&bpf_pkt_bp_map, key);
    if(!(*bp)) {
        struct TCPBP new_bp = {0};
        new_bp.seq_num = 0;
        bpf_map_update_elem(&bpf_pkt_bp_map, key, &new_bp, BPF_NOEXIST);
        *bp = bpf_map_lookup_elem(&bpf_pkt_bp_map, key);
        if(!(*bp)) {
            bpf_printk("Error get_pkt_bp_mtp");
            return 0;
        }
    }
    return 1;
}

#endif
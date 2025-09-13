#pragma once

#include <stdlib.h>
#include "common_funcs.h"

// TODO: fix bug when there's a bpf_printk
// Probably some error related to the lower rate of transmitting packets

// Fill TCP header excpet for ports
static __always_inline void mtp_fill_tcp_hdr(struct tcphdr *tcph, struct bpf_tcp_conn *c, void *data_end, __u16 flags,
    struct TCPBP *bp)
{
    __u32 tx_seq = bp->seq_num;
    __u32 rx_wnd = bp->rwnd_size;
    __u32 ack_seq = bp->ack_seq;
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
    tcph->ack = bp->is_ack;

    ts_opt->kind = TCPI_OPT_TIMESTAMPS;
    ts_opt->length = sizeof(*ts_opt) / 4;
    ts_opt->ts_val = bpf_htonl(bp->ts_opt.desired_tx_ts);
    ts_opt->ts_ecr = bpf_htonl(ts_ecr);
    
    tcph->window = bpf_htons(rx_wnd) >> TCP_WND_SCALE;
    tcph->urg_ptr = 0;

    // Newer kernel has supported XDP_TXMD_FLAGS_CHECKSUM, ignore the overhead
    tcph->check = 0;
}

static __always_inline void mtp_pkt_gen_wrapper(bool seg_unseg, struct TCPBP *bp, struct bpf_tcp_conn *c,
    struct tcphdr *tcph, struct iphdr *iph, void *data_end, __u32 data_size, __u32 seq_num,
    __u8 ev_type, struct meta_info *data_meta, struct bpf_tcp_conn_per_stream *stream_c) {

    if(seg_unseg == SEG_DATA || (stream_c->buf_curr_seq < seq_num)) {
        stream_c->buf_curr_seq += min(data_size, TCP_MSS_W_TS);
        stream_c->tx_next_pos += min(data_size, TCP_MSS_W_TS);
        if (stream_c->tx_next_pos >= stream_c->tx_buf_size)
            stream_c->tx_next_pos -= stream_c->tx_buf_size;
        mtp_fill_tcp_hdr(tcph, c, data_end, 0, bp);
        fill_ip_hdr(iph, min(data_size, TCP_MSS_W_TS), c->ecn_enable);

        bp->seq_num += min(data_size, TCP_MSS_W_TS);

    } else {
        __u32 go_back_bytes = stream_c->buf_curr_seq - seq_num;
        stream_c->buf_curr_seq -= go_back_bytes;
        if (stream_c->tx_next_pos >= go_back_bytes) {
            stream_c->tx_next_pos -= go_back_bytes;
        } else {
            stream_c->tx_next_pos = stream_c->tx_buf_size - (go_back_bytes - stream_c->tx_next_pos);
        }
    
        data_meta->rx.go_back_pos = stream_c->tx_next_pos;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(stream_c);
        data_meta->rx.rx_pos = POISON_32;
        data_meta->rx.poff = POISON_16;
        data_meta->rx.plen = POISON_16;
    
        if(ev_type == TIMER_EVENT) {
            data_meta->rx.qid = POISON_32;
            data_meta->rx.conn = c->opaque_connection;
            data_meta->rx.go_back_pos |= RECOVERY_MASK;
            data_meta->rx.ooo_bump = POISON_32;
        } else if(ev_type == NET_EVENT) {
            data_meta->rx.go_back_pos |= RECOVERY_MASK;
        }
    }
}

static __always_inline void mtp_pkt_gen_for_xdp_gen(struct TCPBP *bp, struct bpf_tcp_conn *c,  __u32 cpu) {
    struct bpf_tcp_ack *ack = NULL;
    __u32 prod = ack_prod[cpu];
    __u32 cons = ack_cons[cpu];

    // check if ack queue is full
    if (unlikely(cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1)))) {
        xdp_log_err("ack queue is full");
    } else {
        ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
        if (unlikely(!ack)) {
            xdp_log_err("ack is NULL");
            return;
        }
    }

    ack->local_ip = c->local_ip;
    ack->remote_ip = c->remote_ip;
    ack->local_port = bp->src_port;
    ack->remote_port = bp->dest_port;
    ack->seq = bp->seq_num;
    ack->ack = bp->ack_seq;
    ack->rxwnd = bp->rwnd_size;
    ack->is_ack = bp->is_ack;
    ack->ts_val = bp->ts_opt.desired_tx_ts;
    ack->ts_ecr = c->tx_next_ts;
    c->tx_next_ts = 0;

    ack_prod[cpu] = (ack_prod[cpu] + 1) & (NAPI_BATCH_SIZE - 1);
}

static __always_inline void mtp_tx_data_flush(struct bpf_tcp_conn *c, struct interm_out *int_out,
    __u32 rmlen, struct meta_info *data_meta, struct bpf_tcp_conn_per_stream *stream_c) {
    if(rmlen > 0 || xsk_budget_avail(stream_c)) {
        int_out->drop = 0;
        data_meta->rx.ack_bytes = rmlen;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(stream_c);
        data_meta->rx.rx_pos = POISON_32;
        data_meta->rx.poff = POISON_16;
        data_meta->rx.plen = POISON_16;
    }
}

static __always_inline void mtp_add_data_seg_wrapper(__u32 data_len, __u32 offset,
    struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    struct bpf_tcp_conn_per_stream *stream_c) {
    if(data_len || xsk_budget_avail(stream_c)) {
        int_out->drop = 0;
        data_meta->rx.rx_pos = offset;
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(stream_c);
        if (!data_len) {
            data_meta->rx.rx_pos = POISON_32;
            data_meta->rx.poff = POISON_16;
            data_meta->rx.plen = POISON_16;
        }
    }
}


static __always_inline struct app_timer_event parse_req_to_app_event(struct meta_info *data_meta) {
    struct app_timer_event ev;
    ev.type = APP_EVENT;
    //ev.data_size = data_meta->tx.plen;
    ev.data_size = data_meta->tx.tx_pending;
    return ev;
}

static __always_inline struct app_timer_event parse_req_to_timer_event(struct meta_info *data_meta) {
    struct app_timer_event ev;
    ev.type = TIMER_EVENT;
    return ev;
}

static __always_inline void parse_pkt_to_event(struct net_event *ev, struct tcphdr *tcph, struct iphdr *iph, struct tcp_timestamp_opt *ts_opt) {
    // 1 == NET_EVENT_ACK, 0 == NET_EVENT_DATA
    ev->minor_type = tcph->ack;
    ev->ack_seq = bpf_ntohl(tcph->ack_seq);
    ev->rwnd_size = bpf_ntohs(tcph->window);
    ev->seq_num = bpf_ntohl(tcph->seq);
    ev->data_len = bpf_ntohs(iph->tot_len) - (sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE);
    ev->ecn_mark = tcph->ece;
    ev->ts_ecr = bpf_ntohl(ts_opt->ts_ecr);
    ev->ts_val = bpf_ntohl(ts_opt->ts_val);
}

static __always_inline void send_ep (struct app_timer_event *ev, struct bpf_tcp_conn *c,
    struct interm_out *int_out, struct meta_info *data_meta, struct bpf_cc *cc, struct tcphdr *tcph,
    struct iphdr *iph, void *data_end, struct TCPBP *bp, struct bpf_tcp_conn_per_stream *stream_c) {

    bpf_printk("SEND_EP");
    stream_c->data_end += ev->data_size;

    bp->src_port = c->local_port;
    bp->dest_port = c->remote_port;
    bp->seq_num = stream_c->tx_next_seq;
    bp->is_ack = false;

    // TODO: add other values to BP and add default values
    bp->ack_seq = stream_c->rx_next_seq;
    bp->rwnd_size = stream_c->rx_avail;

    __u64 ns_delta = (__u64)1000000000 * ev->data_size / cc->rate;
    __u64 desired_tx_ts = cc->prev_desired_tx_ts + ns_delta;
    desired_tx_ts = max(ev->timestamp, desired_tx_ts);
    cc->prev_desired_tx_ts = desired_tx_ts;
    bp->ts_opt.desired_tx_ts = desired_tx_ts;

    // Note: I am abstracting the seg_data and pkt_gen_instr in this function.
    // The 5th argument is the second argument of seg_data (the length)
    mtp_pkt_gen_wrapper(SEG_DATA, bp, c, tcph, iph, data_end, ev->data_size, 0, 0, data_meta, stream_c);

    stream_c->tx_next_seq += ev->data_size;

    cc->txp = stream_c->tx_next_seq != stream_c->send_una;

    // TODO: add functions to initialize timers
}

static __always_inline void following_pkts (struct TCPBP *bp, struct bpf_tcp_conn *c, struct meta_info *data_meta,
    struct bpf_cc *cc, struct tcphdr *tcph, struct iphdr *iph, __u32 ref_ts, void *data_end, struct bpf_tcp_conn_per_stream *stream_c) {
    
    __u64 ns_delta = (__u64)1000000000 * data_meta->tx.plen / cc->rate;
    __u64 desired_tx_ts = cc->prev_desired_tx_ts + ns_delta;
    desired_tx_ts = max(ref_ts, desired_tx_ts);
    cc->prev_desired_tx_ts = desired_tx_ts;
    bp->ts_opt.desired_tx_ts = desired_tx_ts;

    stream_c->buf_curr_seq += data_meta->tx.plen;
    stream_c->tx_next_pos += data_meta->tx.plen;
    if (stream_c->tx_next_pos >= stream_c->tx_buf_size)
        stream_c->tx_next_pos -= stream_c->tx_buf_size;

    mtp_fill_tcp_hdr(tcph, c, data_end, 0, bp);
    fill_ip_hdr(iph, data_meta->tx.plen, c->ecn_enable);

    bp->seq_num += data_meta->tx.plen;

    cc->txp = stream_c->tx_next_seq != stream_c->send_una;
}


static __always_inline int ack_timeout_xdp_ep (struct app_timer_event *ev, struct bpf_tcp_conn *c,
    struct interm_out *int_out, struct meta_info *data_meta, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {

    if (stream_c->tx_next_seq == stream_c->send_una) {
        return XDP_DROP;
    }

    __u32 go_back_bytes = stream_c->tx_next_seq - stream_c->send_una;

    /* reset flow state as if we never transmitted those segments */
    stream_c->rx_dupack_cnt = 0;

    stream_c->tx_next_seq -= go_back_bytes;

    //c->tx_pending = 0;
    stream_c->rx_remote_avail += go_back_bytes;

    cc->txp = 0;

    stream_c->data_end -= go_back_bytes;

    /* cut rate by half if first drop in control interval */
    if (cc->cnt_tx_drops == 0) {
        cc->rate >>= 1;
    }

    cc->cnt_tx_drops++;

    // Question IMPORTANT:
    // In MTP, when we want to retransmit the packet with unseg_data,
    // we specify that it should retransmit from send_una.
    // However, in eTran we have to send the position in the TX buffer
    // that should start retransmitting from (tx_next_pos).
    // To get this position, we have to know how many go_back_bytes
    // we have to decrease the position.
    // We can obtain the go_back_bytes from send_next - send_una.
    // But, in unseg_data/pkt_gen_instr we just specify send_una as
    // one the arguments. So, how can we get the go_back_bytes to
    // get tx_next_pos?
    // (This whole thing is a problem because we want to abstract tx_next_pos)
    // A: photo

    // Question:
    // Can we simply ignore pkt_bp when it is generated for retransmission?
    // In the end, the userspace won't use it in any way and a pkt_bp will be
    // generated when it regenerates the packet
    // A: ignore for now

    // Question:
    // I would like to have this function that wraps the code that eTran uses
    // for packet retransmission and translate from a pkt_gen_instr.
    // But would the compiler be able to know it is for a retransmission?
    // A: have a single wrapper and use buf_cur_seq for the decision and see if it is alligned
    struct TCPBP bp = {0};
    mtp_pkt_gen_wrapper(UNSEG_DATA, &bp, c, NULL, NULL, NULL, 0, stream_c->send_una, TIMER_EVENT, data_meta, stream_c);
    return XDP_PASS; // redirect to userspace
}

static __always_inline void fast_retr_rec_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {

    int_out->drop = 1;

    __u32 exp_ack_first = stream_c->send_una;
    __u32 exp_ack_last = stream_c->tx_next_seq;

    // allow receving ack that we haven't sent yet, this is probably caused by retransmission
    //exp_ack_last += c->tx_pending;
    
    if (exp_ack_first <= exp_ack_last) {
        if (ev->ack_seq < exp_ack_first || ev->ack_seq > exp_ack_last) {
            return;
        }
        int_out->num_acked_bytes = ev->ack_seq - exp_ack_first;
    } else {
        if (exp_ack_first > ev->ack_seq && ev->ack_seq > exp_ack_last) {
            return;
        }
        int_out->num_acked_bytes = ev->ack_seq - exp_ack_first;
    }
    
    // Redirect it to userspace
    int_out->drop = 0;

    cc->cnt_rx_ack_bytes += int_out->num_acked_bytes;
    if(ev->ecn_mark)
        cc->cnt_rx_ecn_bytes += int_out->num_acked_bytes;

    cc->txp = stream_c->tx_next_seq != stream_c->send_una;

    int_out->change_cwnd = 1;

    __u32 go_back_bytes = 0;
    if(int_out->num_acked_bytes) {
        stream_c->rx_dupack_cnt = 0;
    }
    else if((stream_c->rx_remote_avail == (ev->rwnd_size << TCP_WND_SCALE)) && ++stream_c->rx_dupack_cnt == 3) {
        int_out->change_cwnd = 0;

        go_back_bytes = stream_c->tx_next_seq - stream_c->send_una;

        stream_c->tx_next_seq -= go_back_bytes;

        // Question: this section of code isn't covered in MTP (is used by the other parts of the code)
        // If everything works out by adding our EPs, we can remove this part safely
        //c->tx_pending = 0;
        stream_c->rx_remote_avail += go_back_bytes;
        cc->txp = 0;

        stream_c->data_end -= go_back_bytes;

        if(cc->cnt_tx_drops == 0) {
            cc->rate >>= 1;
        }

        cc->cnt_tx_drops++;
        // Question IMPORTANT: in MTP we would have a set_rate function here.
        // But this rate would only be used in XDP_EGRESS and enqueueing the packets to the timing wheel
        // Can we consider the compiler would simply ignore the function?
    }

    //int_out->go_back_bytes = go_back_bytes;
    //c->send_una = ev->ack_seq;
}

static __always_inline void ack_net_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {

    if(stream_c->rx_dupack_cnt == 3) {
        int_out->drop = 0;
        stream_c->rx_dupack_cnt = 0;

        // Question IMPORTANT:
        // Similar to the problem before, here we also specify the go_back_pos,
        // but in MTP we give send_una
        struct TCPBP bp = {0};
        mtp_pkt_gen_wrapper(UNSEG_DATA, &bp, c, NULL, NULL, NULL, 0, stream_c->send_una, NET_EVENT, data_meta, stream_c);

        return;
    }

    if(!int_out->drop) {
        if(int_out->num_acked_bytes || stream_c->rx_remote_avail < (ev->rwnd_size << TCP_WND_SCALE))
            stream_c->rx_remote_avail = ev->rwnd_size << TCP_WND_SCALE;
        
        if(ev->ts_ecr && int_out->num_acked_bytes) {
            __u32 now = bpf_ktime_get_ns();
            __u32 rtt = (now - ev->ts_ecr);
            rtt /= 1000; // microseconds
            rtt -= (int_out->num_acked_bytes * 1000000) / LINK_BANDWIDTH;
            // bpf_printk("CPU#%u, RTT: %u us", bpf_get_smp_processor_id(), rtt);
            if (rtt < TCP_MAX_RTT) {
                if (cc->rtt_est)
                    cc->rtt_est = (cc->rtt_est * 7 + rtt) / 8;
                else
                    cc->rtt_est = rtt;
            }
        }
    }
    
    /*__u32 data_rest = c->data_end - c->tx_next_seq;
    if(data_rest == 0 && ev->ack_seq == c->tx_next_seq) {
        // TODO: add cancel timer functions?
        return;
    }*/

    __u32 rmlen = int_out->num_acked_bytes;
    if(rmlen > 0) {
        stream_c->send_una = ev->ack_seq;
    }
    // Question IMPORTANT:
    // Is it okay to assume that tx_data_flush can be converted
    // into the code that notifies ACKs to the app?
    // The problem is that eTran also does that in case xsk_budget_avail(c, ev->stream_id)
    mtp_tx_data_flush(c, int_out, rmlen, data_meta, stream_c);

}

static __always_inline void verify_trim_data_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {
    int_out->skip_data_eps = false;
    int_out->drop = true;
    int_out->trigger_ack = true;

    __u32 trim_start = 0;
    __u32 trim_end = 0;

    __u32 exp_seq_first = stream_c->rx_next_seq;
    __u32 exp_seq_last = stream_c->rx_next_seq + stream_c->rx_avail;
    __u32 pkt_seq_first = ev->seq_num;
    __u32 pkt_seq_last = ev->seq_num + ev->data_len;

    bool valid = seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false) ||
                    seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true) ||
                    seq_in_range(exp_seq_first, pkt_seq_first, pkt_seq_last, false) ||
                    seq_in_range(exp_seq_last, pkt_seq_first, pkt_seq_last, true);
    
    if (!valid) {
        int_out->skip_data_eps = true;
        int_out->trigger_ack = false;
        return;
    }

    if (seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false)) {
        trim_start = 0;
    } else {
        trim_start = exp_seq_first - pkt_seq_first;
    }

    if (seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true)) {
        trim_end = 0;
    } else {
        trim_end = pkt_seq_last - exp_seq_last;
    }

    __u32 payload_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE;
    payload_off += trim_start;
    if ((ev->data_len >= trim_start + trim_end))
        ev->data_len -= trim_start + trim_end;

    // Question:
    // How can we abstract this part? We depend on this trim_start
    data_meta->rx.poff = payload_off;

    // Question BUG:
    // This could be easily abstracted in mtp_add_data_seg_wrapper,
    // but the problem is that moving this line to that point, a segmentation
    // fault happens. The segmentation fault starts happening if we move it
    // to flush_ooo_data_ep, right after the first condition.
    // This problem doesn't make sense. I wonder if it might be a problem
    // with the eBPF virtual machine (like that mysterious enum problem we had).
    // I've started to wonder if this problem is related to the size of the variables,
    // plen being u16 and data_len being u32. But that doesn't seem to be the case
    data_meta->rx.plen = ev->data_len;

    ev->seq_num += trim_start;
}

static __always_inline void detect_ooo_data_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {
    
    if(int_out->skip_data_eps) {
        return;
    }

    if ((ev->seq_num != stream_c->rx_next_seq)) {
        if (!ev->data_len) {
            int_out->skip_data_eps = true;
            return;
        }
        if (stream_c->rx_ooo_len == 0) {
            stream_c->rx_ooo_start = ev->seq_num;
            stream_c->rx_ooo_len = ev->data_len;
        } else if (ev->seq_num + ev->data_len == stream_c->rx_ooo_start) {
            stream_c->rx_ooo_start = ev->seq_num;
            stream_c->rx_ooo_len += ev->data_len;
        } else if (stream_c->rx_ooo_start + stream_c->rx_ooo_len == ev->seq_num) {
            stream_c->rx_ooo_len += ev->data_len;
        } else {
            // unfortunately, we can't accept this payload
            ev->data_len = 0;
            // Question BUG:
            // Similar to the other problem, I can't remove this line
            // even if it doesn't matter in anyway. Also, simply having
            // this bpf_printk causes a segmentation fault. 
            //bpf_printk("HERE");
            data_meta->rx.plen = POISON_16;
        }
        // mark this packet is an out-of-order segment
        //data_meta->rx.ooo_bump = OOO_SEGMENT_MASK;
        int_out->skip_data_eps = true;
    }
}



static __always_inline void flush_ooo_data_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {
    
    // Question: this check is problematic in the client side
    /*if(int_out->skip_data_eps) {
        return;
    }*/
    __u32 trim_start = 0;
    __u32 trim_end = 0;

    if ((stream_c->rx_remote_avail < ev->rwnd_size << TCP_WND_SCALE)) {
        /* update TCP receive window */
        stream_c->rx_remote_avail = ev->rwnd_size << TCP_WND_SCALE;
    }
    /* update RTT estimate */
    if (ev->data_len && !c->tx_next_ts)
        c->tx_next_ts = ev->ts_val;

    /* update TCP state if we have payload */
    if (ev->data_len) {
        stream_c->rx_avail -= ev->data_len;
        stream_c->rx_next_seq += ev->data_len;

        /* handle existing out-of-order segments */
        if (stream_c->rx_ooo_len) {

            __u32 exp_seq_first = stream_c->rx_next_seq;
            __u32 exp_seq_last = stream_c->rx_next_seq + stream_c->rx_avail;
            __u32 pkt_seq_first = stream_c->rx_ooo_start;
            __u32 pkt_seq_last = stream_c->rx_ooo_start + stream_c->rx_ooo_len;
        
            bool valid = seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false) ||
                            seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true) ||
                            seq_in_range(exp_seq_first, pkt_seq_first, pkt_seq_last, false) ||
                            seq_in_range(exp_seq_last, pkt_seq_first, pkt_seq_last, true);
            
            if (!valid) {
                int_out->trigger_ack = false;
                return;
            } else {
                if (seq_in_range(pkt_seq_first, exp_seq_first, exp_seq_last, false)) {
                    trim_start = 0;
                } else {
                    trim_start = exp_seq_first - pkt_seq_first;
                }
            
                if (seq_in_range(pkt_seq_last, exp_seq_first, exp_seq_last, true)) {
                    trim_end = 0;
                } else {
                    trim_end = pkt_seq_last - exp_seq_last;
                }

                stream_c->rx_ooo_start += trim_start;
                stream_c->rx_ooo_len -= trim_start + trim_end;

                // accept out-of-order segments
                if (stream_c->rx_ooo_len && stream_c->rx_ooo_start == stream_c->rx_next_seq) {
                    stream_c->rx_avail -= stream_c->rx_ooo_len;
                    stream_c->rx_next_seq += stream_c->rx_ooo_len;
                    stream_c->rx_ooo_len = 0;
                    // out-of-order segment is processed
                    //data_meta->rx.ooo_bump = OOO_FIN_MASK;
                }
            }
        }

        /*if (unlikely((c->rx_avail >> TCP_WND_SCALE) == 0)) {
            data_meta->rx.qid |= FORCE_RX_BUMP_MASK;
        }*/
    }
}

static __always_inline void data_net_ep(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {
    
    mtp_add_data_seg_wrapper(ev->data_len, (ev->seq_num - stream_c->recv_init_seq), c, int_out, data_meta, stream_c);

}

static __always_inline void send_ack(struct net_event *ev, struct bpf_tcp_conn *c, struct interm_out *int_out, struct meta_info *data_meta,
    __u32 cpu, struct bpf_cc *cc, struct bpf_tcp_conn_per_stream *stream_c) {
    if(!int_out->trigger_ack) {
        return;
    }

    struct TCPBP bp;
    bp.src_port = c->local_port;
    bp.dest_port = c->remote_port;
    bp.seq_num = stream_c->tx_next_seq;
    bp.is_ack = 1;
    // TODO: maybe change to rx_next_seq, depending on how we implement the 
    bp.ack_seq = stream_c->rx_next_seq;
    bp.rwnd_size = stream_c->rx_avail;
    bp.ts_opt.desired_tx_ts = ev->timestamp;

    // Note: this function will be equivalent to pkt_gen_instruction when the pkt_bp
    // doesn't have data (goes to XDP_GEN)
    mtp_pkt_gen_for_xdp_gen(&bp, c, cpu);
}
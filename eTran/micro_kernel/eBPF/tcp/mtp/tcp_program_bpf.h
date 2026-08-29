#pragma once
/*
 * tcp_program_bpf.h -- the TCP program's eBPF half, in generated shape.
 *
 * Read as generated code, like the control path's mtp/tcp_program.h. This file
 * holds what the compiler emits for the sites that run in eBPF: the flow id as
 * the packet carries it, the parser that builds it, and the context store
 * instantiated over TCP's own map with TCP's own key type.
 *
 * Ported so far:  the ingress flow id, its parser, the context store, and the
 *                 RX event processing (tcp_ack + tcp_data).
 */

#include "mtp_target_bpf.h"   /* same directory */

/* ------------------------------------------------------------------ *
 * flow_id tcp_fid : (uint32, uint32, uint16, uint16)
 *
 * The eBPF side's id is `struct ebpf_flow_tuple` (intf_ebpf.h:190-195), which is
 * the SAME four values as the control path's flow_tuple in a different field
 * order and a different byte order. Two representations of one program-level
 * flow id, because the two sites keep their state in different containers -- a
 * target detail the program never sees.
 * ------------------------------------------------------------------ */
typedef struct ebpf_flow_tuple tcp_fid_bpf;

/*
 * net_parser: the id of the flow this packet belongs to, as seen from THIS host.
 * Host byte order, because that is what the map's keys are in.
 */
static __always_inline void tcp_fid_of_pkt_bpf(const struct iphdr *iph,
                                               const struct tcphdr *tcph,
                                               tcp_fid_bpf *out)
{
    out->local_ip    = bpf_ntohl(iph->daddr);
    out->remote_ip   = bpf_ntohl(iph->saddr);
    out->local_port  = bpf_ntohs(tcph->dest);
    out->remote_port = bpf_ntohs(tcph->source);
}

/* The context store for tcp_ctx's eBPF half (storage class (a)). */
MTP_DEFINE_CTX_STORE(tcp_bpf, tcp_fid_bpf, struct bpf_tcp_conn, bpf_tcp_conn_map)

/*
 * Which event is this packet?
 *
 * The classification MTP puts in the parser, and eTran already had as a guard:
 * SYN, SYN-ACK and RST are not fast-path events at all -- they are redirected to
 * the control path, where the ported tcp_syn / tcp_synack / tcp_rst processors
 * handle them. Everything else is an ACK and/or data, which is one call into
 * eTran's tcp_rx_process until those two events are split out.
 */
static __always_inline bool tcp_is_slow_path_event(const struct tcphdr *tcph)
{
    return is_tcp_syn(tcph) || is_tcp_syn_ack(tcph) || is_tcp_rst(tcph);
}

/* ------------------------------------------------------------------ *
 * scratchpad_t tcp_scratch { ... }
 *
 * MTP's scratchpad (paper §4): the values one event's processors hand to one
 * another, living only for that event. In the donor these were fifteen locals of
 * a single 290-line function; naming them is what makes the processor boundaries
 * below mean anything.
 * ------------------------------------------------------------------ */
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
    bool  trigger_ack;
    bool  clear_ooo;
    bool  drop;
};

/*
 * dispatch: tcp_ack -> { proc_ack, proc_fast_retransmit, proc_window, proc_rtt }
 *           tcp_data -> { proc_seq, proc_ooo, proc_recv, post_data, send_ack }
 *
 * WHY THIS IS ONE FUNCTION AND NOT TEN, AND WHAT THAT SAYS ABOUT THE DOC.
 *
 * The event documents present tcp_ack and tcp_data as two events with two
 * processor lists. eTran does not run them that way, and the difference is not
 * cosmetic: **the two lists interleave**. In execution order the code does
 *
 *     proc_ack / proc_fast_retransmit   (tcp_ack)
 *     proc_seq / proc_ooo               (tcp_data)
 *     proc_window / proc_rtt            (tcp_ack again)
 *     proc_recv                         (tcp_data)
 *     post_data, send_ack               (shared epilogue)
 *
 * so tcp_ack's window and RTT updates run AFTER tcp_data's sequence validation
 * and are skipped by its early exits -- a packet with a bad sequence number
 * never updates the window, even though the window is ACK state. Running the
 * doc's two lists one after the other would be a different program.
 *
 * The processors are therefore marked in place rather than extracted, and each
 * "goto" is preserved: they are the chain-termination MTP expresses as a guard
 * at the top of each subsequent processor. Extracting them is a real next step,
 * but it has to move the guards with them, and doing it in the same commit as
 * the scratchpad would make a behaviour change indistinguishable from a
 * refactor.
 *
 * Everything below is the donor's code with its locals moved into the
 * scratchpad. Nothing else changed.
 */
static __always_inline int dispatch_tcp_rx(struct tcphdr *tcph, struct bpf_tcp_conn *c,
                                           __u32 pkt_len, struct meta_info *data_meta,
                                           bool ece, __u32 cpu)
{
    /* scratchpad_t tcp_scratch -- the values this event's processors pass to one
     * another. In the donor these were fifteen locals of one 290-line function;
     * naming them as a scratchpad is what makes the processor boundaries below
     * mean anything. */
    struct tcp_scratch s = {0};
    s.trigger_ack = false;
    s.drop        = true;
    s.payload_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE;
    s.payload_len = pkt_len - s.payload_off;
    s.seq         = bpf_ntohl(tcph->seq);
    s.ack_seq     = bpf_ntohl(tcph->ack_seq);

    struct tcp_timestamp_opt *ts_opt = (struct tcp_timestamp_opt *)(tcph + 1);
    #ifndef ACK_COALESCING
    struct bpf_tcp_ack *ack = NULL;
    #endif

    if (!rx_cached_ts[cpu])
        s.now = bpf_ktime_get_ns();
    else
        s.now = rx_cached_ts[cpu];

    /* trigger an ACK if there is payload (even if we discard it) */
    if (s.payload_len) {
        s.trigger_ack = true;

        #ifndef ACK_COALESCING
        __u32 prod = ack_prod[cpu];
        __u32 cons = ack_cons[cpu];

        // check if ack queue is full
        if (unlikely(cons == ((prod + 1) & (NAPI_BATCH_SIZE - 1)))) {
            xdp_log_err("ack queue is full");
        } else {
            ack = bpf_map_lookup_elem(&bpf_tcp_ack_map, &prod);
            if (unlikely(!ack))
                xdp_log_err("ack is NULL");
        }
        #endif
    }

    struct bpf_cc *cc = bpf_map_lookup_elem(&bpf_cc_map, &c->cc_idx);
    if (unlikely(!cc)) {
        xdp_log_panic("cc is NULL, BUG!!!");
        return XDP_DROP;
    }

    TCP_LOCK(c);
    
    /* --- proc_ack + proc_fast_retransmit (EVENT-ACK 1.3) ------------------ */
    if (tcph->ack == 1) {
        // update CC
        cc->cnt_rx_acks++;
        if (likely(tcp_valid_rxack(c, s.ack_seq, &s.tx_bump)) == 0) {
            if (unlikely(s.tx_bump > c->tx_sent)) {
                s.tx_bump = 0;
                /* this is probably caused by retransmission */
                s.trigger_ack = false;
                goto unlock;
            }
            cc->cnt_rx_ack_bytes += s.tx_bump;
            if (unlikely(tcph->ece == 1))
                cc->cnt_rx_ecn_bytes += s.tx_bump;
            
            c->tx_sent -= s.tx_bump;
            cc->txp = c->tx_sent > 0;

            if (likely(s.tx_bump)) {
                c->rx_dupack_cnt = 0;
            } 
            /*
            * Fast retransmit -> detect a duplicate ACK if:
            * 1. The ACK number is the same as the largest seen: tcp_valid_rxack() returns 0
            * 2. There is unacknowledged data pending: tx_sent > 0
            * 3. There is no data payload included with the ACK: s.payload_len == 0
            * 4. There is no window update: c->rx_remote_avail == ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)
            */
            /* duplicate ack ? */
            else if (unlikely(c->tx_sent && s.payload_len == 0 && (c->rx_remote_avail == ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)) && ++c->rx_dupack_cnt == 3)) {
                s.go_back_pos = fast_retransmit(c, cc);
                xdp_log("Duplicate ACK triggers fast retransmission");
                goto unlock;
            }
        } else {
            s.trigger_ack = false;
            xdp_log_err("Bad ack");
            goto unlock;
        }
    }

    /* --- proc_seq + proc_ooo (EVENT-DATA 1.3) ----------------------------- */
    /* Payload validation */
    #ifdef OOO_RECV
    if (unlikely(tcp_valid_rxseq_ooo(c, s.seq, s.payload_len, &s.trim_start, &s.trim_end))) {
        s.trigger_ack = false;
        xdp_log_err("Bad seq");
        goto unlock;
    }

    s.payload_off += s.trim_start;
    if (likely(s.payload_len >= s.trim_start + s.trim_end))
        s.payload_len -= s.trim_start + s.trim_end;
    data_meta->rx.poff = s.payload_off;
    data_meta->rx.plen = s.payload_len;

    s.seq += s.trim_start;
    data_meta->rx.rx_pos = c->rx_next_pos + (s.seq - c->rx_next_seq);
    if (data_meta->rx.rx_pos >= c->rx_buf_size)
        data_meta->rx.rx_pos -= c->rx_buf_size;

    /* check if we can add it to the out of order interval */
    if (unlikely(s.seq != c->rx_next_seq)) {
        if (!s.payload_len) goto unlock;
        xdp_log("OOO packet, seq(%u), c->rx_next_seq(%u)", s.seq, c->rx_next_seq);
        if (c->rx_ooo_len == 0) {
            c->rx_ooo_start = s.seq;
            c->rx_ooo_len = s.payload_len;
            xdp_log("New segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (s.seq + s.payload_len == c->rx_ooo_start) {
            c->rx_ooo_start = s.seq;
            c->rx_ooo_len += s.payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else if (c->rx_ooo_start + c->rx_ooo_len == s.seq) {
            c->rx_ooo_len += s.payload_len;
            xdp_log("Merge segment, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        } else {
            // unfortunately, we can't accept this payload
            s.payload_len = 0;
            data_meta->rx.plen = POISON_16;
            xdp_log("Drop packet, ooo_start(%u), ooo_len(%u)", c->rx_ooo_start, c->rx_ooo_len);
        }
        // mark this packet is an out-of-order segment
        data_meta->rx.ooo_bump = OOO_SEGMENT_MASK;

        goto unlock;
    }

    #else
        if (unlikely(tcp_valid_rxseq(c, s.seq, s.payload_len, &s.trim_start, &s.trim_end))) {
            s.trigger_ack = false;
            xdp_log_err("Bad seq");
            goto unlock;
        }

        s.payload_off += s.trim_start;
        s.payload_len -= s.trim_start + s.trim_end;
        data_meta->rx.poff = s.payload_off;
        data_meta->rx.plen = s.payload_len;
        data_meta->rx.rx_pos = c->rx_next_pos;

        xdp_log("Good seq, payload_off(%u), payload_len(%u), trim_start(%u), trim_end(%u)", 
            s.payload_off, s.payload_len, s.trim_start, s.trim_end);

    #endif

    if (likely(s.tx_bump || (c->rx_remote_avail < ((bpf_ntohs(tcph->window)) << TCP_WND_SCALE)))) {
        /* --- proc_window (EVENT-ACK 1.3) --- */
        /* update TCP receive window */
        c->rx_remote_avail = (bpf_ntohs(tcph->window)) << TCP_WND_SCALE;
        // bpf_printk("(%u),ack_seq(%u), c->rx_remote_avail(%u), c->tx_sent(%u)", s.tx_bump, s.ack_seq, c->rx_remote_avail, c->tx_sent);
    }
    
    /* --- proc_rtt (EVENT-ACK 1.3) ----------------------------------------- */
    /* update RTT estimate */
    if (s.payload_len && !c->tx_next_ts)
        c->tx_next_ts = s.ts_val;
    if (likely(tcph->ack == 1 && s.ts_ecr && s.tx_bump)) {
        // RTT = t{completion} - t{sent} - t{serialization}
        __u32 rtt = (s.now - s.ts_ecr);
        rtt /= 1000; // microseconds
        rtt -= (s.tx_bump * 1000000) / LINK_BANDWIDTH;
        // bpf_printk("CPU#%u, RTT: %u us", bpf_get_smp_processor_id(), rtt);
        if (likely(rtt < TCP_MAX_RTT)) {
            if (likely(cc->rtt_est))
                cc->rtt_est = (cc->rtt_est * 7 + rtt) / 8;
            else
                cc->rtt_est = rtt;
        }
    }

    /* --- proc_recv (EVENT-DATA 1.3) --------------------------------------- */
    /* update TCP state if we have payload */
    if (likely(s.payload_len)) {
        s.rx_bump = s.payload_len;
        c->rx_avail -= s.payload_len;
        c->rx_next_pos += s.payload_len;
        if (c->rx_next_pos >= c->rx_buf_size)
            c->rx_next_pos -= c->rx_buf_size;
        c->rx_next_seq += s.payload_len;

        // xdp_log("seq(%u), payload_len(%u), c->rx_avail(%u), c->rx_next_pos(%u), c->rx_next_seq(%u)", s.seq, s.payload_len, c->rx_avail, c->rx_next_pos, c->rx_next_seq);
        
        /* handle existing out-of-order segments */
        if (unlikely(c->rx_ooo_len)) {
            if (tcp_valid_rxseq_ooo(c, c->rx_ooo_start, c->rx_ooo_len, &s.trim_start, &s.trim_end)) {
                /* completely superfluous: s.drop out of order interval */
                c->rx_ooo_len = 0;
                data_meta->rx.ooo_bump = OOO_CLEAR_MASK;
                s.trigger_ack = false;
                s.clear_ooo = true;
            } else {
                c->rx_ooo_start += s.trim_start;
                c->rx_ooo_len -= s.trim_start + s.trim_end;

                // accept out-of-order segments
                if (c->rx_ooo_len && c->rx_ooo_start == c->rx_next_seq) {
                    xdp_log("c->rx_ooo_len(%u), c->rx_ooo_start(%u), c->rx_next_seq(%u)", c->rx_ooo_len, c->rx_ooo_start, c->rx_next_seq);
                    s.rx_bump += c->rx_ooo_len;
                    c->rx_avail -= c->rx_ooo_len;
                    c->rx_next_pos += c->rx_ooo_len;
                    if (c->rx_next_pos >= c->rx_buf_size)
                        c->rx_next_pos -= c->rx_buf_size;
                    c->rx_next_seq += c->rx_ooo_len;

                    c->rx_ooo_len = 0;
                    // out-of-order segment is processed
                    data_meta->rx.ooo_bump = OOO_FIN_MASK;
                    xdp_log("Out-of-order segment is processed");
                }
            }
        }

        if (unlikely((c->rx_avail >> TCP_WND_SCALE) == 0)) {
            // ebpf realized that the receive buffer is empty,
            // piggyback a signal to lib, once application releases the buffer, force it sync with us
            data_meta->rx.qid |= FORCE_RX_BUMP_MASK;
            // bpf_printk("force");
        }
        // bpf_printk("c->rx_avail = %u", c->rx_avail);
    }

unlock:

    /* --- post_data (EVENT-DATA 1.3): the epilogue both events share ------- */
    /* redirect this packet to userspace */
    if (likely(s.rx_bump || s.tx_bump || s.go_back_pos || xsk_budget_avail(c)) || s.clear_ooo) {
        s.drop = false;
        
        data_meta->rx.xsk_budget_avail = xsk_budget_avail(c);
        xdp_log("xsk_budget_avail(%u)", data_meta->rx.xsk_budget_avail);
        if (s.tx_bump)
            data_meta->rx.ack_bytes = s.tx_bump;
        else if (unlikely(s.go_back_pos)) {
            xdp_log("go_back_pos(%u)", s.go_back_pos);
            data_meta->rx.go_back_pos = s.go_back_pos;
            data_meta->rx.go_back_pos |= RECOVERY_MASK;
        }

        if (!s.payload_len) {
            data_meta->rx.rx_pos = POISON_32;
            data_meta->rx.poff = POISON_16;
            data_meta->rx.plen = POISON_16;
            goto out;
        }

        if (unlikely(data_meta->rx.ooo_bump & OOO_FIN_MASK)) {
            /* piggyback s.rx_bump */
            data_meta->rx.ooo_bump |= s.rx_bump;
        }

    }

out:

    if (s.trigger_ack) {
        // TODO
        xdp_log("trigger_ack");
        #ifdef ACK_COALESCING
        // make verifier happy
        if (likely(cpu < MAX_CPU) && prev_conn[cpu] == NULL_CONN) {
            prev_conn[cpu] = c->cc_idx;
            prev_conn_li[cpu] = c->local_ip;
            prev_conn_lp[cpu] = c->local_port;
            prev_conn_ri[cpu] = c->remote_ip;
            prev_conn_rp[cpu] = c->remote_port;
            prev_conn_ece[cpu] |= ece;
        }
        #else
        if (likely(cpu < MAX_CPU && ack)) {
            enqueue_ack(c, ack, cpu, s.now, ece);
        }
        #endif
    }
    TCP_UNLOCK(c);

    return s.drop ? XDP_DROP : XDP_REDIRECT;
}


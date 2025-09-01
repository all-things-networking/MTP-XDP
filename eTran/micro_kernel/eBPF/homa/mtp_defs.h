#define MTP_ON 1

#define ceil DIV_ROUND_UP

#define NEW_RX_ORDERED_DATA 1
#define ADD_RX_DATA_SEG     2

struct ack_net_info {
    __u64 rpcid;
    __u16 sport;
    __u16 dport;
    __u32 remote_ip;
};

struct hkey
{
    __u64 rpcid;
    __u16 local_port;
    __u16 remote_port;
    __u32 remote_ip;
};

struct net_event {
    struct hkey flow_id;

    // Common header
    __u8 type;
    __u16 seq;

    // Data header
    __u32 message_length;
    __u32 incoming;
    __u8 retransmit;
    __u32 segment_length;

    // Grant/Resend header
    __u32 offset;
    __u8 priority;

    // Grant header
    __u8 resend_all;

    // Resend header
    __u32 length;
};

struct app_event {
    __u32 local_ip;
    __u32 remote_ip;
    __u32 msg_len;
    __u64 addr;
    __u16 src_port;
    __u16 dest_port;
    __u64 rpcid;
};

struct HOMA_ACK {
    __be64 rpcid;
    __be16 sport;
    __be16 dport;
};

struct DATA_SEG {
    __be32 offset;
    __be32 segment_length;
    struct HOMA_ACK ack;
};

struct DATA_HDR {
    __be32 message_length;
    __be32 incoming;
    __be16 cutoff_version;
    __u8 retransmit;
    struct DATA_SEG seg;
};

struct COMMON_HDR {
    __be16 src_port;
    __be16 dest_port;
    __u8 doff;
    __u8 type;
    __u16 seq;
    __be64 sender_id;
};

struct HOMABP {
    struct COMMON_HDR common;
    struct DATA_HDR data;
};

struct GRANT_HDR {
    __be32 offset;
    __u8 priority;
    __u8 resend_all;
};

struct HOMABP_GEN {
    struct COMMON_HDR common;
    struct GRANT_HDR grant;
};


struct interm_out {
    __u8 type_pkt;
    bool complete;
    bool new_state;
    bool need_schedule;
    bool dup_data_pkt;
    __u32 last_bytes_remaining;
    bool last_grant;
    bool send_fifo_rpc;
    bool trigger;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rpc_key_t);
    __type(value, struct HOMABP);
    __uint(max_entries, MAX_RPC_TBL_SIZE);
} pkt_bp_tbl SEC(".maps");


static __always_inline
int get_context_mtp_egress(struct app_event * ev, struct rpc_state **state) {
    struct rpc_key_t hkey = {0};
    hkey.local_port = ev->src_port;
    hkey.remote_port = bpf_ntohs(ev->dest_port);
    hkey.rpcid = ev->rpcid;
    hkey.remote_ip = bpf_ntohl(ev->remote_ip);

    *state = bpf_map_lookup_elem(&rpc_tbl, &hkey);
    if(!(*state)) {
        struct rpc_state new_state = {0};
        new_state.local_port = hkey.local_port;
        bpf_map_update_elem(&rpc_tbl, &hkey, &new_state, BPF_NOEXIST);
        *state = bpf_map_lookup_elem(&rpc_tbl, &hkey);
        if(!(*state)) {
            bpf_printk("Error get_context_mtp_egress");
            return 0;
        }
    }
    return 1;
}

static __always_inline
int get_pkt_bp_mtp(struct app_event * ev, struct HOMABP **bp) {
    struct rpc_key_t hkey = {0};
    hkey.local_port = ev->src_port;
    hkey.remote_port = bpf_ntohs(ev->dest_port);
    hkey.rpcid = ev->rpcid;
    hkey.remote_ip = bpf_ntohl(ev->remote_ip);

    *bp = bpf_map_lookup_elem(&pkt_bp_tbl, &hkey);
    if(!(*bp)) {
        struct HOMABP new_bp = {0};
        new_bp.common.seq = 0;
        bpf_map_update_elem(&pkt_bp_tbl, &hkey, &new_bp, BPF_NOEXIST);
        *bp = bpf_map_lookup_elem(&pkt_bp_tbl, &hkey);
        if(!(*bp)) {
            bpf_printk("Error get_pkt_bp_mtp");
            return 0;
        }
    }
    return 1;
}

// Question: if we don't use BP to fill the initial context
// values, what should we use?
static __always_inline
void new_ctx_instr_wrapper(struct rpc_state *ctx, struct app_event *ev, bool first_packet, bool client) {
    if (first_packet) {
        if(client) {
            /* create a new RPC state */
            ctx->state = BPF_RPC_OUTGOING;
            ctx->message_length = ev->msg_len;
            //ctx->next_xmit_offset = bpf_ntohl(bp->data.seg.segment_length);
            ctx->next_xmit_offset = min(ev->msg_len, Homa_unsched_bytes);
            ctx->buffer_head = ev->addr;
            ctx->remote_port = ev->dest_port;
            ctx->local_port = ev->src_port;
            ctx->remote_ip = bpf_ntohl(ev->remote_ip);
            ctx->id = ev->rpcid;
            ctx->cc.granted = min(ev->msg_len, Homa_unsched_bytes);
            ctx->qid = MAX_BUCKET_SIZE;
        } else {
            /* first received response packet */
            ctx->state = BPF_RPC_OUTGOING;
            ctx->message_length = ev->msg_len;
            //ctx->next_xmit_offset = bpf_ntohl(bp->data.seg.segment_length);
            ctx->next_xmit_offset = min(ev->msg_len, Homa_unsched_bytes);
            ctx->buffer_head = ev->addr;
            ctx->nr_pkts_in_rl = 0;
            ctx->cc.sched_prio = 0;
            ctx->cc.granted = min(ev->msg_len, Homa_unsched_bytes);
            ctx->qid = MAX_BUCKET_SIZE;
        }
    }
}

static __always_inline
void pkt_gen_instr_data_wrapper(struct data_header *d, struct HOMABP *bp) {
    d->common.sport = bp->common.src_port;
    d->common.dport = bp->common.dest_port;
    d->common.doff = bp->common.doff;
    d->common.type = bp->common.type;
    d->common.seq = bp->common.seq;
    d->common.sender_id = bp->common.sender_id;

    d->message_length = bp->data.message_length;
    d->retransmit = bp->data.retransmit;
    d->incoming = bp->data.incoming;
    d->cutoff_version = bp->data.cutoff_version;

    d->seg.offset = bp->data.seg.offset;
    d->seg.segment_length = bp->data.seg.segment_length;

    d->seg.ack.rpcid = bp->data.seg.ack.rpcid;
    d->seg.ack.sport = bp->data.seg.ack.sport;
    d->seg.ack.dport = bp->data.seg.ack.dport;

    // Update BP
    __u32 temp_len = bpf_ntohl(bp->data.seg.segment_length);
    __u32 temp_offset = bpf_ntohl(bp->data.seg.offset);
    temp_offset += temp_len;
    bp->data.seg.offset = bpf_htonl(temp_offset);

    __u16 temp_seq = bpf_ntohs(bp->common.seq);
    temp_seq += 1;
    bp->common.seq = bpf_htons(temp_seq);
}

static __always_inline
void new_tx_ordered_data_wrapper(__u32 msg_len, struct rpc_state *ctx) {
    ctx->new_rx_ord_data_msg_len = msg_len;
}


/*static __always_inline
void sched_instr_wrapper(__u32 bytes_remaining, struct rpc_state *ctx) {
    ctx->bytes_remaining = bytes_remaining;
}*/
 
static __always_inline
int send_req_ep_client(struct data_header *d, struct iphdr *iph, struct app_event *ev, 
    struct rpc_state *ctx, struct HOMABP *bp, struct interm_out *int_out, __u32 seg_len)
{

    bool first_packet = bpf_ntohs(bp->common.seq) == 0 ? 1 : 0;
    __u32 message_length = ev->msg_len;
    __u32 offset = bpf_ntohl(bp->data.seg.offset);
    __u32 packet_bytes = seg_len;
    bool single_packet = message_length <= HOMA_MSS;
    __u64 cc_granted = atomic_read(&ctx->cc.granted);

    if(first_packet) {

        new_tx_ordered_data_wrapper(message_length, ctx);

        new_ctx_instr_wrapper(ctx, ev, first_packet, true);

        //struct HOMABP bp;
        bp->common.src_port = bpf_htons(ev->src_port);
        bp->common.dest_port = ev->dest_port;
        bp->common.doff = 40 >> 2;
        bp->common.type = DATA;
        bp->common.seq = bpf_htons(0);
        bp->common.sender_id = bpf_cpu_to_be64(ev->rpcid);

        bp->data.message_length = bpf_htonl(ev->msg_len);
        bp->data.retransmit = 0;
        bp->data.incoming = 0;
        bp->data.cutoff_version = 0;

        bp->data.seg.offset = bpf_htonl(0);

        __u32 plen = ev->msg_len;
        if(plen > HOMA_MSS)
            plen = HOMA_MSS;
        bp->data.seg.segment_length = bpf_htonl(plen);

        bp->data.seg.ack.rpcid = 0;
        bp->data.seg.ack.dport = 0;
        bp->data.seg.ack.sport = 0;

        bp->data.incoming = bpf_htonl(cc_granted);

        if (likely(single_packet)) {
            set_prio(iph, HOMA_MAX_PRIORITY - 1);
            bp->data.incoming = bpf_htonl(message_length);
        }

        // Question: the priority is set also based on the length
        // of the segment. How should we represent that in MTP and here?
        if (offset + packet_bytes < Homa_unsched_bytes)
            set_prio(iph, get_prio(message_length));
        else
            set_prio(iph, atomic_read(&ctx->cc.sched_prio));

        pkt_gen_instr_data_wrapper(d, bp);

        //__u32 bytes_remaining = ev->msg_len - cc_granted;
        //sched_instr_wrapper(bytes_remaining, ctx);

        return XDP_TX;

    }

    bpf_printk("AQUIIIII %u %u", bpf_ntohs(bp->common.seq), bpf_ntohl(bp->data.seg.offset));

    bp->data.incoming = bpf_htonl(cc_granted);
    if (offset + packet_bytes < Homa_unsched_bytes)
        set_prio(iph, get_prio(message_length));
    else
        set_prio(iph, atomic_read(&ctx->cc.sched_prio));

    pkt_gen_instr_data_wrapper(d, bp);

    // TODO: debug here
    if (offset + packet_bytes <= ctx->next_xmit_offset && (atomic_read(&ctx->nr_pkts_in_rl) == 0 &&
        (packet_bytes <= Homa_min_throttled_bytes || check_nic_queue(packet_bytes)))) {
            
        //ctx->next_xmit_offset = offset + packet_bytes;
        return XDP_TX;
    }
    bpf_printk("HERE");

    struct rpc_state_cc *cc_node = NULL;
    struct rpc_state_cc *ref_cc_node = NULL;

    /* Unfortunately, we should enqueue this packet to rate limiter */
    atomic_inc(&ctx->nr_pkts_in_rl);

    if (unlikely(ctx->qid == MAX_BUCKET_SIZE))
    {
        /* this RPC has not been enqueued before */
        ctx->qid = allocate_qid();
        CHECK_AND_DROP_LOG(ctx->qid == MAX_BUCKET_SIZE, "client_request, allocate_qid failed.");

        /* we create the qid, so we need to create an object and enqueue it to throttle list */
        cc_node = bpf_obj_new(typeof(*cc_node));
        CHECK_AND_DROP_LOG(!cc_node, "client_request, bpf_obj_new failed.");
        
        cc_node->birth = bpf_ktime_get_ns();
        cc_node->hkey.rpcid = ctx->id;
        cc_node->hkey.local_port = ctx->local_port;
        cc_node->hkey.remote_ip = ctx->remote_ip;
        cc_node->hkey.remote_port = ctx->remote_port;
        cc_node->bytes_remaining = ctx->message_length - ctx->next_xmit_offset;
        ref_cc_node = bpf_refcount_acquire(cc_node);
        CHECK_AND_DROP_LOG(!ref_cc_node, "client_request, bpf_refcount_acquire failed.");

        THROTTLE_LOCK();
        
        /* insert ref pointer to throttle list */
        bpf_rbtree_add(&troot, &ref_cc_node->rbtree_link, srpt_less_pacer);
        atomic_inc(&nr_rpc_in_throttle);
        
        THROTTLE_UNLOCK();

        /* store pointer in map for future update */
        PUT_POINTER(cc_node, ctx);
    }

    int_out->trigger = cc_granted >= (offset + packet_bytes);

    return XDP_REDIRECT;
}

static __always_inline
int send_resp_ep_server(struct data_header *d, struct iphdr *iph, struct app_event *ev, 
    struct rpc_state *ctx, struct HOMABP *bp, struct interm_out *int_out, __u32 seg_len)
{

    bool first_packet = bp->common.seq == 0 ? 1 : 0;
    __u32 message_length = ev->msg_len;
    __u32 offset = bp->data.seg.offset;
    __u32 packet_bytes = seg_len;
    bool single_packet = message_length <= HOMA_MSS;
    __u64 cc_granted = atomic_read(&ctx->cc.granted);

    if(first_packet) {

        new_ctx_instr_wrapper(ctx, ev, first_packet, false);

        bp->common.src_port = bpf_htons(ev->src_port);
        bp->common.dest_port = ev->dest_port;
        bp->common.doff = 40 >> 2;
        bp->common.type = DATA;
        bp->common.seq = bpf_htons(0);
        bp->common.sender_id = bpf_cpu_to_be64(ev->rpcid);

        bp->data.message_length = bpf_htonl(ev->msg_len);
        bp->data.retransmit = 0;
        bp->data.incoming = 0;
        bp->data.cutoff_version = 0;

        bp->data.seg.offset = bpf_htonl(0);

        __u32 plen = ev->msg_len;
        if(plen > HOMA_MSS)
            plen = HOMA_MSS;
        bp->data.seg.segment_length = bpf_htonl(plen);

        bp->data.seg.ack.rpcid = 0;
        bp->data.seg.ack.dport = 0;
        bp->data.seg.ack.sport = 0;

        bp->data.incoming = bpf_htonl(cc_granted);
        /* optimization for single-packet case */
        if (likely(single_packet)) {
            set_prio(iph, HOMA_MAX_PRIORITY - 1);
            bp->data.incoming = bpf_htonl(message_length);
        }

        if (offset + packet_bytes < Homa_unsched_bytes)
            set_prio(iph, get_prio(message_length));
        else
            set_prio(iph, atomic_read(&ctx->cc.sched_prio));

        pkt_gen_instr_data_wrapper(d, bp);
        return XDP_TX;
    }

    bp->data.incoming = bpf_htonl(cc_granted);
    if (offset + packet_bytes < Homa_unsched_bytes)
        set_prio(iph, get_prio(message_length));
    else
        set_prio(iph, atomic_read(&ctx->cc.sched_prio));

    pkt_gen_instr_data_wrapper(d, bp);

    if (offset + packet_bytes <= ctx->next_xmit_offset && (atomic_read(&ctx->nr_pkts_in_rl) == 0 &&
    (packet_bytes <= Homa_min_throttled_bytes || check_nic_queue(packet_bytes)))) {
        
        //ctx->next_xmit_offset = offset + packet_bytes;
        return XDP_TX;
    }

    struct rpc_state_cc *cc_node = NULL;
    struct rpc_state_cc *ref_cc_node = NULL;

    /* Unfortunately, we should enqueue this packet to rate limiter */
    atomic_inc(&ctx->nr_pkts_in_rl);

    if (unlikely(ctx->qid == MAX_BUCKET_SIZE))
    {
        /* this RPC has not been enqueued before */
        ctx->qid = allocate_qid();
        CHECK_AND_DROP_LOG(ctx->qid == MAX_BUCKET_SIZE, "server_response, allocate_qid failed.");

        /* we create the qid, so we need to create an object and enqueue it to throttle list */
        cc_node = bpf_obj_new(typeof(*cc_node));
        CHECK_AND_DROP_LOG(!cc_node, "server_response, bpf_obj_new failed.");


        cc_node->birth = bpf_ktime_get_ns();

        cc_node->hkey.rpcid = ctx->id;
        cc_node->hkey.local_port = ctx->local_port;
        cc_node->hkey.remote_ip = ctx->remote_ip;
        cc_node->hkey.remote_port = ctx->remote_port;
        cc_node->bytes_remaining = ctx->message_length - ctx->next_xmit_offset;
        ref_cc_node = bpf_refcount_acquire(cc_node);
        CHECK_AND_DROP_LOG(!ref_cc_node, "server_response, bpf_refcount_acquire failed.");

        THROTTLE_LOCK();
        
        /* insert ref pointer to throttle list */
        bpf_rbtree_add(&troot, &ref_cc_node->rbtree_link, srpt_less_pacer);
        atomic_inc(&nr_rpc_in_throttle);
        
        THROTTLE_UNLOCK();

        /* store pointer in map for future update */
        PUT_POINTER(cc_node, ctx);
    }
    int_out->trigger = cc_granted >= (offset + packet_bytes);

    return XDP_REDIRECT;
}


/*************** Network Events ****************/

static __always_inline void parse_data_hdr_mtp(struct common_header *c,
    void *data_end, struct net_event *ev) {

    struct data_header *d = (struct data_header *)c;
    if(d + 1 > data_end)
        return;

    ev->message_length = bpf_ntohl(d->message_length);
    ev->incoming = bpf_ntohl(d->incoming);
    ev->retransmit = d->retransmit;
    ev->segment_length = bpf_ntohl(d->seg.segment_length);
}

static __always_inline void parse_grant_hdr_mtp(struct common_header *c,
    void *data_end, struct net_event *ev) {

    struct grant_header *g = (struct grant_header *)c;
    if(g + 1 > data_end)
        return;

    ev->offset = bpf_ntohl(g->offset);
    ev->priority = g->priority;
    ev->resend_all = g->resend_all;
}

static __always_inline void parse_resend_hdr_mtp(struct common_header *c,
    void *data_end, struct net_event *ev) {

    struct resend_header *r = (struct resend_header *)c;
    if(r + 1 > data_end)
        return;

    ev->offset = bpf_ntohl(r->offset);
    ev->priority = r->priority;
    ev->length = bpf_ntohl(r->length);
}

static __always_inline int parse_packet_mtp(struct hdr_cursor *nh, struct iphdr *iph,
    void *data_end, struct net_event *ev) {

    struct common_header *homa_common_h = nh->pos;

    if (homa_common_h + 1 > data_end)
        return -1;

    ev->flow_id.remote_ip = bpf_ntohl(iph->saddr);

    ev->flow_id.local_port = bpf_ntohs(homa_common_h->dport);
    ev->flow_id.remote_port = bpf_ntohs(homa_common_h->sport);
    ev->type = homa_common_h->type;
    ev->seq = bpf_ntohs(homa_common_h->seq);
    ev->flow_id.rpcid = bpf_be64_to_cpu(homa_common_h->sender_id);

    switch(ev->type) {
        case DATA:
            parse_data_hdr_mtp(homa_common_h, data_end, ev);
            break;
        case GRANT:
            parse_grant_hdr_mtp(homa_common_h, data_end, ev);
            break;
        case RESEND:
            parse_resend_hdr_mtp(homa_common_h, data_end, ev);
            break;
        default:
            return -1;
    }

    return ev->type;
}

static __always_inline
int parse_ack_info(struct hdr_cursor *nh, void *data_end,
    struct ack_net_info *ack_info, __u32 remote_ip) {

    struct data_header *d = (struct data_header *)nh->pos;
    if(d + 1 > data_end)
        return 0;

    ack_info->rpcid = bpf_be64_to_cpu(d->seg.ack.rpcid);
    ack_info->dport = bpf_ntohs(d->seg.ack.dport);
    ack_info->sport = bpf_ntohs(d->seg.ack.sport);
    ack_info->remote_ip = remote_ip;
    return 1;
}

static __always_inline
int get_context_mtp(struct hkey key, struct rpc_state **state, bool *first_req) {
    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(key.rpcid);
    hkey.local_port = key.local_port;
    hkey.remote_port = key.remote_port;
    hkey.remote_ip = key.remote_ip;

    *state = bpf_map_lookup_elem(&rpc_tbl, &hkey);
    if(!(*state)) {
        *first_req = true;
        struct rpc_state new_state = {0};
        new_state.local_port = key.local_port;
        bpf_map_update_elem(&rpc_tbl, &hkey, &new_state, BPF_NOEXIST);
        *state = bpf_map_lookup_elem(&rpc_tbl, &hkey);
        if(!(*state)) {
            bpf_printk("Error get_context_mtp");
            return 0;
        }
    }
    return 1;
}


static __always_inline
void reclaim_rpc_mtp(struct ack_net_info ack_info, struct homa_meta_info *data_meta)
{
    struct rpc_state *delete_rpc_slot = NULL;
    __u64 del_rpcid = ack_info.rpcid;
    __u16 del_local_port = ack_info.dport;
    __u16 del_remote_port = ack_info.sport;
    
    if (del_rpcid == 0 && del_local_port == 0 && del_remote_port == 0)
        return;

    del_rpcid = local_id(del_rpcid);

    struct rpc_key_t delete_hkey = {0};
    delete_hkey.rpcid = del_rpcid;
    delete_hkey.local_port = del_local_port;
    delete_hkey.remote_port = del_remote_port;
    delete_hkey.remote_ip = ack_info.remote_ip;

    delete_rpc_slot = bpf_map_lookup_elem(&rpc_tbl, &delete_hkey);
    if (!delete_rpc_slot)
        return;

    RPC_LOCK(delete_rpc_slot);
    if (delete_rpc_slot->state == BPF_RPC_DEAD)
    {
        RPC_UNLOCK(delete_rpc_slot);
        return;
    }
    /* ensure that only we can delete it */
    delete_rpc_slot->state = BPF_RPC_DEAD;
    RPC_UNLOCK(delete_rpc_slot);
    
    data_meta->rx.reap_server_buffer_addr = delete_rpc_slot->buffer_head;
    
    if (delete_rpc_slot->qid != MAX_BUCKET_SIZE)
        free_qid(delete_rpc_slot->qid);

    /* free rpc_state_cc object if it exists */
    struct rpc_state_cc *cc_node = NULL;
    GET_POINTER(cc_node, delete_rpc_slot);
    if (cc_node)
        bpf_obj_drop(cc_node);

    bpf_map_delete_elem(&rpc_tbl, &delete_hkey);
    bpf_map_delete_elem(&pkt_bp_tbl, &delete_hkey);
}

// Question: for both of these functions I set some values
// that I added to RX metadata. Is this okay? Because the
// RX metadata is different in TCP
static __always_inline
void new_rx_ordered_data_wrapper(__u32 msg_len, struct homa_meta_info *data_meta, struct rpc_state *ctx) {
    data_meta->rx.msg_len = msg_len;
    ctx->new_rx_ord_data_msg_len = msg_len;
}

static __always_inline
void add_rx_data_seg_wrapper(__u32 seg_len, __u32 offset, struct homa_meta_info *data_meta, struct rpc_state *ctx) {
    data_meta->rx.seg_len = seg_len;
    data_meta->rx.offset = offset;
    if(data_meta->rx.msg_len == 0)
        data_meta->rx.msg_len = ctx->new_rx_ord_data_msg_len;
}

static __always_inline
int first_req_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out) {

    __u16 seq = ev->seq;
    __u32 message_length = ev->message_length;
    __u32 incoming = ev->incoming;
    __u64 seg_length = ev->segment_length;
    bool single_packet = ev->message_length <= HOMA_MSS;

    CHECK_AND_DROP_LOG(ev->retransmit, "server_request: retransmitted packet tries to create state.");

    RPC_LOCK(ctx);
    ctx->remote_ip = ev->flow_id.remote_ip;
    ctx->remote_port = ev->flow_id.remote_port;
    ctx->local_port = ev->flow_id.local_port;
    ctx->id = ev->flow_id.rpcid;
    ctx->state = BPF_RPC_INCOMING;
    if(single_packet)
        ctx->state = BPF_RPC_IN_SERVICE;

    // TODO: wrap sliding window into bitmap
    ctx->bit_width = ceil(message_length, HOMA_MSS);
    clear_all_bitmaps(ctx);
    set_bitmap(ctx, seq);

    ctx->message_length = message_length;
    ctx->cc.incoming = incoming;
    ctx->cc.bytes_remaining = message_length - seg_length;

    int_out->complete = single_packet;
    int_out->new_state = true;
    int_out->need_schedule = message_length > ctx->cc.incoming;
    int_out->last_bytes_remaining = message_length - seg_length;

    RPC_UNLOCK(ctx);

    __sync_fetch_and_add(&total_incoming, (__u64)(incoming - seg_length));

    new_rx_ordered_data_wrapper(ev->message_length, data_meta, ctx);

    add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta, ctx);

    /*
    if (int_out->complete) {
        // Question: I also wanted to have some kind of wrapper for
        // flush_and_notify, but there isn't enough space in RX metadata
        // for the signal. Any suggestions on how to do that?
        // flush_and_notify_wrapper();
        return XDP_REDIRECT;
    }

    //if (need_schedule)
    //    cache_this_rpc(hkey);

    if (!int_out->new_state || !int_out->need_schedule)
        return XDP_REDIRECT;


    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(ev->flow_id.rpcid);
    hkey.local_port = ev->flow_id.local_port;
    hkey.remote_port = ev->flow_id.remote_port;
    hkey.remote_ip = ev->flow_id.remote_ip;
    return insert_grant_list(ctx, &hkey, message_length);*/
    return XDP_REDIRECT;
}

static __always_inline
int next_req_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out) {

    __u16 seq = ev->seq;
    __u32 message_length = ev->message_length;
    __u32 incoming = ev->incoming;
    __u64 seg_length = ev->segment_length;

    RPC_LOCK(ctx);
    
    if (unlikely(ctx->state == BPF_RPC_DEAD))
    {
        RPC_UNLOCK(ctx);
        return XDP_DROP;
    }

    // Question: see how we can wrap sliding window to bitmap
    int complete = set_bitmap(ctx, seq);
    if (complete == 1) {
        ctx->state = BPF_RPC_IN_SERVICE;
    }
    else if (complete == -1)
    {
        RPC_UNLOCK(ctx);
        bpf_printk("set_bitmap failed, rpcid = %llu, seq = %u", ev->flow_id.rpcid, seq);
        return XDP_DROP;
    }
    
    if (incoming > ctx->cc.incoming)
        ctx->cc.incoming = incoming;

    int_out->complete = complete;
    
    int_out->last_bytes_remaining = ctx->cc.bytes_remaining;
    ctx->cc.bytes_remaining -= seg_length;
    
    int_out->need_schedule = message_length > ctx->cc.incoming;
    
    RPC_UNLOCK(ctx);
    
    __sync_fetch_and_sub(&total_incoming, (__u64)seg_length);

    add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta, ctx);

    /*if (int_out->complete)
        return XDP_REDIRECT;

    //if (need_schedule)
    //    cache_this_rpc(hkey);

    if (!int_out->new_state || !int_out->need_schedule)
        return XDP_REDIRECT;


    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(ev->flow_id.rpcid);
    hkey.local_port = ev->flow_id.local_port;
    hkey.remote_port = ev->flow_id.remote_port;
    hkey.remote_ip = ev->flow_id.remote_ip;
    return insert_grant_list(ctx, &hkey, message_length);*/
    return XDP_REDIRECT;
}

static __always_inline
int recv_resp_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out) {

    __u16 seq = ev->seq;
    __u32 message_length = ev->message_length;
    __u32 incoming = ev->incoming;
    __u64 seg_length = ev->segment_length;
    
    RPC_LOCK(ctx);

    if (unlikely(ctx->state == BPF_RPC_DEAD)) {
        RPC_UNLOCK(ctx);
        return XDP_DROP;
    }

    int_out->new_state = ctx->state == BPF_RPC_OUTGOING;

    bool single_packet = ev->message_length <= HOMA_MSS;
    
    if(likely(int_out->new_state)) {
        if (likely(single_packet)) 
        {
            /* ensure that only we can delete it */
            ctx->state = BPF_RPC_DEAD;

            add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta, ctx);
            RPC_UNLOCK(ctx);
            
            /* userspace will use this metadata to free buffers */
            data_meta->rx.reap_client_buffer_addr = ctx->buffer_head;

            /* if we allocate qid for this rpc, we need to free it */
            if (ctx->qid != MAX_BUCKET_SIZE)
                free_qid(ctx->qid);

            struct rpc_key_t hkey = {0};
            hkey.rpcid = local_id(ev->flow_id.rpcid);
            hkey.local_port = ev->flow_id.local_port;
            hkey.remote_port = ev->flow_id.remote_port;
            hkey.remote_ip = ev->flow_id.remote_ip;
            bpf_map_delete_elem(&rpc_tbl, &hkey);
            bpf_map_delete_elem(&pkt_bp_tbl, &hkey);
            
            enqueue_dead_crpc(hkey.remote_ip, hkey.remote_port, hkey.local_port, hkey.rpcid);

            int_out->complete = true;

            return XDP_REDIRECT;
        }
        
        ctx->state = BPF_RPC_INCOMING;
        ctx->bit_width = DIV_ROUND_UP(message_length, HOMA_MSS);
        
        clear_all_bitmaps(ctx);

        set_bitmap(ctx, seq);

        ctx->message_length = message_length;
        ctx->cc.incoming = incoming;
        
        ctx->cc.bytes_remaining = message_length - seg_length;
        int_out->last_bytes_remaining = ctx->cc.bytes_remaining;

        add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta, ctx);
        RPC_UNLOCK(ctx);

        __sync_fetch_and_add(&total_incoming, (__u64)(incoming - seg_length));

        /* free rpc_state_cc object if it exists (used for pacing before) */
        struct rpc_state_cc *cc_node = NULL;
        GET_POINTER(cc_node, ctx);
        if (cc_node)
            bpf_obj_drop(cc_node);
    } else {
        int complete = set_bitmap(ctx, seq);
        int_out->complete = complete;
        if (complete == -1)
        {
            RPC_UNLOCK(ctx);
            bpf_printk("set_bitmap failed, rpcid = %llu, seq = %u", ev->flow_id.rpcid, seq);
            return XDP_DROP;
        }
        if (incoming > ctx->cc.incoming)
            ctx->cc.incoming = incoming;

        int_out->last_bytes_remaining = ctx->cc.bytes_remaining;
        ctx->cc.bytes_remaining -= seg_length;

        add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta, ctx);
        if (int_out->complete == 1)
        {   /* all response packets have been received */
            ctx->state = BPF_RPC_DEAD;
            RPC_UNLOCK(ctx);
            /* userspace will use this metadata to free buffers */
            data_meta->rx.reap_client_buffer_addr = ctx->buffer_head;

            /* if we allocate qid for this rpc, we need to free it */
            if (ctx->qid != MAX_BUCKET_SIZE)
                free_qid(ctx->qid);

            struct rpc_key_t hkey = {0};
            hkey.rpcid = local_id(ev->flow_id.rpcid);
            hkey.local_port = ev->flow_id.local_port;
            hkey.remote_port = ev->flow_id.remote_port;
            hkey.remote_ip = ev->flow_id.remote_ip;
            enqueue_dead_crpc(hkey.remote_ip, hkey.remote_port, hkey.local_port, hkey.rpcid);

            /* note: after we delete the rpc state, our CC object may still be in the grant_list, 
                * but it would be finally removed, don't worry about it 
                */
            bpf_map_delete_elem(&rpc_tbl, &hkey);
            bpf_map_delete_elem(&pkt_bp_tbl, &hkey);

            return XDP_REDIRECT;
        }
        
        RPC_UNLOCK(ctx);
        
        __sync_fetch_and_sub(&total_incoming, (__u64)seg_length);
    }

    int_out->need_schedule = message_length > ctx->cc.incoming;

    //if (need_schedule)
    //    cache_this_rpc(hkey);
    
    /*if (!int_out->new_state || !need_schedule)
        return XDP_REDIRECT;

    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(ev->flow_id.rpcid);
    hkey.local_port = ev->flow_id.local_port;
    hkey.remote_port = ev->flow_id.remote_port;
    hkey.remote_ip = ev->flow_id.remote_ip;
    return insert_grant_list(ctx, &hkey, message_length);*/

    return XDP_REDIRECT;
}

static __always_inline
int no_ctx_sched_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out) {
    
    if (int_out->complete)
        return XDP_REDIRECT;

    if (!int_out->need_schedule)
        return XDP_REDIRECT;

    
    struct rpc_state_cc *elem = NULL;
    struct rpc_state_cc *next_elem = NULL;
    struct rpc_state_cc *search_elem = NULL;
    struct rpc_state_cc *prio_elem = NULL;
    struct bpf_rb_node *rb_node = NULL;
    
    /* allocate new object for Tree0 */
    elem = bpf_obj_new(typeof(*elem));
    CHECK_AND_DROP_LOG(!elem, "server_request: bpf_obj_new failed.");
    /* allocate new object for Tree1 */
    prio_elem = bpf_obj_new(typeof(*prio_elem));
    if (unlikely(!prio_elem))
    {
        bpf_obj_drop(elem);
        return XDP_DROP;
    }
    /* use bpf_refcount_acquire rather than bpf_obj_new for better performance */
    search_elem = bpf_refcount_acquire(prio_elem);
    if (unlikely(!search_elem))
    {
        bpf_obj_drop(elem);
        bpf_obj_drop(prio_elem);
        return XDP_DROP;
    }

    next_elem = bpf_refcount_acquire(search_elem);
    if (unlikely(!next_elem))
    {
        bpf_obj_drop(elem);
        bpf_obj_drop(prio_elem);
        bpf_obj_drop(search_elem);
        return XDP_DROP;
    }

    elem->tree_id = 0;
    elem->peer_id = get_peerid(ev->flow_id.remote_ip);
    elem->bytes_remaining = int_out->last_bytes_remaining;
    elem->incoming = ev->incoming;
    elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
    elem->hkey.local_port = ev->flow_id.local_port;
    elem->hkey.remote_ip = ev->flow_id.remote_ip;
    elem->hkey.remote_port = ev->flow_id.remote_port;
    elem->message_length = ev->message_length;
    // Question: in MTP we use int_out.rpc_birth, but it isn't used anywhere else
    elem->birth = bpf_ktime_get_ns();
    elem->birth &= ~(__u64)1;

    GRANT_LOCK();
    bpf_rbtree_add(&groot, &elem->rbtree_link, srpt_less_rpc);

    search_elem->tree_id = 0;
    search_elem->peer_id = elem->peer_id;
    search_elem->bytes_remaining = 0;
    search_elem->hkey.rpcid = 0;
    search_elem->hkey.local_port = 0;
    search_elem->hkey.remote_port = 0;
    search_elem->hkey.remote_ip = 0;

    rb_node = bpf_rbtree_lower_bound(&groot, &search_elem->rbtree_link, srpt_less_rpc);
    if (unlikely(!rb_node))
    {   /* this should never happen */
        GRANT_UNLOCK();
        bpf_obj_drop(prio_elem);
        prio_elem = NULL;
        search_elem = NULL;
        goto out;
    }
    else
    {
        struct rpc_state_cc * highest_prio = container_of(rb_node, struct rpc_state_cc, rbtree_link);
        //search_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
        if (unlikely(highest_prio->tree_id != 0 || highest_prio->peer_id != elem->peer_id))
        {   /* this should never happen */
            GRANT_UNLOCK();
            bpf_obj_drop(prio_elem);
            prio_elem = NULL;
            search_elem = NULL;
            goto out;
        } else if(highest_prio->hkey.rpcid == elem->hkey.rpcid &&
            highest_prio->hkey.local_port == elem->hkey.local_port &&
            highest_prio->hkey.remote_port == elem->hkey.remote_port &&
            highest_prio->hkey.remote_ip == elem->hkey.remote_ip){

            next_elem->tree_id = 0;
            next_elem->peer_id = elem->peer_id;
            next_elem->bytes_remaining = elem->bytes_remaining;
            next_elem->hkey.rpcid = elem->hkey.rpcid;
            next_elem->hkey.local_port = elem->hkey.local_port;
            next_elem->hkey.remote_port = elem->hkey.remote_port;
            next_elem->hkey.remote_ip = elem->hkey.remote_ip + 1;

            rb_node = bpf_rbtree_lower_bound(&groot, &next_elem->rbtree_link, srpt_less_rpc);
            if (rb_node)
            {
                next_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                if (next_elem->tree_id != 0 || next_elem->peer_id != elem->peer_id){
                //if (next_elem->tree_id == 0 && next_elem->peer_id == elem->peer_id){
                    if(int_out->new_state || !(highest_prio->birth & 1)) { // lowest bit of birth 1 means it is in peer tree) 
                        
                        prio_elem->tree_id = 1;
                        prio_elem->peer_id = elem->peer_id;
                        prio_elem->bytes_remaining = elem->bytes_remaining;
                        prio_elem->incoming = ev->incoming;
                        prio_elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
                        prio_elem->hkey.local_port = ev->flow_id.local_port;
                        prio_elem->hkey.remote_ip = ev->flow_id.remote_ip;
                        prio_elem->hkey.remote_port = ev->flow_id.remote_port;
                        prio_elem->message_length = ev->message_length;
                        elem->birth |= (__u64)1;
                        prio_elem->birth = elem->birth;

                        bpf_rbtree_add(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                        prio_elem = NULL;
                    }

                } else {
                    /* use prio_elem to search and remove it from Tree1 */
                    prio_elem->tree_id = 1;
                    prio_elem->peer_id = next_elem->peer_id;
                    prio_elem->bytes_remaining = next_elem->bytes_remaining;
                    rb_node = bpf_rbtree_lower_bound(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                    if (rb_node)
                    {
                        prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                        if (prio_elem->tree_id == 1 && prio_elem->peer_id == next_elem->peer_id)
                        {
                            rb_node = bpf_rbtree_remove(&groot, &prio_elem->rbtree_link);
                            if (rb_node)
                            {
                                prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                                /* update incoming from Tree1 here as it may be modified */
                                next_elem->birth &= ~(__u64)1;
                                next_elem->incoming = prio_elem->incoming;

                                prio_elem->tree_id = 1;
                                prio_elem->peer_id = elem->peer_id;
                                prio_elem->bytes_remaining = elem->bytes_remaining;
                                prio_elem->incoming = ev->incoming;
                                prio_elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
                                prio_elem->hkey.local_port = ev->flow_id.local_port;
                                prio_elem->hkey.remote_ip = ev->flow_id.remote_ip;
                                prio_elem->hkey.remote_port = ev->flow_id.remote_port;
                                prio_elem->message_length = ev->message_length;
                                /* mark this rpc is in Tree1 */
                                elem->birth |= (__u64)1;
                                prio_elem->birth = elem->birth;
                
                                bpf_rbtree_add(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                                prio_elem = NULL;
                            }
                            else { /* this should never happen */
                                prio_elem = NULL;
                            }
                        }
                        else { /* this should never happen */
                            prio_elem = NULL;
                        }
                    }
                    else { /* this should never happen */
                        prio_elem = NULL;
                    }
                }
            }
            next_elem = NULL;
            search_elem = NULL;
        } else {
            search_elem = NULL;
        }
    }

    GRANT_UNLOCK();
out:
    if (prio_elem)
        bpf_obj_drop(prio_elem);
    if (search_elem)
        bpf_obj_drop(search_elem);
    if (next_elem)
        bpf_obj_drop(next_elem);
    
    return XDP_REDIRECT;
}


/*static __always_inline
struct rpc_state_cc * find_ge_wrapper(struct rpc_state_cc *elem,
    bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b)) {

    struct bpf_rb_node *rb_node = NULL;
    rb_node = bpf_rbtree_lower_bound(&groot, &elem->rbtree_link, less);
    if (unlikely(!rb_node)) {
        return NULL;
    } else {
        elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
        return elem;
    }
}*/

static __always_inline
int sched_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out)
{
    if (int_out->complete)
        return XDP_REDIRECT;

    if (!int_out->need_schedule)
        return XDP_REDIRECT;

    
    struct rpc_state_cc *elem = NULL;
    struct rpc_state_cc *next_elem = NULL;
    struct rpc_state_cc *search_elem = NULL;
    struct rpc_state_cc *prio_elem = NULL;
    struct bpf_rb_node *rb_node = NULL;
    
    /* allocate new object for Tree0 */
    elem = bpf_obj_new(typeof(*elem));
    CHECK_AND_DROP_LOG(!elem, "server_request: bpf_obj_new failed.");
    /* allocate new object for Tree1 */
    prio_elem = bpf_obj_new(typeof(*prio_elem));
    if (unlikely(!prio_elem))
    {
        bpf_obj_drop(elem);
        return XDP_DROP;
    }

    elem->tree_id = 0;
    elem->peer_id = get_peerid(ev->flow_id.remote_ip);
    elem->bytes_remaining = int_out->last_bytes_remaining;
    elem->incoming = ctx->cc.incoming;
    elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
    elem->hkey.local_port = ev->flow_id.local_port;
    elem->hkey.remote_ip = ev->flow_id.remote_ip;
    elem->hkey.remote_port = ev->flow_id.remote_port;
    elem->message_length = ctx->message_length;
    // Question: what is ctx->birth and why is it used here?
    elem->birth = bpf_ktime_get_ns();
    elem->birth &= ~(__u64)1;

    GRANT_LOCK();
    if(int_out->new_state) {
        bpf_rbtree_add(&groot, &elem->rbtree_link, srpt_less_rpc);
    } else {
        rb_node = bpf_rbtree_lower_bound(&groot, &elem->rbtree_link, srpt_less_rpc);
        if (unlikely(!rb_node))
        {   /* this should never happen */
            GRANT_UNLOCK();
            goto middle;
        } else {
            // elem is ctx.all_rpcs[ind] here
            struct rpc_state_cc * temp = container_of(rb_node, struct rpc_state_cc, rbtree_link);   
            if (temp->tree_id != 0) {
                ctx->cc.incoming = ctx->message_length;
                int_out->need_schedule = false;
                GRANT_UNLOCK();
                goto middle;
            } else {
                temp->bytes_remaining -= ev->segment_length;

                if(temp->birth & 1) { // lowest bit of birth 1 means it is in peer tree)
                    prio_elem->tree_id = 1;
                    prio_elem->bytes_remaining = temp->bytes_remaining + ev->segment_length;
                    prio_elem->peer_id = temp->peer_id;
                    rb_node = bpf_rbtree_lower_bound(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                    if (likely(rb_node != NULL))
                    {
                        prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                        if (likely(prio_elem->tree_id == 1 && prio_elem->peer_id == temp->peer_id))
                        {
                            rb_node = bpf_rbtree_remove(&groot, &prio_elem->rbtree_link);
                            if (likely(rb_node != NULL))
                            {
                                prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                                prio_elem->bytes_remaining = temp->bytes_remaining;
                                bpf_rbtree_add(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                            }
                            prio_elem = NULL;
                        }
                        else {
                            /* this should never happen */
                            prio_elem = NULL;
                        }
                    }
                    else {
                        /* this should never happen */
                        prio_elem = NULL;
                    }
                }
            }
        }

        elem->bytes_remaining -= ev->segment_length;
    }

    GRANT_UNLOCK();
middle:
    if (prio_elem)
        bpf_obj_drop(prio_elem);

    /* allocate new object for Tree0 */
    elem = bpf_obj_new(typeof(*elem));
    CHECK_AND_DROP_LOG(!elem, "server_request: bpf_obj_new failed.");
    /* allocate new object for Tree1 */
    prio_elem = bpf_obj_new(typeof(*prio_elem));
    if (unlikely(!prio_elem))
    {
        bpf_obj_drop(elem);
        return XDP_DROP;
    }
    /* use bpf_refcount_acquire rather than bpf_obj_new for better performance */
    search_elem = bpf_refcount_acquire(prio_elem);
    if (unlikely(!search_elem))
    {
        bpf_obj_drop(elem);
        bpf_obj_drop(prio_elem);
        return XDP_DROP;
    }

    next_elem = bpf_refcount_acquire(search_elem);
    if (unlikely(!next_elem))
    {
        bpf_obj_drop(elem);
        bpf_obj_drop(prio_elem);
        bpf_obj_drop(search_elem);
        return XDP_DROP;
    }

    GRANT_LOCK();
    
    search_elem->tree_id = 0;
    search_elem->peer_id = elem->peer_id;
    search_elem->bytes_remaining = 0;
    search_elem->hkey.rpcid = 0;
    search_elem->hkey.local_port = 0;
    search_elem->hkey.remote_port = 0;
    search_elem->hkey.remote_ip = 0;


    rb_node = bpf_rbtree_lower_bound(&groot, &search_elem->rbtree_link, srpt_less_rpc);
    if (unlikely(!rb_node))
    {   /* this should never happen */
        GRANT_UNLOCK();
        bpf_obj_drop(prio_elem);
        prio_elem = NULL;
        search_elem = NULL;
        goto out;
    }
    else
    {
        struct rpc_state_cc * highest_prio = container_of(rb_node, struct rpc_state_cc, rbtree_link);
        //search_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
        if (unlikely(highest_prio->tree_id != 0 || highest_prio->peer_id != elem->peer_id))
        {   /* this should never happen */
            GRANT_UNLOCK();
            bpf_obj_drop(prio_elem);
            prio_elem = NULL;
            search_elem = NULL;
            goto out;
        } else if(highest_prio->hkey.rpcid == elem->hkey.rpcid &&
            highest_prio->hkey.local_port == elem->hkey.local_port &&
            highest_prio->hkey.remote_port == elem->hkey.remote_port &&
            highest_prio->hkey.remote_ip == elem->hkey.remote_ip){

            next_elem->tree_id = 0;
            next_elem->peer_id = elem->peer_id;
            next_elem->bytes_remaining = elem->bytes_remaining;
            next_elem->hkey.rpcid = elem->hkey.rpcid;
            next_elem->hkey.local_port = elem->hkey.local_port;
            next_elem->hkey.remote_port = elem->hkey.remote_port;
            next_elem->hkey.remote_ip = elem->hkey.remote_ip + 1;

            rb_node = bpf_rbtree_lower_bound(&groot, &next_elem->rbtree_link, srpt_less_rpc);
            if (rb_node)
            {
                next_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                if (next_elem->tree_id != 0 || next_elem->peer_id != elem->peer_id){
                //if (next_elem->tree_id == 0 && next_elem->peer_id == elem->peer_id){
                    if(int_out->new_state || !(highest_prio->birth & 1)) { // lowest bit of birth 1 means it is in peer tree) 
                        
                        prio_elem->tree_id = 1;
                        prio_elem->peer_id = elem->peer_id;
                        prio_elem->bytes_remaining = elem->bytes_remaining;
                        prio_elem->incoming = elem->incoming;
                        prio_elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
                        prio_elem->hkey.local_port = ev->flow_id.local_port;
                        prio_elem->hkey.remote_ip = ev->flow_id.remote_ip;
                        prio_elem->hkey.remote_port = ev->flow_id.remote_port;
                        prio_elem->message_length = elem->message_length;
                        elem->birth |= (__u64)1;
                        prio_elem->birth = elem->birth;

                        bpf_rbtree_add(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                        prio_elem = NULL;
                    }

                } else {
                    /* use prio_elem to search and remove it from Tree1 */
                    prio_elem->tree_id = 1;
                    prio_elem->peer_id = next_elem->peer_id;
                    prio_elem->bytes_remaining = next_elem->bytes_remaining;
                    rb_node = bpf_rbtree_lower_bound(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                    if (rb_node)
                    {
                        prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                        if (prio_elem->tree_id == 1 && prio_elem->peer_id == next_elem->peer_id)
                        {
                            rb_node = bpf_rbtree_remove(&groot, &prio_elem->rbtree_link);
                            if (rb_node)
                            {
                                prio_elem = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                                /* update incoming from Tree1 here as it may be modified */
                                next_elem->birth &= ~(__u64)1;
                                next_elem->incoming = prio_elem->incoming;

                                prio_elem->tree_id = 1;
                                prio_elem->peer_id = elem->peer_id;
                                prio_elem->bytes_remaining = elem->bytes_remaining;
                                prio_elem->incoming = elem->incoming;
                                prio_elem->hkey.rpcid = local_id(ev->flow_id.rpcid);
                                prio_elem->hkey.local_port = ev->flow_id.local_port;
                                prio_elem->hkey.remote_ip = ev->flow_id.remote_ip;
                                prio_elem->hkey.remote_port = ev->flow_id.remote_port;
                                prio_elem->message_length = elem->message_length;
                                /* mark this rpc is in Tree1 */
                                elem->birth |= (__u64)1;
                                prio_elem->birth = elem->birth;
                
                                bpf_rbtree_add(&groot, &prio_elem->rbtree_link, srpt_less_peer);
                                prio_elem = NULL;
                            }
                            else { /* this should never happen */
                                prio_elem = NULL;
                            }
                        }
                        else { /* this should never happen */
                            prio_elem = NULL;
                        }
                    }
                    else { /* this should never happen */
                        prio_elem = NULL;
                    }
                }
            }
            next_elem = NULL;
            search_elem = NULL;
        } else {
            search_elem = NULL;
        }
    }

    GRANT_UNLOCK();
    
out:
    bpf_obj_drop(elem);
    if (prio_elem)
        bpf_obj_drop(prio_elem);
    if (search_elem)
        bpf_obj_drop(search_elem);
    if (next_elem)
        bpf_obj_drop(next_elem);

    return XDP_REDIRECT;
}

static __always_inline
int choose_grants(struct xdp_md *ctx)
{
    struct rpc_state_cc * cc_node[8];
    cc_node[0] = NULL;
    cc_node[1] = NULL;
    cc_node[2] = NULL;
    cc_node[3] = NULL;
    cc_node[4] = NULL;
    cc_node[5] = NULL;
    cc_node[6] = NULL;
    cc_node[7] = NULL;
    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU))
    {
        bpf_printk("ERROR: CPU Mapping, cpu=%d\n", cpu);
        return XDP_ABORTED;
    }
    struct rpc_state_cc *n = NULL;
    struct bpf_rb_node *rb_node = NULL;
    __u16 nr_rpc = 0;
    struct remove_info *ri = NULL;
    __u16 next_peer_id = 0;
    __u32 min_last_bytes_remaining = 0;
    __u32 new_grant = 0;
    int available = 0;
    __u32 increment = 0;
    __u32 total_increment = 0;
    int priority = 0;
    int extra_levels = 0;
    int prio_idx = 0;
    int actual_rpc = 0;

    if (!try_grantable_lock())
    {
        return XDP_ABORTED;
    }

    ri = bpf_map_lookup_elem(&per_cpu_remove_info, ZERO_KEY);
    if (!ri)
    {
        release_grantable_lock();
        return XDP_ABORTED;
    }

    cc_node[0] = bpf_obj_new(typeof(*cc_node[0]));
    if (!cc_node[0])
    {
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[1] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[1])
    {
        bpf_obj_drop(cc_node[0]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[2] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[2])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[3] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[3])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        bpf_obj_drop(cc_node[2]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[4] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[4])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        bpf_obj_drop(cc_node[2]);
        bpf_obj_drop(cc_node[3]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[5] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[5])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        bpf_obj_drop(cc_node[2]);
        bpf_obj_drop(cc_node[3]);
        bpf_obj_drop(cc_node[4]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[6] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[6])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        bpf_obj_drop(cc_node[2]);
        bpf_obj_drop(cc_node[3]);
        bpf_obj_drop(cc_node[4]);
        bpf_obj_drop(cc_node[5]);
        release_grantable_lock();
        return XDP_ABORTED;
    }
    cc_node[7] = bpf_refcount_acquire(cc_node[0]);
    if (!cc_node[7])
    {
        bpf_obj_drop(cc_node[0]);
        bpf_obj_drop(cc_node[1]);
        bpf_obj_drop(cc_node[2]);
        bpf_obj_drop(cc_node[3]);
        bpf_obj_drop(cc_node[4]);
        bpf_obj_drop(cc_node[5]);
        bpf_obj_drop(cc_node[6]);
        release_grantable_lock();
        return XDP_ABORTED;
    }

    // step2: choose rpcs to grant (not dequeue)
    GRANT_LOCK();

    for(int i = 0; i < 8; i++) {
        cc_node[i]->tree_id = 1;
        cc_node[i]->bytes_remaining = min_last_bytes_remaining;
        cc_node[i]->peer_id = next_peer_id;
        rb_node = bpf_rbtree_lower_bound(&groot, &cc_node[i]->rbtree_link, srpt_less_peer);
        cc_node[i] = NULL;
        if (rb_node)
        {
            n = container_of(rb_node, struct rpc_state_cc, rbtree_link);
            // no need to check, if rb_node!= NULL, tree_id must be 1
            min_last_bytes_remaining = n->bytes_remaining;
            ri->rpcid[i] = n->hkey.rpcid;
            ri->local_port[i] = n->hkey.local_port;
            ri->remote_port[i] = n->hkey.remote_port;
            ri->remote_ip[i] = n->hkey.remote_ip;
            next_peer_id = get_peerid(n->hkey.remote_ip) + 1;

            // grant the rpc
            new_grant = n->message_length - n->bytes_remaining + Homa_grant_window;
            if (new_grant > n->message_length)
                new_grant = n->message_length;
            available = Homa_max_incoming - total_incoming;
            increment = new_grant - n->incoming;
            if (increment > 0 && available > 0)
            {
                if (increment > available)
                {
                    increment = available;
                    new_grant = n->incoming + increment;
                }

                n->incoming = new_grant;
                remove[cpu][i] = n->incoming >= n->message_length;
                if (remove[cpu][i])
                {
                    rb_node = bpf_rbtree_remove(&groot, &n->rbtree_link);
                    if (rb_node)
                    {
                        n = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                        n->tree_id = 0;
                        rb_node = bpf_rbtree_lower_bound(&groot, &n->rbtree_link, srpt_less_rpc);
                        if (rb_node)
                        {
                            n = container_of(rb_node, struct rpc_state_cc, rbtree_link);

                            rb_node = bpf_rbtree_remove(&groot, &n->rbtree_link);
                            cc_node[i] = rb_node ? container_of(rb_node, struct rpc_state_cc, rbtree_link) : NULL;
                        }
                    }
                }
                total_increment += increment;
                ri->newgrant[i] = new_grant;
            }
            nr_rpc++;
        }
        else
            break;
    }

    __sync_fetch_and_add(&total_incoming, total_increment);

    grant_nonfifo_left -= total_increment;
    if (grant_nonfifo_left <= 0)
    {
        grant_nonfifo_left += grant_nonfifo;
#ifndef DISABLE_GRANT_FIFO
        need_grant_fifo[cpu] = 1;
#endif
    }

    GRANT_UNLOCK();

    if (cc_node[0])
        bpf_obj_drop(cc_node[0]);
    if (cc_node[1])
        bpf_obj_drop(cc_node[1]);
    if (cc_node[2])
        bpf_obj_drop(cc_node[2]);
    if (cc_node[3])
        bpf_obj_drop(cc_node[3]);
    if (cc_node[4])
        bpf_obj_drop(cc_node[4]);
    if (cc_node[5])
        bpf_obj_drop(cc_node[5]);
    if (cc_node[6])
        bpf_obj_drop(cc_node[6]);
    if (cc_node[7])
        bpf_obj_drop(cc_node[7]);

    //   bpf_printk("%d RPCs are choosen to grant", nr_rpc);
    if (nr_rpc == 0)
    {
#ifdef HELP_PACER
        help_pacer();
#endif
        release_grantable_lock();
        return XDP_ABORTED;
    }

    nr_grant_candidate[cpu] = nr_rpc;

    for (int i = 0; i < nr_rpc; i++)
    {
        if (ri->newgrant[i & 7])
        {
            actual_rpc++;
            priority = HOMA_MAX_SCHED_PRIO - (prio_idx++);
            if (priority < 0)
                priority = 0;
            ri->priority[i & 7] = priority;
            // bpf_printk("Grant to RPC#%llu to offset: %lu", ri->rpcid[i&7], ri->newgrant[i&7]);
        }
    }
    nr_grant_ready[cpu] = actual_rpc;

    if (actual_rpc == 0)
    {
#ifdef HELP_PACER
        help_pacer();
#endif
        release_grantable_lock();
        return XDP_ABORTED;
    }

    extra_levels = HOMA_MAX_SCHED_PRIO + 1 - actual_rpc;
    if (extra_levels >= 0)
    {
        for (int i = 0; i < nr_rpc; i++)
        {
            if (ri->newgrant[i & 7])
            {
                priority = ri->priority[i & 7];
                priority -= extra_levels;
                if (priority)
                    ri->priority[i & 7] = priority;
            }
        }
    }
    
    // TODO: change later
    return XDP_PASS;
}

static __always_inline
int update_prios(struct xdp_md *ctx)
{

    __u32 cpu = bpf_get_smp_processor_id();
    if (unlikely(cpu >= MAX_CPU))
    {
        bpf_printk("ERROR: CPU Mapping, cpu=%d\n", cpu);
        return XDP_ABORTED;
    }
    __u16 peer_id = 0;
    struct remove_info *ri = NULL;

    if (nr_grant_candidate[cpu] < 1)
    {
        release_grantable_lock();
        if (nr_grant_ready[cpu] > 0)
        {
            finish_grant_choose[cpu] = 1;
            return XDP_DROP;
        }
        else
            return XDP_ABORTED;
    }

    ri = bpf_map_lookup_elem(&per_cpu_remove_info, ZERO_KEY);
    if (!ri)
    {
        // this should never happen
        release_grantable_lock();
        return XDP_ABORTED;
    }

    for(int i = 0; i < 8; i++) {
        if (remove[cpu][i])
        {
            struct rpc_state_cc *cc_node_t0 = NULL;
            struct rpc_state_cc *cc_node_t1 = NULL;
            struct bpf_rb_node *rb_node = NULL;
            peer_id = get_peerid(ri->remote_ip[i]);

            cc_node_t0 = bpf_obj_new(typeof(*cc_node_t0));
            if (!cc_node_t0)
            {
                release_grantable_lock();
                return XDP_ABORTED;
            }

            cc_node_t1 = bpf_refcount_acquire(cc_node_t0);
            if (!cc_node_t1)
            {
                bpf_obj_drop(cc_node_t0);
                release_grantable_lock();
                return XDP_ABORTED;
            }

            cc_node_t0->tree_id = 0;
            cc_node_t0->peer_id = peer_id;
            cc_node_t0->bytes_remaining = 0;
            cc_node_t0->hkey.rpcid = 0;
            cc_node_t0->hkey.local_port = 0;
            cc_node_t0->hkey.remote_port = 0;
            cc_node_t0->hkey.remote_ip = 0;
            GRANT_LOCK();
            rb_node = bpf_rbtree_lower_bound(&groot, &cc_node_t0->rbtree_link, srpt_less_rpc);
            if (rb_node)
            {
                cc_node_t0 = container_of(rb_node, struct rpc_state_cc, rbtree_link);
                if (cc_node_t0->tree_id == 0 && cc_node_t0->peer_id == peer_id && (cc_node_t0->birth & 1) == 0)
                {
                    // we should add this rpc to peer tree
                    cc_node_t1->tree_id = 1;
                    cc_node_t1->peer_id = cc_node_t0->peer_id;
                    cc_node_t1->bytes_remaining = cc_node_t0->bytes_remaining;
                    cc_node_t1->incoming = cc_node_t0->incoming;
                    cc_node_t1->hkey.rpcid = cc_node_t0->hkey.rpcid;
                    cc_node_t1->hkey.local_port = cc_node_t0->hkey.local_port;
                    cc_node_t1->hkey.remote_ip = cc_node_t0->hkey.remote_ip;
                    cc_node_t1->hkey.remote_port = cc_node_t0->hkey.remote_port;
                    cc_node_t1->message_length = cc_node_t0->message_length;
                    // mark this rpc is in peer tree
                    cc_node_t0->birth |= (__u64)1;
                    cc_node_t1->birth = cc_node_t0->birth;

                    bpf_rbtree_add(&groot, &cc_node_t1->rbtree_link, srpt_less_peer);
                    cc_node_t1 = NULL;
                }
            }
            GRANT_UNLOCK();
            if (cc_node_t1)
                bpf_obj_drop(cc_node_t1);
        }
    }

    release_grantable_lock();
    
    if (nr_grant_ready[cpu] > 0)
    {
        finish_grant_choose[cpu] = 1;
        return XDP_DROP;
    }
    else
        return XDP_ABORTED;
}

static __always_inline
int pkt_gen_instr_grant_wrapper(struct HOMABP_GEN *bp, struct xdp_md *ctx, __u32 local_ip, __u32 remote_ip) {
    if (bpf_xdp_adjust_tail(ctx, -HOMA_GRANT_HEADER_CUTOFF))
    {
        bpf_printk("ERROR: bpf_xdp_adjust_tail failed\n");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)data;
    if (unlikely(eth + 1 > data_end))
    {
        return XDP_DROP;
    }

    // IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (unlikely(iph + 1 > data_end))
    {
        return XDP_DROP;
    }

    iph->saddr = bpf_htonl(local_ip);
    iph->daddr = bpf_htonl(remote_ip);
    iph->version = IPVERSION;
    iph->protocol = IPPROTO_HOMA;
    iph->ihl = 0x5;
    iph->tos = bp->grant.priority << 5;
    iph->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct grant_header));
    iph->id = 0;
    iph->ttl = IPDEFTTL;
    iph->check = 0;

    // grant header
    struct grant_header *gh = (struct grant_header *)(iph + 1);
    if (unlikely(gh + 1 > data_end))
    {
        return XDP_DROP;
    }

    gh->common.type = bp->common.type;
    gh->common.dport = bpf_htons(bp->common.dest_port);
    gh->common.sport = bpf_htons(bp->common.src_port);
    gh->common.sender_id = bpf_cpu_to_be64(bp->common.sender_id);
    gh->offset = bpf_htonl(bp->grant.offset);
    gh->priority = bp->grant.priority;
    gh->resend_all = bp->grant.resend_all;

    // TODO: this might be problematic, because some parts of
    // reset_grants_state come first
    int err = fib_lookup(ctx, eth, iph);
    if (unlikely(err))
    {
        bpf_printk("ERROR: bpf_fib_lookup failed in XDP_GEN, check routing table in kernel");
        return XDP_DROP;
    }

    return XDP_TX;
}

static __always_inline
int gen_grants(struct xdp_md *ctx, struct interm_out *int_out)
{
    __u32 cpu = bpf_get_smp_processor_id();

    if(!finish_grant_choose[cpu]) {
        return XDP_DROP;
    }

    int_out->last_grant = false;
    bool no_work = false;
    int_out->send_fifo_rpc = false;

    unsigned int gi_idx;

    struct ret_grant_info gi = {0};

    granting_idx[cpu]++;
    // bpf_printk("DEBUG: granting_idx[cpu]: %d\n", granting_idx[cpu]);

    if (nr_grant_ready[cpu] == 0 && !need_grant_fifo[cpu])
    {
        int_out->last_grant = 1;
        no_work = 1;
        return XDP_DROP;
    }

    __u16 cnt = HOMA_OVERCOMMITMENT;
    if(nr_grant_candidate[cpu] < cnt)
        cnt = nr_grant_candidate[cpu];

    // bpf_printk("need_grant_fifo[cpu]: %d", need_grant_fifo[cpu]);
    if (need_grant_fifo[cpu] == 1)
    {
        // If we have RPC in the FIFO queue, we should grant it at last
        if (granting_idx[cpu] == cnt + 1)
        {
            int_out->last_grant = 1;
        }
    }
    else if (granting_idx[cpu] == cnt)
    {
        // after processing the packet, we should return XDP_ABORTED to terminate
        int_out->last_grant = 1;
    }

    

    if (need_grant_fifo[cpu] == 1 && int_out->last_grant == 1)
    {
        // it's time to grant the RPC in the FIFO queue

        struct rpc_state_cc __kptr *cc_node_search = NULL;
        struct bpf_rb_node *rb_node = NULL;

        cc_node_search = bpf_obj_new(typeof(*cc_node_search));
        if (unlikely(!cc_node_search)) {
            no_work = 1;
            need_grant_fifo[cpu] = 0; // error or no fifo rpc to grant
            return XDP_DROP;
        }

        cc_node_search->birth = POISON_64;

        GRANT_LOCK();

        rb_node = bpf_rbtree_search_less(&groot, &cc_node_search->rbtree_link, less_birth_grant);
        if (unlikely(!rb_node)) {
            GRANT_UNLOCK();
            no_work = 1;
            need_grant_fifo[cpu] = 0; // error or no fifo rpc to grant
            return XDP_DROP;
        }
        cc_node_search = container_of(rb_node, struct rpc_state_cc, rbtree_link);


        __u64 increment = 0, newgrant = 0;
        bool need_remove = false;

        increment = GRANT_FIFO_INCREMENT;
        newgrant = increment + cc_node_search->incoming;
        cc_node_search->incoming = newgrant;
        if (newgrant >= cc_node_search->message_length) {
            increment -= newgrant - cc_node_search->message_length;
            cc_node_search->incoming = cc_node_search->message_length;
            need_remove = true;
        }

        __sync_fetch_and_add(&total_incoming, increment);

        gi.rpcid = cc_node_search->hkey.rpcid;
        gi.sport = cc_node_search->hkey.local_port;
        gi.dport = cc_node_search->hkey.remote_port;
        gi.remote_ip = cc_node_search->hkey.remote_ip;
        gi.newgrant = cc_node_search->incoming;
        gi.priority = HOMA_MAX_SCHED_PRIO;

        if (need_remove) {
            rb_node = bpf_rbtree_remove(&groot, &cc_node_search->rbtree_link);
            if (rb_node)
                cc_node_search = container_of(rb_node, struct rpc_state_cc, rbtree_link);
            else
                cc_node_search = NULL;
        }
        else
            cc_node_search = NULL;

        GRANT_UNLOCK();
        
        if (cc_node_search)
            bpf_obj_drop(cc_node_search);
        
        int_out->send_fifo_rpc = 1;
    
    } else {
        // grant the RPC in the Priority queue
        gi_idx = (granting_idx[cpu] - 1);
        gi_idx = gi_idx % HOMA_OVERCOMMITMENT;

        struct remove_info *ri;
        ri = bpf_map_lookup_elem(&per_cpu_remove_info, ZERO_KEY);
        if (unlikely(!ri))
        {
            no_work = 1;
            return XDP_DROP;
        }

        if (unlikely(!ri->newgrant[gi_idx])) {
            no_work = 1;
            return XDP_DROP;
        }

        gi.sport = ri->local_port[gi_idx];
        gi.dport = ri->remote_port[gi_idx];
        gi.rpcid = ri->rpcid[gi_idx];
        gi.newgrant = ri->newgrant[gi_idx];
        gi.remote_ip = ri->remote_ip[gi_idx];
        gi.priority = ri->priority[gi_idx];

        ri->newgrant[gi_idx] = 0;
    }

    struct HOMABP_GEN bp;
    bp.common.type = GRANT;
    bp.common.dest_port = gi.dport;
    bp.common.src_port = gi.sport;
    bp.common.sender_id = gi.rpcid;
    bp.grant.offset = gi.newgrant;
    bp.grant.priority = gi.priority;
    bp.grant.resend_all = 0;

    return pkt_gen_instr_grant_wrapper(&bp, ctx, local_ip, gi.remote_ip);
}


static __always_inline
int reset_grants_state(struct xdp_md *ctx, struct interm_out *int_out)
{
    __u32 cpu = bpf_get_smp_processor_id();

    if(!finish_grant_choose[cpu]) {
        return XDP_DROP;
    }
    if(int_out->last_grant) {
        granting_idx[cpu] = 0;
        nr_grant_candidate[cpu] = 0;
        finish_grant_choose[cpu] = 0;
    }
    if(int_out->send_fifo_rpc)
        need_grant_fifo[cpu] = 0;
    
    return XDP_TX;
}

static __always_inline
int pkt_gen_instr_xdp_data_wrapper(struct HOMABP *bp, __u64 addr, __u32 length,
    struct xdp_md *xdp_ctx, struct homa_meta_info *data_meta, struct rpc_state *ctx) {

    data_meta->rx.reap_server_buffer_addr = addr;

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    int curr_len = (int) (data_end - data);

    int target_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct resend_header);

    if (bpf_xdp_adjust_tail(xdp_ctx, target_len - curr_len)) {
        return 0;
    }

    data = (void *)(long)xdp_ctx->data;
    data_end = (void *)(long)xdp_ctx->data_end;
    
    struct ethhdr *eth = (struct ethhdr *)data;
    if (eth + 1 > data_end) {
        return 0;
    }
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (iph + 1 > data_end) {
        return 0;
    }
    struct resend_header *homa_resend_h = (struct resend_header *)(iph + 1);
    if (homa_resend_h + 1 > data_end) {
        return 0;
    }

    homa_resend_h->common.type = RESEND;
    homa_resend_h->offset = bpf_htonl(bp->data.seg.offset);
    homa_resend_h->length = bpf_htonl(length);

    return 1;
}

static __always_inline
int resend_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out,
    struct xdp_md *xdp_ctx) {

    //bool need_kick = false;
    int_out->type_pkt = RESEND;

    RPC_LOCK(ctx);

    if (ctx->state == BPF_RPC_DEAD) {
        RPC_UNLOCK(ctx);
        int_out->type_pkt = UNKNOWN;
        return UNKNOWN;
    }

    if (!rpc_is_client(ev->flow_id.rpcid) && ctx->state != BPF_RPC_OUTGOING) {
        /* We are the server for this RPC. If we haven't received
         * all of the bytes we've granted then request a resend
         * of the missing bytes; otherwise just send a BUSY.
         */
        if (
            ctx->message_length - ctx->cc.bytes_remaining > (ctx->cc.incoming/HOMA_MSS) * HOMA_MSS || 
            ((ctx->message_length - ctx->cc.bytes_remaining == (ctx->cc.incoming/HOMA_MSS) * HOMA_MSS) && 
            ctx->cc.incoming != ctx->message_length)
            )
        {
            // case#1: we have received all the bytes we've granted
            int_out->type_pkt = BUSY;
        }
        else
        {
            // case#2: it seems that we lost some packets, which causes **client** to
            // send RESEND packets. Leave server timeout to handle this.
            int_out->type_pkt = 0;
        }

    } else if (ev->offset >= ctx->next_xmit_offset) {
        /* We have chosen not to transmit data from this message;
         * send BUSY instead.
         */
        int_out->type_pkt = BUSY;

        /*if (ctx->next_xmit_offset < ctx->message_length && 
            ctx->next_xmit_offset + 1420 <= ctx->cc.granted)
            need_kick = true;*/
    }
    else
    {
        if (ev->length == 0)
        {
            /* This RESEND is from a server just trying to determine
             * whether the client still cares about the RPC; return
             * BUSY so the server doesn't time us out.
             */
            int_out->type_pkt = BUSY;
        }
    }

    RPC_UNLOCK(ctx);

    if (int_out->type_pkt == RESEND) {

        //data_meta->rx.reap_server_buffer_addr = ctx->buffer_head;

        struct HOMABP bp;
        bp.common.src_port = ev->flow_id.local_port;
        bp.common.dest_port = ev->flow_id.remote_port;
        bp.common.doff = 40 >> 2;
        bp.common.type = DATA;
        bp.common.seq = ev->seq;
        bp.common.sender_id = ctx->id;

        bp.data.incoming = ctx->cc.granted;
        bp.data.cutoff_version = 0;
        bp.data.seg.offset = ev->offset;
        bp.data.retransmit = 1;

        //bp.priority = ev->priority << 5;

        __u64 addr = ctx->buffer_head;

        pkt_gen_instr_xdp_data_wrapper(&bp, addr, ev->length, xdp_ctx, data_meta, ctx);

        ctx->resend_count++;
    }

    //RPC_UNLOCK(ctx);

    /*if (need_kick) {
        kick_pacer();
    }*/

    return int_out->type_pkt;
}


static __always_inline
int pkt_gen_instr_xdp_no_data_wrapper(struct HOMABP bp, struct xdp_md *xdp_ctx) {

    __u32 ip_swap;
    __u8 mac_swap[ETH_ALEN];

    int length = (int)sizeof(struct common_header) - (int)sizeof(struct resend_header); // < 0

    if (bpf_xdp_adjust_tail(xdp_ctx, length))
    {
        log_err("bpf_xdp_adjust_tail failed.");
        return XDP_DROP;
    }

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if (eth + 1 > data_end)
        return XDP_DROP;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (iph + 1 > data_end)
        return XDP_DROP;
    struct common_header *c = (struct common_header *)(iph + 1);
    if (c + 1 > data_end)
        return XDP_DROP;

    c->type = bp.common.type;
    c->sender_id = bpf_cpu_to_be64(local_id(bp.common.sender_id));
    c->sport = bp.common.src_port;
    c->dport = bp.common.dest_port;

    ip_swap = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = ip_swap;

    __builtin_memcpy(mac_swap, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, mac_swap, ETH_ALEN);

    return XDP_TX;
}


static __always_inline
int tx_resend_resp(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out,
    struct xdp_md *xdp_ctx) {

    if(int_out->type_pkt != UNKNOWN && int_out->type_pkt != BUSY)
        return int_out->type_pkt;

    struct HOMABP bp;
    bp.common.type = int_out->type_pkt;
    bp.common.sender_id = ev->flow_id.rpcid;
    bp.common.src_port = ev->flow_id.remote_port;
    bp.common.dest_port = ev->flow_id.local_port;

    return pkt_gen_instr_xdp_no_data_wrapper(bp, xdp_ctx);
}

static __always_inline
void destroy_ctx_instr_wrapper(struct rpc_state *ctx, struct hkey flow_id,
    struct homa_meta_info *data_meta, struct xdp_md *xdp_ctx) {

    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct unknown_header *homa_unknown_h = (struct unknown_header *)(sizeof(struct ethhdr) + sizeof(struct iphdr) + 1);
    if (homa_unknown_h + 1 > data_end) {
        return;
    }

    data_meta->rx.reap_client_buffer_addr = ctx->buffer_head;
    ctx->buffer_head = __UINT64_MAX__;

    homa_unknown_h->common.type = RESEND;

    bpf_map_delete_elem(&rpc_tbl, &flow_id);
    bpf_map_delete_elem(&pkt_bp_tbl, &flow_id);
}

static __always_inline
int unkown_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out,
    struct xdp_md *xdp_ctx) {
        
    __u32 next_xmit_offset = 0;

    RPC_LOCK(ctx);
    if (unlikely(ctx->state == BPF_RPC_DEAD))
    {
        RPC_UNLOCK(ctx);
        return XDP_DROP;
    }

    if (rpc_is_client(ev->flow_id.rpcid))
    {
        if (ctx->state == BPF_RPC_OUTGOING)
        {

            //data_meta->rx.reap_server_buffer_addr = ctx->buffer_head;

            next_xmit_offset = ctx->next_xmit_offset;
            RPC_UNLOCK(ctx);


            struct HOMABP bp;
            bp.common.src_port = ev->flow_id.local_port;
            bp.common.dest_port = ev->flow_id.remote_port;
            bp.common.doff = 40 >> 2;
            bp.common.type = DATA;
            bp.common.seq = 0;
            bp.common.sender_id = ctx->id;

            bp.data.incoming = ctx->cc.granted;
            bp.data.cutoff_version = 0;
            bp.data.seg.offset = 0;
            bp.data.retransmit = 1;

            //bp.priority = ev->priority << 5;

            __u64 addr = ctx->buffer_head;

            pkt_gen_instr_xdp_data_wrapper(&bp, addr, next_xmit_offset, xdp_ctx, data_meta, ctx);


            /*if (bpf_xdp_adjust_tail(xdp_ctx, sizeof(struct resend_header) - sizeof(struct unknown_header)))
            {
                return -1;
            }
            void *data = (void *)(long)xdp_ctx->data;
            void *data_end = (void *)(long)xdp_ctx->data_end;
            struct ethhdr *eth = (struct ethhdr *)data;
            if (eth + 1 > data_end) {
                return -1;
            }
            struct iphdr *iph = (struct iphdr *)(eth + 1);
            if (iph + 1 > data_end) {
                return -1;
            }
            struct resend_header *homa_resend_h = (struct resend_header *)(iph + 1);
            if (homa_resend_h + 1 > data_end) {
                return -1;
            }
            homa_resend_h->common.type = RESEND;
            homa_resend_h->offset = 0;
            homa_resend_h->length = bpf_htonl(next_xmit_offset);
            return 0;*/
        }
    }
    else
    {

        // Question: do we have a ctx_destroy or something similar in MTP?
        ctx->state = BPF_RPC_DEAD;

        RPC_UNLOCK(ctx);

        destroy_ctx_instr_wrapper(ctx, ev->flow_id, data_meta, xdp_ctx);
        
        return 0;
    }
    RPC_UNLOCK(ctx);
    return -1;
}

static __always_inline
void busy_pkt_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out) {

    if (ctx->state == BPF_RPC_DEAD) {
        return;
    }

    ctx->busy_count++;
}

// Question: how to abstract this EP?
// Basically, what is defined in the BP was already "used"
// when the packets were first sent by userspace and enqueued
// to the RL.
static __always_inline
void recv_grant_ep(struct net_event *ev, struct rpc_state *ctx,
    struct homa_meta_info *data_meta, struct interm_out *int_out)
{
    struct rpc_state_cc *cc_node = NULL;
    struct rpc_state_cc *ref_cc_node = NULL;

    if (ctx->state != BPF_RPC_OUTGOING)
        return;

    atomic_xchg(&ctx->cc.sched_prio, ev->priority);

    if (ctx->cc.granted < ev->offset)
    {
        // Since we don't enforce load balancing for grant packets, only one CPU will
        // handle this grant packet. So we don't need any lock
        atomic_xchg(&ctx->cc.granted, ev->offset);

        // bpf_printk("RPC#%llu, grant = %u", rpcid, offset);
        
        if (atomic_read(&ctx->qid) != MAX_BUCKET_SIZE)
        {
            GET_POINTER(cc_node, ctx);
            if (unlikely(!cc_node)) {
                // werid case
                kick_pacer();
                return;
            }
            ref_cc_node = bpf_refcount_acquire(cc_node);
            if (unlikely(!ref_cc_node)) {
                // this should never happen
                bpf_printk("We are receiving GRANT, but we can't get cc_node reference for RPC#%llu", ctx->id);
                PUT_POINTER(cc_node, ctx);
                kick_pacer();
                return;
            }
            THROTTLE_LOCK();
            if (bpf_rbtree_add(&troot, &ref_cc_node->rbtree_link, srpt_less_pacer) == 0)
                atomic_inc(&nr_rpc_in_throttle);
            THROTTLE_UNLOCK();
            PUT_POINTER(cc_node, ctx);
        }
    }
    kick_pacer();
    // bpf_printk("kick pacer for RPC#%llu", rpcid);
}
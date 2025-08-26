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
    __u64 rpcid;
    __u16 sport;
    __u16 dport;
};

struct DATA_SEG {
    __u32 offset;
    __u32 segment_length;
    struct HOMA_ACK ack;
};

struct DATA_HDR {
    __u32 message_length;
    __u32 incoming;
    __u16 cutoff_version;
    __u8 retransmit;
    struct DATA_SEG seg;
};

struct COMMON_HDR {
    __u32 src_port;
    __u32 dest_port;
    __u8 doff;
    __u8 type;
    __u16 seq;
    __u64 sender_id;
};

struct HOMABP {
    struct COMMON_HDR common;
    struct DATA_HDR data;
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
};

// Question: if we don't use BP to fill the initial context
// values, what should we use?
static __always_inline
void new_ctx_instr_wrapper(struct rpc_state *ctx, struct app_event *ev, struct HOMABP *bp, bool first_packet, bool client) {
    if (first_packet) {
        if(client) {
            /* create a new RPC state */
            ctx->state = BPF_RPC_OUTGOING;
            ctx->message_length = bpf_ntohl(bp->data.message_length);
            ctx->next_xmit_offset = bpf_ntohl(bp->data.seg.segment_length);
            ctx->buffer_head = ev->addr;
            ctx->remote_port = bpf_ntohs(bp->common.dest_port);
            ctx->local_port = bpf_ntohs(bp->common.src_port);
            ctx->remote_ip = bpf_ntohl(ev->remote_ip);
            ctx->id = bpf_be64_to_cpu(bp->common.sender_id);
            ctx->cc.granted = min(bpf_ntohl(bp->data.message_length), Homa_unsched_bytes);
            ctx->qid = MAX_BUCKET_SIZE;
        } else {
            /* first received response packet */
            ctx->state = BPF_RPC_OUTGOING;
            ctx->message_length = bpf_ntohl(bp->data.message_length);
            ctx->next_xmit_offset = bpf_ntohl(bp->data.seg.segment_length);
            ctx->buffer_head = ev->addr;
            ctx->nr_pkts_in_rl = 0;
            ctx->cc.sched_prio = 0;
            ctx->cc.granted = min(bpf_ntohl(bp->data.message_length), Homa_unsched_bytes);
            ctx->qid = MAX_BUCKET_SIZE;
        }
    }
}

static __always_inline
void pkt_gen_instr_wrapper(struct data_header *d, struct HOMABP *bp) {
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
}

static __always_inline
int send_req_ep_client(struct data_header *d, struct iphdr *iph, struct app_event *ev, 
    struct HOMABP *bp, struct rpc_state *ctx,
    __u64 *rpc_qid, bool *trigger)
{

    bool first_packet = bpf_ntohs(bp->common.seq) == 0 ? 1 : 0;
    __u32 message_length = bpf_ntohl(bp->data.message_length);
    __u32 offset = bpf_ntohl(bp->data.seg.offset);
    __u32 packet_bytes = bpf_ntohl(bp->data.seg.segment_length);
    bool single_packet = message_length <= HOMA_MSS;
    
    new_ctx_instr_wrapper(ctx, ev, bp, first_packet, true);

    /* optimization for single-packet case */
    if (likely(single_packet)) {
        set_prio(iph, HOMA_MAX_PRIORITY - 1);
        bp->data.incoming = bpf_htonl(message_length);
        pkt_gen_instr_wrapper(d, bp);
        return XDP_TX;
    }

    if (offset + packet_bytes < Homa_unsched_bytes)
        set_prio(iph, get_prio(message_length));
    else
        set_prio(iph, atomic_read(&ctx->cc.sched_prio));

    /* check if we have enough credit */
    __u64 cc_granted = atomic_read(&ctx->cc.granted);
    bp->data.incoming = bpf_htonl(cc_granted);

    if (offset + packet_bytes <= cc_granted) {
        /* we have enough credit, further check three conditions to determine if we can send packet directly 
         * 1) no packets in rate limiter
         * 2) packet size is small enough or NIC queue is not busy
         */
        if (atomic_read(&ctx->nr_pkts_in_rl) == 0 &&
            (packet_bytes <= Homa_min_throttled_bytes || check_nic_queue(packet_bytes)))
        {
            /* this update is safe for no packets in rate limiter */
            ctx->next_xmit_offset = offset + packet_bytes;
            pkt_gen_instr_wrapper(d, bp);
            return XDP_TX;
        }
    }

    pkt_gen_instr_wrapper(d, bp);

    // Question: how can we know whether a packet should be sent
    // immediatelly or put in RL? In TCP the EP considers that we'll
    // send the packet immediatelly, and we abstract the whole rate
    // and delay thing.
    // But here the decision on whether the packet should be sent or not
    // (XDP_TX or XDP_REDIRECT) is a part of the EP.

    // TODO: this part underneath should be abstracted

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
    
    *rpc_qid = ctx->qid;

    *trigger = cc_granted >= (offset + packet_bytes);

    return XDP_REDIRECT;
}

static __always_inline
int send_resp_ep_server(struct data_header *d, struct iphdr *iph, struct app_event *ev, 
    struct HOMABP *bp, struct rpc_state *ctx,
    __u64 *rpc_qid, bool *trigger)
{

    bool first_packet = bpf_ntohs(bp->common.seq) == 0 ? 1 : 0;
    __u32 message_length = bpf_ntohl(bp->data.message_length);
    __u32 offset = bpf_ntohl(bp->data.seg.offset);
    __u32 packet_bytes = bpf_ntohl(bp->data.seg.segment_length);
    bool single_packet = message_length <= HOMA_MSS;
    
    new_ctx_instr_wrapper(ctx, ev, bp, first_packet, false);

    /* optimization for single-packet case */
    if (likely(single_packet)) {
        set_prio(iph, HOMA_MAX_PRIORITY - 1);
        bp->data.incoming = bpf_htonl(message_length);
        pkt_gen_instr_wrapper(d, bp);
        return XDP_TX;
    }

    if (offset + packet_bytes < Homa_unsched_bytes)
        set_prio(iph, get_prio(message_length));
    else
        set_prio(iph, atomic_read(&ctx->cc.sched_prio));

    /* check if we have enough credit */
    __u64 cc_granted = atomic_read(&ctx->cc.granted);
    bp->data.incoming = bpf_htonl(cc_granted);

    if (offset + packet_bytes <= cc_granted) {
        /* we have enough credit, further check three conditions to determine if we can send packet directly 
         * 1) no packets in rate limiter
         * 2) packet size is small enough or NIC queue is not busy
         */
        if (atomic_read(&ctx->nr_pkts_in_rl) == 0 &&
            (packet_bytes <= Homa_min_throttled_bytes || check_nic_queue(packet_bytes)))
        {
            /* this update is safe for no packets in rate limiter */
            ctx->next_xmit_offset = offset + packet_bytes;
            return XDP_TX;
        }
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
    *rpc_qid = ctx->qid;
    *trigger = cc_granted >= (offset + packet_bytes);

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
}

/* In MTP program:
first_req_pkt_ep -> everything in recv_req_ep_server() except the else case.
    Also, the conditions in the end are transformed into int_out.

next_req_pkt_ep -> is everything in recv_req_ep_server() except the if case.
    Also, the conditions in the end are transformed into int_out.

sched_ep -> it seems to be insert_grant_list()

choose_grants -> the first XDP_GEN tail call function

update_prios -> the other 8 tail call functions in XDP_GEN

gen_grants -> the main XDP_GEN function (after the tail call happens)
*/

// Question: how can the compiler know that choose_grants, update_prios, etc
// would go to XDP_GEN?

static __always_inline
void new_rx_ordered_data_wrapper(__u32 msg_len, struct homa_meta_info *data_meta) {
    data_meta->rx.msg_len = msg_len;
}

static __always_inline
void add_rx_data_seg_wrapper(__u32 seg_len, __u32 offset, struct homa_meta_info *data_meta) {
    data_meta->rx.seg_len = seg_len;
    data_meta->rx.offset = offset;
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

    __sync_fetch_and_add(&total_incoming, (__u64)(incoming - seg_length));

    new_rx_ordered_data_wrapper(ev->message_length, data_meta);

    add_rx_data_seg_wrapper(ev->segment_length, ev->offset, data_meta);

    if (int_out->complete)
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
    return insert_grant_list(ctx, &hkey, message_length);
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

    if (int_out->complete)
        return XDP_REDIRECT;

    // Question: so no caching for now?
    //if (need_schedule)
    //    cache_this_rpc(hkey);

    if (!int_out->new_state || !int_out->need_schedule)
        return XDP_REDIRECT;


    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(ev->flow_id.rpcid);
    hkey.local_port = ev->flow_id.local_port;
    hkey.remote_port = ev->flow_id.remote_port;
    hkey.remote_ip = ev->flow_id.remote_ip;
    return insert_grant_list(ctx, &hkey, message_length);
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
            
            enqueue_dead_crpc(hkey.remote_ip, hkey.remote_port, hkey.local_port, hkey.rpcid);

            return XDP_REDIRECT;
        }
        
        ctx->state = BPF_RPC_INCOMING;
        ctx->bit_width = DIV_ROUND_UP(message_length, HOMA_MSS);
        
        clear_all_bitmaps(ctx);

        set_bitmap(ctx, seq);

        ctx->message_length = message_length;
        ctx->cc.incoming = incoming;
        
        ctx->cc.bytes_remaining = message_length - seg_length;

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
        ctx->cc.bytes_remaining -= seg_length;

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

            return XDP_REDIRECT;
        }
        
        RPC_UNLOCK(ctx);
        
        __sync_fetch_and_sub(&total_incoming, (__u64)seg_length);
    }

    bool need_schedule = message_length > ctx->cc.incoming;

    //if (need_schedule)
    //    cache_this_rpc(hkey);
    
    if (!int_out->new_state || !need_schedule)
        return XDP_REDIRECT;

    struct rpc_key_t hkey = {0};
    hkey.rpcid = local_id(ev->flow_id.rpcid);
    hkey.local_port = ev->flow_id.local_port;
    hkey.remote_port = ev->flow_id.remote_port;
    hkey.remote_ip = ev->flow_id.remote_ip;
    return insert_grant_list(ctx, &hkey, message_length);
}
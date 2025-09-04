#pragma once
#ifndef HOMA_FUNCS_MTP_H
#define HOMA_FUNCS_MTP_H

#include <stdio.h>
#include <eTran_rpc.h>


#define MTP_ON 1

void RpcSocket::parse_app_request(struct app_event *ev, uint32_t local_ip, uint32_t remote_ip, uint16_t src_port,
    uint16_t dest_port, uint32_t msg_len, uint64_t addr, uint64_t rpcid, uint32_t slot_idx) {
    ev->local_ip = local_ip;
    ev->remote_ip = remote_ip;
    ev->src_port = src_port;
    ev->dest_port = dest_port;
    ev->msg_len = msg_len;
    ev->addr = addr;
    ev->rpcid = rpcid;
    ev->slot_idx = slot_idx;
}

void RpcSocket::send_req_ep_user(struct HOMABP *bp, struct app_event *ev, struct InternalReqMeta *ctx) {
    if(ctx->rest_msg_len == 0) {
        ctx->rest_msg_len = ev->msg_len;
    }

    bp->common.src_port = __cpu_to_be16(ev->src_port);
    bp->common.dest_port = ev->dest_port;
    bp->common.doff = (sizeof(struct data_header) - sizeof(struct data_segment)) >> 2;
    bp->common.type = DATA; 
    bp->common.seq = __cpu_to_be16(ctx->seq);
    bp->common.sender_id = __cpu_to_be64(ev->rpcid);

    bp->data.message_length = __cpu_to_be32(ev->msg_len);
    bp->data.retransmit = 0;
    bp->data.incoming = 0;
    bp->data.cutoff_version = 0;

    bp->data.seg.offset = __cpu_to_be32(ctx->curr_offset);

    uint32_t plen = ctx->rest_msg_len;
    if(plen > HOMA_MSS)
        plen = HOMA_MSS;
    bp->data.seg.segment_length = __cpu_to_be32(plen);

    bp->data.seg.ack.rpcid = 0;
    bp->data.seg.ack.dport = 0;
    bp->data.seg.ack.sport = 0;

    ctx->seq++;
    ctx->curr_offset += plen;
    ctx->rest_msg_len -= plen;
}

#endif
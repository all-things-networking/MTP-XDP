#pragma once

#include <stdio.h>
#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/ethernet.h> 
#include <netinet/tcp.h>
#include "include/xsk_if.h"

#define MTP_ON 1

#define TS_OPT_SIZE 12
#define HEADERS_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE)

static inline void in_order_receive(struct eTrantcp_connection *conn, uint64_t addr, char *pkt, uint32_t stream_id);

static inline void out_of_order_receive(struct eTrantcp_connection *conn, uint64_t addr, char *pkt, uint32_t stream_id);

void parse_packet(char *pkt, unsigned int *start_seq, unsigned int *end_seq, unsigned int py_len) {
    //struct iphdr *ip_header = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    //uint32_t length = ntohs(ip_header->tot_len) - (sizeof(struct iphdr) + sizeof(struct tcphdr) + TS_OPT_SIZE);
    uint32_t seq_num = ntohl(tcp_header->seq);
    uint16_t py_off = rxmeta_poff(pkt);
    //uint32_t rx_pos = rxmeta_pos(pkt);
    //printf("Curr: %u\tNext: %u\tACK? %u\n", seq_num, seq_num + py_len, tcp_header->ack);
    //printf("py_len: %u\tpy_off: %u\trx_pos: %u\n", py_len, py_off, rx_pos);

    *start_seq = seq_num + (py_off - HEADERS_LEN);
    *end_seq = seq_num + py_len;
    //printf("Trimmed start seq: %u\tTrimmed end seq: %u\n", *start_seq, *end_seq);
}

void mtp_add_data_seg_wrapper(struct app_ctx_per_thread *tctx, char *pkt, unsigned int start_seq,
    unsigned int end_seq, unsigned int py_len, struct eTrantcp_connection *conn, uint64_t addr,
    size_t *cached_rx_bump, uint32_t offset, uint32_t stream_id) {
    
    tcp_rxtx_info* info = stream_id == 1? &conn->rxtx1 : &conn->rxtx2;

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));

    struct eTran_tcp_flow_tuple tuple = {ip->saddr, ntohs(tcp->source), ip->daddr, ntohs(tcp->dest)};

    // If it is the first packet
    if(!tctx->mtp_values[tuple].following_packets) {
        *cached_rx_bump += py_len;
        tctx->mtp_values[tuple].expected_seq = end_seq;
        tctx->mtp_values[tuple].following_packets = true;

        // For now, I'm considering that rx_buf_size will be this constant
        // Although that can change in parse_mc_args in micro_kernel.cc
        tctx->mtp_values[tuple].rx_buf_size = 524288;
        tctx->mtp_values[tuple].last_offset = offset;
        // It will always be tctx->mtp_values[tuple].rx_next_pos
        uint32_t rx_pos = tctx->mtp_values[tuple].rx_next_pos + (offset - tctx->mtp_values[tuple].last_offset);
        // Just in case
        if(rx_pos >= tctx->mtp_values[tuple].rx_buf_size) {
            rx_pos -= tctx->mtp_values[tuple].rx_buf_size;
        }
        rxmeta_set_pos(pkt, rx_pos);
        in_order_receive(conn, addr, pkt, stream_id);
        //printf("A: %u\n", rx_pos);
    } else {
        // If this packet is in order
        if(tctx->mtp_values[tuple].expected_seq == start_seq) {
            // If this packet is the last missing to reach the OOO sequence
            if(tctx->mtp_values[tuple].ooo_len > 0 && end_seq == tctx->mtp_values[tuple].ooo_start) {
                *cached_rx_bump += (py_len + tctx->mtp_values[tuple].ooo_len);
                /* append ooo_rx_addrs to the tail of rx_addrs */
                info->rx_addrs.insert(info->rx_addrs.end(), info->ooo_rx_addrs.begin(), info->ooo_rx_addrs.end());
                info->ooo_rx_addrs.clear();

                uint32_t rx_pos = tctx->mtp_values[tuple].rx_next_pos + (offset - tctx->mtp_values[tuple].last_offset);
                if(rx_pos >= tctx->mtp_values[tuple].rx_buf_size) {
                    rx_pos -= tctx->mtp_values[tuple].rx_buf_size;
                }
                rxmeta_set_pos(pkt, rx_pos);
                //printf("B: %u\n", rx_pos);
                tctx->mtp_values[tuple].last_offset = offset;

                // TODO: Think if this is wrong
                tctx->mtp_values[tuple].rx_next_pos += (py_len + tctx->mtp_values[tuple].ooo_len);
                if(tctx->mtp_values[tuple].rx_next_pos >= tctx->mtp_values[tuple].rx_buf_size) {
                    tctx->mtp_values[tuple].rx_next_pos -= tctx->mtp_values[tuple].rx_buf_size;
                }

                in_order_receive(conn, addr, pkt, stream_id);
                tctx->mtp_values[tuple].expected_seq = tctx->mtp_values[tuple].ooo_start + tctx->mtp_values[tuple].ooo_len;
                tctx->mtp_values[tuple].ooo_len = 0;
            // If this packet is in order and does not complete a OOO sequence
            } else {
                tctx->mtp_values[tuple].expected_seq += py_len;
                *cached_rx_bump += py_len;

                uint32_t rx_pos = tctx->mtp_values[tuple].rx_next_pos + (offset - tctx->mtp_values[tuple].last_offset);
                if(rx_pos >= tctx->mtp_values[tuple].rx_buf_size) {
                    rx_pos -= tctx->mtp_values[tuple].rx_buf_size;
                }
                rxmeta_set_pos(pkt, rx_pos);
                //printf("C: %u\n", rx_pos);

                // Before, it was tctx->mtp_values[tuple].rx_next_pos += py_len (and it was causing a really anoying bug)
                tctx->mtp_values[tuple].rx_next_pos += (offset - tctx->mtp_values[tuple].last_offset);
                tctx->mtp_values[tuple].last_offset = offset;
                if(tctx->mtp_values[tuple].rx_next_pos >= tctx->mtp_values[tuple].rx_buf_size) {
                    tctx->mtp_values[tuple].rx_next_pos -= tctx->mtp_values[tuple].rx_buf_size;
                }

                in_order_receive(conn, addr, pkt, stream_id);
            }
        
        // If this packet is OOO
        } else {
            if(tctx->mtp_values[tuple].ooo_len == 0) {
                tctx->mtp_values[tuple].ooo_start = start_seq;
                tctx->mtp_values[tuple].ooo_len = py_len;
            } else if(end_seq == tctx->mtp_values[tuple].ooo_start) {
                tctx->mtp_values[tuple].ooo_start = start_seq;
                tctx->mtp_values[tuple].ooo_len += py_len;
            } else if(tctx->mtp_values[tuple].ooo_start + tctx->mtp_values[tuple].ooo_len == start_seq){
                tctx->mtp_values[tuple].ooo_len += py_len;
            } else {
                return;
            }

            uint32_t rx_pos = tctx->mtp_values[tuple].rx_next_pos + (offset - tctx->mtp_values[tuple].last_offset);
            if(rx_pos >= tctx->mtp_values[tuple].rx_buf_size) {
                rx_pos -= tctx->mtp_values[tuple].rx_buf_size;
            }
            rxmeta_set_pos(pkt, rx_pos);
            //printf("D: %u\n", rx_pos);
            //tctx->mtp_values[tuple].last_offset = offset;

            out_of_order_receive(conn, addr, pkt, stream_id);
        }
    }
}
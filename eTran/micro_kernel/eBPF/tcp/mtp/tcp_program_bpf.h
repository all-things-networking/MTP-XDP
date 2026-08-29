#pragma once
/*
 * tcp_program_bpf.h -- the TCP program's eBPF half, in generated shape.
 *
 * Read as generated code, like the control path's mtp/tcp_program.h. This file
 * holds what the compiler emits for the sites that run in eBPF: the flow id as
 * the packet carries it, the parser that builds it, and the context store
 * instantiated over TCP's own map with TCP's own key type.
 *
 * Ported so far:  the ingress flow id, its parser, and the context store.
 * The RX processing itself (tcp_ack, tcp_data) is still eTran's tcp_rx_process.
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

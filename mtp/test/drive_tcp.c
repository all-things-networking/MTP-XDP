/* Drive the generated program: start it up, open a connection through the
 * control path, then push an ACK and a data segment through the eBPF chain. */
#define __always_inline inline __attribute__((always_inline))
#include "prog.h"
#include "prog_proc_control.h"
#include "prog_proc_bpf.h"
#include "prog_proc_app.h"
#include "prog_dispatch.c"
#include <stdio.h>

void mtp_contract_report(void);

int main(void)
{
    mtp_prog_init();

    struct tcp_fid fid = { .f0 = 0x0a0a0101, .f1 = 1234, .f2 = 0x0a0a0102, .f3 = 80 };
    struct tcp_ctx *c = (struct tcp_ctx *)mtp_ctx_new(MTP_CTX_tcp_ctx, &fid);
    if (!c) { printf("no context\n"); return 1; }
    tcp_ctx_init(c);
    c->key = fid;

    printf("state after init      : %u  (CONN_WAIT_RX_SYN = %u)\n",
           c->control.state, (unsigned)CONN_WAIT_RX_SYN);

    /* An ACK for data we never sent must be rejected, and the chain says so
     * through the scratchpad rather than by returning. */
    c->ebpf.tx_next_seq = 1000; c->ebpf.tx_sent = 0; c->ebpf.tx_pending = 0;
    struct tcp_ack a; __builtin_memset(&a, 0, sizeof a);
    a.ack = 5000; a.payload_len = 0;
    mtp_dispatch_tcp_ack_ebpf(&a, c);
    printf("bogus ack accepted?   : tx_sent=%u (unchanged 0 = rejected)\n", c->ebpf.tx_sent);

    /* An in-order segment must advance the receive sequence. */
    c->ebpf.rx_next_seq = 7000; c->ebpf.rx_avail = 65535;
    struct tcp_data d; __builtin_memset(&d, 0, sizeof d);
    d.seq = 7000; d.payload_len = 1448;
    mtp_dispatch_tcp_data_ebpf(&d, c);
    printf("in-order 1448 bytes   : rx_next_seq 7000 -> %u\n", c->ebpf.rx_next_seq);

    /* And the same segment again is a duplicate. */
    __u32 before = c->ebpf.rx_next_seq;
    mtp_dispatch_tcp_data_ebpf(&d, c);
    printf("same segment again    : rx_next_seq %u -> %u\n", before, c->ebpf.rx_next_seq);

    mtp_ctx_del(MTP_CTX_tcp_ctx, &fid);
    mtp_contract_report();
    return 0;
}

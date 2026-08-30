/*
 * IS THE INTERLEAVE OBSERVABLE?
 *
 * One segment carrying payload AND an acknowledgement raises tcp_ack and
 * tcp_data together. eTran walks the header once and runs half of one chain,
 * then half of the other:
 *
 *     proc_ack | proc_seq_ooo | proc_window_rtt | proc_recv
 *
 * The program does not say that. It declares two chains and says nothing about
 * how a target that gets both at once should schedule them, so generated code
 * runs one and then the other. GENERATED-VS-HANDWRITTEN.md called that
 * untested, which it was.
 *
 * This settles it the way it should be settled -- semantically, not by
 * throughput. Both orders are run from byte-identical starting state over a
 * spread of inputs, and the whole context and scratchpad are compared after.
 * If they never differ, the reordering cannot be observed by this program and
 * the target is free to choose; if they do, the difference is printed and the
 * freedom is not there.
 */
#define __always_inline inline __attribute__((always_inline))
#include "prog.h"
#include "prog_proc_control.h"
#include "prog_proc_bpf.h"
#include "prog_proc_app.h"
#include "prog_dispatch.c"
#include <stdio.h>
#include <string.h>

void mtp_contract_report(void);

/* The chain order eTran actually runs, transcribed from
 * eBPF/tcp/mtp/tcp_program_bpf.h -- ack, then seq/ooo, then window/rtt, then
 * recv. The two fusions there are irrelevant to order and are kept apart. */
static void run_etran_order(struct tcp_ack *a, struct tcp_data *d,
                            struct tcp_ctx *c, struct tcp_scratch *s)
{
    proc_ack(a, c, s);
    proc_fast_retransmit(a, c, s);
    proc_seq(d, &c->ebpf, s);
    proc_ooo(d, &c->ebpf, s);
    proc_window(a, &c->ebpf, s);
    proc_rtt(a, c, s);
    proc_recv(d, &c->ebpf, s);
}

/* What the program says: one chain, then the other -- ON THE SAME SCRATCHPAD,
 * so that this compares ORDER and only order. Whether the generated dispatch
 * shares one is a separate question, asked separately below. */
static void run_program_order(struct tcp_ack *a, struct tcp_data *d,
                              struct tcp_ctx *c, struct tcp_scratch *s)
{
    proc_ack(a, c, s);
    proc_fast_retransmit(a, c, s);
    proc_window(a, &c->ebpf, s);
    proc_rtt(a, c, s);
    proc_seq(d, &c->ebpf, s);
    proc_ooo(d, &c->ebpf, s);
    proc_recv(d, &c->ebpf, s);
}

struct sample { __u32 rx_next_seq, tx_next_seq, tx_sent, tx_pending, ack, seq, plen; };

int main(void)
{
    mtp_prog_init();

    /* A spread that walks the branches: in order, out of order, a duplicate
     * ack, an ack of everything outstanding, and a zero-length segment. */
    struct sample tests[] = {
        { 7000, 1000,  500,  200, 1200, 7000, 1448 },   /* in order, partial ack */
        { 7000, 1000,  500,  200, 1200, 9000, 1448 },   /* out of order */
        { 7000, 1000,  500,  200,  500, 7000, 1448 },   /* duplicate ack */
        { 7000, 1000,  500,    0, 1000, 7000,  100 },   /* everything acked */
        { 7000, 1000,  500,  200, 1200, 7000,    0 },   /* pure ack */
        { 7000, 1000,    0,    0,    0, 7000, 1448 },   /* nothing outstanding */
        {    0, 1000,  500,  200, 1200,    0, 1448 },   /* at zero */
        { 0xfffffc00, 1000, 500, 200, 1200, 0xfffffc00, 1448 }, /* wraps */
    };

    int differ = 0;
    for (unsigned t = 0; t < sizeof tests / sizeof tests[0]; t++) {
        struct sample *v = &tests[t];
        struct tcp_ctx c1, c2;
        struct tcp_scratch s1, s2;
        struct tcp_ack a; struct tcp_data d;

        memset(&c1, 0, sizeof c1);
        tcp_ctx_init(&c1);
        c1.ebpf.rx_next_seq = v->rx_next_seq;  c1.ebpf.rx_avail = 65535;
        c1.ebpf.tx_next_seq = v->tx_next_seq;  c1.ebpf.tx_sent  = v->tx_sent;
        c1.ebpf.tx_pending  = v->tx_pending;
        c2 = c1;

        memset(&a, 0, sizeof a); memset(&d, 0, sizeof d);
        a.ack = v->ack; a.seq = v->seq; a.payload_len = v->plen;
        a.window = 65535; a.ts_val = 12345; a.ts_ecr = 1;
        d.ack = v->ack; d.seq = v->seq; d.payload_len = v->plen;
        d.window = 65535; d.ts_val = 12345; d.ts_ecr = 1;

        memset(&s1, 0, sizeof s1); memset(&s2, 0, sizeof s2);
        run_etran_order(&a, &d, &c1, &s1);
        run_program_order(&a, &d, &c2, &s2);

        int dc = memcmp(&c1, &c2, sizeof c1);
        int ds = memcmp(&s1, &s2, sizeof s1);
        if (dc || ds) {
            differ++;
            printf("case %u DIFFERS%s%s\n", t, dc ? " (context)" : "", ds ? " (scratchpad)" : "");
            printf("   rx_next_seq  etran-order %-10u program-order %u\n",
                   c1.ebpf.rx_next_seq, c2.ebpf.rx_next_seq);
            printf("   tx_sent      etran-order %-10u program-order %u\n",
                   c1.ebpf.tx_sent, c2.ebpf.tx_sent);
            printf("   rx_dupack    etran-order %-10u program-order %u\n",
                   c1.ebpf.rx_dupack_cnt, c2.ebpf.rx_dupack_cnt);
            printf("   tx_bump      etran-order %-10u program-order %u\n",
                   s1.tx_bump, s2.tx_bump);
            printf("   rx_bump      etran-order %-10u program-order %u\n",
                   s1.rx_bump, s2.rx_bump);
            printf("   trigger_ack  etran-order %-10d program-order %d\n",
                   (int)s1.trigger_ack, (int)s2.trigger_ack);
        }
    }

    printf("interleave: %d of %zu cases differ\n",
           differ, sizeof tests / sizeof tests[0]);

    /*
     * A SEPARATE QUESTION, and the one that turned out to matter. The generated
     * dispatch is per EVENT and declares its own scratchpad, so the two chains
     * one packet raises do not share one. eTran's do: rx_bump is written by
     * proc_recv and is how the receive ring is advanced, and a target reading
     * it after the ack chain's dispatch would find nothing.
     */
    {
        struct tcp_ctx c; struct tcp_scratch s;
        struct tcp_ack a; struct tcp_data d;
        memset(&c, 0, sizeof c); tcp_ctx_init(&c);
        c.ebpf.rx_next_seq = 7000; c.ebpf.rx_avail = 65535;
        memset(&a, 0, sizeof a); memset(&d, 0, sizeof d);
        a.seq = 7000; a.payload_len = 1448; a.window = 65535;
        d.seq = 7000; d.payload_len = 1448; d.window = 65535;

        memset(&s, 0, sizeof s);
        proc_seq(&d, &c.ebpf, &s); proc_ooo(&d, &c.ebpf, &s); proc_recv(&d, &c.ebpf, &s);
        printf("\nscratchpad shared across the packet : rx_bump = %u\n", s.rx_bump);

        memset(&c, 0, sizeof c); tcp_ctx_init(&c);
        c.ebpf.rx_next_seq = 7000; c.ebpf.rx_avail = 65535;
        memset(&s, 0, sizeof s);
        /* Both of the packet's chains, on ONE scratchpad the caller owns --
         * which is the whole point of the dispatch taking it rather than
         * declaring it. */
        mtp_dispatch_tcp_ack_ebpf(&a, &c, &s);
        mtp_dispatch_tcp_data_ebpf(&d, &c, &s);
        printf("through the generated dispatches    : rx_bump = %u\n", s.rx_bump);
        if (s.rx_bump != 1448) { printf("FAIL: the packet's chains lost it\n"); return 1; }
    }
    mtp_contract_report();
    return differ ? 1 : 0;
}

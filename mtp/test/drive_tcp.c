/* Drive the generated program: start it up, open a connection through the
 * control path, then push an ACK and a data segment through the eBPF chain. */
#define __always_inline inline __attribute__((always_inline))
#include "prog.h"
#include "prog_proc_control.h"
#include "prog_proc_bpf.h"
#include "prog_proc_app.h"
#include "prog_dispatch_control.c"
#include "prog_dispatch_bpf.h"
#include "prog_dispatch_app.h"
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
    struct tcp_scratch sp; __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true;  /* the ack chain ran */
    struct tcp_ack a; __builtin_memset(&a, 0, sizeof a);
    a.ack = 5000; a.payload_len = 0;
    mtp_dispatch_tcp_ack_ebpf(&a, &c->ebpf, &c->cc_shared, &sp);
    printf("bogus ack accepted?   : tx_sent=%u (unchanged 0 = rejected)\n", c->ebpf.tx_sent);

    /* An in-order segment must advance the receive sequence. rx_buf_size is set
     * because the ring wraps on it now, and a zero would make the wrap a no-op
     * and the test meaningless. */
    c->ebpf.rx_next_seq = 7000; c->ebpf.rx_avail = 65535;
    c->ebpf.rx_buf_size = 4096; c->ebpf.rx_next_pos = 0;
    struct tcp_data d; __builtin_memset(&d, 0, sizeof d);
    d.seq = 7000; d.payload_len = 1448;
    __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true;  /* the ack chain ran */
    mtp_dispatch_tcp_data_ebpf(&d, &c->ebpf, &sp);
    printf("in-order 1448 bytes   : rx_next_seq 7000 -> %u\n", c->ebpf.rx_next_seq);

    /* And the same segment again is a duplicate. */
    __u32 before = c->ebpf.rx_next_seq;
    __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true;  /* the ack chain ran */
    mtp_dispatch_tcp_data_ebpf(&d, &c->ebpf, &sp);
    printf("same segment again    : rx_next_seq %u -> %u\n", before, c->ebpf.rx_next_seq);

    /* A segment overlapping what was already delivered is TRIMMED, not refused:
     * 1000 bytes starting 400 before the stream position deliver 600. */
    c->ebpf.rx_next_seq = 20000; c->ebpf.rx_avail = 65535;
    c->ebpf.rx_next_pos = 0; c->ebpf.rx_ooo_len = 0;
    __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true;  /* the ack chain ran */
    __builtin_memset(&d, 0, sizeof d);
    d.seq = 19600; d.payload_len = 1000;
    mtp_dispatch_tcp_data_ebpf(&d, &c->ebpf, &sp);
    printf("overlapping segment   : trim_start=%u accepted=%u rx_next_seq=%u\n",
           sp.trim_start, sp.rx_bump, c->ebpf.rx_next_seq);

    /* Wholly out of window: nothing accepted, and no ack provoked. */
    c->ebpf.rx_next_seq = 30000; c->ebpf.rx_avail = 1000;
    c->ebpf.rx_next_pos = 0; c->ebpf.rx_ooo_len = 0;
    __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true; sp.trigger_ack = true;
    __builtin_memset(&d, 0, sizeof d);
    d.seq = 90000; d.payload_len = 100;
    mtp_dispatch_tcp_data_ebpf(&d, &c->ebpf, &sp);
    printf("out of window         : rx_bump=%u rx_next_seq=%u trigger_ack=%d\n",
           sp.rx_bump, c->ebpf.rx_next_seq, (int)sp.trigger_ack);

    /* The ring wraps: 300 bytes from position 3900 of a 4096 ring land at 104. */
    c->ebpf.rx_next_seq = 40000; c->ebpf.rx_avail = 65535;
    c->ebpf.rx_next_pos = 3900; c->ebpf.rx_buf_size = 4096; c->ebpf.rx_ooo_len = 0;
    __builtin_memset(&sp, 0, sizeof sp); sp.ack_ok = true;  /* the ack chain ran */
    __builtin_memset(&d, 0, sizeof d);
    d.seq = 40000; d.payload_len = 300;
    mtp_dispatch_tcp_data_ebpf(&d, &c->ebpf, &sp);
    printf("ring wrap             : rx_next_pos 3900 + 300 of 4096 -> %u\n",
           c->ebpf.rx_next_pos);

    /* ---- the egress site ------------------------------------------------ */
    struct tcp_tx_scratch tx;

    /* A segment goes out: the stream advances by its length and the ring wraps
     * on tx_buf_size, exactly as the receive side does. */
    c->ebpf.tx_next_seq = 5000; c->ebpf.tx_next_pos = 3900;
    c->ebpf.tx_buf_size = 4096; c->ebpf.tx_sent = 0; c->ebpf.tx_pending = 300;
    __builtin_memset(&tx, 0, sizeof tx);
    tx.tx_pos = 3900; tx.payload_len = 300;
    struct app_send snd; __builtin_memset(&snd, 0, sizeof snd);
    gen_seg(&snd, &c->ebpf, &c->cc_shared, &tx);
    printf("segment out           : tx_ok=%d seq 5000->%u pos 3900+300 of 4096 -> %u sent=%u\n",
           (int)tx.tx_ok, c->ebpf.tx_next_seq, c->ebpf.tx_next_pos, c->ebpf.tx_sent);

    /* The application and the transport disagree about where the stream is:
     * this frame is not ours to send, and nothing may advance. */
    c->ebpf.tx_next_seq = 5000; c->ebpf.tx_next_pos = 100; c->ebpf.tx_sent = 0;
    __builtin_memset(&tx, 0, sizeof tx);
    tx.tx_pos = 999; tx.payload_len = 300;
    gen_seg(&snd, &c->ebpf, &c->cc_shared, &tx);
    printf("stale position        : tx_ok=%d seq stays %u sent stays %u\n",
           (int)tx.tx_ok, c->ebpf.tx_next_seq, c->ebpf.tx_sent);

    /* Receive buffer freed while nothing is in flight: worth a window update of
     * its own. With data pending it would ride along instead. */
    c->ebpf.rx_avail = 1000; c->ebpf.tx_pending = 0;
    __builtin_memset(&tx, 0, sizeof tx);
    tx.rx_bump = 4000;
    struct app_recv rcv; __builtin_memset(&rcv, 0, sizeof rcv);
    send_wnd_update(&rcv, &c->ebpf, &tx);
    printf("window update alone   : wnd_upd=%d rx_avail 1000+4000 -> %u\n",
           (int)tx.wnd_upd, c->ebpf.rx_avail);

    c->ebpf.rx_avail = 1000; c->ebpf.tx_pending = 512;
    __builtin_memset(&tx, 0, sizeof tx);
    tx.rx_bump = 4000;
    send_wnd_update(&rcv, &c->ebpf, &tx);
    printf("window update rides   : wnd_upd=%d (data pending, no packet of its own)\n",
           (int)tx.wnd_upd);

    /* The retransmission timer with nothing outstanding has nothing to do. */
    c->ebpf.tx_sent = 0;
    __builtin_memset(&tx, 0, sizeof tx);
    struct rto_timeout to; __builtin_memset(&to, 0, sizeof to);
    gen_retransmit(&to, &c->ebpf, &tx);
    printf("rto, nothing in flight: tx_ok=%d\n", (int)tx.tx_ok);
    c->ebpf.tx_sent = 1448;
    __builtin_memset(&tx, 0, sizeof tx);
    gen_retransmit(&to, &c->ebpf, &tx);
    printf("rto, data in flight   : tx_ok=%d\n", (int)tx.tx_ok);

    mtp_ctx_del(MTP_CTX_tcp_ctx, &fid);
    mtp_contract_report();
    return 0;
}

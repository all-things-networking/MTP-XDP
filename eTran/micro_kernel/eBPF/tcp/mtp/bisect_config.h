#pragma once
/*
 * WHICH RX GROUPS ARE GENERATED. One line per bisection step.
 *
 * Nothing defined  = the hand-written port, which measures at eTran's ceiling.
 * All four defined = the generated port, which is pinned ~27% below it.
 *
 * The point of a header rather than a -D is that stage_stack.sh ships a git
 * ref: each step is a commit, so what was measured is recoverable exactly, and
 * nothing but the toggle can differ between two measurements.
 */

/* #define MTP_GEN_ACK    */   /* proc_ack + proc_fast_retransmit */
/* #define MTP_GEN_SEQOOO */   /* proc_seq + proc_ooo             */
/* #define MTP_GEN_WINRTT */   /* proc_window + proc_rtt          */
/* #define MTP_GEN_RECV   */   /* proc_recv                       */

/*
 * AND THE EGRESS SITE. Left out of the first draft on the grounds that on
 * hp100 the TX swap cost about one point of eleven -- but that was a different
 * reservation and a deficit of 11%, where this one is 27%. Carrying a result
 * across nodes as an assumption is what the server-thread mix-up was made of.
 */
/* #define MTP_GEN_RETRANSMIT */  /* gen_retransmit   */
/* #define MTP_GEN_WNDUPD     */  /* send_wnd_update  */
/* #define MTP_GEN_SEG        */  /* gen_seg          */

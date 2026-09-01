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

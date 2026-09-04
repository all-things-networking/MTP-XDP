/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-newconv.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "mtp/mtp_contract.h"

/* ---- const---------------------------------------------- */
#define MTP_FLAG_FIN ((__u8)1)
#define MTP_FLAG_SYN ((__u8)2)
#define MTP_FLAG_RST ((__u8)4)
#define MTP_FLAG_PSH ((__u8)8)
#define MTP_FLAG_ACK ((__u8)16)
#define MTP_FLAG_ECE ((__u8)64)
#define MTP_FLAG_CWR ((__u8)128)
#define MTP_CONN_WAIT_RX_SYN ((__u8)0)
#define MTP_CONN_WAIT_TX_SYNACK ((__u8)1)
#define MTP_CONN_WAIT_RX_SYNACK ((__u8)2)
#define MTP_CONN_WAIT_TX_SYN ((__u8)3)
#define MTP_CONN_OPEN ((__u8)4)
#define MTP_CONN_CLOSED ((__u8)5)
#define MTP_TYPE_FAKE ((__u8)0)
#define MTP_TYPE_NORMAL ((__u8)1)
#define MTP_PARITY_ISN_ACTIVE ((__u32)0)
#define MTP_PARITY_ISN_PASSIVE ((__u32)1)
#define MTP_PARITY_CTRL_WINDOW ((__u16)11680)
#define MTP_PARITY_MSS ((__u16)1460)
#define MTP_PARITY_MSS_W_TS ((__u16)1448)
#define MTP_PROG_MAX_BACKLOG ((__u32)512)
#define MTP_PARITY_ALWAYS_OFFER_ECN ((bool)true)
#define MTP_TRANSPORT_IP_PROTO ((__u8)6)
#define MTP_IP_ECN_CE ((__u8)3)
#define MTP_PRIO_CONTROL ((__u8)2)
#define MTP_PRIO_ACK ((__u8)1)
#define MTP_PRIO_DATA ((__u8)0)
#define MTP_PARITY_DUP_ACK_THRESH ((__u32)3)
#define MTP_TCP_MAX_RTT ((__u32)100000)
#define MTP_TCP_WND_SCALE ((__u32)3)
#define MTP_LINK_BANDWIDTH ((__u64)3125000000)

/* ---- param -- defaults; configuration may override------ */
static __attribute__((unused)) __u32 tcp_handshake_timeout = 50;
static __attribute__((unused)) __u32 tcp_close_timeout = 100;

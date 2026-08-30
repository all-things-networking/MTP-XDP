/* GENERATED from /mnt/home/mtahmasb/MTP-XDP/mtp/tcp.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
#include "mtp/mtp_contract.h"

/* ---- const---------------------------------------------- */
#define FLAG_FIN ((__u8)1)
#define FLAG_SYN ((__u8)2)
#define FLAG_RST ((__u8)4)
#define FLAG_PSH ((__u8)8)
#define FLAG_ACK ((__u8)16)
#define FLAG_ECE ((__u8)64)
#define FLAG_CWR ((__u8)128)
#define CONN_WAIT_RX_SYN ((__u8)0)
#define CONN_WAIT_TX_SYNACK ((__u8)1)
#define CONN_WAIT_RX_SYNACK ((__u8)2)
#define CONN_WAIT_TX_SYN ((__u8)3)
#define CONN_OPEN ((__u8)4)
#define CONN_CLOSED ((__u8)5)
#define TYPE_FAKE ((__u8)0)
#define TYPE_NORMAL ((__u8)1)
#define PARITY_ISN_ACTIVE ((__u32)0)
#define PARITY_ISN_PASSIVE ((__u32)1)
#define PARITY_CTRL_WINDOW ((__u16)11680)
#define PARITY_MSS ((__u16)1460)
#define PARITY_MSS_W_TS ((__u16)1448)
#define PROG_MAX_BACKLOG ((__u32)512)
#define PARITY_ALWAYS_OFFER_ECN ((bool)true)
#define TRANSPORT_IP_PROTO ((__u8)6)
#define IP_ECN_CE ((__u8)3)
#define PRIO_CONTROL ((__u8)2)
#define PRIO_ACK ((__u8)1)
#define PRIO_DATA ((__u8)0)
#define PARITY_DUP_ACK_THRESH ((__u32)3)
#define TCP_MAX_RTT ((__u32)1000000)
#define TCP_WND_SCALE ((__u32)12)
#define LINK_BANDWIDTH ((__u32)-769803776)

/* ---- param -- defaults; configuration may override------ */
static __attribute__((unused)) __u32 tcp_handshake_timeout = 50;
static __attribute__((unused)) __u32 tcp_close_timeout = 100;

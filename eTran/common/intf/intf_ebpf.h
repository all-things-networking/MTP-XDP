#pragma once
/**
 * Common interface for ebpf and microkernel
 */

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#ifndef __cplusplus
#include <bpf/bpf_helpers.h>
#endif

#define MAX_PEER 32

#define MAX_NIC_QUEUES 20
#define MAX_XSK_FD 1024

#define CACHE_LINE_SIZE 64
#define MAX_CPU 20
#define MAXMAX_CPU 32

#define MAX_BUCKET_SIZE 8192
#define MAX_QUEUE_SIZE 1024

#define POISON_64 __UINT64_MAX__
#define POISON_32 __UINT32_MAX__
#define POISON_16 __UINT16_MAX__

#define MAX_TCP_FLOWS 65536

/* allow some conditions to bypass the rate limiter */
#define BYPASS_RL

#define ACK_COALESCING

#define OOO_RECV

//////////////////////// control path ////////////////////////
typedef struct __attribute__((packed)) {
    __u64 slowpath;
    // this packet is a control signal
    __u64 flag;
    #define FLAG_SYNC          0x1
    #define FLAG_TO            0x2
    // application has consumed how many bytes
    __u32 rx_bump;
    // number of bytes submitted in this batch
    __u32 tx_pending;
    // offset in the send buffer
    __u32 tx_pos;
    // payload length of this packet
    __u32 plen;
} tx_t;

typedef struct __attribute__((packed)) {
    // receiving queue id
    __u32 qid;
    #define FORCE_RX_BUMP_MASK  0x80000000
    // opaque connection pointer
    __u64 conn;
    // offset in the received buffer
    __u32 rx_pos;
    // payload start offset
    __u16 poff;
    // payload length
    __u16 plen;
    // newly available AF_XDP budget
    __u32 xsk_budget_avail;
    union {
        // acked bytes
        __u32 ack_bytes;
        // go back postion in send buffer
        __u32 go_back_pos;
    };
    #define RECOVERY_MASK       0x80000000
    __u32 ooo_bump;
    #define OOO_SEGMENT_MASK    0x80000000
    #define OOO_FIN_MASK        0x40000000
    #define OOO_CLEAR_MASK      0x20000000
} rx_t;

struct meta_info {
    union {
        tx_t tx;
        rx_t rx;
    } __attribute__((packed));
} __attribute__((packed));
#ifdef __cplusplus
static_assert(sizeof(struct meta_info) == 32, "meta_info size is not 32 bytes");
#else
_Static_assert (sizeof(struct meta_info) == 32, "meta_info size is not 32 bytes");
#endif

struct slow_path_info {
    bool active;
    int sp_xsk_map_key;
};
//////////////////////////// TCP ////////////////////////////

#define TCP_MAX_RTT 100000

struct timer_event {
    __u64 curr_tsc;
};

struct bpf_cc {
    __u64 prev_desired_tx_ts;
    /** Bps */
    __u32 rate;
    /** Counter drops each control interval */
    __u16 cnt_tx_drops;
    /** Counter acks each control interval */
    __u16 cnt_rx_acks;
    /** Counter bytes sent each control interval */
    __u32 cnt_rx_ack_bytes;
    /** Counter acks marked each control interval */
    __u32 cnt_rx_ecn_bytes;
    /** RTT estimate (us) */
    __u32 rtt_est;
    /** has pending tx data? */
    __u32 txp;
    /** Timer event instance */
    struct timer_event ev;
} __attribute__((packed, aligned(64)));
#ifdef __cplusplus
static_assert(sizeof(struct bpf_cc) == 64, "bpf_cc size is not 64 bytes");
#else
_Static_assert (sizeof(struct bpf_cc) == 64, "bpf_cc size is not 64 bytes");
#endif
/*} __attribute__((packed, aligned(32)));
#ifdef __cplusplus
static_assert(sizeof(struct bpf_cc) == 32, "bpf_cc size is not 32 bytes");
#else
_Static_assert (sizeof(struct bpf_cc) == 32, "bpf_cc size is not 32 bytes");
#endif*/

struct bpf_cc_map_user {
    struct bpf_cc entry[MAX_TCP_FLOWS];
};

// TCP fast path state
struct bpf_tcp_conn {

    struct bpf_spin_lock lock;

    // pointer to connection is userspace
    __u64 opaque_connection;

    __u32 qid;

    __u8 local_mac[ETH_ALEN];
    __u8 remote_mac[ETH_ALEN];

    __u32 local_ip;
    __u32 remote_ip;

    __u16 local_port;
    __u16 remote_port;

    __u32 rx_buf_size;
    __u32 tx_buf_size;

    /** Bytes available in remote end for received segments */
    __u32 rx_remote_avail;
    /** Offset in buffer to place next segment */
    __u32 rx_next_pos;

    /* Number of bytes submitted by AF_XDP but not processed by eBPF yet */
    __u32 tx_pending;    
    /** Number of bytes up to next pos in the buffer that were sent but not
     * acknowledged yet. */
    __u32 tx_sent;
    /** Offset in buffer for next segment to be sent */
    __u32 tx_next_pos;
    /** Timestamp to echo in next packet */
    __u32 tx_next_ts;

    __u32 cc_idx;
    __u8 ecn_enable;

    // Entries used for sliding window
    /** Next sequence number expected */
    __u32 rx_next_seq;          // MTP -> returned by first_unset()
    /* Start of interval of out-of-order received data */
    __u32 rx_ooo_start;
    /* Length of interval of out-of-order received data */
    __u32 rx_ooo_len;

    // eTran entries used in MTP
    /** Duplicate ack count */
    __u16 rx_dupack_cnt;        // MTP -> duplicate_acks
    /** Sequence number of next segment to be sent */
    __u32 tx_next_seq;          // MTP -> send_next
    /** Bytes available for received segments at next position */
    __u32 rx_avail;             // MTP -> rwnd_size

    // MTP-only entries
    __u8 first_rto;
    __u32 RTO;
    __s64 SRTT;
    __u32 RTTVAR;
    __u32 last_ack;
    __u32 rate;
    __u32 send_una;
    __u32 data_end;
    __u32 recv_next;
    __u32 buf_curr_seq;
    __u32 recv_init_seq;

    // used by XDP_REDIRECT
    // this value is updated when application calls open() or accept()
    __u8 qid2xsk[MAX_NIC_QUEUES];

} __attribute__((packed, aligned(64)));

struct ebpf_flow_tuple {
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
};

// 1460 - 12 (Timestamp option)
#define TCP_MSS_W_TS 1448
// timestamp option size
#define TS_OPT_SIZE 12

//////////////////////////// TimingWheel ////////////////////////////
// Maximum rate (Gbps): Per-slot Bytes * 8 / SLOT_WIDTH_NS (ns)
// Minimum rate (Mbps): Per-slot Bytes * 8 *1e6 / HORIZON_NS (ns)
#ifndef __cplusplus
#define SLOT_WIDTH_NS 500
// #define HORIZON_NS ((__u64)3200000)
#endif

#define LINK_BANDWIDTH ((__u64)25000 * 1000 * 1000 / 8)

// HORIZON_NS / SLOT_WIDTH_NS
#define MAX_BUCKETS 50000
#define NR_SLOT_PER_BKT 1024

//////////////////////////// Homa ////////////////////////////
/* dest port <--> xsks_map index */
struct target_xsk
{
    int xsk_map_idx[MAXMAX_CPU];
};

typedef struct __attribute__((packed)) {
    __u32 flag;
    __u32 slowpath;
    __u64 buffer_next;
    __u64 buffer_addr;
    __u32 unused1;
    __u32 unused2;
} homa_tx_t;

typedef struct __attribute__((packed)) {
    __u32 qid;
    __u64 reap_client_buffer_addr;
    __u64 reap_server_buffer_addr;
    __u32 msg_len;
    __u32 seg_len;
    __u32 offset;
} homa_rx_t;

struct homa_meta_info
{
    union {
        homa_tx_t tx;
        homa_rx_t rx;
    } __attribute__((packed));
} __attribute__((packed));
#ifdef __cplusplus
static_assert(sizeof(struct homa_meta_info) == 32, "homa_meta_info size is not 32 bytes");
#else
_Static_assert (sizeof(struct homa_meta_info) == 32, "homa_meta_info size is not 32 bytes");
#endif

// RPC state macros
#define MAX_RPC_TBL_SIZE (1 << 16)

#define BPF_RPC_DEAD 0
#define BPF_RPC_OUTGOING 5
#define BPF_RPC_INCOMING 6
#define BPF_RPC_IN_SERVICE 8

struct homa_cc
{
    // Update in XDP per received packet, protected by rpc lock
    // Read in XDP_GEN without lock
    __u64 bytes_remaining; // 8B
    // Maintain the value in rbtree, protected by **grant_list_lock**, used for finding the rbtree with O(logN)
    __u64 last_bytes_remaining; // 8B
    // Read and update in XDP_GEN, used by receiver to send GRANT packets.
    // protected by **grant_lock**.
    __u64 incoming; // 8B
    __u64 granted;  // 8B
    __u64 sched_prio; // 8B
};

struct rpc_key_t {
    __u64 rpcid;      
    __u16 local_port; 
    __u16 remote_port;
    __u32 remote_ip;
};

#ifdef __cplusplus
struct rpc_state {
    __u8 state;
    __u8 busy_count;
    __u16 remote_port;
    __u16 local_port;
    __u32 remote_ip;
    __u64 id;
    __u16 bit_width;
    __u16 bitmap_round;
    __u32 message_length;
    __u64 nr_pkts_in_rl;
    __u64 qid;
    __u64 next_xmit_offset;
    struct homa_cc cc;
    __u64 buffer_head;
    __u64 bitmap[12];
    __u16 resend_count;
    void *cc_node;
    struct bpf_spin_lock hash_lock; // 4B

    __u32 new_rx_ord_data_msg_len;
} __attribute__((aligned(64)));
static_assert(sizeof(struct rpc_state) == 256, "rpc_state size is not 256 bytes");
#else
struct rpc_state_cc {
    // === cache line ===
    struct bpf_rb_node rbtree_link; // 32B
    struct bpf_refcount ref;        // 4B
    __u32 bytes_remaining;          // 4B

    __u8 pad1; // 1B

    /**
     * @brief tree_id = 0: rpc rbtree, tree_id = 1: peer rbtree
     */
    __u8 tree_id; // 1B
    __u16 peer_id; // 2B
    __u32 incoming;     // 4B
    struct rpc_key_t hkey; // 16B
    // === cache line ===

    // we embed ***in_peer_tree*** to the lowest bit of birth
    __u64 birth; // 8B

    __u32 message_length; // 4B

    __u32 pad; // 4B

} __attribute__((packed)); // FIXME: compiler complains about this but ebpf verifier require

struct rpc_state
{
    __u8 state;
    __u8 busy_count;
    __u16 remote_port;
    __u16 local_port;
    __u32 remote_ip;
    __u64 id;
    __u16 bit_width;
    __u16 bitmap_round;
    __u32 message_length;
    __u64 nr_pkts_in_rl;
    __u64 qid;
    __u64 next_xmit_offset;
    struct homa_cc cc;
    __u64 buffer_head;
    __u64 bitmap_0;
    __u64 bitmap_1;
    __u64 bitmap_2;
    __u64 bitmap_3;
    __u64 bitmap_4;
    __u64 bitmap_5;
    __u64 bitmap_6;
    __u64 bitmap_7;
    __u64 bitmap_8;
    __u64 bitmap_9;
    __u64 bitmap_10;
    __u64 bitmap_11;
    __u16 resend_count;
    // used for throttle list to avoid allocation overhead
    struct rpc_state_cc __kptr *cc_node;
    struct bpf_spin_lock hash_lock; // 4B

    __u32 new_rx_ord_data_msg_len;
} __attribute__((aligned(64)));
_Static_assert (sizeof(struct rpc_state) == 256, "rpc_state size is not 256 bytes");
#endif

#define HOMA_MAX_PRIORITIES 8
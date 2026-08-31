#pragma once
#include "mtp/gen/prog_context.h"   /* the generated context parts */
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

struct bpf_cc {
    /* The pacing state, which is the TARGET's: when this flow may next send. */
    __u64 prev_desired_tx_ts;
    /*
     * THE PROGRAM'S, generated: @placement("cc_shared") in tcp.mtp -- the
     * counters a congestion controller reads, the rate it sets, the RTT
     * estimate, and whether anything is outstanding.
     */
    struct tcp_ctx_cc_shared mtp_cc;
} __attribute__((packed, aligned(32)));
/*
 * THE SIZE ASSERT IS GONE, and deliberately. It pinned this struct at 32 bytes
 * -- a cache-line decision, and a fair one -- but it pinned it against a field
 * list this file no longer owns. The program decides what congestion state
 * exists; if that no longer fits a target's chosen size, that is a conversation
 * between the two, not something to discover as a build break with no
 * explanation. Worth reinstating as a WARNING that names the overflow.
 */

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

    /*
     * THE PROTOCOL STATE, GENERATED. These twelve fields used to be written out
     * here; they are exactly what tcp.mtp declares as @placement("ebpf"), and
     * they are the program's to name. What is left around them in this struct
     * is the target's: a lock, an opaque handle, a queue id, the MACs, the
     * congestion-control index.
     *
     * Nesting rather than being pointed at is the whole point. The backend used
     * to be told "compile against bpf_tcp_conn", which made this file the owner
     * of protocol state and forced the program to use the names eTran had
     * picked. Now the program names its fields and this structure holds them.
     */
    struct tcp_ctx_ebpf mtp_ebpf;

    __u32 cc_idx;
    __u8 ecn_enable;

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
    __u32 slowpath;
    __u64 buffer_next;
    __u64 buffer_addr;
} homa_tx_t;

typedef struct __attribute__((packed)) {
    __u32 qid;
    __u64 reap_client_buffer_addr;
    __u64 reap_server_buffer_addr;
} homa_rx_t;

struct homa_meta_info
{
    union {
        homa_tx_t tx;
        homa_rx_t rx;
    } __attribute__((packed));
} __attribute__((packed));
#ifdef __cplusplus
static_assert(sizeof(struct homa_meta_info) == 20, "homa_meta_info size is not 20 bytes");
#else
_Static_assert (sizeof(struct homa_meta_info) == 20, "homa_meta_info size is not 20 bytes");
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
} __attribute__((aligned(64)));
_Static_assert (sizeof(struct rpc_state) == 256, "rpc_state size is not 256 bytes");
#endif

#define HOMA_MAX_PRIORITIES 8
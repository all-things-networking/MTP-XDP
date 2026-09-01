#pragma once
/*
 * mtp_contract.h -- the TARGET's side of the boundary with generated code.
 *
 * This is the whole surface between the MTP compiler's XDP backend and this
 * target. The backend knows these names and nothing else about the target; the
 * target knows nothing about any program. Everything the generated processors
 * call appears here, and adding an instruction means adding it here first --
 * which is the point, because then a backend emitting a call this file does not
 * declare fails to COMPILE rather than failing to link, or worse, linking
 * against something with the same name.
 *
 * IT IS NOT GENERATED. The compiler never reads or writes it. Compare
 * DPDKGenerator's src/target/contract.h, which draws the same line.
 *
 * WHY C AND NOT C++. Two of the three sites are eBPF, compiled as C under a
 * verifier. The contract has to be spellable at all three, so it is C with no
 * templates, and the C++ sites implement it over the templates in mtp_target.h.
 *
 * NOTHING HERE NAMES A PROTOCOL -- same rule as mtp_target.h, and checkable the
 * same way.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* Widths, so the generated code spells them the same at every site. */
#ifndef __u8
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;
#endif

/* ---- the two aggregate types a program may declare -------------------------
 * A sliding window and a byte stream. Both are the TARGET's: a program says it
 * has a receive window and hands it extents, and what that costs -- a bitmap, a
 * list, a pair of counters -- is not protocol.
 */
struct mtp_sliding_wnd { __u32 head; __u32 tail; __u64 bits; };
struct mtp_stream      { __u64 base; __u32 cap; __u32 head; __u32 used; };

/* ---- storage the generated structs are built from -------------------------
 * These are the target's, not the program's: a program declares a timer and an
 * option list, and THIS decides what they cost. The bound matters -- two of the
 * three sites are eBPF, where nothing may be allocated and the verifier needs a
 * limit it can see -- so an option list is a fixed frame and its capacity is
 * fixed here rather than by whichever program is being compiled.
 */
/* An unbounded capacity, as the language spells it. A data unit declared with
 * INF is one the target sizes, not the program. */
#define INF (~(__u32)0)

#define MTP_OPT_CAP 8

struct mtp_timer {
    __u64 deadline_ns;   /* 0 = not armed. This target has no timer: the control
                          * loop sweeps and compares, so arming is a store. */
    bool  armed;
    __u8  retries;       /* what `retry` reports. It lives here because the count
                          * has to outlive a processor run, and a processor sees
                          * one event and cannot remember. */
};

struct mtp_opt {
    __u8  kind;
    __u8  len;
    __u8  data[16];
};

struct mtp_addr { __u32 ip; __u16 port; __u64 ref; __u32 len; };

/* ---- the socket calls a program's app_parser reads -------------------------
 * ONE struct for every operation, not one per call. The program's parsers name
 * the operation -- `sock_bind(bind op)` -- and read the fields that operation
 * carries; which fields those are is the SCHEMA, and it belongs to the target
 * because the target is what implements the socket API. A program that reads a
 * field the operation does not carry is a bug the compiler can catch, and one
 * struct is what makes that check possible at all.
 */
/*
 * A send may reach the transport in two phases -- record what the application
 * handed over, then generate segments from it -- and which phase this call is
 * rides in the op's flags. A program that does not split them never tests these.
 */
#define OP_PHASE_RECORD   0x1u
#define OP_PHASE_GENERATE 0x2u

struct mtp_sock_op {
    struct mtp_addr local;
    struct mtp_addr remote;
    __u64  handle;        /* the application's socket handle */
    __u32  len;           /* send/recv length, or the listen backlog */
    __u32  flags;         /* the call's own flags, e.g. send's */
    struct mtp_addr data; /* the buffer a send hands over, by address */
    bool   reuseport;
};

/* ---- what a parser returns -------------------------------------------------
 * A bounded frame, for the same reason the option list is one: the eBPF sites
 * cannot allocate. A parser that would exceed it drops the event rather than
 * growing, which the target reports.
 */
#define MTP_EV_CAP 4
struct mtp_ev_list {
    void *ev[MTP_EV_CAP];
    __u8  n;
};

/* ---- the packet a net parser is handed -------------------------------------
 * Opaque. A parser reads it only through the blueprint's extract, so what it
 * actually is -- an AF_XDP frame here, an mbuf elsewhere -- never reaches the
 * program.
 */
struct mtp_pkt { void *data; __u32 len; __u32 qid; };
typedef struct mtp_pkt pkt_t;

/*
 * A LIST, as the language spells one. The generic methods below -- push, pop,
 * len, remove, find_min -- have to have a receiver, and until this existed they
 * took a void* that named nothing: the contract declared behaviour for a type it
 * never defined, which is a boundary with a hole in it. Bounded, like every
 * other frame here, because two of the three sites cannot allocate.
 */
#define MTP_LIST_CAP 16
struct mtp_list { __u64 v[MTP_LIST_CAP]; __u8 n; };


/*
 * Which context declaration a key names. The compiler emits MTP_CTX_<name> for
 * each `context` in the program, and the target uses it to pick the store --
 * this is the type half of set_ctx_lookup_info, and it is what makes a listener
 * key and a connection key distinguishable when both are tuples of scalars.
 */
/*
 * TWO KINDS OF NAME LIVE IN THIS FILE, and the difference is load-bearing.
 *
 * MTP_INLINE marks what the target implements as a DATA STRUCTURE with no
 * opinion about a transport -- a window, a stream, a deadline, a bounded frame.
 * Those are defined `static inline` in mtp_contract_impl.h, because the eBPF
 * sites cannot call out of their own program and must have them inlined or not
 * have them at all.
 *
 * Everything left plain is the part that needs THIS target's runtime: creating
 * a context, putting a packet on the wire, waking the application, reading a
 * frame. Those are ordinary external functions, they are what a different
 * target rewrites, and they are why the control path is a separate site.
 */
#define MTP_INLINE static inline

typedef int mtp_ctx_kind_t;

/* An opaque handle to whatever the target keeps a context in. Generated code
 * passes it back and never looks inside. */
typedef void *mtp_ctx_t;

/* ---- context lifecycle ------------------------------------------------
 * new_ctx_instr / destroy_ctx_instr. Only the sites that CAN create state
 * implement these: the eBPF half of this target cannot, and the backend refuses
 * to emit them there rather than emitting a call that would fail at run time.
 */
/*
 * REGISTRATION, BECAUSE C HAS NO GENERICS. The target has to store contexts it
 * knows nothing about: their layout is the PROGRAM's, and the whole point of
 * the boundary is that the target never sees it. So generated code declares the
 * two sizes once at start-up -- how big a context of this kind is, and how big
 * its key is -- and the store is a slab and a hash over key bytes from there.
 *
 * Without this, mtp_ctx_new could not be written at all: it takes a `const
 * void *key` with no length, and a target cannot hash what it cannot measure.
 */
void mtp_ctx_register(mtp_ctx_kind_t kind, __u32 ctx_size, __u32 key_size);

mtp_ctx_t mtp_ctx_new(mtp_ctx_kind_t kind, const void *key);
void      mtp_ctx_del(mtp_ctx_kind_t kind, const void *key);
/* The lookup half. The dispatch resolves an event's context with this, using
 * the kind and key its parser declared through mtp_ev_key. */
mtp_ctx_t mtp_ctx_get(mtp_ctx_kind_t kind, const void *key);

/* ---- packet generation -------------------------------------------------
 * pkt_gen_instr(bp, prio, rtx). It names no context: the target already knows
 * the flow this processor was dispatched for, so passing one would be the
 * program repeating what the dispatch just decided.
 */
int mtp_pkt_gen(const void *bp, __u8 prio, bool retransmit);

/* ---- timers -------------------------------------------------------------
 * This target has no timer. The control loop visits every context once per pass
 * and compares deadlines, so `start` writes a deadline and the sweep is what
 * fires. A target with real timers implements the same three calls differently
 * and the program does not change.
 */
MTP_INLINE void mtp_timer_start(void *timer, __u64 duration_ns);
MTP_INLINE void mtp_timer_restart(void *timer, __u64 duration_ns);
MTP_INLINE void mtp_timer_stop(void *timer);

/* ---- the application ---------------------------------------------------
 * notify's condition is an ordinary identifier, not an enumeration: a program
 * writes the name that says what it means and the target recognises it.
 */
void mtp_notify(mtp_ctx_t ctx, int condition);

/* The addresses of a context no packet created. An active open builds its
 * context before anything has been received, so the target cannot have learned
 * the peer from a header the way it does on the passive side. */
void mtp_ctx_addrs(void *ctx, __u32 local_ip, __u32 remote_ip);

/* ---- rate ---------------------------------------------------------------- */
void mtp_set_rate(void *ctx, __u32 rate);

/* ---- the parser's declaration of which context an event names -------------
 * NOT a lookup. The parser says "this event is answered from a <kind> keyed by
 * <key>"; the dispatch resolves it. Separating the two is D-33, and it is why a
 * parser cannot accidentally do allocation.
 */
void mtp_ev_key(void *ev, mtp_ctx_kind_t kind, const void *key);




/* The window's methods, as the language spells them. */
MTP_INLINE void  mtp_init (void *w, __u32 at);
MTP_INLINE void  mtp_set  (void *w, __u32 from, __u32 to);
MTP_INLINE __u32 mtp_slide(void *w);
MTP_INLINE __u32 mtp_head (void *w);

/* ---- the methods the language spells on a value ----------------------------
 * `recv.method(args)` in a program becomes mtp_<method>(&recv, args). They take
 * void* because the receiver's type is the PROGRAM's -- a sliding window, a
 * list, a data unit -- and the target implements one behaviour per method
 * rather than one per receiver type. The trade is deliberate: the contract
 * still catches a method the target does not implement, which is the failure
 * that matters, and does not try to type-check the program's own declarations.
 */
MTP_INLINE __u32 mtp_len        (void *recv);
MTP_INLINE void  mtp_push       (void *recv, __u64 v);
MTP_INLINE __u64 mtp_pop        (void *recv);
MTP_INLINE void  mtp_remove     (void *recv, __u64 v);
MTP_INLINE __u32 mtp_first      (void *recv);
MTP_INLINE __u32 mtp_last       (void *recv);
MTP_INLINE bool  mtp_is_set     (void *recv, __u32 at);
MTP_INLINE __u32 mtp_first_set  (void *recv);
MTP_INLINE __u32 mtp_first_unset(void *recv);
MTP_INLINE __u32 mtp_find_ge    (void *recv, __u32 from);
MTP_INLINE __u32 mtp_find_min   (void *recv);
MTP_INLINE bool  mtp_exists_ge  (void *recv, __u32 from);
void  mtp_add_hdr    (void *recv, void *hdr);
void *mtp_extract_hdr(void *recv);
struct mtp_addr mtp_get_data(void *recv);
void  mtp_mem_append (void *recv, struct mtp_addr addr, __u32 len);
__u32 mtp_rate       (void *recv);
/* On a timer. */
MTP_INLINE void  mtp_start       (void *t, __u64 d);
MTP_INLINE void  mtp_cancel      (void *t);
MTP_INLINE void  mtp_restart     (void *t, __u64 d);
MTP_INLINE void  mtp_set_duration(void *t, __u64 d);
MTP_INLINE bool  mtp_isActive    (void *t);

/* ---- ordered data ----------------------------------------------------------
 * A transport's byte streams. The program declares one per direction and hands
 * it segments; the target owns the reassembly, the ring and the buffer cache,
 * because none of that is protocol -- two protocols reassemble identically and
 * differ only in what they do with the result.
 *
 * `cap` is the declared capacity. On this target it bounds a ring the
 * application already owns, which is why it is passed rather than discovered.
 */
MTP_INLINE void  mtp_rx_new(void *stream, __u32 cap);
MTP_INLINE void  mtp_tx_new(void *stream, __u32 cap);
/* These take an ADDRESS, not an integer: the language has one address type and a
 * program hands over the reference it was given. Taking a __u64 here made a
 * legal program a type error in the generated C. */
/* SIGNED: a program tests the result for < 0. An out-of-window or duplicate
 * segment is refused, and "refused" is not a length. */
MTP_INLINE __s32 mtp_rx_add(void *stream, struct mtp_addr addr, __u32 len, __u32 off);
/* Returns how much was taken: a bounded stream may accept less than it was
 * offered, and the program has to know -- that is a protocol decision, not a
 * target one. */
MTP_INLINE __u32 mtp_tx_add(void *stream, struct mtp_addr addr, __u32 len);
MTP_INLINE struct mtp_addr mtp_tx_addr(void *stream, __u32 off);
MTP_INLINE __u32 mtp_rx_flush(void *stream, __u32 len, struct mtp_addr buf);
MTP_INLINE __u32 mtp_tx_flush(void *stream, __u32 len);
/* Flush AND wake the application in one step -- the two directions are separate
 * instructions because they carry different things: rx names the buffer it
 * delivers into, tx only how much was acknowledged. */
__u32 mtp_rx_flush_and_notify(void *stream, __u32 len, struct mtp_addr buf);
__u32 mtp_tx_flush_and_notify(void *stream, __u32 len);

/* Segmentation. The RULE is an argument at the call, not a declaration apart
 * from it, because it belongs where the segmentation is. */
MTP_INLINE struct mtp_addr mtp_seg(void *stream, __u32 off, __u32 len, __u32 mss);
MTP_INLINE struct mtp_addr mtp_unseg(void *stream, __u32 off, __u32 len, __u32 mss);

/* ---- clock --------------------------------------------------------------- */
MTP_INLINE __u64 mtp_now(void);

/* How many times a thing has been retried. The target counts, because the count
 * outlives any single processor run. */
MTP_INLINE __u32 mtp_retry(void *timer);



/* Appending an option to a bounded frame. The target reports a full frame; the
 * program cannot, because MTP has no way to raise an error from a processor. */
MTP_INLINE void mtp_opt_add(struct mtp_opt *arr, __u8 *n, struct mtp_opt o);



/*
 * A blueprint's payload is named by an ADDRESS, not by a distinct type. The
 * language unified those -- "addr_t is every address" -- so `bp.data` and a
 * context's held reference are the same thing and assigning one to the other is
 * legal. Keeping a separate mtp_data would make that assignment a type error in
 * the generated C and a legal statement in the program.
 */




MTP_INLINE void mtp_ev_add(struct mtp_ev_list *out, void *ev);



/* ---- blueprint -------------------------------------------------------------
 * The target reads the fixed header into the blueprint the compiler declared and
 * fills its option frame. It is handed a size because the blueprint's shape is
 * the PROGRAM's, and the target must not have an opinion about it.
 */
void mtp_bp_read(const struct mtp_pkt *p, void *bp, __u32 size,
                 struct mtp_opt *opts, __u8 *opts_n, __u8 opts_cap);


#ifdef __cplusplus
}
#endif

/*
 * THE INLINE HALF, LAST. Generated code includes this file and nothing else of
 * the target's, so the MTP_INLINE names have to arrive with it -- a declaration
 * that reaches a compiler without its definition is a warning at every site
 * that includes it and a link error at the one that calls it. The include is at
 * the END so the implementation sees every type above; the #pragma once in this
 * file makes the include it does of us a no-op.
 */
#ifndef MTP_CONTRACT_NO_IMPL
#include "mtp_contract_impl.h"
#endif

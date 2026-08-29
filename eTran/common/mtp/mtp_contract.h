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

/*
 * Which context declaration a key names. The compiler emits MTP_CTX_<name> for
 * each `context` in the program, and the target uses it to pick the store --
 * this is the type half of set_ctx_lookup_info, and it is what makes a listener
 * key and a connection key distinguishable when both are tuples of scalars.
 */
typedef int mtp_ctx_kind_t;

/* An opaque handle to whatever the target keeps a context in. Generated code
 * passes it back and never looks inside. */
typedef void *mtp_ctx_t;

/* ---- context lifecycle ------------------------------------------------
 * new_ctx_instr / destroy_ctx_instr. Only the sites that CAN create state
 * implement these: the eBPF half of this target cannot, and the backend refuses
 * to emit them there rather than emitting a call that would fail at run time.
 */
mtp_ctx_t mtp_ctx_new(const void *key);
void      mtp_ctx_del(const void *key);

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
void mtp_timer_start(void *timer, __u64 duration_ns);
void mtp_timer_restart(void *timer, __u64 duration_ns);
void mtp_timer_stop(void *timer);

/* ---- the application ---------------------------------------------------
 * notify's condition is an ordinary identifier, not an enumeration: a program
 * writes the name that says what it means and the target recognises it.
 */
void mtp_notify(mtp_ctx_t ctx, int condition);

/* ---- rate ---------------------------------------------------------------- */
void mtp_set_rate(void *ctx, __u32 rate);

/* ---- the parser's declaration of which context an event names -------------
 * NOT a lookup. The parser says "this event is answered from a <kind> keyed by
 * <key>"; the dispatch resolves it. Separating the two is D-33, and it is why a
 * parser cannot accidentally do allocation.
 */
void mtp_ev_key(void *ev, mtp_ctx_kind_t kind, const void *key);

/* ---- blueprint ----------------------------------------------------------- */
void *mtp_bp_extract(void *pkt);

/* ---- clock --------------------------------------------------------------- */
__u64 mtp_now(void);

/* ---- storage the generated structs are built from -------------------------
 * These are the target's, not the program's: a program declares a timer and an
 * option list, and THIS decides what they cost. The bound matters -- two of the
 * three sites are eBPF, where nothing may be allocated and the verifier needs a
 * limit it can see -- so an option list is a fixed frame and its capacity is
 * fixed here rather than by whichever program is being compiled.
 */
#define MTP_OPT_CAP 8

struct mtp_timer {
    __u64 deadline_ns;   /* 0 = not armed. This target has no timer: the control
                          * loop sweeps and compares, so arming is a store. */
    bool  armed;
};

struct mtp_opt {
    __u8  kind;
    __u8  len;
    __u8  data[16];
};

/* Appending an option to a bounded frame. The target reports a full frame; the
 * program cannot, because MTP has no way to raise an error from a processor. */
void mtp_opt_add(struct mtp_opt *arr, __u8 *n, struct mtp_opt o);

struct mtp_addr { __u32 ip; __u16 port; };

struct mtp_data { void *base; __u32 len; __u32 off; };

/* ---- the socket calls a program's app_parser reads -------------------------
 * ONE struct for every operation, not one per call. The program's parsers name
 * the operation -- `sock_bind(bind op)` -- and read the fields that operation
 * carries; which fields those are is the SCHEMA, and it belongs to the target
 * because the target is what implements the socket API. A program that reads a
 * field the operation does not carry is a bug the compiler can catch, and one
 * struct is what makes that check possible at all.
 */
struct mtp_sock_op {
    struct mtp_addr local;
    struct mtp_addr remote;
    __u64  handle;        /* the application's socket handle */
    __u32  len;           /* send/recv length, or the listen backlog */
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
void mtp_ev_add(struct mtp_ev_list *out, void *ev);

/* ---- the packet a net parser is handed -------------------------------------
 * Opaque. A parser reads it only through the blueprint's extract, so what it
 * actually is -- an AF_XDP frame here, an mbuf elsewhere -- never reaches the
 * program.
 */
struct mtp_pkt { void *data; __u32 len; __u32 qid; };
typedef struct mtp_pkt pkt_t;

#ifdef __cplusplus
}
#endif

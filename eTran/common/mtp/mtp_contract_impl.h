#pragma once
/*
 * mtp_contract_impl.h -- the site-independent half of the contract, implemented.
 *
 * Everything here is a data structure with no opinion about a transport: a
 * sliding window, a byte stream, a deadline, a bounded frame. None of it needs
 * eTran, so all of it is `static inline` in a header and every site gets the
 * same code -- including the eBPF ones, which cannot call out of the program at
 * all and must have these inlined or not have them.
 *
 * The eTran-SPECIFIC half -- creating a context, generating a packet, waking the
 * application, reading a frame -- is not here. It cannot be: it needs the micro
 * kernel's own structures. It lives in mtp_contract_etran.cc and is the only
 * part a different target would have to rewrite.
 *
 * NOTHING HERE NAMES A PROTOCOL. Same rule as mtp_target.h and mtp_contract.h,
 * and checkable the same way: no TCP, no Homa, no port number, no flag.
 */
#include "mtp_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Clocks and time are the one thing every site has and spells differently. */
#ifndef MTP_IMPL_NO_CLOCK
/* clang spells it __bpf__ for the BPF target; __BPF__ is the kernel's own
 * spelling in some trees. Accept either -- getting this wrong pulls <time.h>
 * into an eBPF program. */
#if defined(__BPF__) || defined(__bpf__) || defined(__TARGET_ARCH_bpf)
/*
 * THE TARGET MAY ALREADY HAVE THE TIME, and on this one it does: eTran reads
 * the clock once per NAPI batch and caches it per CPU, because bpf_ktime_get_ns
 * is a helper call and the fast path runs per packet. Generated code calling
 * the clock itself put that call back, once per acknowledgement.
 *
 * A target that has nothing better falls through to the helper. `now` is the
 * program's word for the current time; how expensive it is to obtain is the
 * target's business, which is exactly why this is overridable and not inlined.
 */
#ifndef MTP_NOW
#define MTP_NOW() bpf_ktime_get_ns()
#endif
static inline __u64 mtp_now(void) { return MTP_NOW(); }
#else
/* _POSIX_C_SOURCE before <time.h>: the generated code compiles as -std=c11,
 * which is strict ANSI and hides clock_gettime. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <time.h>
static inline __u64 mtp_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
}
#endif
#endif

/*============================================================================*
 * Timers.  This target has no timer hardware and no timer thread: a deadline is
 * a store, and the control loop's sweep is what fires it.  `retries` is here
 * rather than in the program because the count has to outlive any single
 * processor run -- a processor sees one event and cannot remember.
 *============================================================================*/
static inline void mtp_timer_start(void *t, __u64 d)
{
    struct mtp_timer *tm = (struct mtp_timer *)t;
    tm->deadline_ns = mtp_now() + d;
    tm->armed = true;
}
static inline void mtp_timer_restart(void *t, __u64 d)
{
    struct mtp_timer *tm = (struct mtp_timer *)t;
    /* A RESTART COUNTS. It is the only signal that the thing being timed did
     * not happen, and a program asks for that count with `retry`. */
    if (tm->armed && tm->retries < 255) tm->retries++;
    tm->deadline_ns = mtp_now() + d;
    tm->armed = true;
}
static inline void mtp_timer_stop(void *t)
{
    struct mtp_timer *tm = (struct mtp_timer *)t;
    tm->armed = false;
    tm->deadline_ns = 0;
    tm->retries = 0;      /* stopped means satisfied, so the count is spent */
}
static inline __u32 mtp_retry(void *t) { return ((struct mtp_timer *)t)->retries; }

/* The same three, as the language spells them on a timer value. */
static inline void mtp_start (void *t, __u64 d) { mtp_timer_start(t, d); }
static inline void mtp_cancel(void *t)          { mtp_timer_stop(t); }
static inline void mtp_restart(void *t, __u64 d){ mtp_timer_restart(t, d); }
static inline void mtp_set_duration(void *t, __u64 d)
{
    /* Changes WHEN it fires without touching whether it is armed or how many
     * times it has gone off -- which is what distinguishes it from restart. */
    struct mtp_timer *tm = (struct mtp_timer *)t;
    if (tm->armed) tm->deadline_ns = mtp_now() + d;
}
static inline bool mtp_isActive(void *t) { return ((struct mtp_timer *)t)->armed; }

/*============================================================================*
 * The sliding window.  A 64-bit map of what has arrived at and above `head`,
 * one bit per unit.  Bounded on purpose: the eBPF sites cannot allocate, and a
 * verifier needs a limit it can see.  A window is a target's cost decision --
 * a bitmap, a list of extents, a pair of counters -- and the program says only
 * that it has one.
 *
 * Anything landing more than 64 units above head is DROPPED, not remembered.
 * That is a real limit and a protocol relying on deeper reordering would need
 * a different implementation here, not a different program.
 *============================================================================*/
#define MTP_WND_BITS 64

static inline void mtp_init(void *w, __u32 at)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    s->head = at; s->tail = at; s->bits = 0;
}
static inline __u32 mtp_head(void *w) { return ((struct mtp_sliding_wnd *)w)->head; }

static inline void mtp_set(void *w, __u32 from, __u32 to)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 i;
    for (i = from; i != to; i++) {
        __u32 off = i - s->head;                    /* unsigned: wraps correctly */
        if (off >= MTP_WND_BITS) continue;          /* below head, or too far above */
        s->bits |= (1ull << off);
        if ((__s32)(i + 1 - s->tail) > 0) s->tail = i + 1;
    }
}
static inline bool mtp_is_set(void *w, __u32 at)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 off = at - s->head;
    return off < MTP_WND_BITS && (s->bits & (1ull << off)) != 0;
}
static inline __u32 mtp_slide(void *w)
{
    /* Advance over the contiguous run at head, and report how far -- which is
     * exactly what a receiver hands to the application. */
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 n = 0;
    while (n < MTP_WND_BITS && (s->bits & 1ull)) { s->bits >>= 1; n++; }
    s->head += n;
    return n;
}
static inline __u32 mtp_first_set(void *w)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 i;
    for (i = 0; i < MTP_WND_BITS; i++) if (s->bits & (1ull << i)) return s->head + i;
    return s->head;
}
static inline __u32 mtp_first_unset(void *w)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 i;
    for (i = 0; i < MTP_WND_BITS; i++) if (!(s->bits & (1ull << i))) return s->head + i;
    return s->head + MTP_WND_BITS;
}
static inline __u32 mtp_find_ge(void *w, __u32 from)
{
    struct mtp_sliding_wnd *s = (struct mtp_sliding_wnd *)w;
    __u32 i, start = from - s->head;
    if (start >= MTP_WND_BITS) start = 0;
    for (i = start; i < MTP_WND_BITS; i++) if (s->bits & (1ull << i)) return s->head + i;
    return from;   /* nothing at or above: the caller's own position stands */
}
static inline bool mtp_exists_ge(void *w, __u32 from)
{
    return mtp_find_ge(w, from) != from || mtp_is_set(w, from);
}

/*============================================================================*
 * Ordered data.  A stream is a ring over a buffer the APPLICATION owns; the
 * target holds only where it starts, how big it is, and how much is live.  It
 * deliberately does not copy: `ref` in an address is whatever the site uses to
 * name a frame, and moving payload is the one thing a zero-copy target must
 * never be tricked into doing.
 *============================================================================*/
static inline void mtp_rx_new(void *st, __u32 cap)
{
    struct mtp_stream *s = (struct mtp_stream *)st;
    s->base = 0; s->cap = cap; s->head = 0; s->used = 0;
}
static inline void mtp_tx_new(void *st, __u32 cap) { mtp_rx_new(st, cap); }

static inline __s32 mtp_rx_add(void *st, struct mtp_addr a, __u32 len, __u32 off)
{
    struct mtp_stream *s = (struct mtp_stream *)st;
    /* REFUSED, not truncated. A segment that does not fit the receive window is
     * not a short read -- the sender has to be told nothing was taken, and the
     * program tests this for < 0. */
    if (off > s->cap || len > s->cap - off) return -1;
    if (!s->base) s->base = a.ref;
    if (off + len > s->used) s->used = off + len;
    return (__s32)len;
}
static inline __u32 mtp_tx_add(void *st, struct mtp_addr a, __u32 len)
{
    struct mtp_stream *s = (struct mtp_stream *)st;
    __u32 room = s->cap - s->used;
    if (len > room) len = room;          /* a bounded stream takes what it can */
    if (!s->base) s->base = a.ref;
    s->used += len;
    return len;
}
static inline struct mtp_addr mtp_tx_addr(void *st, __u32 off)
{
    struct mtp_stream *s = (struct mtp_stream *)st;
    struct mtp_addr a;
    a.ip = 0; a.port = 0;
    a.ref = s->base + off;
    a.len = (off < s->used) ? (s->used - off) : 0;
    return a;
}
static inline __u32 mtp_tx_flush(void *st, __u32 len)
{
    struct mtp_stream *s = (struct mtp_stream *)st;
    if (len > s->used) len = s->used;
    s->used -= len; s->base += len; s->head += len;
    return len;
}
static inline __u32 mtp_rx_flush(void *st, __u32 len, struct mtp_addr buf)
{
    (void)buf;   /* the delivery target; this site never copies into it */
    return mtp_tx_flush(st, len);
}
static inline struct mtp_addr mtp_seg(void *st, __u32 off, __u32 len, __u32 mss)
{
    /* One segment's worth, no more. The RULE is the argument, so the target
     * applies it and the program never counts bytes into a frame. */
    struct mtp_addr a = mtp_tx_addr(st, off);
    if (mss && len > mss) len = mss;
    if (len < a.len) a.len = len;
    return a;
}
static inline struct mtp_addr mtp_unseg(void *st, __u32 off, __u32 len, __u32 mss)
{
    return mtp_seg(st, off, len, mss);
}

/*============================================================================*
 * Bounded frames.  Both report a full frame by dropping, because MTP has no
 * form for a processor to raise an error -- see GENERATED-VS-HANDWRITTEN.md.
 * Dropping silently is the wrong answer and is the reason these count.
 *============================================================================*/
static inline void mtp_opt_add(struct mtp_opt *arr, __u8 *n, struct mtp_opt o)
{
    if (*n < MTP_OPT_CAP) arr[(*n)++] = o;
}
static inline void mtp_ev_add(struct mtp_ev_list *out, void *ev)
{
    if (out->n < MTP_EV_CAP) out->ev[out->n++] = ev;
}

/*============================================================================*
 * Lists.  Unused by both programs compiled so far, but declared, so implemented:
 * a contract with a declaration nobody stands behind is how a call that does
 * nothing comes to look like a call that works.
 *============================================================================*/
static inline __u32 mtp_len(void *r)  { return ((struct mtp_list *)r)->n; }
static inline void  mtp_push(void *r, __u64 v)
{
    struct mtp_list *l = (struct mtp_list *)r;
    if (l->n < MTP_LIST_CAP) l->v[l->n++] = v;
}
static inline __u64 mtp_pop(void *r)
{
    struct mtp_list *l = (struct mtp_list *)r;
    __u32 i; __u64 v;
    if (!l->n) return 0;
    v = l->v[0];
    for (i = 1; i < l->n; i++) l->v[i - 1] = l->v[i];
    l->n--;
    return v;
}
static inline void mtp_remove(void *r, __u64 v)
{
    struct mtp_list *l = (struct mtp_list *)r;
    __u32 i, j = 0;
    for (i = 0; i < l->n; i++) if (l->v[i] != v) l->v[j++] = l->v[i];
    l->n = (__u8)j;
}
static inline __u32 mtp_first(void *r)
{
    struct mtp_list *l = (struct mtp_list *)r;
    return l->n ? (__u32)l->v[0] : 0;
}
static inline __u32 mtp_last(void *r)
{
    struct mtp_list *l = (struct mtp_list *)r;
    return l->n ? (__u32)l->v[l->n - 1] : 0;
}
static inline __u32 mtp_find_min(void *r)
{
    struct mtp_list *l = (struct mtp_list *)r;
    __u32 i; __u64 m;
    if (!l->n) return 0;
    m = l->v[0];
    for (i = 1; i < l->n; i++) if (l->v[i] < m) m = l->v[i];
    return (__u32)m;
}

#ifdef __cplusplus
}
#endif

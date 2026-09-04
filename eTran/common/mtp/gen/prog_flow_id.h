/* GENERATED from /tmp/claude-11465/-home-mtahmasb-mtp-xdp-session-tmp-mtp-pass/ef347694-90cd-4c3c-80ee-6c5e3721d8a4/scratchpad/src/tcp-newconv.mtp by the MTP compiler's XDP backend.
 * Do not edit: regenerate. The target runtime this is compiled against
 * (mtp_target.h, mtp_target_bpf.h) is NOT generated and is not touched.
 */

#pragma once
/* The contract, for the width typedefs. NOT mtp_target.h: that is C++ and
 * two of the three sites are C. */
#include "mtp/mtp_contract.h"

/* ---- flow_id tcp_fid------------------------------------ */
struct tcp_fid {
    __u32 f0;
    __u16 f1;
    __u32 f2;
    __u16 f3;
};

static inline __u32 tcp_fid_hash(const struct tcp_fid *k)
{
    __u32 h = 0;
    h = h * 31u + (__u32)k->f0;
    h = h * 31u + (__u32)k->f1;
    h = h * 31u + (__u32)k->f2;
    h = h * 31u + (__u32)k->f3;
    return h;
}

#define tcp_fid(_a0, _a1, _a2, _a3) ((struct tcp_fid){.f0 = (_a0), .f1 = (_a1), .f2 = (_a2), .f3 = (_a3)})

/* ---- flow_id tcp_lid------------------------------------ */
struct tcp_lid {
    __u32 f0;
    __u16 f1;
};

static inline __u32 tcp_lid_hash(const struct tcp_lid *k)
{
    __u32 h = 0;
    h = h * 31u + (__u32)k->f0;
    h = h * 31u + (__u32)k->f1;
    return h;
}

#define tcp_lid(_a0, _a1) ((struct tcp_lid){.f0 = (_a0), .f1 = (_a1)})


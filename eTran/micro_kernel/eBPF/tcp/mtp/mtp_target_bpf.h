#pragma once
/*
 * mtp_target_bpf.h -- the MTP target runtime for eTran's eBPF sites (K1, K2, K3).
 *
 * NOTHING IN THIS FILE MAY NAME A PROTOCOL, exactly as in the control path's
 * mtp/mtp_target.h. This is the same split, for a different execution site.
 *
 * WHY IT IS MACROS AND NOT TEMPLATES. The control-path target instantiates
 * ctx_store as a C++ template. eBPF is C, and the verifier wants straight-line
 * code with no indirect calls, so the equivalent here is a macro that EMITS a
 * concrete, named accessor per context declaration. That is not a workaround --
 * it is closer to what an MTP compiler actually does: it knows the program, so
 * it writes TCP's lookup against TCP's map with TCP's key type, and there is no
 * generic key or value anywhere at run time.
 *
 * MTP_DEFINE_CTX_STORE(NAME, FID_T, CTX_T, MAP) emits:
 *
 *   NAME_get_ctx(const FID_T *id) -> CTX_T *     MTP get_ctx / exists
 *
 * There is deliberately no new_ctx or del_ctx here. On this target the eBPF
 * sites never create or destroy a context: the control path does, over the map's
 * syscall interface (intf_ebpf.h, and the paper's appendix C "State handling").
 * A site that cannot create state should not be handed an instruction that says
 * it can.
 */

#define MTP_DEFINE_CTX_STORE(NAME, FID_T, CTX_T, MAP)                    \
    static __always_inline CTX_T *NAME##_get_ctx(const FID_T *id)        \
    {                                                                    \
        return bpf_map_lookup_elem(&MAP, id);                            \
    }

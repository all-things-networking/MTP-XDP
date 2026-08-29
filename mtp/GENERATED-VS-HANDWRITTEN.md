# What the generated code does not say, and why

Generated `proc_bind` against the hand-written one in `micro_kernel/mtp/tcp_program.h`.

## The shape matches

Both materialise the context, mark it `FAKE`, record `reuseport`, and notify.
The generated one routes each field through its `@placement` group
(`ctx->control.type`) where the hand-written one writes the flat struct — that
difference is the target's arrangement and is exactly what `@placement` is for.

## What only the hand-written one has

| missing from the generated code | why |
|---|---|
| the duplicate-handle test (`find_if` for `opaque_connection`) | **the language has no presence test.** `exists()` was removed deliberately: whether a context instance is present is the target's knowledge. `OPEN-QUESTIONS Q8` |
| `-EADDRINUSE` on a taken port, and the `SO_REUSEPORT` ownership test | **a processor cannot raise an error.** MTP has no form for it; error-handling primitives are future work |
| `alloc_port` / `record_port` | **the port allocator is a target service the program cannot name.** Which port an unbound `connect()` gets is on the wire, and no instruction names it |
| `fd`, `tctx`, `opaque_connection`, `flags` | **not protocol state.** A file descriptor and a socket handle are target identity; the docs place them on the event's app base, and the target keeps them |

Forty-four references to those four categories exist in the hand-written program
half. **None of them is a compiler deficiency.** Every one is something
`tcp.mtp` cannot express, and the program says so where it can — the one
`TODO(error handling)` in `proc_bind` covers the first two rows.

## What this means for the port

The hand-built backend is **not** what this compiler would emit from this
program, and the difference is a fair measure of the distance between MTP as it
stands and eTran as it behaves. Three of the four rows are the same finding from
different angles: **a processor can change state and emit packets, but it cannot
refuse.** Bind refuses four ways, and none of them is writable.

The fourth row is different and smaller: target identity riding on the event's
app base, which is a convention the backend could adopt without the language
changing.

## The honest summary

- the **declarative** half of the hand-built code — contexts, events, flow ids,
  blueprints, the dispatch — is reproduced by the compiler, including the
  four-way `@placement` split;
- the **processor bodies** are reproduced for everything the program can say;
- what is left is what the language cannot say, and it clusters almost entirely
  on refusal.

---

## The dispatch differs in one way the program cannot express

Generated (`prog_dispatch.c`), which is the program read literally:

```c
mtp_dispatch_tcp_ack:   proc_ack, proc_fast_retransmit, proc_window, proc_rtt
mtp_dispatch_tcp_data:  proc_seq, proc_ooo, proc_recv
```

Hand-written (`eBPF/tcp/mtp/tcp_program_bpf.h:460`), which is what runs and what
was measured:

```c
proc_ack        /* tcp_ack  */
proc_seq_ooo    /* tcp_data */
proc_window_rtt /* tcp_ack  */
proc_recv       /* tcp_data */
```

Two differences, and they are different in kind.

**Fusion** (`proc_seq`+`proc_ooo`, `proc_window`+`proc_rtt`) is a target
decision and needs no permission from the program: the two processors share
every value they read, and the eBPF verifier is happier with one straight-line
body than two. A compiler is free to do this and the result is the same
program.

**Interleaving is not.** One segment carries an acknowledgement *and* payload,
so it raises `tcp_ack` and `tcp_data` together, and eTran walks the header once
— it runs half of one chain, then half of the other. **The program does not say
that.** It declares two chains and says nothing about how a target that gets
both at once should schedule them, so the generated code runs one and then the
other.

Whether that reordering is observable is untested and should not be assumed
either way: `proc_window`/`proc_rtt` update the send window and the RTT estimate,
`proc_seq`/`proc_recv` the receive side, and they are believed disjoint — but
"believed disjoint" is a hypothesis, and rule 4 applies. It is the one place
where the generated RX fast path would not be instruction-for-instruction the
path measured at 101%.

## A second program, to check the backend is not shaped to this one

`check-xdp.sh <program>` compiles whatever it is given. Run against the
mTCP/DPDK reference program — a different transport program, written for a
different backend, by a different session — the XDP backend emits code that
compiles clean. That found five contract errors and four generator defects that
`tcp.mtp` cannot reach, because it never uses the instructions involved
(ordered data, segmentation, `ctx_addrs`, a generic `event_t` parameter, a
processor calling a sibling declared later).

Its placement is the honest one: **control 41, ebpf 0, app 0**, because that
program carries no `@placement` at all. One address space is the right answer
for a program that never asks for more, and the backend gets there from the
program rather than from a default it was born with.

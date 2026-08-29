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

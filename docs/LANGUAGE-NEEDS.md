# What `mtp/tcp.mtp` needs that MTP does not have

Every place this program departs from the language, listed. The reference
program in `~/mtcp` carries a paragraph like this and this one did not, which is
how four inventions survived a whole session unnoticed. **Anything not on this
list should be assumed a mistake rather than a decision.**

## In use, and load-bearing

| what | why | what it would take |
|---|---|---|
| **no `^`** | The SO_REUSEPORT hash is XOR of the four-tuple and must match eTran's exactly, or a SYN lands on a different socket. Written out as `(a\|b) & ~(a&b)`, twice. Exact, and unreadable. | a `^` operator. The grammar has `~ & \| << >>` and stops |
| **no typed bounded `list<T>`** | A listener holds a queue of SYNs; an endpoint holds a list of sockets. `list<>` reaches the backend only as the event frame and the option frame, so `list<tcp_syn>` emits as itself and does not compile. Written as an array plus a count. | `list<T>` for a declared `T`, with `len`/`push`/indexing |
| **`data_off` declared, never assigned** | It is a real TCP header field and the receiver reads it. On egress its value is a function of the option layout, which is the compiler's. | a way to mark a field the compiler computes. The reference put this in the *type* (`hdrlen4_t`) |
| **`op.local` populated on every socket call** | `listen()` carries no address, but the socket layer knows what the socket bound. | nothing in the language -- a statement about the contract, recorded because a target that does not do it breaks `sock_listen` |

## Deliberate, and not deviations

- **`struct listen_slot`** is a record type, which MTP has. It was only ever
  wrong because it was undeclared in a list like this one.
- **an event stored by value** -- a backlog holds `tcp_syn` itself. The backend
  dereferences, because an event parameter is a pointer in C and MTP has no
  pointers and should not.
- **`ev.socket`**, the application's socket reference carried as ordinary data,
  compared and never taken apart. It replaced `op.handle >> 16`.

## Known gaps, recorded elsewhere

- **a processor cannot refuse** -- `docs/REFUSAL.md`: seven cases, three groups.
- **instructions are CALLED, not returned as a list.** Standard MTP has an event
  processor return the instructions it wants run; this program calls them, as
  the reference does. `instr_t` is not in `MTP.g4`, so the list form cannot be
  written today. The *target* may still execute each instruction where it is
  created -- that is a target's choice -- but the program's form is the
  language's, and this one is wrong about it.

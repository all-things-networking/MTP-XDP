#!/usr/bin/env bash
# Regenerate this tree's backend from mtp/tcp.mtp.
#
# The output IS COMMITTED (rule 4: CloudLab wipes nodes, and a build that needs
# the compiler present is a build that cannot be reproduced from this repo
# alone). Run this after editing tcp.mtp, and commit what changes.
#
#   mtp/generate.sh [path/to/MTP-compiler-worktree]
#
# --ctx-type is what makes the output substitutable rather than parallel: the
# eBPF group's processors take `struct bpf_tcp_conn *`, the struct eTran already
# has, so a generated processor drops in beside the hand-written one it replaces
# with no cast and no copy. A conversion at that boundary would be measured as
# if it were the cost of generated code.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MTPC="${1:-/tmp/mtpc-dpdk}"
[ -x "$MTPC/compiler" ] || { echo "no compiler at $MTPC" >&2; exit 2; }

OUT="$ROOT/eTran/micro_kernel/eBPF/tcp/mtp/gen"
mkdir -p "$OUT"
"$MTPC/compiler" --backend=xdp --out="$OUT" \
    --ctx-type=tcp_ctx.ebpf=bpf_tcp_conn \
    --ctx-type=tcp_ctx.cc_shared=bpf_cc \
    "$ROOT/mtp/tcp.mtp"
echo "generated into $OUT:"
ls "$OUT"

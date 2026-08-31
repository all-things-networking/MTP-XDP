#!/usr/bin/env bash
# Regenerate this tree's backend from mtp/tcp.mtp.
#
# The output IS COMMITTED (rule 4: CloudLab wipes nodes, and a build that needs
# the compiler present is a build that cannot be reproduced from this repo
# alone). Run this after editing tcp.mtp, and commit what changes.
#
#   mtp/generate.sh [path/to/MTP-compiler-worktree]
#
# NO TARGET MAPPING. The backend emits one struct per part of a context -- the
# unplaced fields, and each @placement group -- and THIS TREE nests each part in
# whatever structure holds it: bpf_tcp_conn nests the ebpf part, bpf_cc the
# cc_shared part, tcp_connection the common and control parts. A processor is
# then handed the member, so there is still no cast and no copy in the hot path.
#
# It used to pass --ctx-type, which pointed generated code at eTran's own
# structs. That worked and was backwards: it made the target the owner of
# protocol state and left the program renaming its fields to match names eTran
# had chosen.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MTPC="${1:-/tmp/mtpc-dpdk}"
[ -x "$MTPC/compiler" ] || { echo "no compiler at $MTPC" >&2; exit 2; }

# UNDER common/, BECAUSE BOTH SITES INCLUDE IT. The generated parts of a context
# are nested by structures on either side of the eBPF boundary -- bpf_tcp_conn in
# the map, tcp_connection on the control heap -- so the definitions have to be
# reachable from both. eBPF/tcp/mtp/gen was reachable from one.
OUT="$ROOT/eTran/common/mtp/gen"
mkdir -p "$OUT"
"$MTPC/compiler" --backend=xdp --out="$OUT" "$ROOT/mtp/tcp.mtp"
echo "generated into $OUT:"
ls "$OUT"

#!/usr/bin/env bash
# Compile the MTP program with the XDP backend, link the result against THIS
# target, run it, and check what it did.
#
# WHY THIS EXISTS. check-xdp.sh in the compiler proves generated code compiles
# and links. Neither says it computes anything: a processor whose body was
# dropped links perfectly and does nothing. This runs the receive path and
# checks the numbers, which is the only claim worth making.
#
#   mtp/test/run_generated.sh [path/to/MTP-compiler-worktree]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MTPC="${1:-/tmp/mtpc-dpdk}"
[ -x "$MTPC/compiler" ] || { echo "no compiler at $MTPC (build it first)" >&2; exit 2; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/mtp"
cp "$ROOT/eTran/common/mtp/mtp_contract.h" "$ROOT/eTran/common/mtp/mtp_contract_impl.h" "$OUT/mtp/"
"$MTPC/compiler" --backend=xdp --out="$OUT" "$ROOT/mtp/tcp.mtp" >/dev/null
cp "$HERE/drive_tcp.c" "$OUT/"
gcc -c -std=c11 -Wall -Wextra -Wno-unused-parameter -I"$OUT" -o "$OUT/drive.o" "$OUT/drive_tcp.c"
g++ -std=c++17 -I"$OUT" -I"$OUT/mtp" -o "$OUT/run" "$OUT/drive.o" \
    "$ROOT/eTran/common/mtp/mtp_contract_etran.cc"

got="$("$OUT/run" 2>&1)"
echo "$got"

fail=0
check() { grep -q "$1" <<<"$got" || { echo "FAIL: expected $2" >&2; fail=1; }; }
check "rx_next_seq 7000 -> 8448"  "an in-order 1448-byte segment to advance rx_next_seq by 1448"
check "rx_next_seq 8448 -> 8448"  "a duplicate segment to advance nothing"
check "tx_sent=0"                 "an ack for data never sent to be rejected"
check "new=1 del=1"               "the context to be created and destroyed"
check "live=0"                    "no context left behind"
[ "$fail" -eq 0 ] && echo "ok: the generated program runs and the receive path is right"
exit "$fail"

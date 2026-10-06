#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# SOLUTION SCRIPT — reference solve (scores 1.0000 against tests/test.sh)
# ═══════════════════════════════════════════════════════════════════════════
#
# The reference solution is the oracle's own knowledge expressed as the
# FINAL PRODUCT the verifier drives (V5.1: pure dynamic scoring -- no
# written report is read):
#
#   client      = the generated protocol's own client driver (oracle-side
#                 build of the same engine), placed at the fixed
#                 submission path. It drives a FULL session against a
#                 live oracle (hello -> [params] -> auth -> rounds ->
#                 flag -> bye), prints the per-run delivered flag, and
#                 implements the whole robustness contract (retransmit,
#                 resync dance, reconnect after drop, --parallel N).
#
# Mounted layout (Harbor convention, same as the sibling skills):
#   $0                     this script
#   ground_truth/          binaries/ref_client
#   oracle/oracle_server   built during task assembly
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="/logs/artifacts/agent_output"
GT_DIR="$SCRIPT_DIR/ground_truth"

mkdir -p "$OUTPUT_DIR"

# the reference client binary (oracle-side build of the same engine),
# staged under the fixed submission name the verifier invokes
if [ -x "$GT_DIR/binaries/ref_client" ]; then
    cp "$GT_DIR/binaries/ref_client" "$OUTPUT_DIR/client"
    chmod +x "$OUTPUT_DIR/client"
else
    echo "fatal: ground_truth/binaries/ref_client missing --" \
         "task assembly must export it (SKILL.md Step 8.05)" >&2
    exit 1
fi

echo "reference solve staged:"
echo "  $OUTPUT_DIR/client    (full-session client, robustness contract included)"
echo "expected score: 1.0000  (70 session ladder + 30 robustness battery)"

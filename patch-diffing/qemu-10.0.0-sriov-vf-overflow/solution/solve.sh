#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════ SOLUTION SCRIPT: stage the ground truth as the agent submission ═══════════════════════════════════════════════════════════════════════════
#
# The V2 submission contract is exactly ONE file:
#
#   trigger.bin           the GT differential trigger input
#
# The verifier executes it under the task's CANONICAL invocation against
# both delivered binaries and scores the pure-dynamic ladder (100 raw: 70+20+10).
# No report is read; no spec is submitted -- the invocation belongs to
# the task, not the agent.
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(dirname "$0")"
OUTPUT_DIR="${AGENT_OUTPUT_DIR:-/logs/artifacts/agent_output}"

mkdir -p "$OUTPUT_DIR"
cp "$SCRIPT_DIR/ground_truth/trigger.bin" "$OUTPUT_DIR/trigger.bin"

echo "staged GT trigger.bin ($(stat -c%s "$OUTPUT_DIR/trigger.bin") bytes)"

#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# SOLUTION SCRIPT:
# Generate expected outputs for test.sh verification
# ═══════════════════════════════════════════════════════════════════════════
#
# This script generates the expected outputs and places them at: /logs/artifacts/agent_output/
#
# Scoring breakdown (1.0 total):
#   ├── License Verification        (0.5) - valid license key in input.txt
#   └── Property Validation         (0.5) - defeat-demonstrating binaries
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(dirname "$0")"
OUTPUT_DIR="/logs/artifacts/agent_output"

# Create output directory
mkdir -p "$OUTPUT_DIR/binaries"

# Copy ground truth files to output location
cp "$SCRIPT_DIR/ground_truth/input.txt" "$OUTPUT_DIR/input.txt"
cp "$SCRIPT_DIR/ground_truth/binaries/origin_binary" "$OUTPUT_DIR/binaries/origin_binary"

echo "==============================================================================="
echo "Solution Setup Complete - nginx-1.31.3-tier-license"
echo "==============================================================================="
echo ""
echo "Output files placed at: $OUTPUT_DIR"
echo "  - input.txt"
echo "  - binaries/"
echo "    - origin_binary (fully-defeated artifact)"
echo ""
echo "Run test.sh to verify the solution."
echo "==============================================================================="

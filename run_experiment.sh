#!/bin/bash
# run_experiment.sh — Reproduces the full evaluation from the report.
# 1. Builds both fuzzers (libpng + toy)
# 2. Runs the toy vulnerable parser fuzzer (~30s, expects a crash)
# 3. Runs the libpng fuzzer for 10 minutes

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBPNG_TIME=600   # 10 minutes
TOY_TIME=30       # 30 seconds

echo "============================================"
echo " libpng Fuzzer — Full Experiment"
echo "============================================"
echo ""

# --- Step 1: Build ---
echo "[1/3] Building libpng fuzzer..."
bash "$SCRIPT_DIR/build.sh"
echo ""

echo "[1/3] Building toy vulnerable parser fuzzer..."
bash "$SCRIPT_DIR/basic_eval/build.sh"
echo ""

# --- Step 2: Toy evaluation ---
echo "============================================"
echo "[2/3] Running toy fuzzer (${TOY_TIME}s)..."
echo "       Expect: heap-buffer-overflow crash"
echo "============================================"
echo ""

# The toy fuzzer is expected to crash (exit code != 0), so don't let set -e kill us.
"$SCRIPT_DIR/basic_eval/fuzz_vuln" -max_total_time=$TOY_TIME 2>&1 || true
echo ""

# --- Step 3: libpng evaluation ---
echo "============================================"
echo "[3/3] Running libpng fuzzer (${LIBPNG_TIME}s)..."
echo "============================================"
echo ""

mkdir -p "$SCRIPT_DIR/corpus"
"$SCRIPT_DIR/fuzz_png" "$SCRIPT_DIR/corpus/" "$SCRIPT_DIR/seeds/" -dict="$SCRIPT_DIR/png.dict" -max_total_time=$LIBPNG_TIME 2>&1

echo ""
echo "============================================"
echo " Experiment complete."
echo "============================================"

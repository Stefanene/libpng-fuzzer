#!/bin/bash
# Clean script for libpng fuzzer
# Removes build artifacts, downloaded sources, and generated binaries.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Cleaning build artifacts..."

rm -rf "$SCRIPT_DIR/build"
rm -f  "$SCRIPT_DIR"/libpng-*.tar.gz
rm -f  "$SCRIPT_DIR/fuzz_png"
rm -rf "$SCRIPT_DIR/fuzz_png.dSYM"

# Basic eval artifacts
rm -f  "$SCRIPT_DIR/basic_eval/fuzz_vuln"
rm -rf "$SCRIPT_DIR/basic_eval/fuzz_vuln.dSYM"

# Fuzzer runtime artifacts
rm -f  "$SCRIPT_DIR"/crash-*
rm -rf "$SCRIPT_DIR/corpus"
find "$SCRIPT_DIR/seeds" -type f ! -name 'seed.png' -delete 2>/dev/null || true

echo "Clean complete."

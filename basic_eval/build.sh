#!/bin/bash
# Build script for the toy vulnerable parser fuzzer.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LLVM_PREFIX="/opt/homebrew/opt/llvm"
[ ! -d "$LLVM_PREFIX" ] && LLVM_PREFIX="/usr/local/opt/llvm"
if [ ! -d "$LLVM_PREFIX" ]; then
  echo "Error: Homebrew LLVM not found. Install with: brew install llvm"
  exit 1
fi

CC="$LLVM_PREFIX/bin/clang"
CXX="$LLVM_PREFIX/bin/clang++"

echo "Building toy vulnerable parser fuzzer..."

$CC -fsanitize=address,fuzzer -g -O1 -c "$SCRIPT_DIR/vuln_parser.c" -o "$SCRIPT_DIR/vuln_parser.o"
$CXX -fsanitize=address,fuzzer -g -O1 -std=c++11 "$SCRIPT_DIR/fuzz_vuln.cc" "$SCRIPT_DIR/vuln_parser.o" -o "$SCRIPT_DIR/fuzz_vuln"

rm -f "$SCRIPT_DIR/vuln_parser.o"

echo "Build successful! Binary: $SCRIPT_DIR/fuzz_vuln"
echo "Run: $SCRIPT_DIR/fuzz_vuln"

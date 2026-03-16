#!/bin/bash
# Build script for libpng fuzzer
# Downloads libpng 1.6.55, builds it with ASan + libFuzzer instrumentation,
# and compiles the fuzz target.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Toolchain ---
# Use Homebrew LLVM (Apple clang does not ship libFuzzer).
LLVM_PREFIX="/opt/homebrew/opt/llvm"
if [ ! -d "$LLVM_PREFIX" ]; then
  # Fallback for Intel Macs
  LLVM_PREFIX="/usr/local/opt/llvm"
fi
if [ ! -d "$LLVM_PREFIX" ]; then
  echo "Error: Homebrew LLVM not found. Install with: brew install llvm"
  exit 1
fi

export CC="$LLVM_PREFIX/bin/clang"
export CXX="$LLVM_PREFIX/bin/clang++"

echo "Using CC=$CC"
echo "Using CXX=$CXX"

# --- Download libpng 1.6.55 ---
LIBPNG_TAR="libpng-1.6.55.tar.gz"
LIBPNG_DIR="libpng-1.6.55"
LIBPNG_URL="https://downloads.sourceforge.net/project/libpng/libpng16/1.6.55/libpng-1.6.55.tar.gz"

if [ ! -e "$SCRIPT_DIR/$LIBPNG_TAR" ]; then
  echo "Downloading libpng 1.6.55..."
  curl -L -o "$SCRIPT_DIR/$LIBPNG_TAR" "$LIBPNG_URL"
fi

if [ ! -d "$SCRIPT_DIR/$LIBPNG_DIR" ]; then
  echo "Extracting libpng 1.6.55..."
  tar xf "$SCRIPT_DIR/$LIBPNG_TAR" -C "$SCRIPT_DIR"
fi

# --- Build libpng with instrumentation ---
BUILD_DIR="$SCRIPT_DIR/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp -rf "$SCRIPT_DIR/$LIBPNG_DIR/"* "$BUILD_DIR/"

echo "Building libpng with ASan + coverage instrumentation..."

(
  cd "$BUILD_DIR"
  # -fsanitize=fuzzer adds coverage instrumentation at compile time (main is only added at link time).
  # LDFLAGS omits fuzzer so configure's link tests pass without LLVMFuzzerTestOneInput.
  # UBSan detects integer overflow, shift errors, null deref — bugs ASan misses.
  # -DPNG_DISABLE_ADLER32_CHECK_SUPPORTED enables the ADLER32 bypass option at runtime.
  export CFLAGS="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=all -g -O1 -DPNG_DISABLE_ADLER32_CHECK_SUPPORTED"
  export CXXFLAGS="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=all -g -O1 -DPNG_DISABLE_ADLER32_CHECK_SUPPORTED"
  export LDFLAGS="-fsanitize=address,undefined"
  ./configure --disable-shared --quiet
  make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" --quiet
)

# --- Compile fuzz target ---
echo "Compiling fuzz target..."
$CXX \
  -std=c++11 \
  -fsanitize=address,undefined,fuzzer \
  -fno-sanitize-recover=all \
  -g -O1 \
  -DPNG_DISABLE_ADLER32_CHECK_SUPPORTED \
  -I "$BUILD_DIR" \
  "$SCRIPT_DIR/fuzz_target.cc" \
  "$BUILD_DIR/.libs/libpng16.a" \
  -lz \
  -o "$SCRIPT_DIR/fuzz_png"

echo ""
echo "Build successful! Binary: $SCRIPT_DIR/fuzz_png"
echo ""
echo "Run the fuzzer:"
echo "  ./fuzz_png seeds/ -dict=png.dict"
echo ""
echo "Run with a time limit:"
echo "  ./fuzz_png seeds/ -dict=png.dict -max_total_time=60"

# libpng Fuzzer

Finding memory safety bugs in [libpng](http://www.libpng.org/pub/png/libpng.html) using coverage-guided fuzzing.

**Authors:** Stefan Ene, Younes Bennani
**Course:** CS 295 — Software Engineering

## Overview

This project uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html), [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), and [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) to fuzz test **libpng**, an open-source C library for handling PNG files. libpng is widely used in image processing software, web browsers, and scientific computing libraries for parsing PNG file structure, decoding image data, and handling metadata such as transparency and color profiles.

We evaluate two versions: **libpng 1.2.56** (legacy, commonly used as a fuzzing benchmark) and **libpng 1.6.55** (the current stable release).

## Bug Classes

We aim to detect the following classes of bugs:

- **Buffer overflows** (stack and heap)
- **Out-of-bounds memory reads/writes**
- **Invalid memory accesses**
- **Undefined behavior** (integer overflow, invalid shifts, null dereference)
- **Crashes caused by malformed input**

## Methodology

### 1. Instrumented Build

`build.sh` downloads the libpng 1.6.55 source and compiles it with Homebrew LLVM using:

- **`-fsanitize=address`** — AddressSanitizer detects memory errors (buffer overflows, use-after-free, etc.) at runtime.
- **`-fsanitize=undefined`** — UndefinedBehaviorSanitizer detects integer overflow, invalid shifts, null dereference, and other undefined behavior.
- **`-fsanitize=fuzzer`** — libFuzzer coverage instrumentation tracks which code paths each input exercises. At compile time this inserts coverage counters; at link time (for the final binary only) it provides the fuzzer's `main()` loop.
- **`-DPNG_DISABLE_ADLER32_CHECK_SUPPORTED`** — Enables the ADLER32 bypass option so the harness can disable checksum validation on zlib streams.

### 2. Fuzz Harness

`fuzz_target.cc` implements the `LLVMFuzzerTestOneInput` entry point that libFuzzer calls for each generated input. The harness performs two decode passes:

**Low-level decode with transforms:**
1. **Validates the PNG signature** — rejects inputs that don't start with the 8-byte PNG magic number.
2. **Disables CRC and ADLER32 checking** — allows malformed chunks and corrupted zlib streams to reach deeper parsing logic.
3. **Installs a custom memory allocator** — rejects allocations > 8 MB to prevent OOM kills.
4. **Reads from an in-memory buffer** — uses a custom `user_read_data` callback for maximum throughput.
5. **Applies browser-typical transforms** — `gray_to_rgb`, `expand`, `packing`, `scale_16`, `tRNS_to_alpha` — to exercise the image transformation pipeline.
6. **Decodes the full image** — reads headers, applies transforms, iterates over all rows and interlace passes.
7. **Processes post-IDAT chunks** — calls `png_read_end()` to exercise text chunk handlers (tEXt, zTXt, iTXt).
8. **Cleans up via RAII** — the `ScopedPngObject` struct ensures libpng resources are freed on every exit path.

**Simplified READ API:**
9. **Decodes via `png_image` API** — exercises an entirely separate code path within libpng for additional coverage.

### 3. Seed Corpus & Dictionary

The `seeds/` directory contains 30 PNG files from the PNGSuite test set, covering all color types (grayscale, RGB, palette, gray+alpha, RGBA), bit depths (1–16), interlaced images, and transparency variants. The `png.dict` dictionary provides all 25 standard PNG chunk type tags to accelerate chunk handler discovery.

### 4. Monitoring

libFuzzer reports progress in real time. We track:

- **Executions per second** — throughput of the fuzzing loop
- **Code coverage growth** — new code edges discovered over time
- **Unique crashes** — inputs that trigger ASan violations or program crashes

## Prerequisites

- **LLVM/Clang** with libFuzzer support (Apple clang does **not** include libFuzzer)
- **zlib**

### macOS

```bash
brew install llvm zlib
```

### Ubuntu/Debian

```bash
sudo apt-get install clang llvm zlib1g-dev
```

## Building

```bash
git clone https://github.com/Stefanene/libpng-fuzzer.git
cd libpng-fuzzer

bash build.sh
```

The build script will:
1. Download and extract the libpng 1.6.55 source code
2. Compile libpng as a static library with ASan, UBSan, and libFuzzer coverage instrumentation
3. Link the fuzz harness into the `fuzz_png` binary

## Running the Experiment

To reproduce the full evaluation from the report (build everything, run the toy fuzzer for 30s, then fuzz libpng for 10 minutes):

```bash
bash run_experiment.sh
```

### Running the Fuzzer Manually

```bash
# Basic run with the seed corpus and dictionary
./fuzz_png seeds/ -dict=png.dict

# Run with a time limit (e.g., 60 seconds)
./fuzz_png seeds/ -dict=png.dict -max_total_time=60

# Save new corpus inputs to a separate directory
mkdir -p corpus
./fuzz_png corpus/ seeds/ -dict=png.dict

# Run with parallel workers
./fuzz_png seeds/ -dict=png.dict -fork=4 -max_total_time=300
```

Crash-reproducing inputs are saved as `crash-*` files. To reproduce a crash:

```bash
./fuzz_png crash-<hash>
```

## Cleaning

To remove all build artifacts and downloaded sources:

```bash
bash clean.sh
```

## Project Structure

```
libpng-fuzzer/
├── README.md
├── report.md              # Full evaluation report
├── build.sh               # Downloads libpng 1.6.55, compiles with ASan+UBSan+fuzzer
├── clean.sh               # Removes all build artifacts
├── run_experiment.sh      # Reproduces the full evaluation (build + toy + libpng)
├── fuzz_target.cc         # Fuzz harness (transforms, ADLER32 bypass, simplified API)
├── png.dict               # Fuzzer dictionary with PNG chunk type tags
├── seeds/                 # Seed corpus (30 PNGs from PNGSuite)
│   ├── basn*.png          # All color types and bit depths
│   ├── ibasn*.png         # Interlaced variants
│   ├── ftbbn*.png         # Transparency variants
│   └── seed.png           # Minimal 1x1 PNG seed
├── basic_eval/            # Toy vulnerable parser for basic evaluation
│   ├── vuln_parser.c      # Parser with planted memory safety bugs
│   ├── fuzz_vuln.cc       # Fuzz harness for the toy parser
│   └── build.sh           # Build script for the toy fuzzer
├── build/                 # (generated) Instrumented libpng build
├── corpus/                # (generated) Discovered corpus inputs
└── fuzz_png               # (generated) Fuzzer binary
```

## Fallback Plan

If no previously unknown bugs are discovered, we will reproduce known libpng vulnerabilities from public vulnerability databases to validate that our fuzzing infrastructure is functioning correctly and capable of detecting real bugs.

## License

This project is for educational purposes as part of CS 295 Software Engineering.

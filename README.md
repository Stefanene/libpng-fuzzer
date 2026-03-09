# libpng Fuzzer

Finding memory safety bugs in [libpng](http://www.libpng.org/pub/png/libpng.html) using coverage-guided fuzzing.

**Authors:** Stefan Ene, Younes Bennani
**Course:** CS 295 — Software Engineering

## Overview

This project uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) to fuzz test **libpng 1.2.56**, an open-source C library for handling PNG files. libpng is widely used in image processing software, web browsers, and scientific computing libraries for parsing PNG file structure, decoding image data, and handling metadata such as transparency and color profiles.

We target libpng 1.2.56 specifically because it is an older version with known memory safety history, and because its internal struct layout (exposed via `PNG_INTERNAL`) allows the harness to disable CRC validation — letting the fuzzer explore deeper code paths with malformed chunks that would otherwise be rejected.

## Bug Classes

We aim to detect the following classes of memory safety bugs:

- **Buffer overflows**
- **Out-of-bounds memory reads/writes**
- **Invalid memory accesses**
- **Crashes caused by malformed input**

## Methodology

### 1. Instrumented Build

`build.sh` downloads the libpng 1.2.56 source and compiles it with Homebrew LLVM using:

- **`-fsanitize=address`** — AddressSanitizer detects memory errors (buffer overflows, use-after-free, etc.) at runtime.
- **`-fsanitize=fuzzer`** — libFuzzer coverage instrumentation tracks which code paths each input exercises. At compile time this inserts coverage counters; at link time (for the final binary only) it provides the fuzzer's `main()` loop.

A patch is applied to `pngconf.h` to replace the legacy macOS `<fp.h>` header with `<math.h>`.

### 2. Fuzz Harness

`fuzz_target.cc` implements the `LLVMFuzzerTestOneInput` entry point that libFuzzer calls for each generated input. The harness:

1. **Validates the PNG signature** — rejects inputs that don't start with the 8-byte PNG magic number, so the fuzzer focuses on structurally plausible inputs.
2. **Disables CRC checking** — accesses internal `png_ptr->flags` to ignore CRC errors on both critical and ancillary chunks. This allows malformed chunks to reach deeper parsing logic instead of being rejected at the CRC check.
3. **Reads from an in-memory buffer** — uses a custom `user_read_data` callback instead of file I/O, so libFuzzer can feed data directly from memory.
4. **Decodes the full image** — reads the IHDR, sets up interlace handling, and iterates over all rows and passes, exercising the full PNG decode pipeline.
5. **Guards against resource exhaustion** — rejects images larger than 2 million pixels to prevent timeouts.
6. **Cleans up via RAII** — the `ScopedPngObject` struct ensures libpng resources are freed on every exit path (including `longjmp` error returns).

### 3. Seed Corpus

The `seeds/` directory contains a minimal valid 1x1 PNG file. Starting from a valid seed lets libFuzzer mutate structurally valid PNG data rather than discovering the PNG signature by random chance, dramatically improving early coverage.

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
1. Download and extract the libpng 1.2.56 source code
2. Patch `pngconf.h` for macOS compatibility
3. Compile libpng as a static library with ASan and libFuzzer coverage instrumentation
4. Link the fuzz harness into the `fuzz_png` binary

## Running the Experiment

To reproduce the full evaluation from the report (build everything, run the toy fuzzer for 30s, then fuzz libpng for 3 minutes):

```bash
bash run_experiment.sh
```

### Running the Fuzzer Manually

```bash
# Basic run with the seed corpus
./fuzz_png seeds/

# Run with a time limit (e.g., 60 seconds)
./fuzz_png seeds/ -max_total_time=60

# Save new corpus inputs to a separate directory
mkdir -p corpus
./fuzz_png corpus/ seeds/

# Run with parallel workers
./fuzz_png seeds/ -fork=4 -max_total_time=300
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
├── build.sh               # Downloads libpng 1.2.56, compiles with instrumentation
├── clean.sh               # Removes all build artifacts
├── run_experiment.sh      # Reproduces the full evaluation (build + toy + libpng)
├── fuzz_target.cc         # Fuzz harness (LLVMFuzzerTestOneInput entry point)
├── seeds/                 # Seed corpus
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

# libpng Fuzzer

Finding memory safety bugs in [libpng](http://www.libpng.org/pub/png/libpng.html) using coverage-guided fuzzing.

**Authors:** Stefan Ene, Younes Bennani
**Course:** CS 295 — Software Engineering

## Overview

This project uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) to fuzz test libpng, an open-source C library for handling PNG files. libpng is widely used in image processing software, web browsers, and scientific computing libraries for parsing PNG file structure, decoding image data, and handling metadata such as transparency and color profiles.

libpng is a compelling fuzzing target because it:
- Processes complex, structured input (PNG files)
- Is written in C, a language susceptible to memory safety bugs
- Parses externally supplied files, making it security-relevant
- Has a history of memory safety vulnerabilities

## Bug Classes

We aim to detect the following classes of memory safety bugs:

- **Buffer overflows**
- **Out-of-bounds memory reads/writes**
- **Invalid memory accesses**
- **Crashes caused by malformed input**

## Approach

1. **Compile libpng with instrumentation** — Build libpng with AddressSanitizer and libFuzzer enabled to automatically detect crashes and memory safety violations.
2. **Fuzz target harness** — Feed randomly generated and mutated input data into libpng's image parsing functionality. libFuzzer automatically generates inputs and prioritizes those that explore new execution paths.
3. **Monitor and triage** — When libpng encounters malformed inputs, AddressSanitizer reports any memory safety violations. We track:
   - Number of executions
   - Code coverage growth
   - Unique crashes discovered

## Prerequisites

- **Clang/LLVM** (with libFuzzer and AddressSanitizer support)
- **libpng** source code
- **zlib** (libpng dependency)

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
# Clone the repository
git clone https://github.com/Stefanene/libpng-fuzzer.git
cd libpng-fuzzer

# Download and build libpng with instrumentation
# (build instructions will be updated as the project develops)
```

## Running the Fuzzer

```bash
# Run the fuzzer (instructions will be updated)
./fuzz_png corpus/

# Run with a time limit (e.g., 60 seconds)
./fuzz_png corpus/ -max_total_time=60
```

## Project Structure

```
libpng-fuzzer/
├── README.md
├── corpus/              # Seed corpus of valid PNG files
├── crashes/             # Crash-inducing inputs discovered by the fuzzer
└── ...                  # Fuzz harness and build scripts (TBD)
```

## Fallback Plan

If no previously unknown bugs are discovered, we will reproduce known libpng vulnerabilities from public vulnerability databases to validate that our fuzzing infrastructure is functioning correctly and capable of detecting real bugs.

## License

This project is for educational purposes as part of CS 295 Software Engineering.

# Finding Memory Safety Bugs in libpng using Coverage-Guided Fuzzing

**Authors:** Stefan Ene, Younes Bennani
**Course:** CS 295 — Software Engineering

---

## 1. System Description

We evaluate **coverage-guided fuzzing** as a bug-finding approach for detecting memory safety violations in C programs that parse structured binary input. Our system combines two LLVM-based tools:

- **libFuzzer** — a coverage-guided, mutation-based fuzzer that generates inputs, feeds them to a target function, and uses code coverage feedback to prioritize inputs that explore new execution paths.
- **AddressSanitizer (ASan)** — a compile-time memory error detector that instruments every memory access to detect buffer overflows, out-of-bounds reads/writes, use-after-free, and other memory safety violations at runtime.

**Class of bugs targeted:**

- Buffer overflows (stack and heap)
- Out-of-bounds memory reads and writes
- Invalid memory accesses
- Program crashes caused by malformed input

**Target application:** We target **libpng 1.2.56**, an open-source C library for parsing PNG image files. libpng is widely used in image processing software, web browsers, and scientific computing libraries. It is a compelling fuzzing target because it processes complex structured input (the PNG format includes headers, chunks with CRC checksums, and zlib-compressed image data), is written in C (a language without memory safety guarantees), and has a documented history of memory safety vulnerabilities.

## 2. Technical Overview

### Fuzz Harness (`fuzz_target.cc`)

The core of our system is a fuzz harness that implements the `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` entry point. libFuzzer calls this function repeatedly with mutated inputs. The harness performs the following steps:

1. **PNG signature validation** — The harness rejects inputs that do not begin with the 8-byte PNG magic number (`89 50 4E 47 0D 0A 1A 0A`). This ensures the fuzzer focuses its mutation budget on structurally plausible PNG data rather than wasting cycles on inputs that are immediately rejected.

2. **CRC bypass** — By defining `PNG_INTERNAL` and directly manipulating `png_ptr->flags`, the harness disables CRC checking on both critical and ancillary chunks:
   ```c
   png_ptr->flags &= ~PNG_FLAG_CRC_CRITICAL_MASK;
   png_ptr->flags |= PNG_FLAG_CRC_CRITICAL_IGNORE;
   png_ptr->flags &= ~PNG_FLAG_CRC_ANCILLARY_MASK;
   png_ptr->flags |= PNG_FLAG_CRC_ANCILLARY_NOWARN;
   ```
   This is a critical optimization. Without it, the fuzzer would need to generate valid CRC32 checksums for every mutated chunk — an astronomically unlikely event via random mutation. Disabling CRC validation allows malformed chunks to reach the deeper parsing logic (chunk handlers, decompression, row filtering) where memory safety bugs are most likely to occur.

3. **In-memory I/O** — Instead of reading from files, the harness registers a custom `user_read_data` callback via `png_set_read_fn()`. This callback reads directly from the fuzzer-provided memory buffer, avoiding filesystem overhead and enabling libFuzzer to feed inputs at maximum speed.

4. **Full decode pipeline** — The harness exercises the complete PNG read path: `png_read_info()` → `png_get_IHDR()` → `png_set_interlace_handling()` → `png_start_read_image()` → row-by-row `png_read_row()` across all interlace passes. This ensures coverage of chunk parsing, zlib decompression, row filtering, and interlace reconstruction.

5. **Resource exhaustion guard** — Images exceeding 2 million total pixels are rejected early to prevent individual inputs from consuming excessive time or memory, which would reduce overall fuzzing throughput.

6. **RAII cleanup** — A `ScopedPngObject` struct ensures all libpng resources (read struct, info struct, row buffer) are freed on every exit path, including when libpng's internal error handling triggers a `longjmp`.

### Instrumented Build (`build.sh`)

The build script downloads libpng 1.2.56 source code and compiles it with Homebrew LLVM using:

- **`-fsanitize=address,fuzzer`** in `CFLAGS` — At compile time, `-fsanitize=fuzzer` inserts inline 8-bit coverage counters at every basic block edge, while `-fsanitize=address` instruments every memory access for runtime error detection.
- **`-fsanitize=address`** only in `LDFLAGS` — The `fuzzer` flag is omitted from link flags during the library build because libFuzzer's `main()` is only needed in the final binary, and including it during configure's link tests would fail (no `LLVMFuzzerTestOneInput` symbol exists yet).
- A **patch to `pngconf.h`** replaces the legacy macOS `<fp.h>` header with `<math.h>`, since `<fp.h>` does not exist on modern macOS.

The final fuzz target is compiled with `-fsanitize=address,fuzzer` and linked against the instrumented static library (`libpng12.a`) and system zlib.

### Seed Corpus

The `seeds/` directory contains a minimal valid 1x1 pixel PNG file (69 bytes). Starting from a structurally valid seed is essential for efficiency — without it, libFuzzer would need to discover the 8-byte PNG signature through random mutation before any meaningful coverage is achieved.

## 3. System Setup Steps

### Prerequisites

| Dependency | Purpose |
|------------|---------|
| Homebrew LLVM | Provides `clang`/`clang++` with libFuzzer and AddressSanitizer (Apple's system clang does **not** include libFuzzer) |
| zlib | Compression library required by libpng |
| curl | Used by `build.sh` to download the libpng source tarball |

### Installation (macOS)

```bash
# Install Homebrew LLVM and zlib
brew install llvm zlib
```

### Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/Stefanene/libpng-fuzzer.git
cd libpng-fuzzer

# 2. Build the fuzzer (downloads libpng 1.2.56, patches, compiles everything)
bash build.sh

# 3. Verify the binary was created
ls -la fuzz_png
```

`build.sh` performs the following automatically:
1. Downloads `libpng-1.2.56.tar.gz` from SourceForge (if not already present)
2. Extracts the source and copies it to a `build/` directory
3. Patches `pngconf.h` for macOS compatibility
4. Runs `./configure --disable-shared` with instrumented `CC`/`CXX`
5. Compiles the fuzz harness and links it against the instrumented `libpng12.a`
6. Outputs the `fuzz_png` binary

### Running the Fuzzer

```bash
# Basic run with seed corpus (runs indefinitely until interrupted or crash)
./fuzz_png seeds/

# Run with a time limit
./fuzz_png seeds/ -max_total_time=60

# Save discovered corpus inputs to a separate directory
mkdir -p corpus
./fuzz_png corpus/ seeds/
```

### Cleaning Up

```bash
bash clean.sh
```

### Building and Running the Toy Evaluation Program

```bash
bash basic_eval/build.sh
./basic_eval/fuzz_vuln
```

## 4. Evaluation Methodology

### Metrics

We measure the following metrics to evaluate fuzzer efficacy:

| Metric | Description |
|--------|-------------|
| **Edge coverage** | Number of unique code edges (basic block transitions) exercised, reported as `cov:` by libFuzzer. Higher coverage means more of the program has been explored. |
| **Feature count** | Number of unique coverage features (`ft:`), a finer-grained measure that distinguishes hit counts at each edge. |
| **Executions/second** | Throughput of the fuzzing loop. Higher throughput means more inputs tested per unit time. |
| **Corpus size** | Number of inputs retained by the fuzzer because they triggered new coverage. |
| **Unique crashes** | Number of distinct ASan-detected violations or signals. |
| **RSS (memory)** | Resident set size of the fuzzer process. |

### Bug Detection

Bugs are detected through two mechanisms:

1. **AddressSanitizer reports** — ASan instruments every memory access at compile time. When a memory safety violation occurs (buffer overflow, OOB read/write, use-after-free), ASan immediately halts execution and prints a detailed report including the error type, faulting address, stack trace, and allocation site. No program annotations are needed — ASan detects violations automatically.

2. **Signals** — If libpng encounters a truly corrupted state that causes a segmentation fault (`SIGSEGV`) or abort (`SIGABRT`), libFuzzer catches the signal and saves the triggering input.

In both cases, libFuzzer writes the crash-inducing input to a `crash-<hash>` file for later reproduction and analysis.

### Basic Evaluation Design

To validate that our toolchain and methodology work correctly, we constructed a **toy vulnerable parser** (`basic_eval/vuln_parser.c`) with two intentionally planted memory safety bugs:

- **Bug 1: Stack buffer overflow** — A `parse_name_field` function copies a variable-length name into a fixed 32-byte stack buffer without bounds checking.
- **Bug 2: Heap buffer overflow** — A `parse_dimensions` function allocates a buffer based on a `width` field but copies `height` bytes into it, where `height` can exceed `width`.

The toy program uses a 2-byte magic number (`0xDE 0xAD`) and a type byte to dispatch to the vulnerable sub-parsers. A simple `LLVMFuzzerTestOneInput` harness wraps the parser.

**Success criteria:** The fuzzer should discover at least one of the planted bugs within seconds, producing an ASan report that pinpoints the exact source location.

### Production Evaluation Design

For the production evaluation, we run the fuzzer against **libpng 1.2.56** — a real-world library with ~15,000 lines of C code. We evaluate:

- How much of libpng's code the fuzzer manages to cover
- Whether any ASan violations are triggered
- Which chunk handlers and code paths are reached
- Where coverage growth stalls and why

## 5. Basic Evaluation

### Results: Toy Vulnerable Parser

We ran the toy fuzzer from an empty corpus (no seed files) for 30 seconds:

| Metric | Value |
|--------|-------|
| Total executions at crash | **166,938** |
| Time to first crash | **< 2 seconds** |
| Coverage at crash | 18 edges, 25 features |
| Instrumented counters | 19 |
| Bug found | Heap buffer overflow (Bug 2) |
| Location | `vuln_parser.c:39` in `parse_dimensions` |

**ASan report summary:**
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020003a34d1
WRITE of size 6 at 0x6020003a34d1 thread T0
    #0 __asan_memcpy
    #1 parse_dimensions vuln_parser.c:39
    #2 parse_image_header vuln_parser.c:66
    #3 LLVMFuzzerTestOneInput fuzz_vuln.cc:9
```

The fuzzer synthesized the crash input from scratch: `\xde\xad\x02\x01\x00\x5c\x02...` — magic bytes `0xDEAD`, type `0x02` (dimensions), width=1 (tiny allocation), height=604 (large copy). ASan caught the resulting heap-buffer-overflow in `memcpy` and reported the exact source location and allocation site.

### Discussion

The toy evaluation demonstrates several key properties of our approach:

1. **Coverage guidance is effective at input discovery.** Starting from an empty corpus, the fuzzer discovered the 2-byte magic number, the correct type byte, and the bug-triggering relationship between width and height fields — all through coverage-guided mutation. Each new byte of the magic number (`0xDE`, `0xAD`) and type field (`0x02`) added a new coverage edge, incentivizing the fuzzer to retain and mutate those inputs.

2. **ASan provides precise, actionable reports.** The ASan output identifies the exact error type (heap-buffer-overflow), the faulting instruction (`memcpy` at `vuln_parser.c:39`), and the allocation site (`malloc` at `vuln_parser.c:33`). This level of detail makes triage straightforward compared to raw crash signals.

3. **Input structure affects discovery time.** The fuzzer reached the vulnerable code paths in ~162K executions because the dispatch logic (magic check + type byte) required only 3 specific bytes. A more deeply guarded path would take longer to discover. This is why the CRC bypass in the libpng harness is critical — without it, the fuzzer would need to produce valid CRC32 checksums, which is essentially impossible via random mutation.

## 6. Evaluation on Production Application

### Campaign Configuration

We ran the libpng fuzzer for **120 seconds** starting from a single seed (69-byte, 1x1 pixel PNG):

| Metric | Value |
|--------|-------|
| Total executions | **652,774** |
| Executions/second | **~81,600** |
| Coverage (edges) | **619 / 3,118** (19.9% of instrumented counters) |
| Features | **1,933** |
| Corpus size | **418 inputs, 23 KB total** |
| Peak RSS | **425 MB** |
| ASan crashes | **0** |
| Unique functions reached | **27** (beyond seed) |

### Coverage Analysis

Starting from a single seed with 205 edges of coverage, the fuzzer grew coverage to 619 edges within 2 minutes — a **3x increase**. Coverage growth was rapid in the first ~10 seconds as the fuzzer discovered new chunk types, then plateaued as deeper paths became harder to reach.

**Chunk handlers reached** (27 unique functions discovered during fuzzing):

The fuzzer successfully reached handlers for: `PLTE`, `bKGD`, `cHRM`, `gAMA`, `hIST`, `iCCP`, `oFFs`, `pCAL`, `pHYs`, `sBIT`, `sCAL`, `sPLT`, `sRGB`, `tEXt`, `tIME`, `tRNS`, `zTXt`, `IEND`, and the unknown-chunk handler. It also reached internal routines including `png_do_read_interlace`, `png_do_read_transformations`, and `png_read_filter_row`.

This confirms the CRC bypass is working as intended — the fuzzer is reaching deep into the chunk parsing logic without being rejected at checksum validation.

### Why No Crashes Were Found

No ASan violations were triggered during our 2-minute campaign. This is expected for several reasons:

1. **libpng 1.2.56 has been extensively fuzzed.** Google's fuzzer-test-suite, OSS-Fuzz, and independent researchers have collectively run billions of fuzzing iterations against this exact version. The most accessible bugs have already been found and patched in later releases.

2. **Limited campaign duration.** At ~81K executions/second, our 2-minute campaign explored ~650K inputs. Production fuzzing campaigns typically run for hours or days. Deeper bugs — those requiring specific multi-chunk sequences or precise relationships between header fields — may require substantially more exploration.

3. **Coverage plateau at ~20%.** The fuzzer exercised roughly one-fifth of the instrumented code. The unreached 80% likely includes write-path code (our harness only reads), rarely-triggered error paths, and code guarded by complex state conditions that random mutation struggles to satisfy.

### Behaviors Observed

While no memory safety violations were found, the fuzzer exercised a wide range of error-handling paths within libpng:

- **Invalid chunk types** — The fuzzer generated chunk type tags that libpng does not recognize, exercising the unknown-chunk handler.
- **Invalid IHDR data** — Malformed image headers with invalid color types, compression methods, and interlace methods were processed.
- **Decompression errors** — Corrupt zlib streams within IDAT chunks triggered `incorrect data check` errors.
- **Bad filter types** — The fuzzer produced row data with invalid adaptive filter bytes, exercising filter validation logic.
- **Out-of-order chunks** — Chunks appearing before the required IHDR were detected and rejected.

These behaviors demonstrate that the fuzzer is effectively exploring libpng's error-handling code, which is precisely the code most likely to contain memory safety bugs.

### Path Forward

To increase the likelihood of finding bugs, future campaigns could:

- **Run for significantly longer** (hours/days) to explore deeper state spaces
- **Use a richer seed corpus** with diverse PNG files (different color types, interlacing, ancillary chunks) to start with higher baseline coverage
- **Target older, unpatched versions** of libpng where known CVEs have not been fixed
- **Use structure-aware mutation** (e.g., Google's `png_mutator.h`) to generate mutations that respect PNG chunk boundaries

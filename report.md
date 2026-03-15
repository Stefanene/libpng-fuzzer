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

**Target application:** We target **libpng**, an open-source C library for parsing PNG image files. libpng is widely used in image processing software, web browsers, and scientific computing libraries. It is a compelling fuzzing target because it processes complex structured input (the PNG format includes headers, chunks with CRC checksums, and zlib-compressed image data), is written in C (a language without memory safety guarantees), and has a documented history of memory safety vulnerabilities. We evaluate two versions:

- **libpng 1.2.56** — A legacy release from the 1.2.x branch, commonly used as a fuzzing benchmark (e.g., in Google's fuzzer-test-suite).
- **libpng 1.6.55** — The latest stable release (February 2026), representing the current state of libpng with modern security hardening and recent CVE fixes.

## 2. Technical Overview

### Fuzz Harness (`fuzz_target.cc`)

The core of our system is a fuzz harness that implements the `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` entry point. libFuzzer calls this function repeatedly with mutated inputs. The harness performs the following steps:

1. **PNG signature validation** — The harness rejects inputs that do not begin with the 8-byte PNG magic number (`89 50 4E 47 0D 0A 1A 0A`). This ensures the fuzzer focuses its mutation budget on structurally plausible PNG data rather than wasting cycles on inputs that are immediately rejected.

2. **CRC bypass** — The harness disables CRC checking on both critical and ancillary PNG chunks using the public API:
   ```c
   png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
   ```
   This is a critical optimization. Without it, the fuzzer would need to generate valid CRC32 checksums for every mutated chunk — an astronomically unlikely event via random mutation. Disabling CRC validation allows malformed chunks to reach the deeper parsing logic (chunk handlers, decompression, row filtering) where memory safety bugs are most likely to occur.

3. **In-memory I/O** — Instead of reading from files, the harness registers a custom `user_read_data` callback via `png_set_read_fn()`. This callback reads directly from the fuzzer-provided memory buffer, avoiding filesystem overhead and enabling libFuzzer to feed inputs at maximum speed.

4. **Full decode pipeline** — The harness exercises the complete PNG read path: `png_read_info()` → `png_get_IHDR()` → `png_set_interlace_handling()` → `png_start_read_image()` → row-by-row `png_read_row()` across all interlace passes. This ensures coverage of chunk parsing, zlib decompression, row filtering, and interlace reconstruction.

5. **Resource exhaustion guard** — Images exceeding 2 million total pixels are rejected early to prevent individual inputs from consuming excessive time or memory, which would reduce overall fuzzing throughput.

6. **RAII cleanup** — A `ScopedPngObject` struct ensures all libpng resources (read struct, info struct, row buffer) are freed on every exit path, including when libpng's internal error handling triggers a `longjmp`.

**Portability note:** The harness uses only public libpng API functions (`png_set_crc_action`, `png_jmpbuf`), making it compatible across libpng versions from 1.2.x through 1.6.x without modification. An earlier version of the harness used `#define PNG_INTERNAL` to directly manipulate `png_ptr->flags` for CRC bypass, which required version-specific struct knowledge. The current approach is both cleaner and portable.

### Instrumented Build (`build.sh`)

The build script downloads the libpng source code and compiles it with Homebrew LLVM using:

- **`-fsanitize=address,fuzzer`** in `CFLAGS` — At compile time, `-fsanitize=fuzzer` inserts inline 8-bit coverage counters at every basic block edge, while `-fsanitize=address` instruments every memory access for runtime error detection.
- **`-fsanitize=address`** only in `LDFLAGS` — The `fuzzer` flag is omitted from link flags during the library build because libFuzzer's `main()` is only needed in the final binary, and including it during configure's link tests would fail (no `LLVMFuzzerTestOneInput` symbol exists yet).

The final fuzz target is compiled with `-fsanitize=address,fuzzer` and linked against the instrumented static library (`libpng16.a`) and system zlib.

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

# 2. Build the fuzzer (downloads libpng 1.6.55, compiles everything)
bash build.sh

# 3. Verify the binary was created
ls -la fuzz_png
```

`build.sh` performs the following automatically:
1. Downloads `libpng-1.6.55.tar.gz` from SourceForge (if not already present)
2. Extracts the source and copies it to a `build/` directory
3. Runs `./configure --disable-shared` with instrumented `CC`/`CXX`
4. Compiles the fuzz harness and links it against the instrumented `libpng16.a`
5. Outputs the `fuzz_png` binary

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

For the production evaluation, we run the fuzzer against two versions of libpng — **1.2.56** (legacy, ~15,000 lines of C) and **1.6.55** (current, ~30,000 lines of C). We evaluate:

- How much of libpng's code the fuzzer manages to cover
- Whether any ASan violations are triggered
- Which chunk handlers and code paths are reached
- Where coverage growth stalls and why
- How the results compare across a legacy vs. modern release

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

### 6.1 libpng 1.2.56 (Legacy) — Summary

We previously ran 10-minute fuzzing campaigns against libpng 1.2.56, the legacy version commonly used as a fuzzing benchmark. Key results:

| Metric | Value |
|--------|-------|
| Instrumented counters | **3,118** |
| Coverage (edges) | **644 / 3,118** (20.7%) |
| Features | **2,065** |
| Corpus (deduplicated) | **371 inputs, 17 KB** |
| Executions/second | **~98,000** |
| Peak RSS | **429 MB** |
| ASan crashes | **0** |
| Seed baseline | **205 edges** |

Starting from 205 edges of seed coverage, the fuzzer grew to 644 edges — a **3.1x increase**. The fuzzer reached 27 unique functions beyond the seed, including handlers for `PLTE`, `bKGD`, `cHRM`, `gAMA`, `hIST`, `iCCP`, `oFFs`, `pCAL`, `pHYs`, `sBIT`, `sCAL`, `sPLT`, `sRGB`, `tEXt`, `tIME`, `tRNS`, `zTXt`, `IEND`, and internal routines like `png_do_read_interlace` and `png_read_filter_row`. No ASan violations were triggered, consistent with this version having been extensively fuzzed by Google's OSS-Fuzz and other researchers.

### 6.2 libpng 1.6.55 (Current Release)

#### Campaign Configuration

We ran the fuzzer against libpng 1.6.55 for **10 minutes** starting from the same single seed (69-byte, 1x1 pixel PNG):

| Metric | Value |
|--------|-------|
| Instrumented counters | **6,680** |
| Coverage (edges) | **987 / 6,680** (14.8%) |
| Features | **4,241** |
| Corpus (deduplicated) | **931 inputs, 167 KB** |
| Corpus on disk | **1,216 inputs** |
| Executions/second | **~95,000** |
| Peak RSS | **424 MB** |
| ASan crashes | **0** |
| Seed baseline | **269 edges** |

#### Coverage Analysis

libpng 1.6.55 has **6,680 instrumented counters** — more than **2x** the 3,118 in version 1.2.56, reflecting substantial codebase growth over the 1.2→1.6 major version gap (new chunk handlers, improved validation, ARM NEON-optimized filter routines, and additional safety checks).

Starting from 269 edges of seed coverage, the fuzzer grew to 987 edges — a **3.7x increase** and significantly more absolute coverage than the 644 edges achieved on 1.2.56. However, as a percentage of the instrumented codebase, coverage was **14.8%** vs. 20.7% for 1.2.56, reflecting the larger attack surface in 1.6.55.

| Metric | libpng 1.2.56 | libpng 1.6.55 | Change |
|--------|---------------|---------------|--------|
| Instrumented counters | 3,118 | 6,680 | **+114%** |
| Edges covered | 644 | 987 | **+53%** |
| Coverage % | 20.7% | 14.8% | -5.9 pp |
| Features | 2,065 | 4,241 | **+105%** |
| Corpus size | 371 / 17 KB | 931 / 167 KB | **+151% / +882%** |
| Seed baseline | 205 | 269 | **+31%** |
| Coverage multiplier | 3.1x | 3.7x | — |

The feature count more than doubled (2,065 → 4,241), indicating substantially more diverse execution patterns in the 1.6.55 codebase. The corpus was also much larger and heavier (931 inputs / 167 KB vs. 371 / 17 KB), suggesting the fuzzer found more structurally distinct inputs worth retaining.

#### Functions Reached

The fuzzer discovered **26 unique functions** beyond the seed baseline, including:

- **Chunk handlers:** `png_handle_PLTE`, `png_handle_tRNS`, `png_handle_zTXt`, `png_handle_unknown`
- **Filter routines:** `png_read_filter_row_sub`, `png_read_filter_row_avg`, `png_read_filter_row_paeth_1byte_pixel`, `png_read_filter_row_paeth_multibyte_pixel`
- **ARM NEON optimizations:** `png_read_filter_row_sub3_neon`, `png_read_filter_row_sub4_neon`, `png_read_filter_row_up_neon`, `png_read_filter_row_avg3_neon`, `png_read_filter_row_avg4_neon`, `png_read_filter_row_paeth4_neon`
- **Internal routines:** `png_do_read_interlace`, `png_crc_read`, `png_crc_finish`, `png_zstream_error`, `png_calloc`, `png_set_PLTE`
- **Error handling:** `png_error`, `png_default_error`, `png_chunk_error`, `png_chunk_warning`, `png_chunk_benign_error`, `png_format_buffer`

Notably, the 1.6.55 run reached ARM NEON-optimized filter row implementations (running on Apple Silicon), which do not exist in the 1.2.56 codebase. These NEON routines are performance-critical code with manual SIMD intrinsics — a class of code where memory safety bugs can easily hide.

#### Behaviors Observed

The fuzzer exercised a wide range of error-handling paths within libpng 1.6.55:

- **Invalid IHDR data** (218,604 occurrences) — The most common error. Malformed headers with invalid bit depths, color types, compression methods, filter methods, and interlace methods were consistently rejected.
- **PNG unsigned integer out of range** (64,989) — Fields with extreme values triggered integer validation.
- **IHDR: too long** (28,530) — A 1.6.x-specific check that rejects oversized IHDR chunks, not present in 1.2.56.
- **Invalid chunk types** (27,444+) — Chunks with null bytes, control characters, and non-ASCII tags exercised the unknown-chunk handler.
- **Decompression errors** — IDAT chunks with corrupt zlib streams triggered `invalid distance too far back` (21,227), `incorrect data check` (16,907), `incorrect header check` (12,070), `invalid stored block lengths` (3,675), and `invalid window size` (3,084).
- **Bad adaptive filter values** (17,013) — Row data with invalid filter bytes exercised filter validation.
- **Image dimension limits** — Inputs with zero dimensions (17,491 height / 12,143 width) and oversized dimensions (63,540 height / 27,543 width) were rejected.

#### Why No Crashes Were Found

No ASan violations were triggered during the 10-minute campaign against libpng 1.6.55. Several factors contribute to this result:

1. **libpng 1.6.55 is the current release with recent security fixes.** This version was released in February 2026 with fixes for CVE-2026-22695 and CVE-2026-22801 (heap buffer over-reads). The most recently discovered vulnerabilities have already been patched.

2. **Continuous fuzzing by OSS-Fuzz.** libpng has been continuously fuzzed by Google's OSS-Fuzz infrastructure since 2016, running millions of executions daily across multiple sanitizers. Shallow bugs reachable by generic mutation-based fuzzing have been systematically eliminated.

3. **Improved input validation in 1.6.x.** Compared to 1.2.56, the 1.6.x branch includes stricter IHDR validation (e.g., the `IHDR: too long` check), improved chunk length bounds checking, and hardened integer arithmetic. These defenses reduce the likelihood of malformed inputs reaching vulnerable code paths.

4. **Coverage plateau at ~15%.** The fuzzer exercised roughly one-seventh of the instrumented code. The unreached ~85% likely includes write-path code (our harness only reads), ICC profile processing, gamma correction pipelines, platform-specific I/O, and code guarded by complex multi-chunk state conditions.

## 7. Comparative Analysis

### Version Comparison

The two libpng versions present meaningfully different fuzzing targets:

| Aspect | libpng 1.2.56 | libpng 1.6.55 |
|--------|---------------|---------------|
| Codebase size | ~15K LOC, 3,118 counters | ~30K LOC, 6,680 counters |
| Architecture | Pure C, portable | C + ARM NEON intrinsics |
| Input validation | Basic checks | Stricter bounds, length checks |
| CRC bypass | Required `PNG_INTERNAL` struct access | Public API (`png_set_crc_action`) |
| Error handling | `png_error` / `png_warning` | + `png_chunk_benign_error`, richer error taxonomy |
| Fuzzer throughput | ~98K exec/s | ~95K exec/s |
| Coverage achieved | 20.7% | 14.8% |

Despite the larger codebase, throughput remained comparable (~95K vs. ~98K exec/s), indicating the additional 1.6.x code does not significantly impact per-input execution time. The lower coverage percentage reflects the increased codebase surface area rather than reduced fuzzer effectiveness — the fuzzer actually covered **53% more absolute edges** in 1.6.55.

### Key Findings

1. **No memory safety bugs found in either version.** Both libpng 1.2.56 and 1.6.55 withstood 10 minutes of coverage-guided fuzzing with ASan enabled. This is consistent with both versions having been hardened through years of continuous fuzzing.

2. **The fuzzer achieves consistent ~3–4x coverage amplification** from the seed baseline regardless of version, suggesting the coverage multiplier is a property of the fuzzer's exploration strategy rather than the target.

3. **Coverage percentage decreases with codebase size** (20.7% → 14.8%) despite more absolute coverage, highlighting that larger targets require proportionally more fuzzing effort or smarter mutation strategies.

4. **Corpus characteristics differ significantly.** The 1.6.55 corpus was 2.5x larger in count and 10x larger in bytes, suggesting the newer codebase has more distinct reachable states — likely due to additional chunk handlers, stricter validation branches, and NEON-specific code paths.

### Path Forward

To increase the likelihood of finding bugs, future campaigns could:

- **Run for significantly longer** (hours/days) — our results show diminishing returns within 10 minutes, but deeper state-dependent bugs may require sustained exploration
- **Use a richer seed corpus** with diverse PNG files (different color types, interlacing, ancillary chunks) to start with higher baseline coverage
- **Use structure-aware mutation** (e.g., Google's `png_mutator.h`) to generate mutations that respect PNG chunk boundaries, enabling the fuzzer to produce structurally valid inputs that pass early validation checks
- **Add a custom dictionary** of PNG chunk type tags to help the fuzzer discover chunk handlers more quickly
- **Combine with other sanitizers** (UBSan, MSan) to detect undefined behavior and uninitialized memory reads that ASan does not cover
- **Target intermediate versions** between 1.2.56 and 1.6.55 where known CVEs were present but not yet patched, to validate that the fuzzer can rediscover real-world vulnerabilities

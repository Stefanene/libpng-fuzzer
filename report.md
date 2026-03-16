# Finding Memory Safety Bugs in libpng using Coverage-Guided Fuzzing

**Authors:** Stefan Ene, Younes Bennani
**Course:** CS 295 — Software Engineering

---

## 1. System Description

We evaluate **coverage-guided fuzzing** as a bug-finding approach for detecting memory safety violations in C programs that parse structured binary input. Our system combines two LLVM-based tools:

- **libFuzzer** — a coverage-guided, mutation-based fuzzer that generates inputs, feeds them to a target function, and uses code coverage feedback to prioritize inputs that explore new execution paths.
- **AddressSanitizer (ASan)** — a compile-time memory error detector that instruments every memory access to detect buffer overflows, out-of-bounds reads/writes, use-after-free, and other memory safety violations at runtime.
- **UndefinedBehaviorSanitizer (UBSan)** — a compile-time detector for undefined behavior including signed integer overflow, invalid shifts, null pointer dereference, and out-of-bounds array indexing. UBSan catches a class of bugs that ASan cannot detect.

**Class of bugs targeted:**

- Buffer overflows (stack and heap)
- Out-of-bounds memory reads and writes
- Invalid memory accesses
- Undefined behavior (integer overflow, invalid shifts, null dereference)
- Program crashes caused by malformed input

**Target application:** We target **libpng**, an open-source C library for parsing PNG image files. libpng is widely used in image processing software, web browsers, and scientific computing libraries. It is a compelling fuzzing target because it processes complex structured input (the PNG format includes headers, chunks with CRC checksums, and zlib-compressed image data), is written in C (a language without memory safety guarantees), and has a documented history of memory safety vulnerabilities. We evaluate two versions:

- **libpng 1.2.56** — A legacy release from the 1.2.x branch, commonly used as a fuzzing benchmark (e.g., in Google's fuzzer-test-suite).
- **libpng 1.6.55** — The latest stable release (February 2026), representing the current state of libpng with modern security hardening and recent CVE fixes.

## 2. Technical Overview

### Fuzz Harness (`fuzz_target.cc`)

The core of our system is a fuzz harness that implements the `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` entry point. libFuzzer calls this function repeatedly with mutated inputs. The harness performs two decode passes per input — a low-level row-by-row decode with browser-typical transforms, and a high-level decode using the simplified `png_image` API — to maximize code coverage across libpng's two distinct reading interfaces.

#### Low-Level Decode Path

1. **PNG signature validation** — The harness rejects inputs that do not begin with the 8-byte PNG magic number (`89 50 4E 47 0D 0A 1A 0A`). This ensures the fuzzer focuses its mutation budget on structurally plausible PNG data rather than wasting cycles on inputs that are immediately rejected.

2. **CRC and ADLER32 bypass** — The harness disables both CRC checking on PNG chunks and ADLER32 checking on zlib streams:
   ```c
   png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
   png_set_option(png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
   ```
   Disabling CRC validation allows malformed chunks to reach the deeper parsing logic. Disabling ADLER32 allows mutated compressed data inside IDAT chunks to reach the decompression and row-filtering paths, where memory safety bugs are most likely to occur. Without this, virtually all mutations to compressed data would be rejected at the ADLER32 check before reaching any interesting code.

3. **Custom memory allocator** — The harness installs a custom allocator via `png_set_mem_fn()` that rejects allocations larger than 8 MB. This prevents a single malformed input (e.g., claiming enormous image dimensions) from triggering an OOM kill that terminates the fuzzer process, allowing such inputs to fail gracefully through libpng's error handler instead.

4. **In-memory I/O** — Instead of reading from files, the harness registers a custom `user_read_data` callback via `png_set_read_fn()`. This callback reads directly from the fuzzer-provided memory buffer, avoiding filesystem overhead and enabling libFuzzer to feed inputs at maximum speed.

5. **Browser-typical image transforms** — After reading the PNG header, the harness applies five transforms commonly used by web browsers:
   ```c
   png_set_gray_to_rgb(png_ptr);      // grayscale → RGB conversion
   png_set_expand(png_ptr);           // palette/tRNS expansion
   png_set_packing(png_ptr);          // sub-byte unpacking
   png_set_scale_16(png_ptr);         // 16-bit → 8-bit scaling
   png_set_tRNS_to_alpha(png_ptr);    // transparency → alpha channel
   ```
   These transforms exercise `png_do_expand()`, `png_do_gray_to_rgb()`, `png_do_unpack()`, `png_do_chop()`, and `png_do_expand_palette()` — a large portion of `pngrtran.c` that would otherwise be entirely unreachable.

6. **Full decode pipeline** — The harness exercises the complete PNG read path: `png_read_info()` → `png_get_IHDR()` → transforms → `png_read_update_info()` → `png_set_interlace_handling()` → row-by-row `png_read_row()` across all interlace passes → `png_read_end()`. The call to `png_read_end()` is critical: it processes post-IDAT chunks (tEXt, zTXt, iTXt, tIME) that are only parsed after image data, exercising text chunk decompression and metadata handling code.

7. **Resource exhaustion guard** — Images exceeding 100 million total pixels are rejected early to prevent individual inputs from consuming excessive time or memory, which would reduce overall fuzzing throughput.

8. **RAII cleanup** — A `ScopedPngObject` struct ensures all libpng resources (read struct, info struct, end info struct, row buffer) are freed on every exit path, including when libpng's internal error handling triggers a `longjmp`.

#### Simplified READ API Path

After the low-level decode completes and cleans up, the harness performs a second decode of the same input using `png_image_begin_read_from_memory()` and `png_image_finish_read()`. This exercises an entirely separate code path within libpng (`pngread.c`'s simplified API) including its own internal transform pipeline, colorspace conversion, and error handling. Dimension limits (1024x1024, 5 MB buffer) prevent resource exhaustion.

**Portability note:** The harness uses only public libpng API functions (`png_set_crc_action`, `png_set_option`, `png_jmpbuf`, `png_set_mem_fn`), making it compatible across libpng versions from 1.2.x through 1.6.x without modification.

### Instrumented Build (`build.sh`)

The build script downloads the libpng source code and compiles it with Homebrew LLVM using:

- **`-fsanitize=address,undefined,fuzzer`** in `CFLAGS` — At compile time, `-fsanitize=fuzzer` inserts inline 8-bit coverage counters at every basic block edge, `-fsanitize=address` instruments every memory access for runtime error detection, and `-fsanitize=undefined` instruments arithmetic and pointer operations to detect undefined behavior (integer overflow, invalid shifts, null dereference, out-of-bounds indexing).
- **`-fno-sanitize-recover=all`** — Makes all sanitizer violations fatal, so UBSan findings are treated as crashes by libFuzzer (producing `crash-*` files for reproduction).
- **`-DPNG_DISABLE_ADLER32_CHECK_SUPPORTED`** — Enables the compile-time option that allows the harness to disable ADLER32 checking at runtime via `png_set_option()`.
- **`-fsanitize=address,undefined`** only in `LDFLAGS` — The `fuzzer` flag is omitted from link flags during the library build because libFuzzer's `main()` is only needed in the final binary, and including it during configure's link tests would fail (no `LLVMFuzzerTestOneInput` symbol exists yet).

The final fuzz target is compiled with `-fsanitize=address,undefined,fuzzer` and linked against the instrumented static library (`libpng16.a`) and system zlib.

### Seed Corpus

The `seeds/` directory contains 30 PNG files drawn from the **PNGSuite** test set bundled with libpng. The corpus covers all standard color types and bit depths:

| Color type | Seeds | Bit depths |
|-----------|-------|------------|
| Grayscale | `basn0g01`–`basn0g16` | 1, 2, 4, 8, 16 |
| Truecolor (RGB) | `basn2c08`, `basn2c16` | 8, 16 |
| Paletted | `basn3p01`–`basn3p08` | 1, 2, 4, 8 |
| Gray + Alpha | `basn4a08`, `basn4a16` | 8, 16 |
| RGBA | `basn6a08`, `basn6a16` | 8, 16 |
| Interlaced (Adam7) | `ibasn*` (7 files) | Various |
| Transparency (tRNS) | `ftbbn*` (5 files) | Various |

Starting from structurally diverse seeds is essential for coverage. Each color type and bit depth exercises different code paths in the decoder and transform pipeline (e.g., palette expansion, grayscale-to-RGB conversion, 16-bit scaling). Without diverse seeds, the fuzzer would need to discover these structural variations through random mutation — a slow process for complex binary formats.

### Fuzzer Dictionary

The `png.dict` file provides libFuzzer with all 25 standard PNG chunk type tags (IHDR, PLTE, tRNS, iCCP, gAMA, sRGB, etc.) plus the 8-byte PNG signature. Without a dictionary, the fuzzer must discover these 4-byte tokens by chance mutation. With the dictionary, the fuzzer can splice known chunk tags into inputs immediately, dramatically accelerating the discovery of chunk handler code paths.

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

We ran the enhanced harness against libpng 1.6.55 for **10 minutes** using the full suite of improvements: 30 diverse seeds from PNGSuite, the `png.dict` chunk type dictionary, browser-typical image transforms, ADLER32 checksum bypass, custom memory allocator, `png_read_end()` for post-IDAT chunks, the simplified `png_image` READ API, and both ASan and UBSan instrumentation.

| Metric | Value |
|--------|-------|
| Instrumented counters | **6,680** |
| Coverage (edges) | **1,521 / 6,680** (22.8%) |
| Features | **5,976** |
| Corpus (deduplicated) | **1,544 inputs, 915 KB** |
| Corpus on disk | **1,516 inputs** |
| Total executions | **21,581,148** |
| Executions/second | **~35,900** |
| Peak RSS | **605 MB** |
| ASan/UBSan crashes | **0** |
| Seed baseline | **889 edges** |

#### Coverage Analysis

libpng 1.6.55 has **6,680 instrumented counters** — more than **2x** the 3,118 in version 1.2.56, reflecting substantial codebase growth over the 1.2→1.6 major version gap (new chunk handlers, improved validation, ARM NEON-optimized filter routines, and additional safety checks).

Starting from **889 edges** of seed coverage (vs. 269 with the original single-seed harness), the enhanced fuzzer grew to **1,521 edges** — a **1.7x increase** from the seed baseline and a **54% improvement in absolute edge coverage** over the original harness's 987 edges. As a percentage of the instrumented codebase, coverage reached **22.8%**, surpassing even the 1.2.56 result (20.7%).

| Metric | libpng 1.2.56 | libpng 1.6.55 | Change |
|--------|---------------|---------------|--------|
| Instrumented counters | 3,118 | 6,680 | **+114%** |
| Edges covered | 644 | 1,521 | **+136%** |
| Coverage % | 20.7% | 22.8% | +2.1 pp |
| Features | 2,065 | 5,976 | **+189%** |
| Corpus size | 371 / 17 KB | 1,544 / 915 KB | **+316% / +5,282%** |
| Seed baseline | 205 | 889 | **+334%** |

The feature count nearly tripled (2,065 → 5,976), indicating substantially more diverse execution patterns. The much higher seed baseline (889 vs. 269) demonstrates the impact of the expanded PNGSuite seed corpus — the diverse seeds immediately exercised color type conversions, bit depth handling, interlace processing, and transparency expansion that the original single-seed harness had to discover through mutation.

Throughput decreased from ~95K to ~36K exec/s due to the additional transforms, `png_read_end()`, and the second decode pass through the simplified API. However, the **54% improvement in edge coverage** and **41% improvement in feature count** over the original harness demonstrate that the higher coverage per input more than compensates for the reduced throughput.

#### Functions Reached

The fuzzer discovered **42 unique functions** beyond the seed baseline, including:

- **Chunk handlers:** `png_handle_PLTE`, `png_handle_tRNS`, `png_handle_zTXt`, `png_handle_iTXt`, `png_handle_tEXt`, `png_handle_unknown`, `png_handle_cHRM`, `png_handle_eXIf`, `png_handle_hIST`, `png_handle_iCCP`, `png_handle_pCAL`, `png_handle_sCAL`, `png_handle_sPLT`, `png_handle_sRGB`, `png_handle_tIME`, `png_handle_cLLI`
- **ARM NEON optimizations:** `png_read_filter_row_avg3_neon`
- **Data setters:** `png_set_PLTE`, `png_set_hIST`, `png_set_sCAL_s`, `png_set_sRGB`, `png_set_cHRM_fixed`, `png_set_cLLI_fixed`, `png_set_pCAL`, `png_set_text_2`, `png_set_tIME`, `png_set_sPLT`
- **Decompression:** `png_inflate`, `png_inflate_read`, `png_decompress_chunk`, `png_crc_finish`
- **Internal routines:** `png_zstream_error`, `png_malloc_array`, `png_realloc_array`, `png_get_int_32_checked`, `png_check_fp_number`, `png_check_fp_string`
- **Error handling:** `png_error`, `png_default_error`, `png_safe_error`, `png_warning`, `png_benign_error`, `png_chunk_warning`, `png_chunk_benign_error`, `png_chunk_report`

Compared to the original harness's 26 functions, the enhanced harness reached **42 unique functions** — a 62% increase. The most significant additions are the post-IDAT chunk handlers (`png_handle_iTXt`, `png_handle_tEXt`, `png_handle_tIME`) that were unreachable without `png_read_end()`, and the text decompression routines (`png_decompress_chunk`, `png_inflate`) triggered by compressed text chunks (zTXt, iTXt).

#### Behaviors Observed

The enhanced harness exercised a substantially wider range of error-handling and processing paths. With 21.5 million total executions, the error message frequencies reflect the deeper exploration:

- **Read errors** (2,803,429) — The most common event, triggered when the in-memory buffer is exhausted during chunk parsing.
- **Invalid IHDR data** (2,412,378) — Malformed headers with invalid bit depths, color types, compression methods, filter methods, and interlace methods.
- **PNG unsigned integer out of range** (1,863,702) — Fields with extreme values triggered integer validation.
- **Bad adaptive filter values** (1,797,855) — Row data with invalid filter bytes exercised filter validation. This was much more frequent than in the original run, reflecting the ADLER32 bypass allowing more mutated data to reach the row-filtering stage.
- **Decompression errors** — IDAT chunks with corrupt zlib streams triggered `invalid distance too far back` (846,596), `invalid literal/lengths set` (245,441), `invalid bit length repeat` (196,893), `incorrect header check` (100,700), and other zlib errors. These counts are 10–40x higher than the original run, confirming that the ADLER32 bypass is effective.
- **IHDR: too long** (258,540) — A 1.6.x-specific check that rejects oversized IHDR chunks.
- **Not enough image data** (250,166) — Truncated IDAT streams that exhaust before the full image is decoded.

The warning-level messages reveal the enhanced harness's deeper exploration of ancillary chunk processing:

- **Duplicate chunk warnings** — `gAMA: duplicate` (4,012,075), `tRNS: duplicate` (1,473,385), `bKGD: duplicate` (1,064,232) show the fuzzer generating inputs with repeated ancillary chunks.
- **Text chunk processing** — `zTXt: incorrect header check` (1,560,003), `iTXt: truncated` (733,260), `zTXt: unknown compression method` (706,191) confirm that `png_read_end()` is exercising compressed text chunk decompression.
- **Chunk validation** — `malformed sPLT chunk` (1,818,126), `PLTE: out of place` (1,609,533), `bKGD: invalid` (1,349,397), `sCAL: bad width format` (1,015,336), `pCAL: unrecognized equation type` (864,100) demonstrate thorough coverage of ancillary chunk parsers.
- **IDAT post-processing** — `Too many IDATs found` (731,439), `Extra compressed data` (601,326) exercise edge cases in the IDAT stream handling.

#### Why No Crashes Were Found

No ASan or UBSan violations were triggered during the 10-minute campaign against libpng 1.6.55. Several factors contribute to this result:

1. **libpng 1.6.55 is the current release with recent security fixes.** This version was released in February 2026 with fixes for CVE-2026-22695 and CVE-2026-22801 (heap buffer over-reads). The most recently discovered vulnerabilities have already been patched.

2. **Continuous fuzzing by OSS-Fuzz.** libpng has been continuously fuzzed by Google's OSS-Fuzz infrastructure since 2016, running millions of executions daily across multiple sanitizers (ASan, UBSan, MSan). Shallow bugs reachable by generic mutation-based fuzzing have been systematically eliminated.

3. **Improved input validation in 1.6.x.** Compared to 1.2.56, the 1.6.x branch includes stricter IHDR validation (e.g., the `IHDR: too long` check), improved chunk length bounds checking, and hardened integer arithmetic. These defenses reduce the likelihood of malformed inputs reaching vulnerable code paths.

4. **No UBSan findings.** The absence of undefined behavior violations (integer overflow, invalid shifts, null dereference) across 21.5 million executions confirms that libpng's arithmetic and pointer operations are well-guarded, consistent with the library's maturity.

5. **Coverage at ~23%.** Despite the substantial improvements, the fuzzer exercised roughly one-quarter of the instrumented code. The unreached ~77% likely includes write-path code (our harness only reads), ICC profile processing, gamma correction pipelines, platform-specific I/O, and code guarded by complex multi-chunk state conditions that would benefit from structure-aware mutation.

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
| Sanitizers | ASan only | ASan + UBSan |
| Fuzzer throughput | ~98K exec/s | ~36K exec/s |
| Coverage achieved | 20.7% | 22.8% |

The 1.6.55 campaign used the enhanced harness with image transforms, ADLER32 bypass, `png_read_end()`, simplified API, dictionary, and expanded seeds. Throughput decreased from ~98K to ~36K exec/s due to the additional per-input work (transforms, two decode passes), but edge coverage increased from 14.8% (original harness) to **22.8%**, now surpassing even the 1.2.56 result despite the 2x larger codebase.

### Key Findings

1. **No memory safety bugs found in either version.** Both libpng 1.2.56 and 1.6.55 withstood 10 minutes of coverage-guided fuzzing with ASan (and UBSan for 1.6.55) enabled. This is consistent with both versions having been hardened through years of continuous fuzzing.

2. **Harness quality matters more than throughput.** The enhanced harness achieved **54% more edge coverage** (1,521 vs. 987) despite running at **38% of the throughput** (36K vs. 95K exec/s). The improvements — transforms, ADLER32 bypass, diverse seeds, dictionary, and simplified API — each unlocked code regions that were structurally unreachable by the original harness regardless of how long it ran.

3. **Seed diversity provides outsized returns.** The expanded seed corpus alone raised the baseline from 269 to 889 edges — a **3.3x increase** — before any fuzzing occurred. This demonstrates that for structured binary formats like PNG, seed selection is one of the highest-leverage optimizations.

4. **Checksum bypass is critical for decompression coverage.** The ADLER32 bypass increased decompression-related error messages by 10–40x, confirming that without it, virtually all mutations to compressed data were rejected before reaching interesting code.

5. **Corpus characteristics differ significantly.** The 1.6.55 corpus was 4.2x larger in count and 54x larger in bytes than the 1.2.56 corpus, reflecting the combination of a larger codebase, richer seeds, and more code paths opened by the enhanced harness.

### Harness Improvements

After the initial evaluation, we enhanced the harness with several optimizations inspired by the OSS-Fuzz harnesses bundled with libpng 1.6.55 (`contrib/oss-fuzz/`):

| Improvement | Impact |
|------------|--------|
| **PNG dictionary** (`png.dict`) | Provides 25 chunk type tags for guided mutation; accelerates chunk handler discovery |
| **Expanded seed corpus** (30 PNGs) | Covers all color types, bit depths, interlacing, and transparency from PNGSuite |
| **ADLER32 bypass** | Lets mutated zlib streams reach decompression/row-filter code |
| **Browser-typical transforms** | Exercises `png_do_expand`, `png_do_gray_to_rgb`, `png_do_unpack`, `png_do_chop`, `png_do_expand_palette` |
| **`png_read_end()`** | Exercises post-IDAT chunk handlers (tEXt, zTXt, iTXt, tIME) |
| **Custom memory allocator** | Prevents OOM kills from oversized allocation requests |
| **Simplified READ API** | Exercises `png_image_begin_read_from_memory` / `png_image_finish_read` — a separate code path |
| **UBSan** | Detects integer overflow, shift errors, null dereference — bugs ASan misses |

In the full 10-minute campaign, the enhanced harness reached **1,521 edges** (22.8%) — a **54% improvement** over the original harness's 987 edges (14.8%). Feature count increased by 41% (5,976 vs. 4,241), and the number of unique functions discovered increased by 62% (42 vs. 26). Throughput decreased from ~95K to ~36K exec/s due to the additional transforms and dual decode passes, but the substantially higher coverage per input more than compensates.

### Path Forward

To further increase the likelihood of finding bugs, future campaigns could:

- **Run for significantly longer** (hours/days) — deeper state-dependent bugs may require sustained exploration
- **Use structure-aware mutation** (e.g., Google's `png_mutator.h`) to generate mutations that respect PNG chunk boundaries
- **Add specialized harnesses** for color quantization (`png_set_quantize`), alpha transforms, and the colormap API (`PNG_FORMAT_RGB_COLORMAP`) to cover additional code in `pngrtran.c`
- **Add MSan** (MemorySanitizer) to detect uninitialized memory reads — a separate bug class from ASan and UBSan
- **Target intermediate versions** between 1.2.56 and 1.6.55 where known CVEs were present but not yet patched, to validate that the fuzzer can rediscover real-world vulnerabilities

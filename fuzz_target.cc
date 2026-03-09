// Fuzz target for libpng-1.2.56
// Adapted from Google's fuzzer-test-suite (Apache 2.0)
// https://github.com/google/fuzzer-test-suite/tree/master/libpng-1.2.56

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define PNG_INTERNAL
#include "png.h"

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

void user_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

static const int kPngHeaderSize = 8;

// RAII wrapper for libpng resources.
struct ScopedPngObject {
  ~ScopedPngObject() {
    if (row && png_ptr) {
      png_free(png_ptr, row);
    }
    if (png_ptr && info_ptr) {
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    }
    delete buf_state;
  }
  png_infop info_ptr = nullptr;
  png_voidp row = 0;
  png_structp png_ptr = nullptr;
  BufState *buf_state = nullptr;
};

// Entry point for libFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  // Verify PNG signature before proceeding.
  if (png_sig_cmp(const_cast<uint8_t*>(data), 0, kPngHeaderSize)) {
    return 0;
  }

  ScopedPngObject O;

  auto &png_ptr = O.png_ptr;
  png_ptr = png_create_read_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  assert(png_ptr);

  // Disable CRC checking so malformed chunks are still processed.
  png_ptr->flags &= ~PNG_FLAG_CRC_CRITICAL_MASK;
  png_ptr->flags |= PNG_FLAG_CRC_CRITICAL_IGNORE;
  png_ptr->flags &= ~PNG_FLAG_CRC_ANCILLARY_MASK;
  png_ptr->flags |= PNG_FLAG_CRC_ANCILLARY_NOWARN;

  auto &info_ptr = O.info_ptr;
  info_ptr = png_create_info_struct(png_ptr);
  assert(info_ptr);

  // Set up reading from the in-memory buffer.
  auto &buf_state = O.buf_state;
  buf_state = new BufState();
  buf_state->data = data + kPngHeaderSize;
  buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_ptr, buf_state, user_read_data);
  png_set_sig_bytes(png_ptr, kPngHeaderSize);

  // libpng error handling — longjmp back here on errors.
  if (setjmp(png_ptr->jmpbuf)) {
    return 0;
  }

  // Read the PNG header and image info.
  png_read_info(png_ptr, info_ptr);

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type, filter_type;

  if (!png_get_IHDR(png_ptr, info_ptr, &width, &height,
                    &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    return 0;
  }

  // Skip very large images to avoid timeouts.
  if (static_cast<uint64_t>(height) * width > 2000000) {
    return 0;
  }

  int passes = png_set_interlace_handling(png_ptr);
  png_start_read_image(png_ptr);

  O.row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_ptr, static_cast<png_bytep>(O.row), NULL);
    }
  }

  return 0;
}

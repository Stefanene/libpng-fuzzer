// Fuzz target for libpng 1.6.55
// Enhanced harness with image transforms, ADLER32 bypass, custom allocator,
// post-IDAT chunk processing, and simplified READ API coverage.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <vector>

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

// Custom allocator that rejects large allocations to prevent OOM kills
void* limited_malloc(png_structp, png_alloc_size_t size) {
  if (size > 8000000)
    return nullptr;
  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

static const int kPngHeaderSize = 8;

// RAII wrapper for libpng resources
struct ScopedPngObject {
  ~ScopedPngObject() {
    if (row && png_ptr) {
      png_free(png_ptr, row);
    }
    if (png_ptr && end_info_ptr) {
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    } else if (png_ptr && info_ptr) {
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    } else if (png_ptr) {
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    }
    delete buf_state;
  }
  png_infop info_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row = nullptr;
  png_structp png_ptr = nullptr;
  BufState *buf_state = nullptr;
};


// Entry point for libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  // Verify PNG signature before proceeding
  if (png_sig_cmp(const_cast<uint8_t*>(data), 0, kPngHeaderSize)) {
    return 0;
  }

  // ---- Low-level decode with transforms ----
  {
    ScopedPngObject O;

    auto &png_ptr = O.png_ptr;
    png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;

    // Custom allocator: reject allocations > 8 MB to avoid OOM
    png_set_mem_fn(png_ptr, nullptr, limited_malloc, default_free);

    // Disable CRC checking so malformed chunks are still processed
    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

    // Disable ADLER32 checking so mutated zlib streams reach deeper code
#ifdef PNG_IGNORE_ADLER32
    png_set_option(png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

    auto &info_ptr = O.info_ptr;
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) return 0;

    O.end_info_ptr = png_create_info_struct(png_ptr);
    if (!O.end_info_ptr) return 0;

    // Set up reading from the in-memory buffer
    auto &buf_state = O.buf_state;
    buf_state = new BufState();
    buf_state->data = data + kPngHeaderSize;
    buf_state->bytes_left = size - kPngHeaderSize;
    png_set_read_fn(png_ptr, buf_state, user_read_data);
    png_set_sig_bytes(png_ptr, kPngHeaderSize);

    // libpng error handling (longjmp back here on errors)
    if (setjmp(png_jmpbuf(png_ptr))) {
      return 0;
    }

    // Read the PNG header and image info
    png_read_info(png_ptr, info_ptr);

    png_uint_32 width, height;
    int bit_depth, color_type, interlace_type, compression_type, filter_type;

    if (!png_get_IHDR(png_ptr, info_ptr, &width, &height,
                      &bit_depth, &color_type, &interlace_type,
                      &compression_type, &filter_type)) {
      return 0;
    }

    // Skip very large images to avoid timeouts
    if (width && height > 100000000 / width) {
      return 0;
    }

    // Apply browser-typical transforms to exercise the transform pipeline
    png_set_gray_to_rgb(png_ptr);
    png_set_expand(png_ptr);
    png_set_packing(png_ptr);
    png_set_scale_16(png_ptr);
    png_set_tRNS_to_alpha(png_ptr);

    int passes = png_set_interlace_handling(png_ptr);
    png_read_update_info(png_ptr, info_ptr);

    // Allocate row buffer AFTER transforms (row size may have changed)
    O.row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));

    for (int pass = 0; pass < passes; ++pass) {
      for (png_uint_32 y = 0; y < height; ++y) {
        png_read_row(png_ptr, static_cast<png_bytep>(O.row), nullptr);
      }
    }

    // Read post-IDAT chunks (tEXt, zTXt, iTXt, tIME, etc.)
    png_read_end(png_ptr, O.end_info_ptr);
  }

  // ---- Simplified READ API (separate code path) ----
#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
  {
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;

    if (png_image_begin_read_from_memory(&image, data, size)) {
      if (image.width <= 1024 && image.height <= 1024) {
        image.format = PNG_FORMAT_RGBA;
        size_t buf_size = PNG_IMAGE_SIZE(image);
        if (buf_size > 0 && buf_size < 5 * 1024 * 1024) {
          std::vector<png_byte> buffer(buf_size);
          png_image_finish_read(&image, nullptr, buffer.data(), 0, nullptr);
        }
      }
      png_image_free(&image);
    }
  }
#endif

  return 0;
}

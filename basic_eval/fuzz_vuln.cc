// fuzz_vuln.cc — libFuzzer harness for the toy vulnerable parser.

#include <stddef.h>
#include <stdint.h>

extern "C" int parse_image_header(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_image_header(data, size);
    return 0;
}

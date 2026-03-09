// vuln_parser.c — Toy "image header" parser with planted memory safety bugs.
// Used to validate the fuzzing approach on a controlled target.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Stack buffer overflow
// If the "name" field length exceeds 32 bytes, memcpy overflows a stack buffer.
static int parse_name_field(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    uint8_t name_len = data[0];
    if (name_len == 0 || (size_t)name_len + 1 > size) return 0;

    char name[32];  // Fixed-size stack buffer
    memcpy(name, data + 1, name_len);  // BUG: no bounds check against sizeof(name)
    name[name_len] = '\0';
    return 1;
}

// Bug 2: Heap out-of-bounds read
// Allocates a buffer based on a "width" field but reads "height" bytes from input,
// where height can exceed the allocation.
static int parse_dimensions(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint16_t width  = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t height = (uint16_t)(data[2] | (data[3] << 8));

    if (width == 0 || height == 0) return 0;
    if (width > 1024) return 0;  // Some validation, but not enough

    uint8_t *buf = (uint8_t *)malloc(width);
    if (!buf) return 0;

    // BUG: reads 'height' bytes into a buffer of size 'width'
    // when height > width, this is a heap buffer overflow
    size_t read_len = height < (size - 4) ? height : (size - 4);
    memcpy(buf, data + 4, read_len);  // BUG when read_len > width

    volatile uint8_t sum = 0;
    for (size_t i = 0; i < read_len; i++) {
        sum += buf[i];  // BUG: OOB read when read_len > width
    }

    free(buf);
    return 1;
}

// Entry point called by the fuzz harness.
// Dispatches to sub-parsers based on a "type" byte.
int parse_image_header(const uint8_t *data, size_t size) {
    if (size < 5) return 0;

    // Magic bytes: 0xDE 0xAD
    if (data[0] != 0xDE || data[1] != 0xAD) return 0;

    uint8_t type = data[2];
    const uint8_t *payload = data + 3;
    size_t payload_size = size - 3;

    switch (type) {
        case 0x01:
            return parse_name_field(payload, payload_size);
        case 0x02:
            return parse_dimensions(payload, payload_size);
        default:
            return 0;
    }
}

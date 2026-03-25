/*
 * Buggy library: triggers a heap-buffer-overflow detectable by ASan.
 * The overflow writes one byte past the end of a 64-byte allocation.
 */

#include <stdlib.h>

void buggy_heap_overflow(void) {
    volatile char *buf = (volatile char *)malloc(64);
    buf[64] = 0x41; /* heap-buffer-overflow: 1 byte past end */
    free((void *)buf);
}

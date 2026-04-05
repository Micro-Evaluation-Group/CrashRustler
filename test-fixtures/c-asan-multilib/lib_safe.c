/*
 * Safe library: performs valid heap operations with no sanitizer violations.
 * Compiled with -fsanitize=address to have ASan instrumentation loaded,
 * but never triggers an error.
 */

#include <stdlib.h>
#include <string.h>

void safe_heap_operation(void) {
    volatile char *buf = (volatile char *)malloc(64);
    memset((void *)buf, 0x42, 64);
    free((void *)buf);
}

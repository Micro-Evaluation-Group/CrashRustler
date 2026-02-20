/*
 * Integer sanitizer crash dummy: triggers -fsanitize=integer-detected errors.
 *
 * Used by integration tests to exercise exc_handler's handling of integer
 * sanitizer errors from clang-compiled C binaries. Accepts one CLI arg to
 * select the crash mode.
 *
 * Must be compiled with:
 *   clang -fsanitize=integer -fno-sanitize-recover=integer -O1 -fno-omit-frame-pointer
 *
 * The -fno-sanitize-recover=integer flag is required to make the sanitizer
 * abort on error (default behavior is to print and continue).
 *
 * These checks are unique to -fsanitize=integer and NOT covered by
 * -fsanitize=undefined: unsigned-integer-overflow, unsigned-shift-base,
 * implicit-unsigned-integer-truncation, implicit-signed-integer-truncation.
 *
 * When --wait is passed, prints its PID to stdout and blocks until SIGUSR1
 * is received, allowing exc_handler to attach via PID before the crash.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void sigusr1_handler(int sig) { (void)sig; }

static void wait_for_signal(void) {
    signal(SIGUSR1, sigusr1_handler);
    printf("%d\n", getpid());
    fflush(stdout);
    pause();
}

/* Unsigned integer overflow: 0u - 1 wraps. */
__attribute__((noinline))
static void do_unsigned_overflow(void) {
    volatile unsigned int x = 0;
    volatile unsigned int y = x - 1;
    (void)y;
}

/* Unsigned shift base overflow: left shift overflows unsigned. */
__attribute__((noinline))
static void do_unsigned_shift_base(void) {
    volatile unsigned int x = 0x80000001u;
    volatile unsigned int y = x << 1;
    (void)y;
}

/* Implicit unsigned integer truncation: uint32_t to uint8_t loses data. */
__attribute__((noinline))
static void do_implicit_unsigned_truncation(void) {
    volatile uint32_t x = 0xDEADBEEFu;
    volatile uint8_t y = x;
    (void)y;
}

/* Implicit signed integer truncation: int to signed char loses data. */
__attribute__((noinline))
static void do_implicit_signed_truncation(void) {
    volatile int x = 0x1234;
    volatile signed char y = x;
    (void)y;
}

int main(int argc, char *argv[]) {
    int wait = 0;
    const char *mode = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wait") == 0)
            wait = 1;
        else if (!mode)
            mode = argv[i];
    }

    if (!mode) {
        fprintf(stderr,
            "Usage: c-intsan-crash-dummy [--wait] "
            "<unsigned_overflow|unsigned_shift_base|"
            "implicit_unsigned_truncation|implicit_signed_truncation>\n");
        return 2;
    }

    if (wait)
        wait_for_signal();

    if (strcmp(mode, "unsigned_overflow") == 0)
        do_unsigned_overflow();
    else if (strcmp(mode, "unsigned_shift_base") == 0)
        do_unsigned_shift_base();
    else if (strcmp(mode, "implicit_unsigned_truncation") == 0)
        do_implicit_unsigned_truncation();
    else if (strcmp(mode, "implicit_signed_truncation") == 0)
        do_implicit_signed_truncation();
    else {
        fprintf(stderr, "Unknown crash mode: %s\n", mode);
        return 2;
    }

    return 0;
}

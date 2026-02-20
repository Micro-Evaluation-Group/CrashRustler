/*
 * UBSan crash dummy: triggers UndefinedBehaviorSanitizer-detected errors.
 *
 * Used by integration tests to exercise exc_handler's handling of UBSan-detected
 * crashes from clang-compiled C binaries. Accepts one CLI arg to select the
 * crash mode.
 *
 * Must be compiled with:
 *   clang -fsanitize=undefined -fno-sanitize-recover=undefined -O1 -fno-omit-frame-pointer
 *
 * The -fno-sanitize-recover=undefined flag is required to make UBSan abort on
 * error (default behavior is to print and continue).
 *
 * When --wait is passed, prints its PID to stdout and blocks until SIGUSR1
 * is received, allowing exc_handler to attach via PID before the crash.
 */

#include <limits.h>
#include <signal.h>
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

/* Shift exponent larger than bit width of the type. */
__attribute__((noinline))
static void do_shift_overflow(void) {
    volatile int x = 1;
    volatile int y = 32;
    volatile int z = x << y;
    (void)z;
}

/* Signed integer overflow: INT_MAX + 1. */
__attribute__((noinline))
static void do_signed_overflow(void) {
    volatile int x = INT_MAX;
    volatile int y = x + 1;
    (void)y;
}

/* Integer division by zero. */
__attribute__((noinline))
static void do_divide_by_zero(void) {
    volatile int x = 1;
    volatile int y = 0;
    volatile int z = x / y;
    (void)z;
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
            "Usage: c-ubsan-crash-dummy [--wait] "
            "<shift_overflow|signed_overflow|divide_by_zero>\n");
        return 2;
    }

    if (wait)
        wait_for_signal();

    if (strcmp(mode, "shift_overflow") == 0)
        do_shift_overflow();
    else if (strcmp(mode, "signed_overflow") == 0)
        do_signed_overflow();
    else if (strcmp(mode, "divide_by_zero") == 0)
        do_divide_by_zero();
    else {
        fprintf(stderr, "Unknown crash mode: %s\n", mode);
        return 2;
    }

    return 0;
}
